#!/usr/bin/env python3

import time
import json
import re
import os
from datetime import datetime, timedelta, timezone

import requests

API_ENDPOINT = "http://18.142.200.244:5000/api/correlation"
API_KEY = "ids_vm_secret_key_123"
CORRELATOR_AGENT_ID = os.environ.get("AGENT_ID", "vm-correlator-01")
AGENT_NAME = os.environ.get("AGENT_NAME", "agent2")

# ---------- CONFIG ----------

SNORT_FAST_LOG = "/var/log/snort/snort.alert.fast"
WAZUH_ALERTS_URL = "http://47.130.204.203:8001/alerts.json"
CORRELATION_JSON = "/opt/ids/output/correlation.json"
# Time windows for correlation
SCAN_TO_SUDO_WINDOW = timedelta(seconds=180)
SCAN_TO_SSH_WINDOW = timedelta(seconds=120)
SSH_FAIL_WINDOW = timedelta(seconds=120)
PACKAGE_INSTALL_WINDOW = timedelta(seconds=90)
WEB_TO_PKG_WINDOW = timedelta(seconds=180)

# How often to poll Wazuh alerts.json (seconds)
WAZUH_POLL_INTERVAL = 5


# ---------- HELPERS ----------

def parse_wazuh_timestamp(ts: str) -> datetime:
    """
    Wazuh timestamp example:
    2025-12-04T20:18:01.093+0000
    """
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z")
    except Exception:
        # Fallback: treat as naive UTC
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=timezone.utc)


def parse_snort_time(line: str) -> datetime:
    """
    Parse Snort timestamp from fast alert format.
    Example: 12/29-14:23:45.123456
    """
    try:
        ts = line.split(" ")[0:2]
        return datetime.strptime(
            " ".join(ts), "%m/%d-%H:%M:%S.%f"
        ).replace(year=datetime.now().year, tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def extract_first_ip(text: str) -> str | None:
    """Return first IPv4 addr in text, or None."""
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return m.group(0) if m else None


def write_correlation_event(event: dict):
    """Write correlation event to JSON log file"""
    try:
        with open(CORRELATION_JSON, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to write correlation JSON: {e}")


def push_correlation_event(event):
    """Push correlation event to API endpoint"""
    try:
        r = requests.post(
            API_ENDPOINT,
            json=event,
            headers={
                "X-API-Key": API_KEY,
                "Content-Type": "application/json"
            },
            timeout=3
        )
        if r.status_code != 200:
            print(f"[WARN] Correlation push failed: {r.status_code}")
    except Exception as e:
        print(f"[ERROR] Correlation push error: {e}")


# ---------- SNORT CLASSIFIERS ----------

def is_nmap_scan_snort(line: str) -> bool:
    """Detect Nmap scans (ICMP, ping sweep)"""
    up = line.upper()
    return "NMAP" in up or "PING SWEEP" in up


def is_port_scan_snort(line: str) -> bool:
    """Detect SYN/FIN/Xmas scans - matches YOUR rule messages"""
    up = line.upper()
    return (
        "TCP SYN PORT SCAN" in up or
        "TCP FIN PORT SCAN" in up or
        "TCP XMAS PORT SCAN" in up
    )


def is_ssh_bruteforce_snort(line: str) -> bool:
    """Detect SSH brute force from Snort"""
    up = line.upper()
    return "SSH BRUTE FORCE" in up


def is_web_attack_snort(line: str) -> bool:
    """
    Detect web-based exploit payloads (command injection / web shell)
    """
    up = line.upper()
    return "WEB COMMAND INJECTION ATTEMPT DETECTED" in up


# ---------- WAZUH CLASSIFIERS ----------

def is_sudo_or_priv_esc_wazuh(alert: dict) -> bool:
    """Detect privilege escalation (rule 200001, 200004)"""
    rule_id = str(alert.get("rule", {}).get("id", ""))
    desc = alert.get("rule", {}).get("description", "").lower()

    return (
        rule_id in ["200001", "200004"] or
        "privilege escalation" in desc or
        ("sudo" in desc and "root" in desc) or
        "suspicious privileged modification" in desc
    )


def is_ssh_fail_wazuh(alert: dict) -> bool:
    """Detect SSH authentication failure (rule 100001, 5716)"""
    rule_id = str(alert.get("rule", {}).get("id", ""))
    desc = alert.get("rule", {}).get("description", "").lower()

    return (
        rule_id in ["100001", "5716"] or
        ("authentication failed" in desc and "sshd" in desc) or
        "failed password" in desc
    )


def is_ssh_success_wazuh(alert: dict) -> bool:
    """Detect successful SSH login (rule 200003)"""
    rule_id = str(alert.get("rule", {}).get("id", ""))
    desc = alert.get("rule", {}).get("description", "").lower()

    return (
        rule_id == "200003" or
        ("session opened" in desc and "sshd" in desc)
    )


def is_package_install_wazuh(alert: dict) -> bool:
    """Detect package installation (rule 12002)"""
    rule_id = str(alert.get("rule", {}).get("id", ""))
    desc = alert.get("rule", {}).get("description", "").lower()

    return (
        rule_id == "12002" or
        "package was installed" in desc or
        "dpkg" in desc
    )


def is_cron_persistence_wazuh(alert: dict) -> bool:
    """
    Detect cron persistence (local override of rule 2834)
    """
    rule_id = str(alert.get("rule", {}).get("id", ""))
    desc = alert.get("rule", {}).get("description", "").lower()

    return (
        rule_id == "2834" or
        "cron" in desc or
        "scheduled task" in desc
    )


def pretty_time(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")


# ---------- MAIN CORRELATOR ----------

def main():
    print("[INFO] Starting Enhanced Correlation Engine")
    print(f"       Correlator Agent ID: {CORRELATOR_AGENT_ID}")
    print(f"       Watching Snort log : {SNORT_FAST_LOG}")
    print(f"       Reading Wazuh JSON: {WAZUH_ALERTS_URL}")
    print(f"       Output JSON       : {CORRELATION_JSON}")
    print()

    # State for Snort
    snort_pos = 0
    recent_nmap_scans = []      # {time, src_ip, raw}
    recent_port_scans = []      # {time, src_ip, raw}
    recent_ssh_bruteforce = []  # {time, src_ip, raw}
    recent_web_attacks = []     # {time, src_ip, raw} - NEW!

    # State for Wazuh
    last_wazuh_ts = datetime.min.replace(tzinfo=timezone.utc)
    recent_ssh_fails = []       # list of {time, src_ip}
    recent_priv_esc = []        # list of {time, agent, desc}
    recent_cron_persistence = [] # list of {time, agent, desc}

    last_wazuh_poll = 0

    while True:
        now = datetime.now(timezone.utc)

        # ----- 1) Read new Snort alerts (tail) -----
        try:
            with open(SNORT_FAST_LOG, "r", errors="ignore") as f:
                f.seek(snort_pos)
                new_lines = f.readlines()
                snort_pos = f.tell()
        except FileNotFoundError:
            new_lines = []

        for line in new_lines:
            line = line.strip()
            if not line:
                continue

            src_ip = extract_first_ip(line) or "unknown"
            event = {
                "time": parse_snort_time(line),
                "src_ip": src_ip,
                "raw": line,
            }

            # Classify Snort alerts
            if is_nmap_scan_snort(line):
                recent_nmap_scans.append(event)
                print("\n[SNORT] Detected Nmap/ICMP scan:")
                print(f"  Time : {pretty_time(event['time'])}")
                print(f"  SrcIP: {event['src_ip']}")
                print(f"  Raw  : {event['raw']}")

            elif is_port_scan_snort(line):
                recent_port_scans.append(event)
                print("\n[SNORT] Detected port scan (SYN/FIN/Xmas):")
                print(f"  Time : {pretty_time(event['time'])}")
                print(f"  SrcIP: {event['src_ip']}")
                print(f"  Raw  : {event['raw']}")

            elif is_ssh_bruteforce_snort(line):
                recent_ssh_bruteforce.append(event)
                print("\n[SNORT] Detected SSH brute force:")
                print(f"  Time : {pretty_time(event['time'])}")
                print(f"  SrcIP: {event['src_ip']}")
                print(f"  Raw  : {event['raw']}")

            elif is_web_attack_snort(line):
                recent_web_attacks.append(event)
                print("\n[SNORT] Detected Web Command Injection:")
                print(f"  Time : {pretty_time(event['time'])}")
                print(f"  SrcIP: {event['src_ip']}")
                print(f"  Raw  : {event['raw']}")

        # Remove old Snort events
        max_window = max(SCAN_TO_SUDO_WINDOW, SCAN_TO_SSH_WINDOW, SSH_FAIL_WINDOW, PACKAGE_INSTALL_WINDOW, WEB_TO_PKG_WINDOW)
        cutoff = now - max_window
        recent_nmap_scans = [e for e in recent_nmap_scans if e["time"] >= cutoff]
        recent_port_scans = [e for e in recent_port_scans if e["time"] >= cutoff]
        recent_ssh_bruteforce = [e for e in recent_ssh_bruteforce if e["time"] >= cutoff]
        recent_web_attacks = [e for e in recent_web_attacks if e["time"] >= cutoff]

        # ----- 2) Periodically pull new Wazuh alerts -----
        if (now - datetime.fromtimestamp(last_wazuh_poll, tz=timezone.utc)).total_seconds() >= WAZUH_POLL_INTERVAL:
            last_wazuh_poll = time.time()
            try:
                resp = requests.get(WAZUH_ALERTS_URL, timeout=3)
                resp.raise_for_status()
                body = resp.json()  # Directly parse JSON response
            except Exception as e:
                print(f"[WARN] Could not fetch Wazuh alerts: {e}")
                body = []

            max_ts_seen = last_wazuh_ts

            for alert in body:  # Iterate over each alert in the list

                ts_str = alert.get("timestamp")
                if not ts_str:
                    continue

                ts = parse_wazuh_timestamp(ts_str)

                # Only process new alerts
                if ts <= last_wazuh_ts:
                    continue

                if ts > max_ts_seen:
                    max_ts_seen = ts

                # Improved source IP extraction
                agent_name = alert.get("agent", {}).get("name", "unknown")
                rule_desc = alert.get("rule", {}).get("description", "")
                src_ip = (
                    alert.get("data", {}).get("srcip") or
                    extract_first_ip(alert.get("full_log", "")) or
                    "unknown"
                )

                # --- CORRELATION LOGIC ---

                # CORRELATION 1: Nmap/Port Scan → Privilege Escalation
                if is_sudo_or_priv_esc_wazuh(alert):
                    recent_priv_esc.append({
                        "time": ts,
                        "agent": agent_name,
                        "desc": rule_desc
                    })

                    # CORRELATION 1A: Web Attack → Privilege Escalation (NEW!)
                    for web in recent_web_attacks[:]:
                        if (web["src_ip"] == src_ip or src_ip == "unknown") and \
                           abs((ts - web["time"]).total_seconds()) <= SCAN_TO_SUDO_WINDOW.total_seconds():

                            correlation_event = {
                                "correlation_id": f"CORR-{int(time.time()*1000)}",
                                "timestamp": pretty_time(now),
                                "correlation_type": "WEB_ATTACK_TO_PRIVILEGE_ESCALATION",
                                "severity": "critical",
                                "agent_id": CORRELATOR_AGENT_ID,
                                "stage1": {
                                    "type": "web_command_injection",
                                    "time": pretty_time(web["time"]),
                                    "src_ip": web["src_ip"],
                                    "snort_alert": web["raw"]
                                },
                                "stage2": {
                                    "type": "privilege_escalation",
                                    "time": pretty_time(ts),
                                    "agent": agent_name,
                                    "wazuh_alert": rule_desc
                                },
                                "time_difference_seconds": abs((ts - web["time"]).total_seconds()),
                                "source": "correlation",
                                "correlated": True
                            }

                            write_correlation_event(correlation_event)
                            push_correlation_event(correlation_event)

                            print("\n" + "="*60)
                            print("[CRITICAL] CORRELATED ATTACK:")
                            print("WEB COMMAND INJECTION → PRIVILEGE ESCALATION")
                            print("="*60)
                            print(f"[*] Correlation ID  : {correlation_event['correlation_id']}")
                            print(f"[*] Attack Timeline:")
                            print(f"    1. Web injection  : {pretty_time(web['time'])} from {web['src_ip']}")
                            print(f"    2. Priv escalation: {pretty_time(ts)} on {agent_name}")
                            print(f"[*] Time difference : {abs((ts - web['time']).total_seconds()):.1f} seconds")
                            print(f"[*] Snort Alert     : {web['raw']}")
                            print(f"[*] Wazuh Alert     : {rule_desc}")
                            print("="*60 + "\n")

                            recent_web_attacks.remove(web)
                            break

                    # CORRELATION 1B: Nmap Scan → Privilege Escalation
                    for scan in recent_nmap_scans[:]:
                        if (scan["src_ip"] == src_ip or src_ip == "unknown") and \
                           abs((ts - scan["time"]).total_seconds()) <= SCAN_TO_SUDO_WINDOW.total_seconds():
                            correlation_event = {
                                "correlation_id": f"CORR-{int(time.time()*1000)}",
                                "timestamp": pretty_time(now),
                                "correlation_type": "NMAP_SCAN_TO_PRIV_ESC",
                                "severity": "critical",
                                "agent_id": CORRELATOR_AGENT_ID,
                                "stage1": {
                                    "type": "nmap_scan",
                                    "time": pretty_time(scan['time']),
                                    "src_ip": scan['src_ip'],
                                    "snort_alert": scan['raw']
                                },
                                "stage2": {
                                    "type": "privilege_escalation",
                                    "time": pretty_time(ts),
                                    "agent": agent_name,
                                    "wazuh_alert": rule_desc
                                },
                                "time_difference_seconds": abs((ts - scan['time']).total_seconds()),
                                "source": "correlation",
                                "correlated": True
                            }

                            write_correlation_event(correlation_event)
                            push_correlation_event(correlation_event)

                            print("\n" + "="*60)
                            print("[CRITICAL] CORRELATED ATTACK: NMAP SCAN → PRIVILEGE ESCALATION")
                            print("="*60)
                            print(f"[*] Correlation ID  : {correlation_event['correlation_id']}")
                            print(f"[*] Attack Timeline:")
                            print(f"    1. Nmap scan    : {pretty_time(scan['time'])} from {scan['src_ip']}")
                            print(f"    2. Priv escalation: {pretty_time(ts)} on {agent_name}")
                            print(f"[*] Time difference : {abs((ts - scan['time']).total_seconds()):.1f} seconds")
                            print(f"[*] Snort Alert     : {scan['raw']}")
                            print(f"[*] Wazuh Alert     : {rule_desc}")
                            print("="*60 + "\n")

                            recent_nmap_scans.remove(scan)
                            break

                    # CORRELATION 1C: Port Scan → Privilege Escalation
                    for scan in recent_port_scans[:]:
                        if (scan["src_ip"] == src_ip or src_ip == "unknown") and \
                           abs((ts - scan["time"]).total_seconds()) <= SCAN_TO_SUDO_WINDOW.total_seconds():
                            correlation_event = {
                                "correlation_id": f"CORR-{int(time.time()*1000)}",
                                "timestamp": pretty_time(now),
                                "correlation_type": "PORT_SCAN_TO_PRIV_ESC",
                                "severity": "critical",
                                "agent_id": CORRELATOR_AGENT_ID,
                                "stage1": {
                                    "type": "port_scan",
                                    "time": pretty_time(scan['time']),
                                    "src_ip": scan['src_ip'],
                                    "snort_alert": scan['raw']
                                },
                                "stage2": {
                                    "type": "privilege_escalation",
                                    "time": pretty_time(ts),
                                    "agent": agent_name,
                                    "wazuh_alert": rule_desc
                                },
                                "time_difference_seconds": abs((ts - scan['time']).total_seconds()),
                                "source": "correlation",
                                "correlated": True
                            }

                            write_correlation_event(correlation_event)
                            push_correlation_event(correlation_event)

                            print("\n" + "="*60)
                            print("[CRITICAL] CORRELATED ATTACK: PORT SCAN → PRIVILEGE ESCALATION")
                            print("="*60)
                            print(f"[*] Correlation ID  : {correlation_event['correlation_id']}")
                            print(f"[*] Attack Timeline:")
                            print(f"    1. Port scan    : {pretty_time(scan['time'])} from {scan['src_ip']}")
                            print(f"    2. Priv escalation: {pretty_time(ts)} on {agent_name}")
                            print(f"[*] Time difference : {abs((ts - scan['time']).total_seconds()):.1f} seconds")
                            print(f"[*] Snort Alert     : {scan['raw']}")
                            print(f"[*] Wazuh Alert     : {rule_desc}")
                            print("="*60 + "\n")

                            recent_port_scans.remove(scan)
                            break

                # CORRELATION 2: SSH Brute Force (Snort + Wazuh) → Success
                if is_ssh_fail_wazuh(alert):
                    recent_ssh_fails.append({"time": ts, "src_ip": src_ip})

                    # Correlate: Snort SSH brute force + Wazuh SSH failure
                    snort_bruteforce = [
                        b for b in recent_ssh_bruteforce
                        if (b["src_ip"] == src_ip or src_ip == "unknown") and
                           (ts - b["time"]) <= SSH_FAIL_WINDOW
                    ]

                    if snort_bruteforce:
                        correlation_event = {
                            "correlation_id": f"CORR-{int(time.time()*1000)}",
                            "timestamp": pretty_time(now),
                            "correlation_type": "SSH_BRUTEFORCE_WITH_FAILURE",
                            "severity": "warning",
                            "agent_id": CORRELATOR_AGENT_ID,
                            "failed_attempt_time": pretty_time(ts),
                            "src_ip": src_ip,
                            "snort_alert": snort_bruteforce[0]["raw"],
                            "wazuh_alert": rule_desc,
                            "source": "correlation",
                            "correlated": True
                        }

                        write_correlation_event(correlation_event)
                        push_correlation_event(correlation_event)

                        print("\n" + "="*60)
                        print("[WARNING] CORRELATED ACTIVITY: SSH BRUTE FORCE → SSH FAILURE")
                        print("="*60)
                        print(f"[*] Src IP      : {src_ip}")
                        print(f"[*] Snort Alert : {snort_bruteforce[0]['raw']}")
                        print(f"[*] Wazuh Alert : {rule_desc}")
                        print("="*60 + "\n")

                        recent_ssh_bruteforce.remove(snort_bruteforce[0])
                        recent_ssh_fails.clear()

                if is_ssh_success_wazuh(alert):
                    # Filter SSH failures by same IP
                    recent_ssh_fails[:] = [
                        f for f in recent_ssh_fails
                        if f["src_ip"] == src_ip and (ts - f["time"]) <= SSH_FAIL_WINDOW
                    ]

                    # Check Snort SSH brute force
                    snort_bruteforce = [
                        b for b in recent_ssh_bruteforce
                        if ((b["src_ip"] == src_ip or src_ip == "unknown") and
                            (ts - b["time"]) <= SCAN_TO_SSH_WINDOW)
                    ]

                    if len(recent_ssh_fails) >= 3 or snort_bruteforce:
                        correlation_event = {
                            "correlation_id": f"CORR-{int(time.time()*1000)}",
                            "timestamp": pretty_time(now),
                            "correlation_type": "SSH_BRUTEFORCE_TO_SUCCESS",
                            "severity": "critical",
                            "agent_id": CORRELATOR_AGENT_ID,
                            "failed_attempts": len(recent_ssh_fails),
                            "snort_detections": len(snort_bruteforce),
                            "successful_login": {
                                "time": pretty_time(ts),
                                "agent": agent_name,
                                "wazuh_alert": rule_desc
                            },
                            "source": "correlation",
                            "correlated": True
                        }
                        if snort_bruteforce:
                            correlation_event["snort_alert"] = snort_bruteforce[0]['raw']

                        write_correlation_event(correlation_event)
                        push_correlation_event(correlation_event)

                        print("\n" + "="*60)
                        print("[CRITICAL] CORRELATED ATTACK: SSH BRUTE FORCE → SUCCESS")
                        print("="*60)
                        print(f"[*] Correlation ID  : {correlation_event['correlation_id']}")
                        print(f"[*] Successful login: {pretty_time(ts)} on {agent_name}")
                        print(f"[*] Failed attempts (Wazuh): {len(recent_ssh_fails)}")
                        print(f"[*] Snort detections: {len(snort_bruteforce)}")
                        if snort_bruteforce:
                            print(f"[*] Snort alert: {snort_bruteforce[0]['raw']}")
                        print(f"[*] Wazuh alert: {rule_desc}")
                        print("="*60 + "\n")

                        recent_ssh_fails.clear()
                        recent_ssh_bruteforce.clear()

                # CORRELATION 4: Privilege Escalation → Package Install
                if is_package_install_wazuh(alert):
                    # CORRELATION 4A: Priv Esc → Package Install
                    for priv in recent_priv_esc[:]:
                        if abs((ts - priv["time"]).total_seconds()) <= PACKAGE_INSTALL_WINDOW.total_seconds():
                            correlation_event = {
                                "correlation_id": f"CORR-{int(time.time()*1000)}",
                                "timestamp": pretty_time(now),
                                "correlation_type": "PRIV_ESC_TO_PACKAGE_INSTALL",
                                "severity": "warning",
                                "agent_id": CORRELATOR_AGENT_ID,
                                "stage1": {
                                    "type": "privilege_escalation",
                                    "time": pretty_time(priv['time']),
                                    "agent": priv['agent'],
                                    "wazuh_alert": priv['desc']
                                },
                                "stage2": {
                                    "type": "package_installation",
                                    "time": pretty_time(ts),
                                    "agent": agent_name,
                                    "wazuh_alert": rule_desc
                                },
                                "time_difference_seconds": abs((ts - priv['time']).total_seconds()),
                                "source": "correlation",
                                "correlated": True
                            }

                            write_correlation_event(correlation_event)
                            push_correlation_event(correlation_event)

                            print("\n" + "="*60)
                            print("[WARNING] CORRELATED ACTIVITY: PRIV ESC → PACKAGE INSTALL")
                            print("="*60)
                            print(f"[*] Correlation ID  : {correlation_event['correlation_id']}")
                            print(f"[*] Activity Timeline:")
                            print(f"    1. Privilege escalation: {pretty_time(priv['time'])} on {priv['agent']}")
                            print(f"    2. Package installation: {pretty_time(ts)} on {agent_name}")
                            print(f"[*] Time difference: {abs((ts - priv['time']).total_seconds()):.1f} seconds")
                            print(f"[*] Priv esc alert : {priv['desc']}")
                            print(f"[*] Package alert  : {rule_desc}")
                            print("="*60 + "\n")

                            recent_priv_esc.remove(priv)
                            break

                    # CORRELATION 4B: Web Command Injection → Package Install
                    for web in recent_web_attacks[:]:
                        if (web["src_ip"] == src_ip or src_ip == "unknown") and \
                           abs((ts - web["time"]).total_seconds()) <= WEB_TO_PKG_WINDOW.total_seconds():

                            correlation_event = {
                                "correlation_id": f"CORR-{int(time.time()*1000)}",
                                "timestamp": pretty_time(now),
                                "correlation_type": "WEB_ATTACK_TO_PACKAGE_INSTALL",
                                "severity": "critical",
                                "agent_id": CORRELATOR_AGENT_ID,
                                "stage1": {
                                    "type": "web_command_injection",
                                    "time": pretty_time(web["time"]),
                                    "src_ip": web["src_ip"],
                                    "snort_alert": web["raw"]
                                },
                                "stage2": {
                                    "type": "package_installation",
                                    "time": pretty_time(ts),
                                    "agent": agent_name,
                                    "wazuh_alert": rule_desc
                                },
                                "time_difference_seconds": abs((ts - web["time"]).total_seconds()),
                                "source": "correlation",
                                "correlated": True
                            }

                            write_correlation_event(correlation_event)
                            push_correlation_event(correlation_event)

                            print("\n" + "="*60)
                            print("[CRITICAL] CORRELATED ATTACK:")
                            print("WEB COMMAND INJECTION → PACKAGE INSTALLATION")
                            print("="*60)
                            print(f"[*] Correlation ID  : {correlation_event['correlation_id']}")
                            print(f"[*] Attack Timeline:")
                            print(f"    1. Web injection  : {pretty_time(web['time'])} from {web['src_ip']}")
                            print(f"    2. Package install: {pretty_time(ts)} on {agent_name}")
                            print(f"[*] Time difference : {abs((ts - web['time']).total_seconds()):.1f} seconds")
                            print(f"[*] Snort Alert     : {web['raw']}")
                            print(f"[*] Wazuh Alert     : {rule_desc}")
                            print("="*60 + "\n")

                            recent_web_attacks.remove(web)
                            break

                # CORRELATION 5: Network Recon → Cron Persistence
                if is_cron_persistence_wazuh(alert):

                    recent_cron_persistence.append({
                        "time": ts,
                        "agent": agent_name,
                        "desc": rule_desc
                    })

                    # Check for prior Nmap scan OR port scan
                    for scan in (recent_nmap_scans + recent_port_scans):
                        if abs((ts - scan["time"]).total_seconds()) <= SCAN_TO_SUDO_WINDOW.total_seconds():

                            correlation_event = {
                                "correlation_id": f"CORR-{int(time.time()*1000)}",
                                "timestamp": pretty_time(now),
                                "correlation_type": "RECON_TO_CRON_PERSISTENCE",
                                "severity": "critical",
                                "agent_id": CORRELATOR_AGENT_ID,
                                "stage1": {
                                    "type": "network_scan",
                                    "time": pretty_time(scan["time"]),
                                    "src_ip": scan["src_ip"],
                                    "snort_alert": scan["raw"]
                                },
                                "stage2": {
                                    "type": "cron_persistence",
                                    "time": pretty_time(ts),
                                    "agent": agent_name,
                                    "wazuh_alert": rule_desc
                                },
                                "time_difference_seconds": abs((ts - scan["time"]).total_seconds()),
                                "source": "correlation",
                                "correlated": True
                            }

                            write_correlation_event(correlation_event)
                            push_correlation_event(correlation_event)

                            print("\n" + "="*60)
                            print("[CRITICAL] CORRELATED ATTACK:")
                            print("NETWORK SCAN → CRON PERSISTENCE")
                            print("="*60)
                            print(f"[*] Correlation ID : {correlation_event['correlation_id']}")
                            print(f"[*] Attack Timeline:")
                            print(f"    1. Network scan : {pretty_time(scan['time'])} from {scan['src_ip']}")
                            print(f"    2. Cron modify  : {pretty_time(ts)} on {agent_name}")
                            print(f"[*] Time difference: {abs((ts - scan['time']).total_seconds()):.1f} seconds")
                            print(f"[*] Scan alert     : {scan['raw']}")
                            print(f"[*] Cron alert     : {rule_desc}")
                            print("="*60 + "\n")

                            # Clear both scan lists to prevent duplicate correlations
                            recent_port_scans.clear()
                            recent_nmap_scans.clear()
                            break

            last_wazuh_ts = max_ts_seen

        time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Correlator stopped by user")
