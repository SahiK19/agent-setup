#!/usr/bin/env python3

import os
import time
import re
import requests
from datetime import datetime, timezone

ENV_FILE = "/etc/ids-agent/agent.env"

def load_env_file(path: str) -> None:
    """Load KEY=VALUE lines into os.environ if not already set."""
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                os.environ.setdefault(k, v)
    except Exception:
        # If env loading fails, we still continue with defaults/systemd env
        pass

# Load env when running manually (systemd already sets EnvironmentFile)
load_env_file(ENV_FILE)

DASHBOARD_API_BASE_URL = os.getenv("DASHBOARD_API_BASE_URL", "http://18.142.200.244:5000").rstrip("/")
API_KEY = os.getenv("API_KEY", "ids_vm_secret_key_123")
AGENT_ID = os.getenv("AGENT_ID", "vm-snort-01")
SNORT_LOG = os.getenv("SNORT_FAST_LOG", "/var/log/snort/snort.alert.fast")

API_URL = f"{DASHBOARD_API_BASE_URL}/api/snort"

def parse_snort_line(line: str) -> dict:
    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+).*-> (\d+\.\d+\.\d+\.\d+)', line)
    priority_match = re.search(r'Priority: (\d+)', line)

    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "source": "snort",
        "agent_id": AGENT_ID,
        "message": line.strip(),
        "priority": priority_match.group(1) if priority_match else "3",
        "src_ip": ip_match.group(1) if ip_match else None,
        "dest_ip": ip_match.group(2) if ip_match else None,
    }

def push_event(event: dict) -> None:
    print("[DEBUG] Payload being sent:", event)

    try:
        r = requests.post(
            API_URL,
            json=event,
            headers={
                "X-API-Key": API_KEY,
                "Content-Type": "application/json",
            },
            timeout=(10, 20),  # connect timeout, read timeout
        )

        if r.status_code != 200:
            print(f"[WARN] Push failed: {r.status_code} body={r.text[:200]}")
        else:
            print("[OK] Snort event pushed")

    except Exception as e:
        print("[ERROR] Push error:", e)

def main() -> None:
    print("[INFO] Snort push service started")
    print("[INFO] API_URL:", API_URL)
    print("[INFO] AGENT_ID:", AGENT_ID)
    print("[INFO] Watching:", SNORT_LOG)

    try:
        with open(SNORT_LOG, "r", errors="ignore") as f:
            f.seek(0, 2)  # jump to end

            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue

                if line.strip():
                    print("[DEBUG] New snort alert:", line.strip())
                    event = parse_snort_line(line)
                    push_event(event)

    except Exception as e:
        print("[FATAL]", e)
        time.sleep(5)

if __name__ == "__main__":
    main()
