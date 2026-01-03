#!/usr/bin/env python3

import time
import re
import requests
from datetime import datetime, timezone


import os

API_BASE = os.environ.get("DASHBOARD_API_BASE_URL", "http://18.142.200.244:5000").rstrip("/")
API_URL = f"{API_BASE}/api/snort"
API_KEY = os.environ.get("API_KEY", "ids_vm_secret_key_123")
AGENT_ID = os.environ.get("AGENT_ID", "vm-snort-01")


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
            timeout=5,   # slightly safer than 3s
        )

        if r.status_code == 200:
            print("[OK] Snort event pushed")
        else:
            print("[WARN] Push failed:", r.status_code, r.text[:200])
    except Exception as e:
        print("[ERROR] Push error:", e)


def main() -> None:
    print("[INFO] Snort push service started")
    print("[INFO] Watching:", SNORT_LOG)

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


if __name__ == "__main__":
    main()
