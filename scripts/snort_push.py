#!/usr/bin/env python3

import time
import re
import requests
from datetime import datetime, timezone

SNORT_LOG = "/var/log/snort/snort.alert.fast"

API_URL = "http://18.142.200.244:5000/api/snort"
API_KEY = "ids_vm_secret_key_123"

AGENT_ID = "vm-snort-01"

def parse_snort_line(line):
    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+).*-> (\d+\.\d+\.\d+\.\d+)', line)
    priority_match = re.search(r'Priority: (\d+)', line)

    return {
    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    "source": "snort",
    "agent_id": AGENT_ID,
    "message": line.strip(),
    "priority": priority_match.group(1) if priority_match else "3",
    "src_ip": ip_match.group(1) if ip_match else None,
    "dest_ip": ip_match.group(2) if ip_match else None
}



def push_event(event):
    print("[DEBUG] Payload being sent:", event)   # ← ADD THIS

    try:
        r = requests.post(
            API_URL,
            json=event,
            headers={
                "X-API-Key": API_KEY,
                "Content-Type": "application/json"
            },
            timeout=3
        )
        if r.status_code != 200:
            print("[WARN] Push failed:", r.status_code)
        else:
            print("[OK] Snort event pushed")
    except Exception as e:
        print("[ERROR] Push error:", e)


def main():
    print("[INFO] Snort push service started")
    print("[INFO] Watching:", SNORT_LOG)

    try:
        with open(SNORT_LOG, "r", errors="ignore") as f:
            # 🔑 Jump to end of file
            f.seek(0, 2)

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
