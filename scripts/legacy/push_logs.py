#!/usr/bin/env python3

import time
import requests
import os

# ================= CONFIG =================

DASHBOARD_API = "http://DASHBOARD_EC2_PUBLIC_IP:5000/api/ingest"
API_KEY = "CHANGE_ME_LATER"

SNORT_LOG = "/var/log/snort/snort.alert.fast"
CORRELATION_LOG = "/var/log/correlation.log"

STATE_DIR = "/opt/log-pusher/state"
SNORT_STATE = f"{STATE_DIR}/snort.offset"
CORR_STATE = f"{STATE_DIR}/corr.offset"

INTERVAL = 5  # seconds

# ==========================================

os.makedirs(STATE_DIR, exist_ok=True)


def read_new_lines(logfile, statefile):
    last_pos = 0

    # Read last offset
    if os.path.exists(statefile):
        try:
            with open(statefile, "r") as f:
                last_pos = int(f.read().strip())
        except Exception:
            last_pos = 0

    # Handle log rotation / truncation
    try:
        current_size = os.path.getsize(logfile)
    except FileNotFoundError:
        return []

    if current_size < last_pos:
        # Log rotated or truncated
        print(f"[DEBUG] Log rotated: resetting offset for {logfile}")
        last_pos = 0

    # Read new lines
    with open(logfile, "r") as f:
        f.seek(last_pos)
        lines = f.readlines()
        new_pos = f.tell()

    # Save new offset
    with open(statefile, "w") as f:
        f.write(str(new_pos))

    return [line.strip() for line in lines if line.strip()]


def push_logs(source, logs):
    if not logs:
        return

    print(f"[DEBUG] Pushing {len(logs)} {source} log(s)")

    payload = {
        "source": source,
        "logs": logs
    }

    headers = {
        "Authorization": f"Bearer {API_KEY}"
    }

    try:
        r = requests.post(
            DASHBOARD_API,
            json=payload,
            headers=headers,
            timeout=5
        )

        if r.status_code == 200:
            print(f"[OK] {source} logs pushed successfully")
        else:
            print(f"[WARN] Push failed ({source}): HTTP {r.status_code}")

    except Exception as e:
        print(f"[ERROR] Exception pushing {source}: {e}")


def main():
    print("[*] Log pusher started (rotation-safe, debug enabled)")

    while True:
        if os.path.exists(SNORT_LOG):
            snort_logs = read_new_lines(SNORT_LOG, SNORT_STATE)
            push_logs("snort", snort_logs)
        else:
            print("[WARN] Snort log file not found")

        if os.path.exists(CORRELATION_LOG):
            corr_logs = read_new_lines(CORRELATION_LOG, CORR_STATE)
            push_logs("correlation", corr_logs)

        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
