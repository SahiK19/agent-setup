#!/usr/bin/env python3
import json
import time
import os
import requests

# ================= CONFIG =================
SNORT_JSON = "/opt/ids/output/snort.json"
CORRELATION_JSON = "/opt/ids/output/correlation.json"
STATE_DIR = "/opt/ids/state"
SNORT_OFFSET_FILE = f"{STATE_DIR}/snort.offset"
CORR_OFFSET_FILE = f"{STATE_DIR}/correlation.offset"

API_BASE = "http://18.142.200.244:5000/api"
API_KEY = "ids_vm_secret_key_123"
CORRELATOR_AGENT_ID = os.environ.get("AGENT_ID", "vm-correlator-01")
AGENT_NAME = os.environ.get("AGENT_NAME", "agent2")

PUSH_INTERVAL = 5  # seconds
# =========================================

def read_offset(path):
    try:
        with open(path, "r") as f:
            return int(f.read().strip())
    except:
        return 0

def write_offset(path, value):
    with open(path, "w") as f:
        f.write(str(value))

def push_events(file_path, offset_file, endpoint, source, correlated):
    if not os.path.exists(file_path):
        return
    
    offset = read_offset(offset_file)
    events = []
    
    try:
        with open(file_path, "r") as f:
            content = f.read().strip()
            
            # Case 1: JSON array (Snort)
            if content.startswith("["):
                data = json.loads(content)
                if isinstance(data, list):
                    events = data[offset:]
            
            # Case 2: Line-delimited JSON (Correlation)
            else:
                lines = content.splitlines()
                for line in lines[offset:]:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    
    except Exception as e:
        print(f"[ERROR] Failed reading {file_path}: {e}")
        return
    
    if not events:
        return
    
    for event in events:
        event["source"] = source
        event["correlated"] = correlated
        # 🔑 Inject agent_id ONLY for correlation
        if source == "correlation":
            event["agent_name"] = AGENT_NAME
            print(f"[PUSH] {source} event →", event.get("correlation_id", "no-id"))
        
        try:
            r = requests.post(
                endpoint,
                json=event,
                headers={"X-API-Key": API_KEY},
                timeout=3
            )
            if r.status_code != 200:
                print(f"[WARN] Push failed ({source}): {r.status_code}")
        except Exception as e:
            print(f"[ERROR] Push failed: {e}")
            return
    
    write_offset(offset_file, offset + len(events))

def main():
    os.makedirs(STATE_DIR, exist_ok=True)
    
    while True:
        push_events(
            CORRELATION_JSON,
            CORR_OFFSET_FILE,
            f"{API_BASE}/correlation",
            "correlation",
            True
        )
        
        push_events(
            SNORT_JSON,
            SNORT_OFFSET_FILE,
            f"{API_BASE}/snort",
            source="snort",
            correlated=False
        )
        
        time.sleep(PUSH_INTERVAL)

if __name__ == "__main__":
    main()
