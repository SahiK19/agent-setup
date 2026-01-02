import json
import re

SNORT_LOG = "/var/log/snort/snort.alert.fast"
OUTPUT_JSON = "/opt/ids/output/snort.json"

# Regex that matches Snort fast alert format with classification & priority
ALERT_REGEX = re.compile(
    r"\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\]\s+"
    r"\[Classification:\s+(.*?)\]\s+"
    r"\[Priority:\s+(\d+)\]\s+"
    r"\{(\w+)\}\s+([\d\.]+):\d+\s+->\s+([\d\.]+):\d+",
    re.MULTILINE
)

def parse_snort_logs():
    alerts = []

    try:
        with open(SNORT_LOG, "r") as f:
            data = f.read()
    except FileNotFoundError:
        return []

    for match in ALERT_REGEX.finditer(data):
        message, classification, priority, protocol, src_ip, dst_ip = match.groups()

        alert = {
            "source": "snort",
            "message": message,
            "classification": classification,
            "priority": int(priority),
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "severity": "high" if int(priority) <= 2 else "medium",
            "correlated": False
        }

        alerts.append(alert)

    return alerts

def write_json(alerts):
    with open(OUTPUT_JSON, "w") as f:
        json.dump(alerts, f, indent=2)

if __name__ == "__main__":
    alerts = parse_snort_logs()
    write_json(alerts)

