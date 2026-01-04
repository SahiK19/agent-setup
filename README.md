# IDS Agent Setup (Snort + Correlator + Log Push)
1) Configure Agent IDs + Dashboard API (agent.env)

Both snort_push.py and correlate.py read settings from:

📌 /etc/ids-agent/agent.env
Use this repo example as reference:

📄 config/agent.env.example

Edit the config file
sudo nano /etc/ids-agent/agent.env

Required values
# Dashboard / API
DASHBOARD_API_BASE_URL=http://18.142.200.244:5000
API_KEY=ids_vm_secret_key_123

# Identity (IMPORTANT)
SNORT_AGENT_ID=vm-snort-01
CORRELATOR_AGENT_ID=vm-correlator-01

# Snort
SNORT_FAST_LOG=/var/log/snort/snort.alert.fast

# Wazuh (if correlator reads alerts.json)
WAZUH_ALERTS_URL=http://YOUR_WAZUH_MANAGER_IP:8001/alerts.json
WAZUH_POLL_INTERVAL=5


✅ Why this matters

The dashboard uses agent_id to label events.

If you don’t set unique IDs, multiple machines will look identical on the dashboard.

2) Set Snort HOME_NET (Must match your VM IP/subnet)

Snort rules depend on HOME_NET. If it is wrong, you will miss alerts.

Check your VM IP
ip -br a


Example:

eth0 UP 172.21.93.154/20

Update HOME_NET in Snort config

📌 Usually in:

/etc/snort/snort.conf

Edit:

sudo nano /etc/snort/snort.conf


Find something like:

ipvar HOME_NET any


Change it to match your network (example):

ipvar HOME_NET 172.21.93.154/20


(or use the subnet form if you prefer, depending on your rules design)

✅ Why this matters

Many rules only trigger when traffic matches HOME_NET logic.

Wrong HOME_NET = no alerts / incomplete detection.

3) Ensure Snort Interface is Correct (eth0 vs others)

Snort must listen on the correct interface (example: eth0).

Check the default interface
ip route | grep default


Example output:

default via 172.21.80.1 dev eth0 proto kernel

If Snort is listening on the wrong interface, fix:

📌 /etc/snort/snort.init.conf

Edit:

sudo nano /etc/snort/snort.init.conf


Set the interface:

DEBIAN_SNORT_INTERFACE="eth0"


✅ Why this matters

If Snort listens on the wrong interface, it captures nothing → nothing gets pushed.

4) Restart Services After Config Changes

After updating:

/etc/ids-agent/agent.env

/etc/snort/snort.conf (HOME_NET)

/etc/snort/snort.init.conf (interface)

Restart services:

sudo systemctl restart snort
sudo systemctl restart snort-push
sudo systemctl restart correlator

5) Verify Services + Logs
Check service status
sudo systemctl status snort-push --no-pager -l
sudo systemctl status correlator --no-pager -l

Follow logs live
sudo journalctl -u snort-push -f
sudo journalctl -u correlator -f

6) Quick Connectivity Test to Dashboard API
Check port 5000 reachable
nc -vz -w 3 18.142.200.244 5000

Manual Snort push test (should return 200 OK)
curl -m 5 -i -X POST http://18.142.200.244:5000/api/snort \
  -H "X-API-Key: ids_vm_secret_key_123" \
  -H "Content-Type: application/json" \
  -d '{"timestamp":"2026-01-04 00:00:00","agent_id":"manual-test-snort","msg":"manual test","priority":"1","src_ip":"1.1.1.1","dest_ip":"2.2.2.2"}'


✅ If it returns:

{"status":"snort log stored"}


…the dashboard API is receiving Snort events.
## Quick Install
```bash
git clone https://github.com/SahiK19/agent-setup.git
cd agent-setup
chmod +x install.sh
sudo ./install.sh


