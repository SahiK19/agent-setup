#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[1/9] Updating packages..."
sudo apt-get update -y

echo "[2/9] Installing OS dependencies..."
sudo apt-get install -y python3 python3-venv curl jq rsyslog logrotate

echo "[3/9] Installing Snort..."
sudo apt-get install -y snort

echo "[4/9] Re-deploying /opt/ids-agent..."
sudo rm -rf /opt/ids-agent
sudo mkdir -p /opt/ids-agent

echo "[5/9] Copying scripts..."
sudo cp -r "${REPO_DIR}/scripts" /opt/ids-agent/
sudo chmod +x /opt/ids-agent/scripts/*.py 2>/dev/null || true
sudo chmod +x /opt/ids-agent/scripts/*.sh 2>/dev/null || true

echo "[6/9] Creating Python venv..."
sudo python3 -m venv /opt/ids-agent/venv

echo "[7/9] Installing Python requirements into venv..."
sudo /opt/ids-agent/venv/bin/python3 -m pip install --upgrade pip >/dev/null
sudo /opt/ids-agent/venv/bin/python3 -m pip install -r "${REPO_DIR}/requirements.txt" >/dev/null

echo "[8/9] Installing config to /etc/ids-agent..."
sudo mkdir -p /etc/ids-agent
if [ ! -f /etc/ids-agent/agent.env ]; then
  sudo cp "${REPO_DIR}/config/agent.env.example" /etc/ids-agent/agent.env
  echo "  -> Created /etc/ids-agent/agent.env (edit if needed)."
else
  echo "  -> Keeping existing /etc/ids-agent/agent.env"
fi

echo "[9/9] Installing and starting services..."
sudo cp "${REPO_DIR}/systemd/"*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable snort-push.service correlator.service
sudo systemctl restart snort-push.service correlator.service

echo ""
echo "✅ Install complete."
echo "Check:"
echo "  sudo systemctl status snort-push correlator --no-pager"
