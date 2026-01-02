#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[1/8] Updating packages..."
sudo apt-get update -y

echo "[2/8] Installing OS dependencies..."
sudo apt-get install -y python3 python3-pip curl jq rsyslog logrotate

echo "[3/8] Installing Snort..."
sudo apt-get install -y snort

echo "[4/8] Installing Python requirements (venv)..."
sudo apt-get install -y python3-venv

# Create venv under /opt/ids-agent (we create the folder first)
sudo mkdir -p /opt/ids-agent
sudo python3 -m venv /opt/ids-agent/venv

# Install requirements using venv pip
sudo /opt/ids-agent/venv/bin/pip install --upgrade pip >/dev/null
sudo /opt/ids-agent/venv/bin/pip install -r "${REPO_DIR}/requirements.txt" >/dev/null

echo "[5/8] Deploying scripts to /opt/ids-agent..."
sudo rm -rf /opt/ids-agent
sudo mkdir -p /opt/ids-agent
sudo cp -r "${REPO_DIR}/scripts" /opt/ids-agent/
sudo chmod +x /opt/ids-agent/scripts/*.py 2>/dev/null || true
sudo chmod +x /opt/ids-agent/scripts/*.sh 2>/dev/null || true

echo "[6/8] Installing config to /etc/ids-agent..."
sudo mkdir -p /etc/ids-agent
if [ ! -f /etc/ids-agent/agent.env ]; then
  sudo cp "${REPO_DIR}/config/agent.env.example" /etc/ids-agent/agent.env
  echo "  -> Created /etc/ids-agent/agent.env (PLEASE EDIT IT)."
else
  echo "  -> Keeping existing /etc/ids-agent/agent.env"
fi

echo "[7/8] Installing systemd services..."
sudo cp "${REPO_DIR}/systemd/"*.service /etc/systemd/system/
sudo systemctl daemon-reload

echo "[8/8] Enabling and restarting services..."
sudo systemctl enable snort-push.service correlator.service
sudo systemctl restart snort-push.service correlator.service

echo ""
echo "✅ Install complete."
echo "Next:"
echo "  1) sudo nano /etc/ids-agent/agent.env"
echo "  2) sudo systemctl restart snort-push correlator"
echo "  3) sudo systemctl status snort-push correlator --no-pager"
