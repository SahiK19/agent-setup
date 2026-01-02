#!/usr/bin/env bash
set -euo pipefail

echo "[1/5] Stopping services..."
sudo systemctl disable --now snort-push.service 2>/dev/null || true
sudo systemctl disable --now correlator.service 2>/dev/null || true

echo "[2/5] Removing systemd unit files..."
sudo rm -f /etc/systemd/system/snort-push.service
sudo rm -f /etc/systemd/system/correlator.service

echo "[3/5] Reloading systemd..."
sudo systemctl daemon-reload

echo "[4/5] Removing installed files..."
sudo rm -rf /opt/ids-agent

echo "[5/5] Removing config files..."
sudo rm -rf /etc/ids-agent

echo "✅ Uninstalled."
