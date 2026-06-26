#!/bin/bash
# Idempotent installer for sniff-web.
# Usage: sudo bash sniff-web/scripts/install_web.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (sudo bash $0)" >&2
    exit 1
fi

echo "==> [1/7] Installing Python deps (sniff-web/requirements-web.txt)"
pip install --break-system-packages -r sniff-web/requirements-web.txt

echo "==> [2/7] Installing Node deps + building frontend"
cd "$REPO_DIR/sniff-web/web"
if [[ ! -d node_modules ]]; then
    npm install
fi
npm run build
cd "$REPO_DIR"

echo "==> [3/7] Granting setcap cap_net_admin,cap_net_raw to python3"
PYTHON_BIN="$(command -v python3)"
if [[ -z "$PYTHON_BIN" ]]; then
    echo "ERROR: python3 not found" >&2
    exit 1
fi
setcap cap_net_admin,cap_net_raw+ep "$PYTHON_BIN"
echo "    setcap on $PYTHON_BIN OK"

echo "==> [4/7] Installing sudoers rule"
SUDOERS_SRC="$REPO_DIR/sniff-web/deploy/sudoers/sniff-web"
SUDOERS_DEST="/etc/sudoers.d/sniff-web"
if ! visudo -c -f "$SUDOERS_SRC" >/dev/null 2>&1; then
    echo "ERROR: sudoers file failed validation" >&2
    visudo -c -f "$SUDOERS_SRC"
    exit 1
fi
cp "$SUDOERS_SRC" "$SUDOERS_DEST"
chmod 0440 "$SUDOERS_DEST"
echo "    $SUDOERS_DEST installed"

echo "==> [5/7] Installing systemd unit"
UNIT_SRC="$REPO_DIR/sniff-web/deploy/systemd/sniff-web.service"
UNIT_DEST="/etc/systemd/system/sniff-web.service"
sed "s|/opt/realtime-packet-sniff|$REPO_DIR|g" "$UNIT_SRC" > "$UNIT_DEST"
echo "    $UNIT_DEST installed (with $REPO_DIR)"

echo "==> [6/7] Preparing persistence dir + log dir"
mkdir -p /var/lib/sniff-web /var/log/sniff-web
chown -R tu:tu /var/lib/sniff-web /var/log/sniff-web
chmod 0750 /var/lib/sniff-web /var/log/sniff-web

echo "==> [7/7] Enabling + starting sniff-web"
systemctl daemon-reload
systemctl enable sniff-web
systemctl restart sniff-web

echo ""
echo "==============================================="
echo "  sniff-web installed and started"
echo "==============================================="
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo "URL:      http://${HOST_IP:-localhost}:8000"
echo "Username: admin"
echo "Password: sniff  (CHANGE IMMEDIATELY in config.yaml)"
echo ""
echo "Next steps:"
echo "  1. Edit config.yaml to set a real bcrypt password:"
echo "       python3 -c \"import bcrypt; print(bcrypt.hashpw(b'NEW_PASS', bcrypt.gensalt()).decode())\""
echo "  2. systemctl restart sniff-web"
