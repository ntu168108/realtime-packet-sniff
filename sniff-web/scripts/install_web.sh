#!/bin/bash
# Idempotent installer for sniff-web.
# Usage: sudo bash sniff-web/scripts/install_web.sh
#
# What it does (7 steps):
#   1. Install Python deps from sniff-web/requirements-web.txt
#   2. Install Node.js + npm (if missing) and build the React/Vite frontend
#   3. Grant setcap cap_net_admin,cap_net_raw to /usr/bin/python3
#      (so the capture engine can open raw sockets without running as root)
#   4. Install /etc/sudoers.d/sniff-web (allowlist for systemctl + 6 services)
#   5. Render sniff-web.service from the template, substitute REPO_DIR,
#      real username, and the site-packages path into PYTHONPATH
#   6. Prepare /var/lib/sniff-web (state) and /var/log/sniff-web (logs)
#   7. daemon-reload + enable + restart sniff-web
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (sudo bash $0)" >&2
    exit 1
fi

# Resolve the real (non-root) user that invoked sudo so the service and
# state directories don't end up owned by an arbitrary hard-coded user.
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
if [[ "$REAL_USER" == "root" ]]; then
    echo "WARNING: running as root with no SUDO_USER; defaulting to 'tu'." >&2
    echo "         (install_web.sh will patch this on a normal 'sudo bash'.)" >&2
    REAL_USER="tu"
fi
REAL_GROUP="$(id -gn "$REAL_USER" 2>/dev/null || echo "$REAL_USER")"

echo "==> Install target user: ${REAL_USER}:${REAL_GROUP}"

# ----------------------------- [1/7] Python deps -----------------------------
echo "==> [1/7] Installing Python deps (sniff-web/requirements-web.txt)"
# Use --break-system-packages on Ubuntu 24.04 where PEP 668 blocks system pip.
# On Ubuntu 22.04 pip honours the flag silently (no-op).
PIP_EXTRA_ARGS=""
if python3 -m pip install --help 2>&1 | grep -q -- "--break-system-packages"; then
    PIP_EXTRA_ARGS="--break-system-packages"
fi
python3 -m pip install --quiet $PIP_EXTRA_ARGS -r sniff-web/requirements-web.txt

# ----------------------------- [2/7] Node + frontend build -------------------
echo "==> [2/7] Installing Node deps + building frontend"

# Ensure node + npm are present. Most Ubuntu server images don't ship them.
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    echo "    node/npm not found; installing via apt..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nodejs npm
fi

# Some distros (Ubuntu 22.04) ship an old node (v12) that vite >=5 won't run on.
NODE_MAJOR="$(node -e 'console.log(process.versions.node.split(".")[0])' 2>/dev/null || echo 0)"
if [[ "${NODE_MAJOR:-0}" -lt 18 ]]; then
    echo "    node ${NODE_MAJOR:-?}.x too old for vite >=5; installing NodeSource 20.x..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nodejs
fi

cd "$REPO_DIR/sniff-web/web"
if [[ ! -d node_modules ]]; then
    npm install
fi
npm run build
# Fail loud if the build produced nothing — otherwise uvicorn will serve 404s.
if [[ ! -f dist/index.html ]]; then
    echo "ERROR: npm run build did not produce dist/index.html" >&2
    echo "       re-run with 'cd sniff-web/web && npm install && npm run build' to diagnose" >&2
    exit 1
fi
cd "$REPO_DIR"

# ----------------------------- [3/7] setcap on python3 -----------------------
echo "==> [3/7] Granting setcap cap_net_admin,cap_net_raw to python3"
PYTHON_BIN="$(command -v python3)"
if [[ -z "$PYTHON_BIN" ]]; then
    echo "ERROR: python3 not found" >&2
    exit 1
fi
setcap cap_net_admin,cap_net_raw+ep "$PYTHON_BIN"
echo "    setcap on $PYTHON_BIN OK"

# ----------------------------- [4/7] sudoers ---------------------------------
echo "==> [4/7] Installing sudoers rule"
SUDOERS_SRC="$REPO_DIR/sniff-web/deploy/sudoers/sniff-web"
SUDOERS_DEST="/etc/sudoers.d/sniff-web"
if ! visudo -c -f "$SUDOERS_SRC" >/dev/null 2>&1; then
    echo "ERROR: sudoers file failed validation" >&2
    visudo -c -f "$SUDOERS_SRC"
    exit 1
fi
# Patch the username in the sudoers file from 'tu' to the real user.
TMP_SUDOERS="$(mktemp)"
sed "s|^tu ALL=(root) NOPASSWD:|${REAL_USER} ALL=(root) NOPASSWD:|" \
    "$SUDOERS_SRC" > "$TMP_SUDOERS"
# Re-validate after substitution.
if ! visudo -c -f "$TMP_SUDOERS" >/dev/null 2>&1; then
    echo "ERROR: patched sudoers file failed validation" >&2
    visudo -c -f "$TMP_SUDOERS"
    rm -f "$TMP_SUDOERS"
    exit 1
fi
install -m 0440 -o root -g root "$TMP_SUDOERS" "$SUDOERS_DEST"
rm -f "$TMP_SUDOERS"
echo "    $SUDOERS_DEST installed (user=${REAL_USER})"

# ----------------------------- [5/7] systemd unit ----------------------------
echo "==> [5/7] Installing systemd unit"
UNIT_SRC="$REPO_DIR/sniff-web/deploy/systemd/sniff-web.service"
UNIT_DEST="/etc/systemd/system/sniff-web.service"
if [[ ! -f "$UNIT_SRC" ]]; then
    echo "ERROR: unit template $UNIT_SRC missing" >&2
    exit 1
fi
TMP_UNIT="$(mktemp)"
sed \
    -e "s|/opt/realtime-packet-sniff|${REPO_DIR}|g" \
    -e "s|^User=tu|User=${REAL_USER}|" \
    -e "s|^Environment=PYTHONPATH=.*|Environment=PYTHONPATH=$(python3 -c 'import site; print(site.getusersitepackages())')|" \
    "$UNIT_SRC" > "$TMP_UNIT"
install -m 0644 -o root -g root "$TMP_UNIT" "$UNIT_DEST"
rm -f "$TMP_UNIT"
echo "    $UNIT_DEST installed (repo=${REPO_DIR}, user=${REAL_USER})"

# ----------------------------- [6/7] state + log dirs ------------------------
echo "==> [6/7] Preparing persistence dir + log dir"
mkdir -p /var/lib/sniff-web /var/log/sniff-web
chown -R "${REAL_USER}:${REAL_GROUP}" /var/lib/sniff-web /var/log/sniff-web
chmod 0750 /var/lib/sniff-web /var/log/sniff-web

# ----------------------------- [7/7] enable + start --------------------------
echo "==> [7/7] Enabling + starting sniff-web"
systemctl daemon-reload
systemctl enable sniff-web
systemctl restart sniff-web

# Wait briefly for uvicorn to bind, then sanity-check.
sleep 2
if systemctl is-active --quiet sniff-web; then
    STATUS="RUNNING"
else
    STATUS="FAILED — check: journalctl -u sniff-web -n 50"
fi

echo ""
echo "==============================================="
echo "  sniff-web install: $STATUS"
echo "==============================================="
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo "URL:      http://${HOST_IP:-localhost}:8000"
echo "Username: admin"
echo "Password: sniff  (CHANGE IMMEDIATELY in config.yaml)"
echo ""
echo "Next steps:"
echo "  1. Edit config.yaml to set a real bcrypt password:"
echo "       python3 -c \"import bcrypt; print(bcrypt.hashpw(b'NEW_PASS', bcrypt.gensalt()).decode())\""
echo "  2. sudo systemctl restart sniff-web"
