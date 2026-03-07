#!/usr/bin/env bash
# Deploy TrustChain seed node to a remote server via SSH.
#
# Usage:
#   ./deploy/deploy.sh [HOST] [SSH_USER]
#
# Defaults:
#   HOST=5.161.255.238  SSH_USER=root
#
# Prerequisites:
#   - SSH key-based auth to the target host
#   - GitHub release v0.2.0+ with linux-x64 binary

set -euo pipefail

HOST="${1:-5.161.255.238}"
USER="${2:-root}"
REMOTE="${USER}@${HOST}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Deploying TrustChain to ${REMOTE}"

# Determine latest release tag from GitHub
LATEST_TAG=$(curl -sf https://api.github.com/repos/viftode4/trustchain/releases/latest | grep '"tag_name"' | sed 's/.*"tag_name": "\(.*\)".*/\1/')
if [ -z "$LATEST_TAG" ]; then
    echo "ERROR: Could not fetch latest release tag from GitHub"
    exit 1
fi
echo "==> Latest release: ${LATEST_TAG}"

DOWNLOAD_URL="https://github.com/viftode4/trustchain/releases/download/${LATEST_TAG}/trustchain-node-linux-x64.tar.gz"

echo "==> Downloading binary from release..."
ssh "${REMOTE}" "
    set -e
    cd /tmp
    curl -sfL '${DOWNLOAD_URL}' -o trustchain-node.tar.gz
    tar xzf trustchain-node.tar.gz
    chmod +x trustchain-node
"

echo "==> Setting up system user and directories..."
ssh "${REMOTE}" "
    set -e
    id -u trustchain &>/dev/null || useradd -r -s /bin/false trustchain
    mkdir -p /var/lib/trustchain /etc/trustchain
    chown trustchain:trustchain /var/lib/trustchain
"

echo "==> Backing up identity key (if exists)..."
ssh "${REMOTE}" "
    if [ -f /var/lib/trustchain/identity.key ]; then
        cp /var/lib/trustchain/identity.key /var/lib/trustchain/identity.key.bak
        echo '  identity.key backed up'
    else
        echo '  no existing identity.key'
    fi
"

echo "==> Installing binary and config..."
ssh "${REMOTE}" "mv /tmp/trustchain-node /usr/local/bin/trustchain-node"
scp "${SCRIPT_DIR}/seed-node.toml" "${REMOTE}:/etc/trustchain/node.toml"
scp "${SCRIPT_DIR}/trustchain.service" "${REMOTE}:/etc/systemd/system/trustchain.service"

echo "==> Starting service..."
ssh "${REMOTE}" "
    set -e
    systemctl daemon-reload
    systemctl enable trustchain
    systemctl restart trustchain
    sleep 3
    systemctl status trustchain --no-pager || true
"

echo "==> Verifying health..."
sleep 2
if curl -sf "http://${HOST}:8202/healthz" > /dev/null; then
    echo "  /healthz: OK"
else
    echo "  WARNING: /healthz not responding yet (may need more time)"
fi

STATUS=$(curl -sf "http://${HOST}:8202/status" 2>/dev/null || echo '{}')
echo "==> Node status: ${STATUS}"

echo "==> Done! Seed node deployed at http://${HOST}:8202"
