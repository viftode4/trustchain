#!/bin/bash
# TrustChain Node installer.
# Usage: curl -sSfL https://trustchain.network/install.sh | bash
set -euo pipefail

REPO="trustchain-network/trustchain"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture.
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    linux)  OS_NAME="linux" ;;
    darwin) OS_NAME="macos" ;;
    *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH_NAME="x64" ;;
    aarch64|arm64) ARCH_NAME="arm64" ;;
    *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

BINARY="trustchain-node-${OS_NAME}-${ARCH_NAME}"

echo "Detecting system: ${OS_NAME}-${ARCH_NAME}"

# Get latest release tag.
LATEST=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
if [ -z "$LATEST" ]; then
    echo "Failed to detect latest release."
    exit 1
fi

echo "Latest release: $LATEST"

URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY}"
echo "Downloading ${URL}..."

TMPFILE=$(mktemp)
curl -sSfL "$URL" -o "$TMPFILE"
chmod +x "$TMPFILE"

# Install.
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMPFILE" "${INSTALL_DIR}/trustchain-node"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "$TMPFILE" "${INSTALL_DIR}/trustchain-node"
fi

echo ""
echo "TrustChain node installed to ${INSTALL_DIR}/trustchain-node"
echo ""
echo "Quick start:"
echo "  trustchain-node sidecar --name my-agent --endpoint http://localhost:8080"
echo ""
echo "Or run a full node:"
echo "  trustchain-node run"
