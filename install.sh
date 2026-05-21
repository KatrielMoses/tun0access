#!/usr/bin/env sh
# tun0access installer — Linux & macOS
# Usage:  curl -fsSL https://raw.githubusercontent.com/tun0access/tun0access/main/install.sh | sh
set -e

REPO="KatrielMoses/tun0access"
BIN="tun0access"
INSTALL_DIR="/usr/local/bin"

# ── detect OS ────────────────────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux)  OS="linux"  ;;
  darwin) OS="darwin" ;;
  *)
    echo "Unsupported OS: $OS" >&2
    echo "For Windows, run the PowerShell one-liner from the README." >&2
    exit 1
    ;;
esac

# ── detect arch ──────────────────────────────────────────────────────────────
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)    ARCH="amd64"  ;;
  aarch64|arm64)   ARCH="arm64"  ;;
  armv7l|armv6l)   ARCH="arm"    ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

# ── resolve latest release ───────────────────────────────────────────────────
echo "Fetching latest release…"
if command -v curl >/dev/null 2>&1; then
  FETCH="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  FETCH="wget -qO-"
else
  echo "Neither curl nor wget found. Install one and retry." >&2
  exit 1
fi

VERSION=$($FETCH "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | cut -d'"' -f4)

if [ -z "$VERSION" ]; then
  echo "Could not determine latest version. Check https://github.com/${REPO}/releases" >&2
  exit 1
fi

# ── download & install ───────────────────────────────────────────────────────
TARBALL="${BIN}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

echo "Downloading tun0access ${VERSION} (${OS}/${ARCH})…"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

$FETCH "$URL" > "${TMP}/${TARBALL}"
tar -xzf "${TMP}/${TARBALL}" -C "$TMP"

# ── put binary on PATH ───────────────────────────────────────────────────────
if [ -w "$INSTALL_DIR" ]; then
  mv "${TMP}/${BIN}" "${INSTALL_DIR}/${BIN}"
else
  echo "Installing to ${INSTALL_DIR} (sudo required)…"
  sudo mv "${TMP}/${BIN}" "${INSTALL_DIR}/${BIN}"
fi
chmod +x "${INSTALL_DIR}/${BIN}"

echo ""
echo "tun0access ${VERSION} installed to ${INSTALL_DIR}/${BIN}"
echo "Run:  tun0access connect"
