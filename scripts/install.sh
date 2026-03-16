#!/bin/sh
set -eu

# --- detect OS ---
OS=$(uname -s)
case "$OS" in
  Linux) ;;
  Darwin)
    echo "yoq is a Linux-only tool (requires kernel 6.1+, cgroups v2, eBPF)."
    echo "macOS is not supported. Consider running yoq in a Linux VM or container."
    exit 1
    ;;
  MINGW*|MSYS*|CYGWIN*)
    echo "yoq is a Linux-only tool (requires kernel 6.1+, cgroups v2, eBPF)."
    echo "Windows is not supported. Consider running yoq in a Linux VM or WSL2."
    exit 1
    ;;
  *)
    echo "unsupported operating system: $OS"
    echo "yoq requires Linux 6.1+ with cgroups v2 and eBPF support."
    exit 1
    ;;
esac

# --- detect architecture ---
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)   ARCH_NAME="amd64" ;;
  aarch64|arm64)   ARCH_NAME="arm64" ;;
  riscv64)         ARCH_NAME="riscv64" ;;
  *)
    echo "unsupported architecture: $ARCH"
    echo "yoq supports: x86_64 (amd64), aarch64 (arm64), riscv64"
    exit 1
    ;;
esac

# --- find latest release ---
REPO="kacy/yoq"
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
  grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "$LATEST" ]; then
  echo "failed to determine latest release. check https://github.com/${REPO}/releases"
  exit 1
fi

echo "installing yoq ${LATEST} (linux/${ARCH_NAME})..."

# --- download ---
BASE_URL="https://github.com/${REPO}/releases/download/${LATEST}"
TARBALL="yoq-linux-${ARCH_NAME}-${LATEST}.tar.gz"
CHECKSUM="yoq-linux-${ARCH_NAME}-${LATEST}.sha256"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -fsSL "${BASE_URL}/${TARBALL}" -o "${TMPDIR}/${TARBALL}"
curl -fsSL "${BASE_URL}/${CHECKSUM}" -o "${TMPDIR}/${CHECKSUM}"

# --- verify checksum ---
(cd "$TMPDIR" && sha256sum -c "${CHECKSUM}")

# --- install ---
tar -xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

INSTALL_DIR="/usr/local/bin"
if [ "$(id -u)" -ne 0 ]; then
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

mv "${TMPDIR}/yoq" "${INSTALL_DIR}/yoq"
chmod +x "${INSTALL_DIR}/yoq"

echo "yoq ${LATEST} installed to ${INSTALL_DIR}/yoq"

if [ "$INSTALL_DIR" = "${HOME}/.local/bin" ]; then
  case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "add ${INSTALL_DIR} to your PATH if not already present" ;;
  esac
fi

echo "run 'yoq doctor' to verify your system is ready"
