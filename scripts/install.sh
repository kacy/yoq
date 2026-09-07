#!/bin/sh
set -eu

# Verify publisher attestations before extracting or installing any release.
for tool in curl gh python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "installation requires $tool (GitHub CLI with attestation support)" >&2
    exit 1
  fi
done

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

if ! printf '%s\n' "$LATEST" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "invalid release tag" >&2
  exit 1
fi

echo "installing yoq ${LATEST} (linux/${ARCH_NAME})..."

# --- download ---
BASE_URL="https://github.com/${REPO}/releases/download/${LATEST}"
TARBALL="yoq-linux-${ARCH_NAME}-${LATEST}.tar.gz"
CHECKSUM="yoq-linux-${ARCH_NAME}-${LATEST}.sha256"

INSTALL_TMP=$(mktemp -d)
trap 'rm -rf "$INSTALL_TMP"' EXIT

curl -fsSL "${BASE_URL}/${TARBALL}" -o "${INSTALL_TMP}/${TARBALL}"
curl -fsSL "${BASE_URL}/${CHECKSUM}" -o "${INSTALL_TMP}/${CHECKSUM}"

# --- verify checksum ---
# strip any directory prefix from the checksum file (older releases used dist/ prefix)
sed -i "s|[^ ]*/||" "${INSTALL_TMP}/${CHECKSUM}"
(cd "$INSTALL_TMP" && sha256sum -c "${CHECKSUM}")

curl -fsSL "${BASE_URL}/provenance.json" -o "${INSTALL_TMP}/provenance.json"
for artifact in "$TARBALL" provenance.json; do
  gh attestation verify "${INSTALL_TMP}/${artifact}" --repo "$REPO" \
    --signer-workflow "${REPO}/.github/workflows/release.yml" \
    --deny-self-hosted-runners
done

# The signed metadata binds this archive's digest to the requested release tag.
python3 - "${INSTALL_TMP}/provenance.json" "$LATEST" "$TARBALL" "${INSTALL_TMP}/${TARBALL}" <<'PYVERIFY'
import hashlib
import json
import sys
from pathlib import Path
metadata, tag, name, archive = sys.argv[1:]
provenance = json.loads(Path(metadata).read_text())
digest = hashlib.sha256(Path(archive).read_bytes()).hexdigest()
if provenance['invocation']['tag'] != tag or not any(
    item['name'] == name and item['sha256'] == digest for item in provenance['subject']
):
    raise SystemExit('signed release metadata does not match requested archive')
PYVERIFY

# --- install ---
tar -xzf "${INSTALL_TMP}/${TARBALL}" -C "$INSTALL_TMP"

INSTALL_DIR="/usr/local/bin"
if [ "$(id -u)" -ne 0 ]; then
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

mv "${INSTALL_TMP}/yoq" "${INSTALL_DIR}/yoq"
chmod +x "${INSTALL_DIR}/yoq"

echo "yoq ${LATEST} installed to ${INSTALL_DIR}/yoq"

if [ "$INSTALL_DIR" = "${HOME}/.local/bin" ]; then
  case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "add ${INSTALL_DIR} to your PATH if not already present" ;;
  esac
fi

echo "run 'yoq doctor' to verify your system is ready"
