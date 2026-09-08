#!/bin/sh
set -eu

# Verify publisher attestations before extracting or installing any release.
for tool in curl gh python3 tar sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "installation requires $tool. install it and run this command again." >&2
    exit 1
  fi
done
if ! gh attestation verify --help >/dev/null 2>&1; then
  echo "installation requires GitHub CLI with attestation support. update gh and try again." >&2
  exit 1
fi
if ! gh auth status --hostname github.com >/dev/null 2>&1; then
  echo "release verification requires GitHub authentication. run 'gh auth login' or set GH_TOKEN, then try again." >&2
  exit 1
fi

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
if ! RELEASE=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest"); then
  echo "could not find the latest release. check https://github.com/${REPO}/releases" >&2
  exit 1
fi
LATEST=$(printf '%s' "$RELEASE" | python3 -c '
import json
import re
import sys
try:
    tag = json.load(sys.stdin)["tag_name"]
    if not isinstance(tag, str) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("invalid tag")
except (ValueError, KeyError, TypeError):
    raise SystemExit("latest release metadata has no valid version tag")
print(tag)
')

echo "installing yoq ${LATEST} (linux/${ARCH_NAME})..."

# --- download ---
BASE_URL="https://github.com/${REPO}/releases/download/${LATEST}"
TARBALL="yoq-linux-${ARCH_NAME}-${LATEST}.tar.gz"
CHECKSUM="yoq-linux-${ARCH_NAME}-${LATEST}.sha256"

INSTALL_TMP=$(mktemp -d)
trap 'rm -rf "$INSTALL_TMP"' EXIT

verify_attestation() {
  if ! gh attestation verify "${INSTALL_TMP}/$1" --repo "$REPO" \
    --signer-workflow "${REPO}/.github/workflows/release.yml" \
    --deny-self-hosted-runners; then
    echo "could not verify the publisher attestation for $1. nothing was installed." >&2
    exit 1
  fi
}

# Check the release metadata before downloading the larger archive.
if ! curl -fsSL "${BASE_URL}/provenance.json" -o "${INSTALL_TMP}/provenance.json"; then
  echo "release ${LATEST} has no available verification metadata (provenance.json). nothing was installed." >&2
  echo "check https://github.com/${REPO}/releases/tag/${LATEST}" >&2
  exit 1
fi
verify_attestation provenance.json

# The signed metadata binds this archive's digest to the requested release tag.
EXPECTED_DIGEST=$(python3 - "${INSTALL_TMP}/provenance.json" "$LATEST" "$TARBALL" <<'PYVERIFY'
import json
import re
import sys
from pathlib import Path
metadata, tag, name = sys.argv[1:]
try:
    provenance = json.loads(Path(metadata).read_text())
    matches = [item['sha256'] for item in provenance['subject'] if item['name'] == name]
    if provenance['invocation']['tag'] != tag or len(matches) != 1:
        raise ValueError('release or archive mismatch')
    digest = matches[0]
    if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ValueError('invalid digest')
except (ValueError, KeyError, TypeError):
    raise SystemExit('signed release metadata does not identify the requested release and archive')
print(digest)
PYVERIFY
)

curl -fsSL "${BASE_URL}/${TARBALL}" -o "${INSTALL_TMP}/${TARBALL}"
curl -fsSL "${BASE_URL}/${CHECKSUM}" -o "${INSTALL_TMP}/${CHECKSUM}"

# Older releases used a dist/ prefix in the checksum filename.
sed -i "s|[^ ]*/||" "${INSTALL_TMP}/${CHECKSUM}"
(cd "$INSTALL_TMP" && sha256sum -c "${CHECKSUM}")
verify_attestation "$TARBALL"
if ! (cd "$INSTALL_TMP" && printf '%s  %s\n' "$EXPECTED_DIGEST" "$TARBALL" | sha256sum -c -); then
  echo "archive checksum does not match the signed release metadata. nothing was installed." >&2
  exit 1
fi

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
