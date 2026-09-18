#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:?usage: install-node.sh <server|agent-cpu|agent-gpu>}"

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  ca-certificates \
  curl \
  iproute2 \
  iptables \
  jq \
  python3 \
  wireguard-tools

# use the upstream package repository; older distro packages lack attestations.
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  -o /etc/apt/keyrings/githubcli-archive-keyring.gpg
chmod 0644 /etc/apt/keyrings/githubcli-archive-keyring.gpg
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\n' \
  "$(dpkg --print-architecture)" > /etc/apt/sources.list.d/github-cli.list
apt-get update
apt-get install -y gh
gh attestation verify --help >/dev/null

modprobe wireguard || true

install -d -m 0755 /opt/yoq-gcp
install -m 0644 /tmp/smoke.py /opt/yoq-gcp/smoke.py

if [ "${ROLE}" = "agent-gpu" ]; then
  nvidia-smi -L >/opt/yoq-gcp/nvidia-smi.txt
fi
