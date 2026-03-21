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

modprobe wireguard || true

install -d -m 0755 /opt/yoq-gcp
install -m 0644 /tmp/smoke.py /opt/yoq-gcp/smoke.py

if [ "${ROLE}" = "agent-gpu" ]; then
  nvidia-smi -L >/opt/yoq-gcp/nvidia-smi.txt
fi
