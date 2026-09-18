#!/usr/bin/env bash
set -euo pipefail

repo="$(cd -- "$(dirname -- "$0")/.." && pwd)"
fixture_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/yoq-bpf-lb.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT
cd "$repo"
zig build-exe -O ReleaseSafe --dep linux_platform --dep lb_bytecode \
  -Mroot=src/test_bpf_load_balancer.zig \
  -Mlinux_platform=src/lib/linux_platform.zig \
  -Mlb_bytecode=src/network/bpf/lb.zig -lc -femit-bin="$fixture_dir/fixture"
# No attachment or pinning: these private maps and programs disappear on close.
sudo "$fixture_dir/fixture"
zig build-exe -O ReleaseSafe --dep linux_platform --dep lb_bytecode \
  --dep port_bytecode --dep policy_bytecode --dep dns_bytecode \
  --dep metrics_bytecode --dep storage_bytecode --dep gpu_bytecode \
  -Mroot=src/test_bpf_packets.zig \
  -Mlinux_platform=src/lib/linux_platform.zig \
  -Mlb_bytecode=src/network/bpf/lb.zig \
  -Mport_bytecode=src/network/bpf/port_map.zig \
  -Mpolicy_bytecode=src/network/bpf/policy.zig \
  -Mdns_bytecode=src/network/bpf/dns_intercept.zig \
  -Mmetrics_bytecode=src/network/bpf/metrics.zig \
  -Mstorage_bytecode=src/network/bpf/storage_metrics.zig \
  -Mgpu_bytecode=src/network/bpf/gpu_prio.zig \
  -lc -femit-bin="$fixture_dir/packets"
sudo "$fixture_dir/packets"
