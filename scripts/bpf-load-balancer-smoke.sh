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
