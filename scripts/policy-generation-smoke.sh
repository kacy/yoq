#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname -- "$0")/.."
fixture_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/yoq-policy-generation.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT
zig build-exe -O ReleaseSafe -lc --dep linux_platform \
  -Mroot=src/test_policy_generation.zig -Mlinux_platform=src/lib/linux_platform.zig \
  -femit-bin="$fixture_dir/fixture"
sudo unshare --net -- bash -s -- "$fixture_dir/fixture" <<'FIXTURE'
set -euo pipefail
ip link add yoq0 type bridge
ip link set yoq0 up
"$1"
[[ "$(tc -j filter show dev yoq0 ingress)" == '[]' ]]
echo 'policy generation preserves denies on map failure and repairs replaced ownership'
FIXTURE
