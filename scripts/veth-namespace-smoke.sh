#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "$0")/.."
fixture_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/yoq-veth-namespace.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT
zig build-exe -O ReleaseSafe -lc --dep linux_platform \
  -Mroot=src/test_veth_namespace.zig -Mlinux_platform=src/lib/linux_platform.zig \
  -femit-bin="$fixture_dir/fixture"
# Every link lives in a disposable outer namespace, including the simulated
# host eth0. Namespace holder processes are reaped even when an assertion fails.
sudo unshare --net -- bash -s -- "$fixture_dir/fixture" <<'FIXTURE'
set -euo pipefail
fixture="$1"
holders=()
cleanup() {
  for pid in "${holders[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${holders[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
ip link add eth0 type dummy
ip addr add 192.0.2.10/24 dev eth0
ip link set eth0 up
host_before="$(ip -j addr show dev eth0)"
ip link add yoq-fixture type bridge
ip link set yoq-fixture up
# The original create-then-move operation fails on this exact topology.
if "$fixture" veth_old -1; then exit 1; fi
if ip link show dev veth_old 2>/dev/null; then exit 1; fi
outer_ns="$(readlink /proc/self/ns/net)"
for index in 0 1; do
  unshare --net -- sleep 120 &
  holders+=("$!")
  for attempt in {1..100}; do
    child_ns="$(readlink "/proc/${holders[$index]}/ns/net")"
    if [[ "$child_ns" != "$outer_ns" ]]; then break; fi
    sleep 0.01
  done
  [[ "$child_ns" != "$outer_ns" ]]
done
# Both peers use eth0 concurrently without competing for the host name.
"$fixture" veth_one "${holders[0]}" &
first=$!
"$fixture" veth_two "${holders[1]}" &
second=$!
wait "$first"
wait "$second"
for index in 0 1; do
  nsenter -t "${holders[$index]}" -n ip -j -d link show dev eth0 |
    python3 -c 'import json,sys; assert json.load(sys.stdin)[0]["linkinfo"]["info_kind"] == "veth"'
done
for name in veth_one veth_two; do
  ip -j link show dev "$name" |
    python3 -c 'import json,sys; link=json.load(sys.stdin)[0]; assert link["master"] == "yoq-fixture" and "UP" in link["flags"]'
done
[[ "$(ip -j addr show dev eth0)" == "$host_before" ]]
# A missing target cannot leave a half-created pair behind.
if "$fixture" veth_missing 2147483647; then exit 1; fi
if ip link show dev veth_missing 2>/dev/null; then exit 1; fi
"$fixture" veth_local 0
ip link show dev local_peer >/dev/null
ip link delete veth_local
if ip link show dev local_peer 2>/dev/null; then exit 1; fi
ip link delete veth_one
ip link delete veth_two
for pid in "${holders[@]}"; do
  if nsenter -t "$pid" -n ip link show dev eth0 2>/dev/null; then exit 1; fi
done
[[ "$(ip -j addr show dev eth0)" == "$host_before" ]]
echo 'veth namespace fixture passed'
FIXTURE
