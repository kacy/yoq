#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "$0")/.."
fixture_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/yoq-service-gateway.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT
zig build-exe -O ReleaseSafe -lc --dep linux_platform \
  -Mroot=src/test_service_gateway.zig -Mlinux_platform=src/lib/linux_platform.zig \
  -femit-bin="$fixture_dir/fixture"
zig build-exe -O ReleaseSafe -lc --dep linux_platform \
  -Mroot=tests/privileged/http_server.zig -Mlinux_platform=src/lib/linux_platform.zig \
  -femit-bin="$fixture_dir/server"
sudo unshare --net -- bash -s -- "$fixture_dir/fixture" "$fixture_dir/server" <<'FIXTURE'
set -euo pipefail
fixture="$1"
server="$2"
holders=()
servers=()
cleanup() {
  for pid in "${servers[@]}" "${holders[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${servers[@]}" "${holders[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
ip link set lo up
ip link add yoq0 type bridge
ip addr add 10.42.0.1/16 dev yoq0
ip addr add 10.42.2.1/24 dev yoq0
ip link set yoq0 up
echo 1 > /proc/sys/net/ipv4/ip_forward
outer_ns="$(readlink /proc/self/ns/net)"
for index in 0 1 2; do
  unshare --net -- sleep 120 &
  holders+=("$!")
  for attempt in {1..100}; do
    child_ns="$(readlink "/proc/${holders[$index]}/ns/net")"
    if [[ "$child_ns" != "$outer_ns" ]]; then break; fi
    sleep 0.01
  done
  [[ "$child_ns" != "$outer_ns" ]]
  ip link add "veth$index" type veth peer name eth0 netns "${holders[$index]}"
  ip link set "veth$index" master yoq0
  ip link set "veth$index" up
done
"$fixture" configure "${holders[0]}" 10.42.0.3 10.42.0.1 16
"$fixture" configure "${holders[1]}" 10.42.0.2 10.42.0.1 16
"$fixture" configure "${holders[2]}" 10.42.2.2 10.42.2.1 24
"$fixture" load
for index in 1 2; do
  nsenter -t "${holders[$index]}" -n "$server" 8080 "backend-$index" &
  servers+=("$!")
done
for attempt in {1..30}; do
  if curl --noproxy '*' -fsS --max-time 1 http://10.42.0.2:8080/ >/dev/null 2>&1 &&
     curl --noproxy '*' -fsS --max-time 1 http://10.42.2.2:8080/ >/dev/null 2>&1; then break; fi
  sleep .05
done
# Real TCP replies must preserve the VIP through both local and node subnets.
# Repeated connections also catch route changes caused by ICMP redirects.
for attempt in {1..10}; do
  [[ "$(nsenter -t "${holders[0]}" -n curl --noproxy '*' -fsS --max-time 2 http://10.43.0.2:8080/)" == backend-1 ]]
  [[ "$(nsenter -t "${holders[0]}" -n curl --noproxy '*' -fsS --max-time 2 http://10.43.0.3:8080/)" == backend-2 ]]
done
for index in 1 2; do
  nsenter -t "${holders[$index]}" -n ip -j route get 10.42.0.3 |
    python3 -c 'import json,sys; assert "gateway" in json.load(sys.stdin)[0]'
done
nstat -az IcmpOutRedirects
echo 'service gateway fixture passed'
FIXTURE
