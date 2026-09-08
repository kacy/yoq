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
  iptables -nvL FORWARD --line-numbers
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
# An existing host firewall keeps its default drop and explicit administrator chain.
iptables -P FORWARD DROP
iptables -N HOST_POLICY
iptables -A HOST_POLICY -d 203.0.113.0/24 -j DROP
iptables -A FORWARD -j HOST_POLICY
outer_ns="$(readlink /proc/self/ns/net)"
for index in 0 1 2 3; do
  unshare --net -- sleep 120 &
  holders+=("$!")
  for attempt in {1..100}; do
    child_ns="$(readlink "/proc/${holders[$index]}/ns/net")"
    if [[ "$child_ns" != "$outer_ns" ]]; then break; fi
    sleep 0.01
  done
  [[ "$child_ns" != "$outer_ns" ]]
  ip link add "veth$index" type veth peer name eth0 netns "${holders[$index]}"
  if [[ "$index" != 3 ]]; then ip link set "veth$index" master yoq0; fi
  ip link set "veth$index" up
done
"$fixture" configure "${holders[0]}" 10.42.0.3 10.42.0.1 16
"$fixture" configure "${holders[1]}" 10.42.0.2 10.42.0.1 16
"$fixture" configure "${holders[2]}" 10.42.2.2 10.42.2.1 24
# A fake upstream network exercises outbound NAT and established return traffic.
ip addr add 192.0.2.1/24 dev veth3
nsenter -t "${holders[3]}" -n ip link set lo up
nsenter -t "${holders[3]}" -n ip addr add 192.0.2.2/24 dev eth0
nsenter -t "${holders[3]}" -n ip link set eth0 up
nsenter -t "${holders[3]}" -n ip route add 10.42.0.0/16 via 192.0.2.1
"$fixture" load
for index in 1 2 3; do
  nsenter -t "${holders[$index]}" -n "$server" 8080 "backend-$index" &
  servers+=("$!")
done
for attempt in {1..30}; do
  if curl --noproxy '*' -fsS --max-time 1 http://10.42.0.2:8080/ >/dev/null 2>&1 &&
     curl --noproxy '*' -fsS --max-time 1 http://10.42.2.2:8080/ >/dev/null 2>&1 &&
     curl --noproxy '*' -fsS --max-time 1 http://192.0.2.2:8080/ >/dev/null 2>&1; then break; fi
  sleep .05
done
# Without the runtime's forwarding rules, even correctly translated VIP traffic drops.
if nsenter -t "${holders[0]}" -n curl --noproxy '*' -fsS --max-time 1 http://10.43.0.2:8080/; then
  echo 'VIP unexpectedly bypassed default forwarding drop' >&2
  exit 1
fi
iptables -nvL FORWARD --line-numbers
"$fixture" forward
rules="$(iptables -S)"
"$fixture" forward
[[ "$(iptables -S)" == "$rules" ]]
iptables -S FORWARD | head -1 | python3 -c 'import sys; assert sys.stdin.read().strip() == "-P FORWARD DROP"'
iptables -C HOST_POLICY -d 203.0.113.0/24 -j DROP
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
# Outbound connections and their replies work, but unsolicited upstream traffic does not.
[[ "$(nsenter -t "${holders[0]}" -n curl --noproxy '*' -fsS --max-time 2 http://192.0.2.2:8080/)" == backend-3 ]]
if nsenter -t "${holders[3]}" -n curl --noproxy '*' -fsS --max-time 1 http://10.42.0.2:8080/; then
  echo 'unsolicited upstream traffic bypassed forwarding policy' >&2
  exit 1
fi
# An administrator's earlier explicit deny still wins over runtime permits.
iptables -A HOST_POLICY -d 10.42.0.2/32 -j DROP
if nsenter -t "${holders[0]}" -n curl --noproxy '*' -fsS --max-time 1 http://10.43.0.2:8080/; then
  echo 'runtime forwarding bypassed explicit administrator deny' >&2
  exit 1
fi
iptables -nvL HOST_POLICY --line-numbers
iptables -D HOST_POLICY -d 10.42.0.2/32 -j DROP
[[ "$(nsenter -t "${holders[0]}" -n curl --noproxy '*' -fsS --max-time 2 http://10.43.0.2:8080/)" == backend-1 ]]
nstat -az IcmpOutRedirects
echo 'service gateway fixture passed'
FIXTURE
