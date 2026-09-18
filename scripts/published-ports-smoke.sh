#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname -- "$0")/.."
fixture_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/yoq-published-ports.XXXXXX")
trap 'rm -r -- "$fixture_dir"' EXIT
zig build-exe -O ReleaseSafe -lc --dep linux_platform \
  -Mroot=src/test_published_ports.zig -Mlinux_platform=src/lib/linux_platform.zig \
  -femit-bin="$fixture_dir/fixture"
zig build-exe -O ReleaseSafe -lc --dep linux_platform \
  -Mroot=tests/privileged/http_server.zig -Mlinux_platform=src/lib/linux_platform.zig \
  -femit-bin="$fixture_dir/server"
sudo unshare --net -- bash -s -- "$fixture_dir/fixture" "$fixture_dir/server" <<'FIXTURE'
set -euo pipefail
fixture=$1
server=$2
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
ip link set yoq0 up
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -P FORWARD DROP
iptables -N HOST_POLICY
iptables -A HOST_POLICY -d 203.0.113.0/24 -j DROP
iptables -A FORWARD -j HOST_POLICY
outer_ns=$(readlink /proc/self/ns/net)
for index in 0 1 2; do
  unshare --net -- sleep 120 &
  holders+=("$!")
  for attempt in {1..100}; do
    child_ns=$(readlink "/proc/${holders[$index]}/ns/net")
    [[ "$child_ns" != "$outer_ns" ]] && break
    sleep .01
  done
  [[ "$child_ns" != "$outer_ns" ]]
  ip link add "vp$index" type veth peer name eth0 netns "${holders[$index]}"
  ip link set "vp$index" up
  nsenter -t "${holders[$index]}" -n ip link set lo up
  nsenter -t "${holders[$index]}" -n ip link set eth0 up
  if [[ "$index" -lt 2 ]]; then
    ip link set "vp$index" master yoq0
    nsenter -t "${holders[$index]}" -n ip addr add "10.42.0.$((index+2))/16" dev eth0
    nsenter -t "${holders[$index]}" -n ip route add default via 10.42.0.1
    nsenter -t "${holders[$index]}" -n "$server" 8080 "backend-$index" &
    servers+=("$!")
  else
    ip addr add 192.0.2.1/24 dev "vp$index"
    nsenter -t "${holders[$index]}" -n ip addr add 192.0.2.2/24 dev eth0
  fi
done
for attempt in {1..50}; do
  if curl --noproxy '*' -fsS --max-time 1 http://10.42.0.2:8080/ >/dev/null 2>&1 &&
     curl --noproxy '*' -fsS --max-time 1 http://10.42.0.3:8080/ >/dev/null 2>&1; then break; fi
  sleep .02
done
"$fixture" full
"$fixture" full
# applying twice must not duplicate the shared jump rules.
[[ "$(iptables -t nat -S OUTPUT | grep -c -- '-j YOQ-PUBLISHED$')" == 1 ]]
iptables -C HOST_POLICY -d 203.0.113.0/24 -j DROP
seen_zero=false
seen_one=false
for attempt in {1..40}; do
  response=$(curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:18080/)
  case "$response" in backend-0) seen_zero=true;; backend-1) seen_one=true;; *) exit 1;; esac
done
[[ "$seen_zero" == true && "$seen_one" == true ]]
# external and host-address requests exercise both PREROUTING and OUTPUT.
curl --noproxy '*' -fsS --max-time 2 http://10.42.0.1:18080/ >/dev/null
nsenter -t "${holders[2]}" -n curl --noproxy '*' -fsS --max-time 2 http://192.0.2.1:18080/ >/dev/null
"$fixture" one
for attempt in {1..10}; do
  [[ "$(curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:18080/)" == backend-1 ]]
done
"$fixture" empty
if curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:18080/ >/dev/null 2>&1; then
  echo 'an empty service accepted a new connection' >&2
  exit 1
fi
"$fixture" clear
[[ "$(iptables -t nat -S YOQ-PUBLISHED | wc -l)" == 1 ]]
iptables -C HOST_POLICY -d 203.0.113.0/24 -j DROP
echo 'published port balancing, removal, and empty-service rejection passed'
FIXTURE
