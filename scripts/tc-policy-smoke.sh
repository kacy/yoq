#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "$0")/.."
fixture_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/yoq-tc-policy.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT
zig build-exe -O ReleaseSafe -lc --dep linux_platform \
  -Mroot=src/test_tc_policy_chain.zig -Mlinux_platform=src/lib/linux_platform.zig \
  -femit-bin="$fixture_dir/fixture"
zig build-exe -O ReleaseSafe -lc --dep linux_platform \
  -Mroot=tests/privileged/http_server.zig -Mlinux_platform=src/lib/linux_platform.zig \
  -femit-bin="$fixture_dir/server"
for order in default reverse; do
sudo unshare --net -- bash -s -- "$fixture_dir/fixture" "$fixture_dir/server" "$order" <<'FIXTURE'
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
nsenter -t "${holders[0]}" -n ip addr add 10.42.0.127/32 dev eth0
coproc CONTROL { "$fixture" chain "$3"; }
servers+=("$CONTROL_PID")
read -r acknowledgment <&"${CONTROL[0]}"
[[ "$acknowledgment" == ok ]]
control() {
  printf '%s' "$1" >&"${CONTROL[1]}"
  read -r acknowledgment <&"${CONTROL[0]}"
  [[ "$acknowledgment" == ok ]]
}
# A separate administrator classifier must survive all owned load/unload work.
tc filter add dev yoq0 ingress pref 500 handle 99 matchall action pass
assert_filters() {
  tc -j filter show dev yoq0 ingress | python3 -c '
import json,sys
filters=json.load(sys.stdin)
names=[f["options"]["bpf_name"] for f in filters if f.get("kind")=="bpf" and "options" in f]
assert sorted(names)==sorted(sys.argv[1:]), names
assert any(f.get("kind")=="matchall" and f.get("pref")==500 for f in filters), filters
' "$@"
}
assert_filters yoq-policy yoq-dns yoq-lb yoq-metrics
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
# A map miss must still reach the userspace DNS fallback through the chain.
python3 - <<'DNS_SERVER' &
import socket
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server:
    server.bind(("10.42.0.1",53))
    query,peer=server.recvfrom(512)
    server.sendto(query[:2]+b"\x81\x80"+query[4:6]+b"\x00\x01\x00\x00\x00\x00"+query[12:]+b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04"+socket.inet_aton("10.43.0.2"),peer)
DNS_SERVER
servers+=("$!")
for attempt in {1..50}; do
  if ss -H -lun 'sport = :53' | grep -q 10.42.0.1; then break; fi
  sleep .02
done
nsenter -t "${holders[0]}" -n python3 - <<'DNS'
import socket, struct
query=struct.pack('!HHHHHH',0x5151,0x100,1,0,0,0)+b'\x08fallback\x05local\x00'+struct.pack('!HH',1,1)
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
    client.settimeout(2)
    client.sendto(query,('10.42.0.1',53))
    reply,_=client.recvfrom(512)
    assert reply[:2]==query[:2] and reply[-4:]==socket.inet_aton('10.43.0.2')
DNS
control l
assert_filters yoq yoq-policy yoq-dns yoq-lb yoq-metrics
control p
control p
assert_filters yoq-policy yoq-dns yoq-lb yoq-metrics
control d
for ttl in 64 255; do
  nsenter -t "${holders[0]}" -n sh -c "echo $ttl > /proc/sys/net/ipv4/ip_default_ttl"
  for source in 10.42.0.3 10.42.0.127; do
  if nsenter -t "${holders[0]}" -n curl --interface "$source" --noproxy '*' -fsS --max-time 1 http://10.43.0.2:8080/; then
    echo "installed deny was bypassed with ttl=$ttl" >&2
    exit 1
  fi
  done
done
control r
for source in 10.42.0.3 10.42.0.127; do
  [[ "$(nsenter -t "${holders[0]}" -n curl --interface "$source" --noproxy '*' -fsS --max-time 2 http://10.43.0.2:8080/)" == backend-1 ]]
done
nsenter -t "${holders[0]}" -n sh -c 'echo 64 > /proc/sys/net/ipv4/ip_default_ttl'
[[ "$(nsenter -t "${holders[0]}" -n curl --noproxy '*' -fsS --max-time 2 http://10.43.0.2:8080/)" == backend-1 ]]
# Removing one component must preserve both the balancer and deny enforcement.
control u
assert_filters yoq-policy yoq-lb yoq-metrics
control d
if nsenter -t "${holders[0]}" -n curl --noproxy '*' -fsS --max-time 1 http://10.43.0.2:8080/; then exit 1; fi
[[ "$(nsenter -t "${holders[0]}" -n curl --noproxy '*' -fsS --max-time 2 http://10.43.0.3:8080/)" == backend-2 ]]
printf q >&"${CONTROL[1]}"
wait "$CONTROL_PID"
assert_filters
[[ "$(tc -j filter show dev yoq0 egress)" == '[]' ]]
echo "tc policy fixture passed ($3)"
FIXTURE
done

# A classifier owned by an administrator at our policy slot must not be replaced.
sudo unshare --net -- bash -s -- "$fixture_dir/fixture" <<'COLLISION'
set -euo pipefail
ip link add yoq0 type bridge
ip link set yoq0 up
tc qdisc add dev yoq0 clsact
tc filter add dev yoq0 ingress pref 10 handle 1 matchall action drop
if "$1" chain default </dev/null; then
  echo 'administrator classifier was replaced' >&2
  exit 1
fi
tc -j filter show dev yoq0 ingress | python3 -c '
import json,sys
filters=json.load(sys.stdin)
assert any(f.get("kind")=="matchall" and f.get("pref")==10 and "options" in f for f in filters), filters
assert not any(f.get("kind")=="bpf" for f in filters), filters
'
echo 'tc ownership collision fixture passed'
COLLISION

# A different process holding the namespace lock cannot hang startup indefinitely.
sudo unshare --net -- python3 - "$fixture_dir/fixture" <<'CONTENTION'
import fcntl, os, subprocess, sys, time
subprocess.run(["ip","link","add","yoq0","type","bridge"],check=True)
with open("/proc/thread-self/ns/net", "rb") as lock:
    fcntl.flock(lock,fcntl.LOCK_EX)
    start=time.monotonic()
    result=subprocess.run([sys.argv[1],"chain","default"],stdin=subprocess.DEVNULL,timeout=3)
    assert result.returncode != 0
    assert time.monotonic()-start < 3
print("tc namespace contention fixture passed")
CONTENTION
