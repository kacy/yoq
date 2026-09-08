#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "$0")/.."
fixture_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/yoq-dns-cache.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT
zig build-exe -O ReleaseSafe -lc --dep linux_platform \
  -Mroot=src/test_dns_cache_keys.zig -Mlinux_platform=src/lib/linux_platform.zig \
  -femit-bin="$fixture_dir/fixture"
sudo unshare --net -- bash -s -- "$fixture_dir/fixture" <<'FIXTURE'
set -euo pipefail
fixture="$1"
holder=""
cleanup() {
  if [[ -n "$holder" ]]; then
    kill "$holder" 2>/dev/null || true
    wait "$holder" 2>/dev/null || true
  fi
}
trap cleanup EXIT
ip link set lo up
ip link add yoq0 type bridge
ip addr add 10.42.0.1/16 dev yoq0
ip link set yoq0 up
outer_ns="$(readlink /proc/self/ns/net)"
unshare --net -- sleep 120 &
holder="$!"
for attempt in {1..100}; do
  child_ns="$(readlink "/proc/$holder/ns/net")"
  if [[ "$child_ns" != "$outer_ns" ]]; then break; fi
  sleep 0.01
done
[[ "$child_ns" != "$outer_ns" ]]
ip link add fixture-host type veth peer name eth0 netns "$holder"
ip link set fixture-host master yoq0
ip link set fixture-host up
nsenter -t "$holder" -n ip addr add 10.42.0.2/16 dev eth0
nsenter -t "$holder" -n ip link set lo up
nsenter -t "$holder" -n ip link set eth0 up
"$fixture"
nsenter -t "$holder" -n python3 - <<'PY'
import socket
import struct

def query(name, kind=1, dns_class=1):
    wire = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    message = struct.pack("!6H", 0x517A, 0x0100, 1, 0, 0, 0) + wire + struct.pack("!HH", kind, dns_class)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(message, ("10.42.0.1", 53))
        return client.recvfrom(512)[0]

for name in ("web", "fixture.local", "a" * 61):
    response = query(name)
    transaction, flags, questions, answers, _, _ = struct.unpack("!6H", response[:12])
    assert transaction == 0x517A and flags & 0x8000
    assert questions == 1 and answers == 1
    assert response[-4:] == socket.inet_aton("10.43.0.2"), response.hex()

for name, kind, dns_class in (("missing.local", 1, 1), ("fixture.local", 28, 1), ("fixture.local", 1, 3)):
    try:
        query(name, kind, dns_class)
    except (TimeoutError, ConnectionRefusedError):
        continue
    raise AssertionError("unsupported query unexpectedly received a cached answer")
print("DNS kernel cache answers A/IN names and rejects misses, AAAA and other classes")
PY
FIXTURE
