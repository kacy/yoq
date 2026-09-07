#!/usr/bin/env bash
set -euo pipefail

# Use wireguard-tools as an independent reader of the kernel configuration.
# The native writer is confined to a new network namespace, removed on exit.
if [[ "${1:-}" == --inside ]]; then
  test "$(readlink /proc/self/ns/net)" != "$2"
  fixture="$3"
  private_key="$(wg genkey)"
  public_key="$(printf '%s' "$private_key" | wg pubkey)"
  peer_key="$(wg genkey | wg pubkey)"
  "$fixture" create "$private_key" "$peer_key"
  test "$(wg show yoq-fixture public-key)" = "$public_key"
  test "$(wg show yoq-fixture listen-port)" = 51900
  test "$(wg show yoq-fixture allowed-ips)" = "$(printf '%s\t10.77.0.0/24' "$peer_key")"
  test "$(wg show yoq-fixture endpoints)" = "$(printf '%s\t127.0.0.1:51901' "$peer_key")"
  test "$(wg show yoq-fixture persistent-keepalive)" = "$(printf '%s\t25' "$peer_key")"
  "$fixture" remove-peer "$peer_key"
  test -z "$(wg show yoq-fixture peers)"
  "$fixture" delete
  test -z "$(wg show interfaces)"
  echo 'WireGuard kernel interface, key, port, peer, allowed IPs, and removal passed'
  exit
fi

command -v wg >/dev/null
repo="$(cd -- "$(dirname -- "$0")/.." && pwd)"
fixture_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/yoq-wireguard.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT
cd "$repo"
zig build-exe -O ReleaseSafe --dep wireguard -Mroot=scripts/fixtures/wireguard_kernel.zig \
  --dep linux_platform -Mwireguard=src/network/wireguard.zig \
  -Mlinux_platform=src/lib/linux_platform.zig -lc -femit-bin="$fixture_dir/fixture"
sudo --preserve-env=PATH unshare --net bash "$0" --inside "$(readlink /proc/self/ns/net)" "$fixture_dir/fixture"
