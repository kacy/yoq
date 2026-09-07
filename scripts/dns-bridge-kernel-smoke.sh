#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "$0")/.."
fixture_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/yoq-dns-bridge.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT
zig build-exe -O ReleaseSafe -lc -lsqlite3 -Ivendor/zig-sqlite/c \
  vendor/zig-sqlite/c/workaround.c --dep sqlite --dep linux_platform \
  -Mroot=src/test_dns_bridge.zig -Ivendor/zig-sqlite/c \
  -Msqlite=vendor/zig-sqlite/sqlite.zig -Mlinux_platform=src/lib/linux_platform.zig \
  -femit-bin="$fixture_dir/fixture"
sudo python3 tools/test_dns_bridge.py --binary "$fixture_dir/fixture"
