#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "$0")/.."
# The synthetic character inode needs a filesystem that permits device I/O.
fixture_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/yoq-standard-devices.XXXXXX")"
trap 'sudo rm -rf -- "$fixture_dir"' EXIT
zig test -O ReleaseSafe -lc --test-no-exec \
  --dep linux_platform -Mroot=src/test_standard_devices.zig \
  -Mlinux_platform=src/lib/linux_platform.zig \
  --test-filter 'standard devices' -femit-bin="$fixture_dir/fixture"
cd "$fixture_dir"
sudo ./fixture
