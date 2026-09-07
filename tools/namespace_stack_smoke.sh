#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname -- "$0")/.."
fixture_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/yoq-namespace-stack.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT
zig test -O ReleaseSafe -fomit-frame-pointer -lc --test-no-exec \
  --dep linux_platform -Mroot=src/test_namespaces.zig \
  -Mlinux_platform=src/lib/linux_platform.zig \
  -femit-bin="$fixture_dir/fixture"
sudo "$fixture_dir/fixture"
