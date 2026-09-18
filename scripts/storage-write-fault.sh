#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname -- "$0")/.."
fixture_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/yoq-storage-fault.XXXXXX")
trap 'rm -r -- "$fixture_dir"' EXIT
# compile before applying the file-size limit so only object writes are affected.
zig test -O ReleaseSafe -lc --dep linux_platform \
  -Mroot=src/test_storage_write_fault.zig -Mlinux_platform=src/lib/linux_platform.zig \
  --test-filter 'storage write fault' --test-no-exec -femit-bin="$fixture_dir/test"
python3 - "$fixture_dir/test" <<'PY'
import resource
import signal
import subprocess
import sys


def short_writes():
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (8, 8))


subprocess.run([sys.argv[1]], preexec_fn=short_writes, check=True)
PY
