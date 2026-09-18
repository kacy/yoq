#!/usr/bin/env bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
yoq_binary="${YOQ_BIN:-$root_dir/zig-out/bin/yoq}"
artifacts="${YOQ_SMOKE_DIR:-$(mktemp -d /tmp/yoq-agent-drain.XXXXXX)}"
for command in unshare nsenter ip curl openssl python3; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done
[[ -x "$yoq_binary" && -x "$root_dir/zig-out/bin/yoq-test-http-server" ]] || {
  echo "build yoq and the runtime-cluster helpers before running this fixture" >&2
  exit 1
}
[[ "$EUID" == 0 ]] || { echo "run this smoke with sudo and an explicit YOQ_BIN" >&2; exit 1; }
cleanup() {
  # the pid namespace has exited. remove only empty cgroups recorded by these workers.
  python3 - "$artifacts" <<'PY'
from contextlib import closing
from pathlib import Path
import sqlite3
import sys
for database in Path(sys.argv[1]).glob("node-*/.local/share/yoq/yoq.db"):
    with closing(sqlite3.connect(f"file:{database}?mode=ro", uri=True)) as connection:
        for (container_id,) in connection.execute("SELECT id FROM containers"):
            if len(container_id) == 12 and all(char in "0123456789abcdef" for char in container_id):
                directory = Path("/sys/fs/cgroup/yoq") / container_id
                if directory.exists():
                    directory.rmdir()
PY
  printf 'artifacts: %s\n' "$artifacts"
}
trap cleanup EXIT
YOQ_RECOVERY_ISOLATED=1 unshare --mount --net --pid --fork --mount-proc -- \
  python3 "$root_dir/tests/cluster/agent_drain.py" --binary "$yoq_binary" --artifacts "$artifacts"
