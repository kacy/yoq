#!/usr/bin/env bash
set -euo pipefail
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
yoq_binary="${YOQ_BIN:-$root_dir/zig-out/bin/yoq}"
artifacts="${YOQ_SMOKE_DIR:-$(mktemp -d /tmp/yoq-agent-recovery.XXXXXX)}"
for command in unshare nsenter ip iptables python3; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done
[[ -x "$yoq_binary" ]] || { echo "set YOQ_BIN to the built yoq executable" >&2; exit 1; }
[[ "$EUID" == 0 ]] || { echo "run this smoke with sudo and an explicit YOQ_BIN" >&2; exit 1; }
# the outer namespaces contain every fixture interface and process. a failed
# assertion cannot leave a server or alter the host's network rules.
trap 'printf "artifacts: %s\n" "$artifacts"' EXIT
YOQ_RECOVERY_ISOLATED=1 unshare --mount --net --pid --fork --mount-proc -- \
  python3 "$root_dir/tests/cluster/agent_recovery.py" --binary "$yoq_binary" --artifacts "$artifacts"
