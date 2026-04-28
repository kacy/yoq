#!/usr/bin/env bash
set -euo pipefail

pattern='catch unreachable|orelse unreachable|@panic|std\.debug\.panic'
baseline_file="${1:-tools/panic_audit_baseline.txt}"

if [[ ! -f "$baseline_file" ]]; then
  echo "panic audit baseline not found: $baseline_file" >&2
  exit 1
fi

tmp_current="$(mktemp)"
tmp_excess="$(mktemp)"
trap 'rm -f "$tmp_current" "$tmp_excess"' EXIT

rg -c "$pattern" src | sort > "$tmp_current" || true

awk -F: '
  NR == FNR {
    if ($0 == "" || $1 ~ /^#/) next
    allowed[$1] = $2 + 0
    next
  }
  {
    current = $2 + 0
    limit = ($1 in allowed) ? allowed[$1] : 0
    if (current > limit) {
      printf "%s:%d allowed=%d\n", $1, current, limit
      failed = 1
    }
  }
  END { exit failed ? 1 : 0 }
' "$baseline_file" "$tmp_current" > "$tmp_excess" || {
  echo "panic audit failed: panic-shaped constructs increased" >&2
  cat "$tmp_excess" >&2
  exit 1
}

echo "panic audit passed"
