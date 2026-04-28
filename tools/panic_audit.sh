#!/usr/bin/env bash
set -euo pipefail

pattern='catch unreachable|orelse unreachable|@panic|std\.debug\.panic'
total_baseline_file="tools/panic_audit_baseline.txt"
production_baseline_file="tools/panic_audit_production_baseline.txt"
mode="check"

case "${1:-}" in
  --print-total)
    mode="print-total"
    ;;
  --print-production)
    mode="print-production"
    ;;
  --total-only)
    mode="total-only"
    ;;
  --production-only)
    mode="production-only"
    ;;
  "")
    ;;
  *)
    total_baseline_file="$1"
    ;;
esac

tmp_total="$(mktemp)"
tmp_production="$(mktemp)"
tmp_excess="$(mktemp)"
trap 'rm -f "$tmp_total" "$tmp_production" "$tmp_excess"' EXIT

scan_total() {
  rg -c "$pattern" src | sort || true
}

scan_production() {
  while IFS= read -r file; do
    case "$file" in
      src/test_*.zig|src/testing/*)
        continue
        ;;
    esac

    awk -v file="$file" -v pattern="$pattern" '
      function brace_delta(line, tmp, opens, closes) {
        tmp = line
        opens = gsub(/\{/, "{", tmp)
        tmp = line
        closes = gsub(/\}/, "}", tmp)
        return opens - closes
      }
      {
        if (in_test) {
          depth += brace_delta($0)
          if (depth <= 0) in_test = 0
          next
        }

        if ($0 ~ /^[[:space:]]*test[[:space:]]*(\"|\{)/) {
          in_test = 1
          depth = brace_delta($0)
          if (depth <= 0) in_test = 0
          next
        }

        if ($0 ~ pattern) count += 1
      }
      END {
        if (count > 0) printf "%s:%d\n", file, count
      }
    ' "$file"
  done < <(find src -type f -name '*.zig' | sort)
}

check_counts() {
  local label="$1"
  local baseline_file="$2"
  local current_file="$3"

  if [[ ! -f "$baseline_file" ]]; then
    echo "panic audit baseline not found: $baseline_file" >&2
    exit 1
  fi

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
  ' "$baseline_file" "$current_file" > "$tmp_excess" || {
    echo "panic audit failed: ${label} panic-shaped constructs increased" >&2
    cat "$tmp_excess" >&2
    exit 1
  }
}

case "$mode" in
  print-total)
    scan_total
    exit 0
    ;;
  print-production)
    scan_production
    exit 0
    ;;
esac

scan_total > "$tmp_total"
scan_production > "$tmp_production"

if [[ "$mode" != "production-only" ]]; then
  check_counts "total" "$total_baseline_file" "$tmp_total"
fi

if [[ "$mode" != "total-only" ]]; then
  check_counts "production" "$production_baseline_file" "$tmp_production"
fi

echo "panic audit passed"
