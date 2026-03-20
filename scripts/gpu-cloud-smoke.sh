#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
YOQ_BIN="${YOQ_BIN:-$ROOT_DIR/zig-out/bin/yoq}"

cd "$ROOT_DIR"

if ! command -v nvidia-smi >/dev/null 2>&1; then
  echo "nvidia-smi not found; this host does not look GPU-ready" >&2
  exit 1
fi

if [[ ! -x "$YOQ_BIN" ]]; then
  echo "missing yoq binary at $YOQ_BIN; run 'zig build' first or set YOQ_BIN" >&2
  exit 1
fi

echo "== host GPU =="
nvidia-smi

echo "== host NVIDIA device nodes =="
ls -1 /dev/nvidia* 2>/dev/null || {
  echo "missing /dev/nvidia* device nodes" >&2
  exit 1
}

echo "== host NVML library =="
if command -v ldconfig >/dev/null 2>&1; then
  ldconfig -p | grep -F "libnvidia-ml.so.1" >/dev/null || {
    echo "libnvidia-ml.so.1 not visible to the dynamic linker" >&2
    exit 1
  }
else
  found_nvml=0
  for path in \
    /usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1 \
    /usr/lib64/libnvidia-ml.so.1 \
    /usr/lib/aarch64-linux-gnu/libnvidia-ml.so.1
  do
    if [[ -e "$path" ]]; then
      found_nvml=1
      break
    fi
  done
  [[ "$found_nvml" -eq 1 ]] || {
    echo "libnvidia-ml.so.1 not found in common library paths" >&2
    exit 1
  }
fi

echo "== yoq gpu topo =="
topo_json="$("$YOQ_BIN" gpu topo --json)"
printf '%s\n' "$topo_json"

echo "== yoq gpu bench readiness =="
if printf '%s\n' "$topo_json" | grep -q '"index":1'; then
  "$YOQ_BIN" gpu bench --json --gpus 2
else
  echo "single GPU detected; skipping 2-GPU bench readiness check"
fi

echo "== gpu-only tests =="
env YOQ_SKIP_SLOW_TESTS=1 \
  ZIG_GLOBAL_CACHE_DIR="$ROOT_DIR/.zig-global-cache" \
  ZIG_LOCAL_CACHE_DIR="$ROOT_DIR/.zig-local-cache" \
  zig build test-gpu

echo "GPU smoke completed successfully"
