# GPU validation

`src/gpu` is designed for standard NVIDIA Linux hosts that expose the normal
driver stack:

- `libnvidia-ml.so.1`
- `/dev/nvidia*`
- `/proc/driver/nvidia/*`
- `/sys/class/drm/*` and optionally `/sys/class/infiniband/*`

That maps well to GPU VMs on GCP, AWS, and Azure. It is not a strong fit for
opaque GPU products that hide the host driver stack.

## local confidence

For deterministic coverage without physical hardware:

```bash
env YOQ_SKIP_SLOW_TESTS=1 \
  ZIG_GLOBAL_CACHE_DIR="$PWD/.zig-global-cache" \
  ZIG_LOCAL_CACHE_DIR="$PWD/.zig-local-cache" \
  zig build test-gpu
```

This target exercises the GPU subtree plus the manifest GPU env glue. It is
intended to stay green on non-GPU hosts.

## real host smoke test

For one real cloud GPU VM:

1. Provision a Linux VM with an NVIDIA driver installed.
2. Confirm `nvidia-smi` works on the host.
3. Build `yoq`.
4. Run the smoke script:

```bash
scripts/gpu-cloud-smoke.sh
```

The smoke script checks:

- driver and NVML visibility
- `/dev/nvidia*` device presence
- `yoq gpu topo --json`
- `yoq gpu bench --json` when at least 2 GPUs are visible
- `zig build test-gpu`

## recommended first cloud target

Start with a single Linux GPU VM, not Kubernetes and not multi-node NCCL.
That gives the best signal for the least setup work.

Good first targets:

- GCP L4 or T4 VM
- AWS g4dn / g5
- Azure N-series GPU VM

Only add MIG or multi-node InfiniBand validation after the single-node lane is
stable.
