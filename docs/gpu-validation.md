# GPU validation

`src/gpu` is designed for standard NVIDIA Linux hosts that expose the normal
driver stack:

- `libnvidia-ml.so.1`
- `/dev/nvidia*`
- `/proc/driver/nvidia/*`
- `/sys/class/drm/*` and optionally `/sys/class/infiniband/*`

That maps well to GPU VMs on GCP, AWS, and Azure. It is not a good fit for
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

For clustered training validation, the app-first control plane now manages training definitions and remote lifecycle commands. The relevant operator path is:

```bash
yoq up --server 10.0.0.1:7700 -f manifest.toml
yoq train start finetune --server 10.0.0.1:7700
yoq train status finetune --server 10.0.0.1:7700
yoq train logs finetune --server 10.0.0.1:7700
```

`yoq train logs --server ...` now proxies to the agent hosting the selected rank. If that agent is unreachable, the API returns an explicit hosting-agent error.

## recommended first cloud target

Start with a single Linux GPU VM, not Kubernetes and not multi-node NCCL.
That gives the best signal with the least setup work.

Good first targets:

- GCP L4 or T4 VM
- AWS g4dn / g5
- Azure N-series GPU VM

Only add MIG or multi-node InfiniBand validation after the single-node lane is
stable.

## lifecycle acceptance

unit tests exercise concurrent rank startup, cancellation, lease ownership, restart limits, and placement rollback without physical gpus. they do not establish driver passthrough or nccl communication on a real host.

on a host with at least two gpus, run a two-rank `[training.<name>]` job that prints its rank and visible device and performs a collective operation. verify that each container sees a distinct assigned device, both ranks reach the shared rendezvous, and one rank's failure stops its peers before a bounded retry. pause and resume the job with a mounted checkpoint directory, then stop it and verify that containers and gpu leases are released. repeat on two agents with storage shared between them to exercise remote checkpoint recovery.

local `[service.<name>.gpu_mesh]` execution is rejected. use training jobs for local groups; cluster service gangs use the cluster scheduler. dataset preparation and spare-rank failover are not implemented. see [training lifecycle](training-lifecycle.md) for the supported contract.
