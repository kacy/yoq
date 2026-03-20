# GCP cluster validation

This is a temporary 5-node validation rig for proving that `yoq` works on
Google Compute Engine for:

- cluster formation
- WireGuard overlay networking
- container runtime on multiple nodes
- GPU detection and passthrough
- GPU-backed gang scheduling

The rig lives under [`infra/gcp/`](../infra/gcp).

## topology

Default layout:

- 3 on-demand CPU server nodes
- 2 Spot GPU agent nodes

This keeps Raft stable while still keeping GPU costs low.

## prerequisites

- `gcloud` installed and authenticated
- a GCP project with quota for 3 small CPU VMs and 2 T4-class GPU VMs
- local tools: `bash`, `jq`, `curl`, `openssl`, `ssh`, `scp`, `zig`
- local `yoq` repo checkout

Copy the example config first:

```bash
cp infra/gcp/config.env.example infra/gcp/config.env
```

At minimum set:

- `PROJECT_ID`
- `REGION`
- optionally `ZONE`
- optionally `GPU_TYPE`

Leave `ZONE` empty to let the scripts pick the first matching zone in the
region for the requested GPU type.

## workflow

Bring the infrastructure up and wait for SSH readiness:

```bash
infra/gcp/up.sh
```

Build and install the local `yoq` binary plus node prerequisites:

```bash
infra/gcp/install.sh
```

Bootstrap the 3-server cluster and join the 2 GPU agents:

```bash
infra/gcp/bootstrap.sh
```

Run the end-to-end validation suite:

```bash
infra/gcp/validate.sh
```

Tear everything down:

```bash
infra/gcp/down.sh
```

## what `validate.sh` proves

It performs five classes of checks:

1. cluster readiness
   - leader elected
   - both GPU agents registered and active

2. overlay networking
   - `wg-yoq` exists on all nodes
   - the two GPU agents can reach each other over overlay IPs

3. multi-node containers
   - several containers are started directly on the agent nodes
   - one agent can reach a container IP hosted on the other agent

4. GPU host and container visibility
   - `nvidia-smi`
   - `yoq gpu topo --json`
   - `yoq run <cuda-image> nvidia-smi`

5. cluster training smoke
   - a 2-rank GPU training job is submitted through `yoq train start --server`
   - both ranks are placed
   - each GPU agent log shows `MASTER_ADDR`, `WORLD_SIZE`, `RANK`, and `LOCAL_RANK`

Artifacts are written under `infra/gcp/artifacts/<rig>/<timestamp>/`.

## important product note

The current cluster training path transports a single executable string, not a
full argv array. Because of that, the default training smoke uses
`/usr/bin/env` inside the training image to prove mesh-related environment
injection and gang placement. GPU execution itself is validated separately with
direct `yoq run ... nvidia-smi` container smoke on each GPU agent.

The included [`infra/gcp/train/smoke.py`](../infra/gcp/train/smoke.py) is there
for a richer future smoke image or for manual experiments on the nodes, but the
default automated cluster smoke does not depend on it yet.

## cost and stability defaults

- server nodes are on-demand by default
- GPU agents are Spot by default
- one zone only

If Spot interruptions make the run noisy, switch `USE_SPOT_GPU=false` in
`infra/gcp/config.env`.
