# GCP cluster validation

This is a temporary 5-node validation rig for proving that `yoq` works on
Google Compute Engine for:

- cluster formation
- WireGuard overlay networking
- container runtime on multiple nodes
- GPU detection and passthrough when enabled
- GPU-backed gang scheduling when enabled

The rig lives under [`infra/gcp/`](../infra/gcp).

## topology

Default layout:

- 3 on-demand CPU server nodes
- 2 on-demand CPU agent nodes by default
- optional Spot GPU agent nodes if `USE_GPU_AGENTS=true`

This keeps Raft stable while still keeping GPU costs low.

## prerequisites

- `gcloud` installed and authenticated
- a GCP project with quota for 5 small CPU VMs; GPU quota is only needed if `USE_GPU_AGENTS=true`
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
- optionally `USE_GPU_AGENTS=true`
- optionally `GPU_TYPE` if GPU mode is enabled

Leave `ZONE` empty to let the scripts pick a zone in the region.

GPU mode additionally requires non-zero `GPUS_ALL_REGIONS` quota.

## workflow

Bring the infrastructure up and wait for SSH readiness:

```bash
infra/gcp/up.sh
```

Install the `yoq` binary plus node prerequisites:

```bash
infra/gcp/install.sh
```

`install.sh` fetches the node binary from the release installer URL on each VM,
so the remote host chooses the right architecture automatically.

Bootstrap the 3-server cluster and join the agents:

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
   - both agents registered and active

2. control-plane failover
   - the current leader is told to step down
   - another server becomes leader
   - the API remains reachable after the leadership change

3. agent recovery
   - one agent is restarted and rejoins the cluster
   - the recovered agent returns to `active`
   - overlay reachability still works after the restart

4. overlay networking
   - `wg-yoq` exists on all nodes
   - the two agents can reach each other over overlay IPs

5. multi-node containers
   - several containers are started directly on the agent nodes
   - one agent can reach a container IP hosted on the other agent

6. GPU host and container visibility
   - only when `USE_GPU_AGENTS=true`
   - `nvidia-smi`
   - `yoq gpu topo --json`
   - `yoq run <cuda-image> nvidia-smi`

7. cluster training smoke
   - only when `USE_GPU_AGENTS=true`
   - a 2-rank GPU training job is submitted through `yoq train start --server`
   - both ranks are placed
   - each agent log shows `MASTER_ADDR`, `WORLD_SIZE`, `RANK`, and `LOCAL_RANK`

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
- GPU agents are Spot by default when enabled
- one zone only

If GPU mode is enabled and Spot interruptions make the run noisy, switch
`USE_SPOT_GPU=false` in `infra/gcp/config.env`.

`down.sh` prefers `infra/gcp/.state/current` and exits cleanly if no rig state
is present, so you can use it after a failed `up.sh` without hand-editing state
paths.
