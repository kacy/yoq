# GCP cluster validation

this is a temporary 5-node validation rig for proving that `yoq` works on
Google Compute Engine for:

- cluster formation
- WireGuard overlay networking
- container runtime on multiple nodes
- GPU detection and passthrough when enabled
- GPU-backed gang scheduling when enabled

The rig lives under [`infra/gcp/`](../infra/gcp).

## topology

default layout:

- 3 on-demand CPU server nodes
- 2 on-demand CPU agent nodes by default
- optional Spot GPU agent nodes if `USE_GPU_AGENTS=true`

This keeps Raft stable while still keeping GPU costs low.

## prerequisites

- `gcloud` installed and authenticated
- a GCP project with quota for 5 small CPU VMs; GPU quota is only needed if `USE_GPU_AGENTS=true`
- local tools: `bash`, `jq`, `curl`, `openssl`, `ssh`, `scp`, `zig`
- local `yoq` repo checkout
- `GH_TOKEN` set to a github token that can verify public release attestations; an authenticated local `gh` can supply it with `export GH_TOKEN="$(gh auth token)"`

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
node setup installs github cli from its official apt repository. the token is sent over ssh stdin to the root installer and is not persisted on the vm. gcloud's normal host verification remains enabled. unset `GH_TOKEN` when installation finishes.

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

It performs eight classes of checks:

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

4. routed workload recovery
   - the HTTP routing example is deployed through the cluster API
   - routed traffic succeeds through the server listener
   - one non-leader server is restarted without wiping cluster state
   - routed traffic and `/v1/status?mode=service_discovery` recover on that restarted server

5. overlay networking
   - `wg-yoq` exists on all nodes
   - the two agents can reach each other over overlay IPs

6. multi-node containers
   - several containers are started directly on the agent nodes
   - one agent can reach a container IP hosted on the other agent

7. GPU host and container visibility
   - only when `USE_GPU_AGENTS=true`
   - `nvidia-smi`
   - `yoq gpu topo --json`
   - `yoq run <cuda-image> nvidia-smi`

8. cluster training smoke
   - only when `USE_GPU_AGENTS=true`
   - a 2-rank GPU training job is submitted through `yoq train start --server`
   - both ranks are placed
   - each agent log shows `MASTER_ADDR`, `WORLD_SIZE`, `RANK`, and `LOCAL_RANK`

Artifacts are written under `infra/gcp/artifacts/<rig>/<timestamp>/`.

## smoke coverage

cluster assignments preserve the full command argument list. the default training smoke uses `/usr/bin/env` to check environment injection and gang placement; it does not execute a distributed training framework. direct `yoq run ... nvidia-smi` checks device visibility on each gpu agent. use the [gpu validation guide](gpu-validation.md) for concurrent ranks, communication, cancellation, and recovery.

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
