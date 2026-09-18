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

record the version and executable hash for each of the five nodes and the local cli. the installer uses published releases; it does not deploy the current checkout. `YOQ_BINARY_PATH` selects the local cli used by validation and does not replace the remote binaries. testing unreleased changes requires installing that revision on every participating node before bootstrap.

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

## automated checks

`validate.sh` runs eight groups of checks:

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

## hard-failure and result-delivery drill

`validate.sh` exercises graceful leader step-down. it does not kill the active server or interrupt assignment acknowledgments. complete these additional checks on a disposable rig after the coordinated upgrade described in the [cluster guide](cluster-guide.md):

1. record each agent id, the current leader, and the active assignment ids. let agents complete an authenticated heartbeat so they learn the other server endpoints.
2. stop the current leader process without calling the step-down endpoint. keep it stopped while the surviving voters elect a leader. check that agents reconnect, retain their ids, and receive a new assignment without running `join` again.
3. interrupt an agent's access to every server while a one-shot assignment finishes. restart that agent before restoring access. after reconnecting, check that the terminal result appears on the leader and remains present after another leadership change.
4. temporarily remove quorum, submit a status or drain change, and confirm the api does not acknowledge it as committed. restore quorum and check the retried operation's durable result.
5. restore connectivity and start the stopped server with its original data directory and fixed peer list. confirm convergence before tearing down the rig.

save server and agent logs, assignment generations, and api responses with the rig artifacts. a reachable api or a successful graceful handoff alone does not establish durable result delivery. these checks are not part of the automated eight-class cloud smoke suite above. ci separately runs [the process recovery fixture](../scripts/agent-recovery-smoke.sh) with three server processes and a joined agent in isolated network namespaces. it kills the leader, interrupts result delivery, and restarts the agent; it does not replace validation on the cloud rig.

## additional reliability acceptance

these are manual acceptance checks beyond `validate.sh`. use a disposable rig running the revision under review, follow the [upgrade requirements](install-and-recovery.md#cluster-upgrades), and retain application responses and assignment transitions with the run artifacts.

1. deploy a stateless service with a readiness check and record which worker serves it. with no eligible replacement capacity, request a drain and verify `drain_blocked`, fresh source-agent heartbeats, and successful requests to the original service.
2. make replacement capacity available. verify that the original keeps serving until its replacement reports ready, then wait for `drained` and no running containers on the source before stopping it. drain one service host at a time.
3. repeat the handoff while restarting the current leader, preserving a voting quorum. verify that the new leader resumes the saved handoff and that the replacement becomes ready before the original stops. retain the source and replacement assignment ids.
4. verify that a service with a host or local volume blocks automatic migration. drain does not move its data. active jobs and training ranks must finish in place or be stopped explicitly; follow the [training lifecycle guide](training-lifecycle.md) when exercising those controls.
5. stop one follower while quorum remains available, submit a backlog with individual commands larger than 8 kib but within the [raft proposal limits](cluster-guide.md#raft-proposal-sizes), and restart it. compare applied indexes and resulting replicated state, then verify another small mutation commits and reaches the recovered follower. the [local process drill](development.md#cluster-process-drills) provides the 65-command reference case.

`validate.sh` does not currently automate drain handoffs or large-command catch-up. a cloud run should report which additional checks ran, which were blocked, and which were skipped. the default gpu smoke also leaves concurrent framework communication and checkpoint recovery to the [physical gpu acceptance procedure](gpu-validation.md).

## cost and stability defaults

- server nodes are on-demand by default
- GPU agents are Spot by default when enabled
- one zone only

If GPU mode is enabled and Spot interruptions make the run noisy, switch
`USE_SPOT_GPU=false` in `infra/gcp/config.env`.

`down.sh` prefers `infra/gcp/.state/current` and exits cleanly if no rig state
is present, so you can use it after a failed `up.sh` without hand-editing state
paths.
