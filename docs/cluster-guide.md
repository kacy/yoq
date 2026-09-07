# cluster setup guide

yoq clusters let you run workloads across multiple machines under one control plane. this guide walks through bringing a cluster up from scratch, scaling it, and operating it day to day.

## prerequisites

- Linux 6.1+ on every node
- yoq binary installed on every node (same version)
- network connectivity between all nodes
- ports open between nodes:
  - **7700** — API (TCP)
  - **9700** — Raft consensus (TCP)
  - **9800** — gossip protocol (UDP)
  - **51820** — WireGuard overlay (UDP)

run `yoq doctor` on each machine to verify kernel version, permissions, and port availability before starting.

---

## fault-tolerant cluster (3 servers)

A single server can commit writes but cannot tolerate a server failure. For one-server fault tolerance, start three voters with a complete, fixed membership configuration. We will use these machines:

| node | IP | role |
|------|----|------|
| s1 | 10.0.0.1 | server |
| s2 | 10.0.0.2 | server |
| s3 | 10.0.0.3 | server |

### step 1: generate a join token

the join token is a shared secret used to authenticate all cluster communication (HMAC-SHA256). generate one on any machine:

```
TOKEN=$(openssl rand -hex 32)
echo $TOKEN
# e.g. a1b2c3d4e5f6...  (64 hex chars)
```

use the same token on every node.

### step 2: configure the first voter

```
yoq init-server \
  --id 1 \
  --port 9700 \
  --api-port 7700 \
  --peers 2@10.0.0.2:9700,3@10.0.0.3:9700 \
  --token $TOKEN
```

This starts the first voter, the API server, and gossip. It waits for a majority of the configured three voters before electing a leader and committing writes. Start all servers from fresh data directories with the same voter set.

### step 3: start the other configured voters

on s2:

```
yoq init-server \
  --id 2 \
  --port 9700 \
  --api-port 7700 \
  --peers 1@10.0.0.1:9700,3@10.0.0.3:9700 \
  --token $TOKEN
```

on s3:

```
yoq init-server \
  --id 3 \
  --port 9700 \
  --api-port 7700 \
  --peers 1@10.0.0.1:9700,2@10.0.0.2:9700 \
  --token $TOKEN
```

The `--peers` flag lists **every other Raft voter**, including servers that have not started yet. Its format is `id@host:port`, comma-separated. Each server's own ID plus its peer IDs must describe the same set. Do not include its own ID in `--peers`.

Server membership is static. Starting a server with no peers creates a separate single-server cluster; starting another server pointed at it does not join that cluster. Gossip and `yoq join` discover workers, not Raft voters. Dynamic voter additions and removals are not supported. The local Raft database records its node ID and voter IDs and rejects changes on restart. Peer addresses may change while the voter IDs remain fixed.

For existing installations, preserve the original voter configuration on the first upgrade that records it. A configuration that was already inconsistent needs operator-led recovery; editing peer flags on individual running members is not a safe repair. To change the server count, provision a separate cluster and migrate workloads and application data. Keep the existing cluster intact until that migration is validated.

### step 4: verify

Run this locally on each server, using the API token saved during its startup:

```
yoq cluster status
```

Check that exactly one server reports `role: "leader"` and that all three settle on the same term. After a registration or deployment, compare their `commit_index` and `last_applied`; they should converge with no apply backlog. `yoq nodes` lists registered workers and is not a Raft voter-membership check.

---

## adding agents

agents are worker nodes that run containers. they don't participate in consensus, so you can add hundreds without affecting Raft performance.

```
yoq join 10.0.0.1 --token $TOKEN
```

the agent can point at any server — it doesn't have to be the leader. if the agent hits a non-leader server, the server responds with the current leader's address and the agent automatically redirects. this means you can use a load balancer or any server IP for `yoq join`.

this does several things:
1. registers the agent with the cluster via `POST /agents/register`
2. if the server is not the leader, follows the `"leader"` hint in the error response and retries
3. generates a WireGuard keypair and exchanges it with the server
4. creates a `wg-yoq` interface for the overlay network
5. starts heartbeating every 5 seconds

each agent gets an IP from the `10.40.0.0/16` overlay and a `/24` subnet for its containers (`10.42.{node_id}.0/24`). WireGuard encrypts all cross-node traffic automatically.

after joining, verify the agent appears:

```
yoq nodes
```

---

## deploying workloads

once agents are in the cluster, deploy services using `yoq up --server`:

```toml
# manifest.toml
[service.web]
image = "myapp:latest"
command = ["node", "server.js"]
ports = ["80:3000"]
replicas = 3

[service.web.health_check]
type = "http"
path = "/health"
port = 3000
```

```
yoq up --server
```

the `--server` flag tells yoq to submit the manifest to the cluster API instead of running locally. under the hood the CLI sends a single app snapshot to `POST /apps/apply`; `yoq up --server --dry-run` sends the same snapshot to `POST /apps/dry-run` for a non-mutating diff. that snapshot carries services, workers, crons, and training jobs together. the older `/deploy` route remains only for compatibility. the scheduler places containers on agents using bin-packing (scores by free CPU + memory). service discovery and load balancing work transparently across nodes via the WireGuard overlay and eBPF.

after deploy, use the app-first day-2 commands:

```
yoq apps --server 10.0.0.1:7700
yoq status --app [name] --server 10.0.0.1:7700
yoq history --app [name] --server 10.0.0.1:7700
yoq rollback --app [name] --server 10.0.0.1:7700 [--release <release-id>] [--print]
yoq rollout pause --app [name] --server 10.0.0.1:7700
yoq rollout resume --app [name] --server 10.0.0.1:7700
yoq rollout cancel --app [name] --server 10.0.0.1:7700
```

`yoq apps` shows the latest release summary for every app, `status --app` shows the latest release metadata for one app, `history --app` lists prior releases, and remote `rollback --app` re-applies the previous successful app release by default. Add `--release` to target a specific stored release or `--print` to inspect the selected snapshot without applying it. `yoq run-worker --server ...` and `yoq train ... --server ...` resolve workers and training jobs from the current app release on the server. Clustered app applies also register cron schedules from the current app snapshot, and the app summary/status views include live training runtime counts plus previous-successful release context for the app.

clustered service applies are rollout-aware:

- service rollout policy is part of the stored app snapshot
- readiness-gated cutover waits for assignment startup and, when configured, agent-side service health checks
- `failure_action = "rollback"` restores earlier cut-over workloads if a later batch fails
- active rollouts persist checkpoint state and can be paused, resumed, canceled, and recovered after restart or leadership handoff
- status/history show rollout state, control state, target counts, failure details, and checkpoint metadata

---

## scaling examples

### 10 nodes (3 servers + 7 agents)

this is a typical small team setup. no special tuning needed — defaults work well.

```
# on each agent machine:
yoq join 10.0.0.1 --token $TOKEN
```

gossip converges in under a second. all 10 nodes can run workloads (agents run containers, servers can too if needed).

### 500 nodes (5 servers + 495 agents)

For a new cluster at this scale, configure five voters from the start to tolerate two failures. Each server lists the other four; for s1:

```
yoq init-server \
  --id 1 \
  --port 9700 \
  --api-port 7700 \
  --peers 2@10.0.0.2:9700,3@10.0.0.3:9700,4@10.0.0.4:9700,5@10.0.0.5:9700 \
  --gossip-fanout 5 \
  --gossip-suspicion-multiplier 6 \
  --token $TOKEN
```

- `--gossip-fanout 5` — each gossip round, each node forwards to 5 peers (default auto-scales with log2(N), but explicit values give you control)
- `--gossip-suspicion-multiplier 6` — wait longer before declaring a node dead (reduces false positives in larger clusters)

for deploying agents at this scale, use a script. agents auto-discover the leader, so you can point them at any server:

```bash
#!/bin/bash
SERVERS="10.0.0.1"
TOKEN="a1b2c3d4..."

for host in $(cat agent-hosts.txt); do
  ssh $host "yoq join $SERVERS --token $TOKEN" &
done
wait
```

firewall rules — make sure UDP 9800 and UDP 51820 are open between all nodes. with 500 nodes the gossip and WireGuard traffic is lightweight but must be reachable.

### 1000 nodes (5 servers + 995 agents)

same architecture as 500, but pay attention to:

- **gossip tuning:** `--gossip-fanout 6 --gossip-suspicion-multiplier 8` — higher values keep convergence fast at scale
- **server resources:** Raft leader handles all writes and heartbeats from ~1000 agents. give servers at least 4 cores and 8GB RAM
- **SQLite WAL:** the replicated database uses WAL mode — this handles concurrent reads well but writes are serialized through the leader. at 1000 agents heartbeating every 5s, that's 200 writes/sec which SQLite handles comfortably
- **network:** gossip generates ~O(N log N) messages per round. at 1000 nodes this is well under 1MB/s of UDP traffic

---

## multi-region clusters

yoq can run across regions using labels and the WireGuard overlay.

### architecture

the simplest approach: run all servers in a single low-latency region (Raft is latency-sensitive for writes), and place agents in every region with labels for scheduling.

for higher availability, run 3+ servers per region (e.g. 3 regions x 3 servers = 9 servers total), but be aware that Raft commits require majority agreement — cross-region latency directly affects write throughput.

### setting up regions

start servers as normal. then join agents with region labels:

```
yoq join 10.0.0.1 --token $TOKEN --region us-east-1
```

the `--region` flag stores the region on the agent record. for more granular placement, set labels via the API:

```
curl -X PUT http://10.0.0.1:7700/agents/42/labels \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"labels": "region=us-east-1,zone=us-east-1a"}'
```

### label-based scheduling

use `required_labels` in your manifest to pin workloads to specific regions:

```toml
[service.web-us]
image = "myapp:latest"
ports = ["80:3000"]
required_labels = "region=us-east-1"

[service.web-eu]
image = "myapp:latest"
ports = ["80:3000"]
required_labels = "region=eu-west-1"
```

the scheduler checks that all required labels are present on the agent before placing a container there.

### cross-region networking

WireGuard handles cross-region connectivity automatically. peers have endpoints with real public IPs and persistent keepalive handles NAT traversal. no extra configuration needed — the overlay is set up during `yoq join`.

keep in mind:
- cross-region latency affects service-to-service calls — design for it (timeouts, retries)
- WireGuard adds ~60 bytes overhead per packet — negligible in practice
- gossip protocol adapts to network conditions, but higher latency between regions means slightly slower failure detection

### example: 3 regions

| region | servers | agents |
|--------|---------|--------|
| us-east-1 | s1, s2, s3 (10.0.0.1-3) | 50 agents |
| eu-west-1 | s4, s5, s6 (10.1.0.1-3) | 50 agents |
| ap-southeast-1 | s7, s8, s9 (10.2.0.1-3) | 30 agents |

Configure all nine voters before starting them. For s1, list all eight other servers:

```
yoq init-server --id 1 --port 9700 --api-port 7700 \
  --peers 2@10.0.0.2:9700,3@10.0.0.3:9700,4@10.1.0.1:9700,5@10.1.0.2:9700,6@10.1.0.3:9700,7@10.2.0.1:9700,8@10.2.0.2:9700,9@10.2.0.3:9700 \
  --token $TOKEN
```

For each remaining server, use its own ID and list the other eight, including s1. This configuration needs five reachable voters for writes. It is a new nine-voter cluster, not an expansion of an existing three-voter cluster.

join agents with region labels:

```
# us-east-1 agents
yoq join 10.0.0.1 --token $TOKEN --region us-east-1

# eu-west-1 agents
yoq join 10.1.0.1 --token $TOKEN --region eu-west-1

# ap-southeast-1 agents
yoq join 10.2.0.1 --token $TOKEN --region ap-southeast-1
```

---

## operations

### checking cluster status

```
yoq nodes
```

Lists registered workers and their resource usage and status. Run `yoq cluster status` on each server to inspect its Raft role and apply progress.

you can also query any server's API directly:

```
curl http://10.0.0.1:7700/cluster/status \
  -H "Authorization: Bearer $API_TOKEN"
```

for app-first day-2 operations, use:

```bash
yoq apps --server 10.0.0.1:7700
yoq status --app myapp --server 10.0.0.1:7700 --json
yoq history --app myapp --server 10.0.0.1:7700 --json
```

the JSON responses now carry these nested sections:

- `current_release`
- `previous_successful_release`
- `workloads`
- `training_runtime`
- `rollout`

the nested rollout view includes rollout state, control state, target counts, failure details, per-target state, and checkpoint data.

### rollout control drill

for a readiness-gated release, the basic operator drill is:

```bash
yoq rollout pause --app myapp --server 10.0.0.1:7700
yoq status --app myapp --server 10.0.0.1:7700
yoq history --app myapp --server 10.0.0.1:7700
yoq rollout resume --app myapp --server 10.0.0.1:7700
```

what to verify:

- `rollout_control_state` changes to `paused`, then back to `active`
- `rollout_state` shows `blocked` while paused
- target counts and checkpoint data continue from the stored rollout state after resume

to abort instead of continuing:

```bash
yoq rollout cancel --app myapp --server 10.0.0.1:7700
```

what to verify:

- the release ends in a terminal state that reflects any work already completed
- app history preserves the canceled attempt and its checkpoint data

### restart recovery

cluster rollout recovery is checkpoint-aware:

- active app releases persist rollout checkpoints in the state store
- if the leader process restarts or leadership changes, the new leader can recover active rollouts from stored checkpoint state
- resumed execution continues the same release id rather than inventing a brand-new release attempt

this is still not a separate background job system. the rollout engine recovers and resumes from persisted checkpoint state when leadership returns, but it is still the same app-release execution model rather than a detached external worker queue.

the response includes `leader_id` and, on non-leader nodes, a `leader` field with the leader's API address:

```json
{"cluster":true,"id":2,"role":"follower","term":3,"peers":2,"leader_id":1,"leader":"10.0.0.1:7700"}
```

### leader discovery and write forwarding

only the Raft leader can accept write operations (deploy, register, drain, etc.). when a write request hits a non-leader server, the API returns a `400` with the leader's address:

```json
{"error":"not leader","leader":"10.0.0.1:7700"}
```

clients can use the `leader` field to redirect their request. agents do this automatically — both during registration and on every heartbeat, agents check for leader hints and update their target server address. this means agents tolerate leadership changes without manual reconfiguration.

for the CLI, point `--server` at any cluster member. if you get a `"not leader"` error, the response tells you where to send writes.

for app operations, the important write paths are:

- `POST /apps/apply`
- `POST /apps/<name>/rollback`
- `POST /apps/<app>/workers/<name>/run`
- `POST /apps/<app>/training/<name>/start`
- `POST /apps/<app>/training/<name>/stop`
- `POST /apps/<app>/training/<name>/pause`
- `POST /apps/<app>/training/<name>/resume`
- `POST /apps/<app>/training/<name>/scale`

the important read paths are:

- `GET /apps`
- `GET /apps/<name>/status`
- `GET /apps/<name>/history`
- `POST /apps/<name>/rollback`
- `GET /apps/<app>/training/<name>/status`
- `GET /apps/<app>/training/<name>/logs`

`GET /apps/<app>/training/<name>/logs` now proxies the request to the agent that hosts the selected rank. If that agent is unreachable or does not expose the log endpoint, the route returns an explicit hosting-agent error.

### draining a node

before taking a node offline for maintenance:

```
yoq drain <node-id>
```

this marks the node as draining. the scheduler stops placing new containers there and migrates existing workloads to other nodes. wait for the node to show no running containers before shutting it down.

### monitoring

the API exposes cluster metrics:

```
curl http://10.0.0.1:7700/metrics \
  -H "Authorization: Bearer $API_TOKEN"
```

the API token is a 64-char hex string generated on first server start, stored at `~/.local/share/yoq/api_token`.

### rolling upgrades

to upgrade the cluster without downtime:

1. drain and upgrade agents one at a time (or in batches)
2. upgrade non-leader servers one at a time
3. trigger a leader step-down, then upgrade the old leader:

```
curl -X POST http://10.0.0.1:7700/cluster/step-down \
  -H "Authorization: Bearer $API_TOKEN"
```

this gracefully transfers leadership to another server. if the node is not the leader, the response includes a `"leader"` field pointing to the current leader. the old leader can then be drained and upgraded. agents automatically follow the new leader via heartbeat responses.

### routine failure drills

do these on a healthy non-production cluster before you trust a new release:

1. trigger a leader step-down and verify that another server becomes leader
2. restart one agent and verify it returns to `active`
3. for routed workloads, restart the listener path and verify traffic recovers

use `./scripts/http-routing-recovery-smoke.sh` as the local reference drill before doing the same check on a cluster deployment.
4. stop one workload unexpectedly and verify the reconciler restores healthy discovery state

for a shorter end-to-end checklist, see [golden-path.md](golden-path.md).

---

## troubleshooting

**node can't join the cluster**
- check that the token matches exactly — a mismatched token silently fails HMAC auth
- verify ports 9700 (TCP) and 9800 (UDP) are reachable from the joining node
- run `yoq doctor` on both the joining node and a server

**split brain / leader flapping**
- usually caused by network instability between servers
- check that UDP 9800 isn't being rate-limited or filtered
- increase `--gossip-suspicion-multiplier` to reduce false failure detection

**agent shows offline but machine is fine**
- agent heartbeat is every 5 seconds — wait at least 15s before investigating
- check that the agent process is still running
- verify WireGuard interface `wg-yoq` is up: `ip link show wg-yoq`
- check server logs for heartbeat timeouts
- if the leader changed, the agent should follow automatically — check agent logs for "leader moved to" or "redirected to leader" messages

**containers not getting scheduled**
- run `yoq nodes` to check agent capacity (CPU, memory)
- verify agents aren't in draining state
- check that required_labels match at least one agent's labels
- the scheduler uses bin-packing — if all agents are full, no placement happens

**cross-region latency is high**
- this is expected — Raft writes go through the leader, which may be in a different region
- consider placing all servers in a single region and using agents everywhere else
- for read-heavy workloads, the API can be queried from any server (reads don't require consensus)

**WireGuard overlay not forming**
- verify UDP 51820 is open between all nodes
- check that the `wg-yoq` interface was created: `ip link show wg-yoq`
- on the agent, check that the join handshake completed (look for WireGuard key exchange in logs)
