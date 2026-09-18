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

run `sudo -H "$(command -v yoq)" doctor` on each machine to check runtime prerequisites before starting.

---

## fault-tolerant cluster (3 servers)

A single server can commit writes but cannot tolerate a server failure. For one-server fault tolerance, start three voters with a complete, fixed membership configuration. We will use these machines:

| node | IP | role |
|------|----|------|
| s1 | 10.0.0.1 | server |
| s2 | 10.0.0.2 | server |
| s3 | 10.0.0.3 | server |

### step 1: prepare credentials

on one machine, generate separate credentials for cluster transport and the operator api:

```bash
TOKEN=$(openssl rand -hex 32)
API_TOKEN=$(openssl rand -hex 32)
```

copy the same values securely to the three server hosts. agents need the join token; operator hosts need the api token. `init-server` requires an existing api token and does not create one automatically. for this fresh installation, install the api token on each server and operator host before starting commands:

```bash
sudo install -d -m 0700 /root/.local/share/yoq
printf '%s' "$API_TOKEN" | sudo install -m 0600 /dev/stdin /root/.local/share/yoq/api_token
```

use `sudo -H` for these runtime and operator commands so they read the same root-owned state directory. preserve existing credentials when restarting an established cluster. the join token authenticates cluster communication; it does not replace the operator api token.

### step 2: configure the first voter

```
sudo -H "$(command -v yoq)" init-server \
  --id 1 \
  --port 9700 \
  --api-port 7700 \
  --peers 2@10.0.0.2:9700,3@10.0.0.3:9700 \
  --token "$TOKEN"
```

This starts the first voter, the API server, and gossip. It waits for a majority of the configured three voters before electing a leader and committing writes. Start all servers from fresh data directories with the same voter set.

### step 3: start the other configured voters

on s2:

```
sudo -H "$(command -v yoq)" init-server \
  --id 2 \
  --port 9700 \
  --api-port 7700 \
  --peers 1@10.0.0.1:9700,3@10.0.0.3:9700 \
  --token "$TOKEN"
```

on s3:

```
sudo -H "$(command -v yoq)" init-server \
  --id 3 \
  --port 9700 \
  --api-port 7700 \
  --peers 1@10.0.0.1:9700,2@10.0.0.2:9700 \
  --token "$TOKEN"
```

The `--peers` flag lists **every other Raft voter**, including servers that have not started yet. Its format is `id@host:port`, comma-separated. Each server's own ID plus its peer IDs must describe the same set. Do not include its own ID in `--peers`.

Server membership is static. Starting a server with no peers creates a separate single-server cluster; starting another server pointed at it does not join that cluster. Gossip and `yoq join` discover workers, not Raft voters. Dynamic voter additions and removals are not supported. The local Raft database records its node ID and voter IDs and rejects changes on restart. Peer addresses may change while the voter IDs remain fixed.

For existing installations, preserve the original voter configuration on the first upgrade that records it. A configuration that was already inconsistent needs operator-led recovery; editing peer flags on individual running members is not a safe repair. To change the server count, provision a separate cluster and migrate workloads and application data. Keep the existing cluster intact until that migration is validated.

### step 4: verify

Run this locally on each server, using the api token installed above:

```
sudo -H "$(command -v yoq)" cluster status
```

Check that exactly one server reports `role: "leader"` and that all three settle on the same term. After a registration or deployment, compare their `commit_index` and `last_applied`; they should converge with no apply backlog. `yoq nodes` lists registered workers and is not a Raft voter-membership check.

---

## adding agents

agents are worker nodes that run containers. they don't participate in consensus, so you can add hundreds without affecting Raft performance.

```
sudo -H "$(command -v yoq)" join 10.0.0.1 --token "$TOKEN"
```

the agent can point at any server — it doesn't have to be the leader. if the agent hits a non-leader server, the server responds with the current leader's address and the agent automatically redirects. this means you can use a load balancer or any server IP for `yoq join`.

this does several things:
1. registers the agent with the cluster via `POST /agents/register`
2. if the server is not the leader, follows the `"leader"` hint in the error response and retries
3. generates a WireGuard keypair and exchanges it with the server
4. creates a `wg-yoq` interface for the overlay network
5. starts heartbeating every 5 seconds

each agent gets an IP from the `10.40.0.0/16` overlay and a `/24` subnet for its containers (`10.42.{node_id}.0/24`). WireGuard encrypts all cross-node traffic automatically.

Containers keep their assigned subnet mask but route peer traffic through the bridge gateway. This keeps service VIP requests and replies on the load balancer path, including containers on the same node. Existing containers need to be recreated to receive this routing setup.

Container setup appends forwarding rules for traffic originating on `yoq0` from the container subnet and for established replies returning to it. A host default-drop forwarding policy remains in place, as do existing rules and their ordering. Earlier explicit administrator drops still take precedence; administrators must permit the intended container traffic through those rules.

the agent writes its private enrollment identity under `~/.local/share/yoq/enrollment/` before contacting the server. retrying the same join address, API port and token reuses its credential and WireGuard key, including after a lost response or process restart. updated servers return the same committed agent and node IDs and refresh the worker endpoint; a retry cannot revive a revoked credential or replace the WireGuard key.

`yoq join` retries transport failures, unavailable or rate-limited servers, and elections or uncertain quorum commits for up to 120 seconds. retries start after 250 milliseconds and back off to two seconds. each request is limited to ten seconds within that shared deadline. invalid credentials, malformed responses, and local identity or storage errors fail immediately. `SIGINT` and `SIGTERM` cancel enrollment waits and stop a running agent; undelivered assignment reports stay in its local cache. after the startup deadline, restore connectivity and restart the command.

keep this directory across agent restarts. changing the join address, port or token selects a separate identity. older servers remain compatible but do not deduplicate enrollment; upgrade servers before relying on retry recovery. registrations created without a durable enrollment identity are not matched retroactively.

the same enrollment directory stores trusted api alternatives in a `.api-servers` file. registration and heartbeat responses authenticate this list with the enrollment token. peers use the configured cluster-wide api port. the agent tries up to three trusted endpoints per operation and retains its position for the next retry. a bare leader hint cannot authorize sending credentials to a new address. keep the original join arguments when restarting an agent; failover does not change its identity.

assignment attempts and status reports are durable in `~/.local/share/yoq/agent-cache.db`. keep this file with the enrollment directory. terminal reports remain queued until a server confirms committed application. each reassignment increments a generation, so a late result cannot stop a replacement attempt. after restart, the agent stops any cgroup recorded for an interrupted attempt before reporting it failed; it does not start work from an old cached snapshot. failed cleanup leaves that attempt blocked for a later retry.

the result queue holds at most 8,192 attempts. if reports cannot drain, the agent stops admitting new work instead of deleting results. restore API connectivity or resolve local storage errors; deleting the cache can lose completion records. normal loops process at most eight results, and shutdown attempts one delivery before leaving the remainder for restart.

from a server or operator host with the installed api token, verify the agent appears:

```
sudo -H "$(command -v yoq)" nodes --server 10.0.0.1:7700
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
sudo -H "$(command -v yoq)" up --server 10.0.0.1:7700
```

the `--server` flag tells yoq to submit the manifest to the cluster API instead of running locally. under the hood the CLI sends a single app snapshot to `POST /apps/apply`; `yoq up --server 10.0.0.1:7700 --dry-run` sends the same snapshot to `POST /apps/dry-run` for a non-mutating diff. that snapshot carries services, workers, crons, and training jobs together. the older `/deploy` route remains only for compatibility. the scheduler places containers on agents using bin-packing (scores by free CPU + memory). service discovery and load balancing work transparently across nodes via the WireGuard overlay and eBPF.

after deploy, use the app-first day-2 commands:

```
sudo -H "$(command -v yoq)" apps --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" status --app [name] --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" history --app [name] --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" rollback --app [name] --server 10.0.0.1:7700 [--release <release-id>] [--print]
sudo -H "$(command -v yoq)" rollout pause --app [name] --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" rollout resume --app [name] --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" rollout cancel --app [name] --server 10.0.0.1:7700
```

`yoq apps` shows the latest release summary for every app, `status --app` shows the latest release metadata for one app, `history --app` lists prior releases, and remote `rollback --app` re-applies the previous successful app release by default. Add `--release` to target a specific stored release or `--print` to inspect the selected snapshot without applying it. `yoq run-worker --server ...` and `yoq train ... --server ...` resolve workers and training jobs from the current app release on the server. Clustered app applies also register cron schedules from the current app snapshot, and the app summary/status views include live training runtime counts plus previous-successful release context for the app.

clustered service applies are rollout-aware:

- service rollout policy is part of the stored app snapshot
- readiness-gated cutover waits for assignment startup and, when configured, agent-side service health checks
- `failure_action = "rollback"` restores earlier cut-over workloads if a later batch fails
- active rollouts persist checkpoint state and can be paused, resumed, canceled, and recovered after restart or leadership handoff
- status/history show rollout state, control state, target counts, failure details, and checkpoint metadata

---

## sizing a cluster

server membership stays fixed. to tolerate two server failures, start a new cluster with five voters and list the other four on every server. for s1:

```bash
sudo -H "$(command -v yoq)" init-server \
  --id 1 \
  --port 9700 \
  --api-port 7700 \
  --peers 2@10.0.0.2:9700,3@10.0.0.3:9700,4@10.0.0.4:9700,5@10.0.0.5:9700 \
  --token "$TOKEN"
```

agents can join without changing the voter set. keep their foreground `join` processes under your service manager. servers run the control plane; start an agent separately on a server host if it must also run workloads.

size the leader for the observed heartbeat and deployment load. heartbeat intervals adapt from an initial five seconds. measure api latency, raft apply backlog, disk latency, and gossip convergence under the intended workload; this guide does not establish a tested maximum cluster size. open udp 9800 and 51820 between participating nodes.

---

## multi-region clusters

yoq can run across regions using labels and the WireGuard overlay.

### architecture

the simplest approach: run all servers in a single low-latency region (Raft is latency-sensitive for writes), and place agents in every region with labels for scheduling.

for higher availability, run 3+ servers per region (e.g. 3 regions x 3 servers = 9 servers total), but be aware that Raft commits require majority agreement — cross-region latency directly affects write throughput.

### setting up regions

start servers as normal. then join agents with region labels:

```
sudo -H "$(command -v yoq)" join 10.0.0.1 --token "$TOKEN" --region us-east-1
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
sudo -H "$(command -v yoq)" init-server --id 1 --port 9700 --api-port 7700 \
  --peers 2@10.0.0.2:9700,3@10.0.0.3:9700,4@10.1.0.1:9700,5@10.1.0.2:9700,6@10.1.0.3:9700,7@10.2.0.1:9700,8@10.2.0.2:9700,9@10.2.0.3:9700 \
  --token "$TOKEN"
```

For each remaining server, use its own ID and list the other eight, including s1. This configuration needs five reachable voters for writes. It is a new nine-voter cluster, not an expansion of an existing three-voter cluster.

join agents with region labels:

```
# us-east-1 agents
sudo -H "$(command -v yoq)" join 10.0.0.1 --token "$TOKEN" --region us-east-1

# eu-west-1 agents
sudo -H "$(command -v yoq)" join 10.1.0.1 --token "$TOKEN" --region eu-west-1

# ap-southeast-1 agents
sudo -H "$(command -v yoq)" join 10.2.0.1 --token "$TOKEN" --region ap-southeast-1
```

---

## operations

### checking cluster status

```
sudo -H "$(command -v yoq)" nodes
```

Lists registered workers and their resource usage and status. Run `yoq cluster status` on each server to inspect its Raft role and apply progress.

you can also query any server's API directly:

```
curl http://10.0.0.1:7700/cluster/status \
  -H "Authorization: Bearer $API_TOKEN"
```

for app-first day-2 operations, use:

```bash
sudo -H "$(command -v yoq)" apps --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" status --app myapp --server 10.0.0.1:7700 --json
sudo -H "$(command -v yoq)" history --app myapp --server 10.0.0.1:7700 --json
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
sudo -H "$(command -v yoq)" rollout pause --app myapp --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" status --app myapp --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" history --app myapp --server 10.0.0.1:7700
sudo -H "$(command -v yoq)" rollout resume --app myapp --server 10.0.0.1:7700
```

what to verify:

- `rollout_control_state` changes to `paused`, then back to `active`
- `rollout_state` shows `blocked` while paused
- target counts and checkpoint data continue from the stored rollout state after resume

to abort instead of continuing:

```bash
sudo -H "$(command -v yoq)" rollout cancel --app myapp --server 10.0.0.1:7700
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

point deployment and rollout commands at the current leader. the examples use `10.0.0.1:7700` as that leader; substitute the address reported by cluster status. the app cli does not automatically retry a deployment after a `"not leader"` response. read-only status requests can query other members.

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
sudo -H "$(command -v yoq)" drain <node-id>
```

this marks the node as draining. the scheduler stops placing new containers there and migrates existing workloads to other nodes. wait for the node to show no running containers before shutting it down.

### monitoring

the API exposes cluster metrics:

```
curl http://10.0.0.1:7700/metrics \
  -H "Authorization: Bearer $API_TOKEN"
```

the api token is the 64-character lowercase hex value installed during credential setup. these commands read `/root/.local/share/yoq/api_token`.

### assignment recovery upgrade

pause workload mutations and rescheduling while upgrading every voting server to the generation-aware schema. older voters cannot apply the new assignment statements consistently. upgrade agents before resuming scheduling, and preserve both enrollment files and `agent-cache.db`.

successful enrollment from an older server remains readable. an older follower cannot introduce a new endpoint through an unsigned leader hint, and an older server's HTTP 200 does not confirm durable status delivery. those reports remain queued until an upgraded server returns a committed receipt. legacy status updates without a generation are accepted only for the original generation zero.

### rolling upgrades

for a compatible binary upgrade, retain quorum while replacing servers. the replicated-command validation change requires a coordinated voter upgrade instead; see [replicated command recovery](#upgrading-replicated-command-validation). for ordinary compatible upgrades:

1. drain and upgrade agents one at a time (or in batches)
2. upgrade non-leader servers one at a time
3. trigger a leader step-down, then upgrade the old leader:

```
curl -X POST http://10.0.0.1:7700/cluster/step-down \
  -H "Authorization: Bearer $API_TOKEN"
```

this gracefully transfers leadership to another server. if the node is not the leader, the response includes a `"leader"` field pointing to the current leader. the old leader can then be drained and upgraded. agents follow trusted leader hints and try their persisted alternatives if the current server becomes unreachable.

### routine failure drills

do these on a healthy non-production cluster before you trust a new release:

1. trigger a leader step-down and verify that another server becomes leader
2. restart one agent and verify it returns to `active`
3. for routed workloads, restart the listener path and verify traffic recovers

use `./scripts/http-routing-recovery-smoke.sh` as the local reference drill before doing the same check on a cluster deployment.
4. stop one workload unexpectedly and verify the reconciler restores healthy discovery state

for a shorter end-to-end checklist, see [golden-path.md](golden-path.md).

---

### offline cluster backup and restore

`yoq cluster backup` captures one stopped voter. stop **every voter and agent before the first capture**, and keep them stopped until every bundle is complete. use a new set ID for each coordinated stop. the command cannot prove that another host has stopped; taking bundles while any voter is running is unsupported.

on each voter, use the same set ID and a different destination. the join-token file must contain the existing cluster join token and have owner-only permissions:

```sh
sudo -H "$(command -v yoq)" cluster backup /srv/backups/maintenance-2026-voter-1 \
  --set maintenance-2026 \
  --join-token-file /root/.config/yoq/join_token
```

`--data-dir <root>` selects a different source root. the default is `$HOME/.local/share/yoq`, with raft and replicated state under `cluster/`. the source lock rejects a running server; exclusive SQLite locks also reject open database users from older binaries. these checks apply only to the local voter.

bundles contain `raft.db`, `state.db`, `yoq.db` when present, the selected snapshot, the API token, the join token, and `secrets.key` when present. a missing secrets key is rejected if encrypted secrets exist. files are private, and publication never replaces an existing destination. bundles contain credentials in readable form: preserve their `0700` directory and `0600` file permissions when copying them to protected storage. container filesystems, image blobs, application volumes, agent enrollment files, and agent result queues need their own backup.

collect every voter bundle from that stop on a recovery host, then verify the complete set:

```sh
sudo -H "$(command -v yoq)" cluster verify-set --set maintenance-2026 \
  /srv/backups/maintenance-2026-voter-1 \
  /srv/backups/maintenance-2026-voter-2 \
  /srv/backups/maintenance-2026-voter-3
```

verification checks file sizes and hashes, database integrity and schema compatibility, decryption of stored secrets, retained command history, snapshot boundaries, and one bundle for each fixed voter. the set ID and a fingerprint derived from the join token and voter IDs must agree. `cluster verify <bundle>` checks a single voter but does not establish that the complete set is available. neither command authenticates an untrusted backup; use bundles from storage you control.

restore each bundle to its original voter ID and a fresh data root. supply the fingerprint printed by `verify-set`, the same set ID, and the full voter list in ascending order:

```sh
sudo -H "$(command -v yoq)" cluster restore /srv/backups/maintenance-2026-voter-1 \
  --data-dir /srv/recovered/voter-1/.local/share/yoq \
  --node-id 1 --voters 1,2,3 --set maintenance-2026 \
  --cluster <verified-fingerprint>
```

create the destination's parent directory first. restore refuses an existing destination, including a symlink. it keeps the original term, vote, log, snapshot, and applied boundary; it never resets a voter to force an election. do not mix restored voters with live voters or reuse an old set ID for a later capture.

start every restored voter with the original IDs and membership. the server uses `$HOME/.local/share/yoq`; set `HOME` if the restored root is elsewhere. peer addresses may change, but the voter IDs must stay fixed. `--token-file` reads the recovered private token without putting its contents in the command line:

```sh
sudo -H env HOME=/srv/recovered/voter-1 "$(command -v yoq)" init-server \
  --id 1 --port 9700 --api-port 7700 \
  --peers 2@10.0.0.2:9700,3@10.0.0.3:9700 \
  --token-file /srv/recovered/voter-1/.local/share/yoq/join_token
```

wait for a leader and verify existing app and agent records before restarting agents. preserve their original enrollment files and `agent-cache.db` so terminal results can finish delivery. run this drill on disposable hosts before relying on the bundles for production recovery.

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

### upgrading replicated command validation

upgrade every voting server together before allowing new proposals or replaying
an invalid committed command. admission still uses the existing SQL wire format,
but servers now prepare each command against an empty canonical schema and
restrict reads and functions to replicated state. older servers do not enforce
these rules and cannot safely participate in recovery.

an unapplied command with invalid syntax, unknown columns, local table reads,
or node-dependent functions receives a durable rejection. later committed
commands can then apply. storage errors and differences in a live database's
schema still stop application; they are not treated as rejected commands.

startup refuses retained log entries that older servers already applied but the
new validator rejects. do not remove that check or edit the applied index to
force recovery. restore a trusted, consistent backup when old replicas have
already executed unsupported commands. compacted entries are no longer
available for this check, so operators must establish that the snapshot history
is trusted before upgrading; the validator cannot prove that old snapshots
agree.

replicated SQL supports mutations generated by the control plane, not general
SQL queries. subqueries are limited to the singleton applied-index guard,
assignment-claim cleanup, wireguard allocation and peer insertion, and the
credential-checked enrollment refresh. arbitrary scalar subqueries, joins in updates, rowid reads, ordered or
windowed queries, floating-point aggregates, and identity-changing updates are
rejected. these restrictions keep results independent of sqlite's scan order.
new query forms need a deterministic implementation and replay coverage before
being added to admission.
