# Scaling yoq Past 100 Nodes: Gossip Membership + Small Raft Core

## Context

yoq's Raft leader becomes overwhelmed at ~100 nodes due to:

1. **Sequential heartbeat fan-out** — `raft.zig:501-505` loops all peers, `node.zig:583-675` processes sends sequentially under a single mutex, and `transport.zig:215-236` opens a new TCP socket per send. 100 peers = 100 sequential TCP connect+write+close per second.
2. **Full WireGuard mesh** — N*(N-1)/2 tunnels. 100 nodes = ~5000 tunnels per node.
3. **Single mutex** — `node.zig:268` holds `self.mu` for Raft tick + all sends + health checks + reconciliation.

**Goal:** Scale to 500-1000+ nodes while keeping the user experience invisible for small clusters and simple for large ones. Enable multi-region deployments. All changes opt-in via settings.

**Approach:** Restrict Raft to a fixed quorum of 3-7 "server" nodes. Use SWIM gossip for agent health/membership. Hub-and-spoke WireGuard. Region-aware scheduling.

---

## Implementation Plan

### Phase 1: Transport & Concurrency Fixes (prerequisite)

These changes benefit all cluster sizes and are needed regardless.

#### 1a. Connection pool in transport (`src/cluster/transport.zig`)
- Add `ConnectionPool` struct: maps `peer_id -> fd` with auto-reconnect and TCP keepalive
- Replace `sendBytes()` (line 215) to reuse pooled connections instead of connect-per-send
- Add `closePool()` for cleanup on shutdown
- Reuse existing HMAC auth path unchanged
- **~120 lines added, ~20 lines changed** (current file: 1043 lines)

#### 1b. Split mutex in node tick loop (`src/cluster/node.zig`)
- In `processActions()` (line 583): drain actions into a local `ArrayList` under the mutex, release mutex, then send outside the lock
- Add a small thread pool (4 workers) for parallel sends — reuse Zig's `std.Thread.Pool` or a simple work queue
- Leader-only tasks (`checkAgentHealth`, `reconcileOrphanedAssignments`, etc.) remain under the mutex but are already infrequent
- **~80 lines added, ~40 lines changed** (current file: 861 lines)

#### 1c. Expand overlay IP range (`src/network/setup.zig`, `src/network/wireguard.zig`)
- Change overlay from `10.40.0.0/24` to `10.40.0.0/16` — node IDs become `u16` instead of `u8`
- Update `overlay_ip` generation: `10.40.{node_id >> 8}.{node_id & 0xFF}`
- Update container subnet: `10.42.{node_id}.0/24` → use two octets from a `/12` block
- Update `max_peers` constant in `agent.zig:56` from 254 to 65534
- Update `node_id` type from `?u8` to `?u16` in `agent_types.zig`
- **~30 lines changed across 4 files**: `setup.zig` (693 lines), `wireguard.zig` (531 lines), `agent.zig` (767 lines), `agent_types.zig` (163 lines)

---

### Phase 2: SWIM Gossip Protocol (new module)

#### 2a. Create `src/cluster/gossip.zig`
Pure protocol implementation (no I/O), similar to how `raft.zig` is a pure state machine.

**Core types:**
- `MemberState` enum: `alive`, `suspect`, `dead`
- `Member` struct: `node_id`, `address`, `port`, `state`, `incarnation`, `last_update`
- `GossipMessage` union: `ping`, `ping_ack`, `ping_req`, `compound` (piggybacked state updates)
- `GossipAction` union: `send_ping`, `send_ping_ack`, `send_ping_req`, `mark_suspect`, `mark_dead`, `mark_alive`

**Core functions:**
- `tick()` — called every 500ms. Picks a random member, sends ping. If no ack within `ping_timeout` (2s), sends `ping_req` to K=3 indirect members. If still no ack within `suspect_timeout` (5s), marks suspect. If suspect for `dead_timeout` (30s), marks dead.
- `handleMessage()` — processes incoming gossip messages, updates member state
- `getActions()` — returns pending actions (sends, state changes) for the node layer to execute
- `addMember()`, `removeMember()`, `getMembers()` — membership management
- `encodeMember()`, `decodeMember()` — binary serialization for UDP

**Conflict-free merge:** Uses incarnation numbers. A member can refute suspicion by incrementing its incarnation. Higher incarnation always wins.

**~450 lines new**, including inline tests

#### 2b. Gossip transport in `src/cluster/transport.zig`
- Add UDP socket alongside existing TCP socket
- `sendGossip()` — send gossip message via UDP (small, fits in single datagram)
- `receiveGossip()` — non-blocking UDP recv
- Reuse existing HMAC auth for gossip messages (same `shared_key`)
- **~80 lines added**

#### 2c. Gossip integration in `src/cluster/node.zig`
- Server nodes: run both Raft (for state) and gossip (for membership)
- Agent nodes: run gossip only (no Raft participation)
- Add `gossipTickLoop()` — 500ms interval, calls `gossip.tick()` and processes gossip actions
- Gossip state changes (member dead/alive) trigger Raft proposals on the leader to update the agents table
- **~100 lines added**

---

### Phase 3: Role Separation & Adaptive Behavior

#### 3a. Add cluster settings to config (`src/cluster/config.zig`)
```zig
pub const ClusterSettings = struct {
    // Auto-detected from cluster size; user can override
    mode: enum { auto, small, large } = .auto,
    // Server role: runs Raft + API + scheduler
    // Agent role: runs gossip + containers
    // Both: runs everything (default for small clusters)
    role: enum { server, agent, both } = .both,
    // Region label for scheduling affinity
    region: ?[]const u8 = null,
    // Gossip tuning (defaults work for most cases)
    gossip_interval_ms: u32 = 500,
    gossip_suspect_timeout_ms: u32 = 5000,
    gossip_dead_timeout_ms: u32 = 30000,
    // Election timeout (auto-tuned: 1s for LAN, 3s for multi-region)
    election_timeout_ms: ?u32 = null,
    // Agent heartbeat interval (auto-tuned based on cluster size)
    heartbeat_interval_ms: ?u32 = null,
};
```
- **Auto mode:** Cluster with ≤50 agents uses current behavior (all nodes are `both`). Above 50, automatically enables gossip protocol on agents if they joined with `--role agent`. No user action required for small clusters.
- **~60 lines added** (current file: 124 lines)

#### 3b. Update CLI commands (`src/cluster/commands.zig`)
- `yoq init-server` gets optional `--region us-east-1` flag
- `yoq join` gets optional `--role agent` flag (default: `both` for ≤3 servers, `agent` for subsequent joins when servers already exist)
- Smart defaults: if 3+ server nodes already exist, new `yoq join` calls automatically get `role=agent`
- **~50 lines added, ~20 lines changed** (current file: 622 lines)

#### 3c. Update agent registration (`src/api/routes/cluster_agents.zig`)
- `/agents/register` accepts optional `role` and `region` fields
- Response includes gossip seed peers (list of 3-5 known agents for gossip bootstrap)
- **~30 lines added, ~15 lines changed** (current file: 595 lines)

#### 3d. Update schema (`src/state/schema.zig`)
- Add `role TEXT DEFAULT 'both'` column to agents table (migration)
- Add `region TEXT` column to agents table (migration)
- **~15 lines added** (current file: 481 lines)

#### 3e. Update agent types (`src/cluster/agent_types.zig`)
- Add `role` and `region` fields to `AgentRecord`
- Add `NodeRole` enum: `server`, `agent`, `both`
- **~15 lines added** (current file: 163 lines)

---

### Phase 4: Hub-and-Spoke WireGuard

#### 4a. Update mesh topology (`src/cluster/agent.zig`)
- `reconcilePeers()` (line 312): when role is `agent`, only peer with server nodes (not all agents)
- Server nodes still maintain full mesh with each other (3-7 tunnels)
- Agent-to-agent traffic routes through nearest server node
- **~40 lines changed** (current file: 767 lines)

#### 4b. On-demand direct tunnels (`src/network/setup.zig`)
- Add `addDirectPeer()` — establishes direct WireGuard tunnel between two agents when they need to communicate
- Add idle tunnel reaper — tears down unused direct tunnels after 5 minutes
- Server nodes advertise themselves as relay endpoints in gossip
- **~80 lines added** (current file: 693 lines)

#### 4c. Update peer list endpoint (`src/api/routes/cluster_agents.zig`)
- `/wireguard/peers` returns filtered list based on requesting node's role
- Agents get only server peers; servers get all peers
- **~20 lines changed**

---

### Phase 5: Region-Aware Scheduling

#### 5a. Update scheduler (`src/cluster/scheduler.zig`)
- Add `region` field to scoring: prefer agents in same region as deployment target
- Scoring: `score = free_resources + (same_region ? 1000 : 0)` — strong preference, not hard constraint
- If no agents in target region, fall back to any region (graceful degradation)
- Accept optional `region` in `PlacementRequest`
- **~30 lines added, ~10 lines changed** (current file: 311 lines)

#### 5b. Update deploy endpoint (`src/api/routes.zig` / `cluster_agents.zig`)
- `/deploy` accepts optional `region` field
- Passed through to scheduler
- **~10 lines added**

---

### Phase 6: Adaptive Agent Heartbeats (`src/cluster/agent.zig`)

- `agentLoop()` (line 235): adapt heartbeat interval based on cluster size returned in heartbeat response
  - ≤50 agents: 5s (current behavior)
  - 51-200 agents: 10s
  - 200+ agents: 20s
- Server returns `agent_count` in heartbeat response — no extra API call
- Agents using gossip still send infrequent HTTP heartbeats (30s) for resource reporting, but failure detection is via gossip
- **~25 lines added, ~10 lines changed**

---

## Summary: LOC Estimates by File

| File | Current Lines | Lines Added | Lines Changed | What |
|------|--------------|-------------|---------------|------|
| **New: `src/cluster/gossip.zig`** | 0 | **~450** | — | SWIM gossip protocol (pure state machine) |
| `src/cluster/transport.zig` | 1043 | **~200** | ~20 | Connection pool + UDP gossip transport |
| `src/cluster/node.zig` | 861 | **~180** | ~40 | Parallel sends, gossip integration, role dispatch |
| `src/cluster/config.zig` | 124 | **~60** | ~5 | ClusterSettings struct |
| `src/cluster/commands.zig` | 622 | **~50** | ~20 | --role, --region flags |
| `src/cluster/agent.zig` | 767 | **~65** | ~40 | Adaptive heartbeats, hub-spoke peers, gossip bootstrap |
| `src/cluster/agent_types.zig` | 163 | **~15** | ~5 | NodeRole enum, region/role fields |
| `src/cluster/scheduler.zig` | 311 | **~30** | ~10 | Region-aware scoring |
| `src/state/schema.zig` | 481 | **~15** | — | role + region column migrations |
| `src/network/setup.zig` | 693 | **~80** | ~10 | On-demand direct tunnels, idle reaper |
| `src/network/wireguard.zig` | 531 | — | ~15 | Overlay IP range expansion |
| `src/api/routes/cluster_agents.zig` | 595 | **~40** | ~25 | Registration + peer list role filtering |
| `src/api/routes.zig` | 868 | **~10** | ~5 | Region in deploy endpoint |
| **New: `tests/gossip_test.zig`** | 0 | **~200** | — | Gossip protocol unit + integration tests |
| **Totals** | | **~1395 added** | **~195 changed** | |

---

## User Experience

### Small cluster (≤50 nodes) — zero changes
```bash
yoq init-server --id 1 --port 9700 --peers 2@10.0.0.2:9700 --token secret
yoq join 10.0.0.1:7700 --token secret
# Everything works exactly as today. Full mesh, all nodes are both server+agent.
```

### Large cluster (50-1000 nodes) — one flag difference
```bash
# Set up 3-5 server nodes (same as today)
yoq init-server --id 1 --port 9700 --peers 2@10.0.0.2:9700,3@10.0.0.3:9700 --token secret

# Workers just join — auto-detected as agent role when 3+ servers exist
yoq join 10.0.0.1:7700 --token secret
# Internally: gets role=agent, bootstraps gossip, peers only with servers via WireGuard
```

### Multi-region — one extra flag
```bash
# Servers spread across regions
yoq init-server --id 1 --port 9700 --peers ... --token secret --region us-east
yoq init-server --id 2 --port 9700 --peers ... --token secret --region us-west
yoq init-server --id 3 --port 9700 --peers ... --token secret --region eu-west

# Workers join with region
yoq join 10.0.0.1:7700 --token secret --region us-east

# Deploy with region preference
yoq deploy --image myapp --region us-east
```

### Advanced tuning — settings only, not required
```bash
yoq init-server ... --election-timeout 3000    # multi-region Raft tuning
yoq join ... --gossip-interval 1000            # slower gossip for high-latency links
```

---

## Verification

1. **Existing tests must pass:** `zig build test` — all current Raft, transport, scheduler, and schema tests
2. **New gossip tests:** Unit tests for SWIM state transitions (alive→suspect→dead→alive), incarnation conflict resolution, message encoding/decoding
3. **Integration test:** 3-server + 10-agent cluster using `tests/cluster_test_harness.zig` — verify leader election, agent registration with roles, gossip convergence, assignment scheduling
4. **Transport test:** Verify connection pool reuses sockets (count `connect()` calls), verify parallel sends complete faster than sequential
5. **Region test:** Deploy with `--region`, verify scheduler prefers matching region, verify cross-region fallback works
6. **Backwards compatibility:** Run existing `tests/privileged/test_cluster.zig` 3-node and 5-node tests unchanged — they must pass without role flags

## Implementation Order

1. Phase 1 (transport + concurrency) — can be tested and merged independently
2. Phase 2 (gossip protocol) — new module, no existing code depends on it yet
3. Phase 3 (role separation + config) — wires gossip into the system
4. Phase 4 (hub-spoke WireGuard) — depends on roles being in place
5. Phase 5 (region scheduling) — independent, can be done in parallel with Phase 4
6. Phase 6 (adaptive heartbeats) — small, can be done at any point after Phase 3
