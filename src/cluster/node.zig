// node — integration layer for raft consensus
//
// ties together the raft algorithm, TCP transport, persistent log,
// and state machine into a running node. handles threading so the
// raft algorithm (which is a pure state machine) can operate in a
// real networked environment.
//
// runs two threads:
//   - tick thread: calls raft.tick() every 100ms, processes actions
//   - receive thread: accepts messages from transport, feeds to raft
//
// thread safety: all raft state access goes through self.mu.
//
// snapshots: the tick loop periodically checks if enough entries have
// been committed since the last snapshot. when the threshold is exceeded,
// it triggers a snapshot via the state machine and notifies raft.
// incoming InstallSnapshot RPCs are routed to raft, and the resulting
// apply_snapshot actions restore the state machine from the snapshot data.
//
// usage:
//   var node = try Node.init(alloc, config);
//   defer node.deinit();
//   try node.start();
//   // ... use node.propose() to submit commands ...
//   node.stop();

const std = @import("std");
const sqlite = @import("sqlite");
const raft_mod = @import("raft.zig");
const transport_mod = @import("transport.zig");
const log_mod = @import("log.zig");
const state_machine_mod = @import("state_machine.zig");
const types = @import("raft_types.zig");
const agent_registry = @import("registry.zig");
const gossip_mod = @import("gossip.zig");
const heartbeat_batcher_mod = @import("heartbeat_batcher.zig");
const bootstrap = @import("node/bootstrap.zig");
const action_loop = @import("node/action_loop.zig");
const membership_sync = @import("node/membership_sync.zig");
const path_support = @import("node/path_support.zig");
const query_support = @import("node/query_support.zig");
const snapshot_support = @import("node/snapshot_support.zig");

const Raft = raft_mod.Raft;
const Transport = transport_mod.Transport;
const Log = log_mod.Log;
const StateMachine = state_machine_mod.StateMachine;
const NodeId = types.NodeId;
const LogIndex = types.LogIndex;

pub const NodeConfig = struct {
    id: NodeId,
    port: u16,
    /// API port for the HTTP server. used to construct leader addresses.
    /// convention: same port cluster-wide.
    api_port: u16 = 7700,
    peers: []const PeerConfig,
    data_dir: []const u8,
    shared_key: ?[32]u8 = null,
    /// UDP port for gossip protocol. 0 means port + 100 (default: 9800 for port 9700).
    gossip_port: u16 = 0,
    /// override indirect probe fan-out K. null = auto (ceilLog2(N))
    gossip_fanout: ?u32 = null,
    /// multiply suspect/dead timeouts. null = default (1x)
    gossip_suspicion_multiplier: ?u32 = null,
};

pub const PeerConfig = struct {
    id: NodeId,
    addr: [4]u8,
    port: u16,
};

pub const NodeError = error{
    /// failed to open the raft log, state machine database, or transport listener
    InitFailed,
    /// start() was called on a node that is already running
    AlreadyStarted,
    /// propose() was called on a node that is not the current raft leader
    NotLeader,
};

pub const TestInitError = error{
    LogInitFailed,
    StateMachineInitFailed,
    TransportInitFailed,
    AuthInitFailed,
    RaftInitFailed,
};

pub const Node = struct {
    alloc: std.mem.Allocator,
    config: NodeConfig,
    raft: Raft,
    transport: Transport,
    log: Log,
    state_machine: StateMachine,
    mu: std.Thread.Mutex,
    running: std.atomic.Value(bool),
    tick_count: u32,
    leader_id: ?NodeId = null,
    tick_thread: ?std.Thread,
    recv_thread: ?std.Thread,

    // the commit index at the time of the last snapshot.
    // used to decide when a new snapshot is needed.
    last_snapshot_index: LogIndex,

    /// SWIM gossip state machine for scalable agent failure detection.
    /// null when gossip failed to initialize (node falls back to
    /// heartbeat-based health checks only).
    gossip: ?*gossip_mod.Gossip,
    gossip_port: u16,
    heartbeat_batcher: heartbeat_batcher_mod.HeartbeatBatcher,

    pub fn init(alloc: std.mem.Allocator, config: NodeConfig) !Node {
        return initInternal(alloc, config, false);
    }

    /// test-only initializer that skips live transport binding.
    /// route-flow smoke tests use this to exercise cluster handlers
    /// against a real log/state-machine DB without depending on sockets.
    pub fn initForTests(alloc: std.mem.Allocator, config: NodeConfig) TestInitError!Node {
        return initInternalForTests(alloc, config);
    }

    fn initInternal(alloc: std.mem.Allocator, config: NodeConfig, skip_transport_bind: bool) !Node {
        // open persistent log
        var log = if (skip_transport_bind)
            Log.initMemory() catch return NodeError.InitFailed
        else blk: {
            var log_path_buf: [512]u8 = undefined;
            const log_path = bootstrap.raftDbPath(&log_path_buf, config.data_dir) orelse
                return NodeError.InitFailed;
            break :blk Log.init(log_path) catch return NodeError.InitFailed;
        };
        errdefer log.deinit();

        // open state machine database
        var sm = if (skip_transport_bind)
            StateMachine.initMemory() catch return NodeError.InitFailed
        else blk: {
            var sm_path_buf: [512]u8 = undefined;
            const sm_path = bootstrap.stateDbPath(&sm_path_buf, config.data_dir) orelse
                return NodeError.InitFailed;
            break :blk StateMachine.init(sm_path) catch return NodeError.InitFailed;
        };
        errdefer sm.deinit();

        // collect peer IDs for raft
        const peer_ids = try alloc.alloc(NodeId, config.peers.len);
        defer alloc.free(peer_ids); // raft dupes internally
        for (config.peers, 0..) |p, i| {
            peer_ids[i] = p.id;
        }

        // initialize transport
        var transport = if (skip_transport_bind)
            Transport.initForTests(alloc) catch {
                return NodeError.InitFailed;
            }
        else
            Transport.init(alloc, config.port) catch {
                return NodeError.InitFailed;
            };
        errdefer transport.deinit();
        transport.setLocalNodeId(config.id);

        for (config.peers) |p| {
            transport.addPeer(p.id, p.addr, p.port) catch {
                return NodeError.InitFailed;
            };
        }

        // Set shared key before requireAuth check
        if (config.shared_key) |key| {
            transport.shared_key = key;
        }

        transport.requireAuth() catch {
            return NodeError.InitFailed;
        };

        // initialize gossip for agent failure detection.
        // non-fatal: if UDP binding fails, gossip is null and the node
        // falls back to heartbeat-based health checks (30s timeout).
        const gossip_port: u16 = if (config.gossip_port != 0) config.gossip_port else config.port +| 100;
        const gossip_inst = if (skip_transport_bind) null else bootstrap.initGossip(alloc, config, &transport);

        // initialize raft — dupes peer_ids internally
        var raft = Raft.init(alloc, config.id, peer_ids, &log) catch {
            return NodeError.InitFailed;
        };
        errdefer raft.deinit();

        // copy raft's log pointer — the log is stored in the node, so
        // we need to fix up the pointer after the node is moved
        _ = &raft;

        // recover last_snapshot_index from persisted metadata so we
        // don't take a redundant snapshot immediately after restart
        const initial_snap_index: LogIndex = if (log.getSnapshotMeta()) |meta|
            meta.last_included_index
        else
            0;

        return .{
            .alloc = alloc,
            .config = config,
            .raft = raft,
            .transport = transport,
            .log = log,
            .state_machine = sm,
            .mu = .{},
            .running = std.atomic.Value(bool).init(false),
            .tick_count = 0,
            .tick_thread = null,
            .recv_thread = null,
            .last_snapshot_index = initial_snap_index,
            .gossip = gossip_inst,
            .gossip_port = gossip_port,
            .heartbeat_batcher = heartbeat_batcher_mod.HeartbeatBatcher.init(alloc),
        };
    }

    fn initInternalForTests(alloc: std.mem.Allocator, config: NodeConfig) TestInitError!Node {
        var log = Log.initMemory() catch return TestInitError.LogInitFailed;
        errdefer log.deinit();

        var sm = StateMachine.initMemory() catch return TestInitError.StateMachineInitFailed;
        errdefer sm.deinit();

        const peer_ids = alloc.alloc(NodeId, config.peers.len) catch return TestInitError.RaftInitFailed;
        defer alloc.free(peer_ids);
        for (config.peers, 0..) |p, i| {
            peer_ids[i] = p.id;
        }

        var transport = Transport.initForTests(alloc) catch return TestInitError.TransportInitFailed;
        errdefer transport.deinit();
        transport.setLocalNodeId(config.id);

        for (config.peers) |p| {
            transport.addPeer(p.id, p.addr, p.port) catch return TestInitError.TransportInitFailed;
        }

        if (config.shared_key) |key| {
            transport.shared_key = key;
        }

        transport.requireAuth() catch return TestInitError.AuthInitFailed;

        var raft = Raft.init(alloc, config.id, peer_ids, &log) catch return TestInitError.RaftInitFailed;
        errdefer raft.deinit();

        const initial_snap_index: LogIndex = if (log.getSnapshotMeta()) |meta|
            meta.last_included_index
        else
            0;

        return .{
            .alloc = alloc,
            .config = config,
            .raft = raft,
            .transport = transport,
            .log = log,
            .state_machine = sm,
            .mu = .{},
            .running = std.atomic.Value(bool).init(false),
            .tick_count = 0,
            .tick_thread = null,
            .recv_thread = null,
            .last_snapshot_index = initial_snap_index,
            .gossip = null,
            .gossip_port = if (config.gossip_port != 0) config.gossip_port else config.port +| 100,
            .heartbeat_batcher = heartbeat_batcher_mod.HeartbeatBatcher.init(alloc),
        };
    }

    pub fn deinit(self: *Node) void {
        self.stop();
        self.heartbeat_batcher.deinit();
        if (self.gossip) |g| {
            g.deinit();
            self.alloc.destroy(g);
        }
        self.raft.deinit();
        self.transport.deinit(); // also calls deinitUdp
        self.state_machine.deinit();
        self.log.deinit();
        // Note: don't free self.raft.peers here - raft.deinit() already frees it
    }

    /// fix internal pointers after the node struct is moved in memory.
    /// must be called after init() if the node is stored on the heap
    /// or moved to a different stack frame.
    pub fn fixPointers(self: *Node) void {
        self.raft.log = &self.log;
    }

    pub fn start(self: *Node) !void {
        return bootstrap.start(self);
    }

    pub fn stop(self: *Node) void {
        if (!self.running.load(.acquire)) return;
        self.running.store(false, .release);

        if (self.tick_thread) |t| {
            t.join();
            self.tick_thread = null;
        }
        if (self.recv_thread) |t| {
            t.join();
            self.recv_thread = null;
        }
    }

    /// submit a command through raft (leader only).
    pub fn propose(self: *Node, data: []const u8) !LogIndex {
        self.mu.lock();
        defer self.mu.unlock();

        return self.raft.propose(data) catch return NodeError.NotLeader;
    }

    /// buffer a heartbeat for batch proposal. HTTP threads call this
    /// instead of propose() — the tick loop flushes accumulated
    /// heartbeats every ~2s as a single raft entry.
    pub fn recordHeartbeat(self: *Node, id: []const u8, resources: agent_registry.AgentResources, now: i64) void {
        self.heartbeat_batcher.record(id, resources, now);
    }

    /// get a pointer to the state machine's replicated database.
    /// used by API routes for read queries on cluster state (agents, assignments).
    /// caller must not hold the lock across long operations.
    pub fn stateMachineDb(self: *Node) *sqlite.Db {
        return &self.state_machine.db;
    }

    pub fn isLeader(self: *Node) bool {
        self.mu.lock();
        defer self.mu.unlock();
        return self.raft.role == .leader;
    }

    /// gracefully transfer leadership to another node.
    /// used during rolling upgrades to avoid election timeout delays.
    /// returns true if leadership was transferred, false if not leader.
    pub fn transferLeadership(self: *Node) bool {
        self.mu.lock();
        defer self.mu.unlock();
        return self.raft.transferLeadership();
    }

    /// returns the raft protocol version for version negotiation.
    pub fn protocolVersion() u32 {
        return Raft.protocolVersion();
    }

    pub fn currentTerm(self: *Node) types.Term {
        return query_support.currentTerm(self);
    }

    pub fn role(self: *Node) types.Role {
        return query_support.role(self);
    }

    pub fn leaderId(self: *Node) ?NodeId {
        return query_support.leaderId(self);
    }

    /// returns the leader's API address as "ip:port", or null if unknown.
    /// writes into a caller-provided buffer to avoid allocation.
    pub fn leaderAddrBuf(self: *Node, buf: []u8) ?[]const u8 {
        return query_support.leaderAddrBuf(self, buf);
    }

    // -- internal threads --

    pub fn tickLoop(self: *Node) void {
        action_loop.tickLoop(self);
    }

    /// mark agents as offline if they haven't sent a heartbeat in 30 seconds.
    /// only runs on the leader node. called with self.mu held.
    ///
    /// DB queries happen before this call (outside the lock) — the caller
    /// passes the pre-fetched agent list. proposals are idempotent, so
    /// staleness from the unlocked read is safe.
    fn checkAgentHealth(self: *Node, agents: []const agent_registry.AgentRecord) void {
        membership_sync.checkAgentHealth(self, agents);
    }

    /// reschedule orphaned assignments onto active agents.
    /// orphans are assignments with agent_id = '' that were detached
    /// when their agent went offline. called with self.mu held.
    ///
    /// DB queries happen before this call (outside the lock).
    fn reconcileOrphanedAssignments(
        self: *Node,
        orphans: []const agent_registry.Assignment,
        agents: []const agent_registry.AgentRecord,
    ) void {
        membership_sync.reconcileOrphanedAssignments(self, orphans, agents);
    }

    /// remove agents that have been offline for more than 1 hour.
    /// cleans up their remaining terminal assignments, wireguard peers,
    /// and the agent record itself. called with self.mu held.
    ///
    /// DB queries happen before this call (outside the lock).
    fn cleanupDeadAgents(self: *Node, agents: []const agent_registry.AgentRecord) void {
        membership_sync.cleanupDeadAgents(self, agents);
    }

    /// check if enough entries have been committed since the last snapshot
    /// to warrant taking a new one. called with self.mu held.
    fn maybeSnapshot(self: *Node) void {
        snapshot_support.maybeSnapshot(self);
    }

    pub fn recvLoop(self: *Node) void {
        action_loop.recvLoop(self);
    }

    fn handleMessage(self: *Node, received: transport_mod.ReceivedMessage) void {
        action_loop.handleMessage(self, received);
    }

    // -- gossip integration --

    /// advance gossip state machine, process actions, and sync membership.
    /// called every 5th tick (~500ms) with self.mu held.
    fn tickGossip(self: *Node) void {
        membership_sync.tickGossip(self);
    }

    /// receive and dispatch incoming gossip UDP messages.
    /// called from recvLoop when no raft messages are pending.
    ///
    /// drains all available messages into a local buffer first, then
    /// acquires the lock once to process the entire batch.
    fn receiveGossipMessages(self: *Node) void {
        membership_sync.receiveGossipMessages(self);
    }

    /// dispatch gossip actions: encode and send messages, handle membership events.
    /// shared by tickGossip and receiveGossipMessages to avoid duplication.
    fn processGossipActions(self: *Node, actions: []gossip_mod.Action) void {
        membership_sync.processGossipActions(self, actions);
    }

    /// mark an agent offline when gossip detects it as dead.
    /// called with self.mu held, leader only.
    fn handleGossipMemberDead(self: *Node, member_id: u64) void {
        membership_sync.handleGossipMemberDead(self, member_id);
    }

    /// mark an agent active when gossip detects it as alive again.
    /// called with self.mu held, leader only.
    fn handleGossipMemberAlive(self: *Node, member_id: u64) void {
        membership_sync.handleGossipMemberAlive(self, member_id);
    }

    /// sync gossip membership from the agents table. adds active agents
    /// that have a node_id and removes agents no longer in the table.
    /// called periodically (~10s) on the leader with self.mu held.
    fn syncGossipMembership(self: *Node) void {
        membership_sync.syncGossipMembership(self);
    }

    /// return the number of members tracked by gossip (for status endpoints).
    pub fn gossipMemberCount(self: *Node) usize {
        return query_support.gossipMemberCount(self);
    }

    /// resolve a network address to a peer's NodeId by matching against
    /// the configured peer list. returns null if the address doesn't
    /// match any known peer (e.g. a stale connection from a removed node).
    fn resolveNodeId(self: *const Node, addr: std.net.Address) ?NodeId {
        return action_loop.resolveNodeId(self, addr);
    }

    /// process raft actions in two phases:
    ///   1. state actions (commits, snapshots, role changes) run under the lock
    ///   2. send actions (vote requests, append entries, etc.) run with the lock
    ///      released so the recv thread can process incoming messages during
    ///      TCP I/O, reducing head-of-line blocking
    ///
    /// callers (tickLoop, recvLoop) hold self.mu when calling this function.
    /// the unlock/re-lock in phase 2 is transparent to them.
    fn processActions(self: *Node) void {
        action_loop.processActions(self);
    }

    /// read the snapshot file from disk and send it to a lagging follower.
    /// the raft module produces send_install_snapshot actions with empty data;
    /// this method fills in the data from the snapshot file on disk.
    fn sendSnapshot(self: *Node, target: NodeId, args: types.InstallSnapshotArgs) void {
        snapshot_support.sendSnapshot(self, target, args);
    }
};

/// format a string into a buffer and null-terminate it.
/// returns null if the formatted string doesn't fit (needs room for the NUL).
const bufPrintZ = path_support.bufPrintZ;

fn insertAgentForTest(db: *sqlite.Db, id: []const u8, status: []const u8) !void {
    db.exec(
        "INSERT INTO agents (" ++
            "id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at" ++
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            id,
            "10.0.0.10:7700",
            status,
            @as(i64, 4),
            @as(i64, 8192),
            @as(i64, 0),
            @as(i64, 0),
            @as(i64, 0),
            @as(i64, 1000),
            @as(i64, 1000),
        },
    ) catch unreachable;
}

fn getAgentStatusForTest(alloc: std.mem.Allocator, db: *sqlite.Db, id: []const u8) !?[]const u8 {
    const Row = struct { status: sqlite.Text };
    const row = (try db.oneAlloc(
        Row,
        alloc,
        "SELECT status FROM agents WHERE id = ?;",
        .{},
        .{id},
    )) orelse return null;
    return row.status.data;
}

// -- tests --

test "resolveNodeId matches configured peer" {
    const alloc = std.testing.allocator;

    const peers = &[_]PeerConfig{
        .{ .id = 2, .addr = .{ 10, 0, 0, 2 }, .port = 9700 },
        .{ .id = 3, .addr = .{ 10, 0, 0, 3 }, .port = 9700 },
    };

    // create temp directory for data
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    var node = Node.init(alloc, .{
        .id = 1,
        .port = 0,
        .peers = peers,
        .data_dir = tmp_path,
    }) catch return;
    defer node.deinit();

    // build an address matching peer 2 (10.0.0.2:9700)
    const addr2 = std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 9700);
    try std.testing.expectEqual(@as(?NodeId, 2), node.resolveNodeId(addr2));

    // build an address matching peer 3
    const addr3 = std.net.Address.initIp4(.{ 10, 0, 0, 3 }, 9700);
    try std.testing.expectEqual(@as(?NodeId, 3), node.resolveNodeId(addr3));

    // unknown address should return null
    const unknown = std.net.Address.initIp4(.{ 192, 168, 1, 1 }, 9700);
    try std.testing.expect(node.resolveNodeId(unknown) == null);

    // right IP, wrong port should return null
    const wrong_port = std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 8080);
    try std.testing.expect(node.resolveNodeId(wrong_port) == null);
}

test "node init and deinit" {
    // just verify the struct can be created without crashing.
    // full integration tests require network ports and are better
    // done as part of the server integration.
    const alloc = std.testing.allocator;

    // create temp directory for data
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    var node = Node.init(alloc, .{
        .id = 1,
        .port = 0, // let OS assign port — but init will try to bind
        .peers = &.{},
        .data_dir = tmp_path,
    }) catch return; // port binding may fail in test environment
    defer node.deinit();

    try std.testing.expectEqual(types.Role.follower, node.role());
}

test "handleMessage drops request_vote with mismatched sender id" {
    const alloc = std.testing.allocator;

    const peers = &[_]PeerConfig{
        .{ .id = 2, .addr = .{ 10, 0, 0, 2 }, .port = 9700 },
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    var node = Node.init(alloc, .{
        .id = 1,
        .port = 0,
        .peers = peers,
        .data_dir = tmp_path,
    }) catch return;
    defer node.deinit();

    node.handleMessage(.{
        .from_addr = std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 9700),
        .sender_id = 2,
        .message = .{ .request_vote = .{
            .term = 1,
            .candidate_id = 9,
            .last_log_index = 0,
            .last_log_term = 0,
        } },
    });

    try std.testing.expect(node.log.getVotedFor() == null);
}

test "handleMessage accepts append_entries only from authenticated leader" {
    const alloc = std.testing.allocator;

    const peers = &[_]PeerConfig{
        .{ .id = 2, .addr = .{ 10, 0, 0, 2 }, .port = 9700 },
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    var node = Node.init(alloc, .{
        .id = 1,
        .port = 0,
        .peers = peers,
        .data_dir = tmp_path,
    }) catch return;
    defer node.deinit();

    node.handleMessage(.{
        .from_addr = std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 9700),
        .sender_id = 2,
        .message = .{ .append_entries = .{
            .term = 1,
            .leader_id = 9,
            .prev_log_index = 0,
            .prev_log_term = 0,
            .entries = try alloc.alloc(types.LogEntry, 0),
            .leader_commit = 0,
        } },
    });
    try std.testing.expectEqual(@as(types.Term, 0), node.currentTerm());

    node.handleMessage(.{
        .from_addr = std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 9700),
        .sender_id = 2,
        .message = .{ .append_entries = .{
            .term = 1,
            .leader_id = 2,
            .prev_log_index = 0,
            .prev_log_term = 0,
            .entries = try alloc.alloc(types.LogEntry, 0),
            .leader_commit = 0,
        } },
    });
    try std.testing.expectEqual(@as(types.Term, 1), node.currentTerm());
}

test "leader_id defaults to null" {
    const alloc = std.testing.allocator;
    const peers = &[_]PeerConfig{
        .{ .id = 2, .addr = .{ 10, 0, 0, 2 }, .port = 9700 },
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    var node = Node.init(alloc, .{
        .id = 1,
        .port = 0,
        .peers = peers,
        .data_dir = tmp_path,
    }) catch return;
    defer node.deinit();

    try std.testing.expect(node.leaderId() == null);
}

test "become_leader sets leader_id to self" {
    const alloc = std.testing.allocator;
    const peers = &[_]PeerConfig{
        .{ .id = 2, .addr = .{ 10, 0, 0, 2 }, .port = 9700 },
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    var node = Node.init(alloc, .{
        .id = 1,
        .port = 0,
        .peers = peers,
        .data_dir = tmp_path,
    }) catch return;
    defer node.deinit();

    // simulate become_leader
    node.leader_id = node.config.id;
    try std.testing.expectEqual(@as(?NodeId, 1), node.leaderId());
}

test "become_follower sets leader_id to provided id" {
    const alloc = std.testing.allocator;
    const peers = &[_]PeerConfig{
        .{ .id = 2, .addr = .{ 10, 0, 0, 2 }, .port = 9700 },
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    var node = Node.init(alloc, .{
        .id = 1,
        .port = 0,
        .peers = peers,
        .data_dir = tmp_path,
    }) catch return;
    defer node.deinit();

    // simulate become_follower with leader_id = 2
    node.leader_id = 2;
    try std.testing.expectEqual(@as(?NodeId, 2), node.leaderId());
}

test "leaderAddrBuf returns null when leader is self" {
    const alloc = std.testing.allocator;
    const peers = &[_]PeerConfig{
        .{ .id = 2, .addr = .{ 10, 0, 0, 2 }, .port = 9700 },
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    var node = Node.init(alloc, .{
        .id = 1,
        .port = 0,
        .peers = peers,
        .data_dir = tmp_path,
    }) catch return;
    defer node.deinit();

    node.leader_id = 1; // self
    var buf: [64]u8 = undefined;
    try std.testing.expect(node.leaderAddrBuf(&buf) == null);
}

test "leaderAddrBuf returns null when no leader known" {
    const alloc = std.testing.allocator;
    const peers = &[_]PeerConfig{
        .{ .id = 2, .addr = .{ 10, 0, 0, 2 }, .port = 9700 },
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    var node = Node.init(alloc, .{
        .id = 1,
        .port = 0,
        .peers = peers,
        .data_dir = tmp_path,
    }) catch return;
    defer node.deinit();

    var buf: [64]u8 = undefined;
    try std.testing.expect(node.leaderAddrBuf(&buf) == null);
}

test "leaderAddrBuf returns peer address when leader is a peer" {
    const alloc = std.testing.allocator;
    const peers = &[_]PeerConfig{
        .{ .id = 2, .addr = .{ 10, 0, 0, 2 }, .port = 9700 },
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    var node = Node.init(alloc, .{
        .id = 1,
        .port = 0,
        .api_port = 7700,
        .peers = peers,
        .data_dir = tmp_path,
    }) catch return;
    defer node.deinit();

    node.leader_id = 2;
    var buf: [64]u8 = undefined;
    const addr = node.leaderAddrBuf(&buf);
    try std.testing.expect(addr != null);
    try std.testing.expectEqualStrings("10.0.0.2:7700", addr.?);
}

test "processActions snapshot restart preserves last_applied continuity" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    {
        var node = Node.init(alloc, .{
            .id = 1,
            .port = 0,
            .peers = &.{},
            .data_dir = tmp_path,
        }) catch return;
        defer node.deinit();

        try node.log.append(.{
            .index = 1,
            .term = 1,
            .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('snap01', '10.0.0.10:7700', 'active', 4, 8192, 0, 0, 0, 1000, 1000);",
        });

        try node.raft.actions.append(alloc, .{ .commit_entries = .{ .up_to = 1 } });
        node.mu.lock();
        node.processActions();
        node.mu.unlock();
        try std.testing.expectEqual(@as(LogIndex, 1), node.state_machine.last_applied);

        try node.raft.actions.append(alloc, .{ .take_snapshot = .{ .up_to_index = 1, .term = 1 } });
        node.mu.lock();
        node.processActions();
        node.mu.unlock();

        try std.testing.expectEqual(@as(LogIndex, 1), node.last_snapshot_index);
        try std.testing.expect(node.raft.snapshot_meta != null);
        try std.testing.expectEqual(@as(LogIndex, 1), node.raft.snapshot_meta.?.last_included_index);
    }

    var restarted = Node.init(alloc, .{
        .id = 1,
        .port = 0,
        .peers = &.{},
        .data_dir = tmp_path,
    }) catch return;
    defer restarted.deinit();

    try std.testing.expectEqual(@as(LogIndex, 1), restarted.last_snapshot_index);
    try std.testing.expect(restarted.raft.snapshot_meta != null);
    try std.testing.expectEqual(@as(LogIndex, 1), restarted.raft.snapshot_meta.?.last_included_index);
    try std.testing.expectEqual(@as(LogIndex, 1), restarted.state_machine.last_applied);

    const active_status = (try getAgentStatusForTest(alloc, &restarted.state_machine.db, "snap01")).?;
    defer alloc.free(active_status);
    try std.testing.expectEqualStrings("active", active_status);

    try restarted.log.append(.{
        .index = 2,
        .term = 1,
        .data = "UPDATE agents SET status = 'draining' WHERE id = 'snap01';",
    });
    try restarted.raft.actions.append(alloc, .{ .commit_entries = .{ .up_to = 2 } });
    restarted.mu.lock();
    restarted.processActions();
    restarted.mu.unlock();

    try std.testing.expectEqual(@as(LogIndex, 2), restarted.state_machine.last_applied);
    const draining_status = (try getAgentStatusForTest(alloc, &restarted.state_machine.db, "snap01")).?;
    defer alloc.free(draining_status);
    try std.testing.expectEqualStrings("draining", draining_status);
}

test "install_snapshot restart preserves recovered state and future applies" {
    const alloc = std.testing.allocator;

    var snapshot_dir = std.testing.tmpDir(.{});
    defer snapshot_dir.cleanup();
    var snapshot_root_buf: [512]u8 = undefined;
    const snapshot_root = snapshot_dir.dir.realpath(".", &snapshot_root_buf) catch return;

    var snapshot_path_buf: [640]u8 = undefined;
    const snapshot_path = std.fmt.bufPrint(&snapshot_path_buf, "{s}/cluster-snapshot.dat", .{snapshot_root}) catch return;

    var source_sm = StateMachine.initMemory() catch return;
    defer source_sm.deinit();
    try insertAgentForTest(&source_sm.db, "snapmsg", "active");
    try source_sm.takeSnapshot(snapshot_path, .{
        .last_included_index = 5,
        .last_included_term = 2,
        .data_len = 0,
    });

    const snapshot_bytes = std.fs.cwd().readFileAlloc(alloc, snapshot_path, 1024 * 1024) catch return;
    defer alloc.free(snapshot_bytes);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    const peers = &[_]PeerConfig{
        .{ .id = 2, .addr = .{ 10, 0, 0, 2 }, .port = 9700 },
    };

    {
        var node = Node.init(alloc, .{
            .id = 1,
            .port = 0,
            .peers = peers,
            .data_dir = tmp_path,
        }) catch return;
        defer node.deinit();

        try node.log.append(.{
            .index = 1,
            .term = 1,
            .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('stale01', '10.0.0.11:7700', 'active', 4, 8192, 0, 0, 0, 1000, 1000);",
        });
        try node.raft.actions.append(alloc, .{ .commit_entries = .{ .up_to = 1 } });
        node.mu.lock();
        node.processActions();
        node.mu.unlock();

        node.handleMessage(.{
            .from_addr = std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 9700),
            .sender_id = 2,
            .message = .{ .install_snapshot = .{
                .term = 2,
                .leader_id = 2,
                .last_included_index = 5,
                .last_included_term = 2,
                .data = try alloc.dupe(u8, snapshot_bytes),
            } },
        });

        try std.testing.expectEqual(@as(LogIndex, 5), node.last_snapshot_index);
        try std.testing.expect(node.raft.snapshot_meta != null);
        try std.testing.expectEqual(@as(LogIndex, 5), node.raft.snapshot_meta.?.last_included_index);
        try std.testing.expectEqual(@as(LogIndex, 5), node.state_machine.last_applied);
        try std.testing.expect((try node.log.getEntry(alloc, 1)) == null);

        const restored_status = (try getAgentStatusForTest(alloc, &node.state_machine.db, "snapmsg")).?;
        defer alloc.free(restored_status);
        try std.testing.expectEqualStrings("active", restored_status);
    }

    var restarted = Node.init(alloc, .{
        .id = 1,
        .port = 0,
        .peers = peers,
        .data_dir = tmp_path,
    }) catch return;
    defer restarted.deinit();

    try std.testing.expectEqual(@as(LogIndex, 5), restarted.last_snapshot_index);
    try std.testing.expect(restarted.raft.snapshot_meta != null);
    try std.testing.expectEqual(@as(LogIndex, 5), restarted.raft.snapshot_meta.?.last_included_index);
    try std.testing.expectEqual(@as(LogIndex, 5), restarted.state_machine.last_applied);

    try restarted.log.append(.{
        .index = 6,
        .term = 2,
        .data = "UPDATE agents SET status = 'draining' WHERE id = 'snapmsg';",
    });
    try restarted.raft.actions.append(alloc, .{ .commit_entries = .{ .up_to = 6 } });
    restarted.mu.lock();
    restarted.processActions();
    restarted.mu.unlock();

    try std.testing.expectEqual(@as(LogIndex, 6), restarted.state_machine.last_applied);
    const updated_status = (try getAgentStatusForTest(alloc, &restarted.state_machine.db, "snapmsg")).?;
    defer alloc.free(updated_status);
    try std.testing.expectEqualStrings("draining", updated_status);
}

test "install_snapshot restart ignores stale snapshot older than recovered boundary" {
    const alloc = std.testing.allocator;

    var snapshot_dir = std.testing.tmpDir(.{});
    defer snapshot_dir.cleanup();
    var snapshot_root_buf: [512]u8 = undefined;
    const snapshot_root = snapshot_dir.dir.realpath(".", &snapshot_root_buf) catch return;

    var newer_path_buf: [640]u8 = undefined;
    const newer_path = std.fmt.bufPrint(&newer_path_buf, "{s}/snapshot-newer.dat", .{snapshot_root}) catch return;
    var older_path_buf: [640]u8 = undefined;
    const older_path = std.fmt.bufPrint(&older_path_buf, "{s}/snapshot-older.dat", .{snapshot_root}) catch return;

    var newer_sm = StateMachine.initMemory() catch return;
    defer newer_sm.deinit();
    try insertAgentForTest(&newer_sm.db, "snapstale", "active");
    try newer_sm.takeSnapshot(newer_path, .{
        .last_included_index = 5,
        .last_included_term = 2,
        .data_len = 0,
    });

    var older_sm = StateMachine.initMemory() catch return;
    defer older_sm.deinit();
    try insertAgentForTest(&older_sm.db, "snapstale", "draining");
    try older_sm.takeSnapshot(older_path, .{
        .last_included_index = 4,
        .last_included_term = 2,
        .data_len = 0,
    });

    const newer_bytes = std.fs.cwd().readFileAlloc(alloc, newer_path, 1024 * 1024) catch return;
    defer alloc.free(newer_bytes);
    const older_bytes = std.fs.cwd().readFileAlloc(alloc, older_path, 1024 * 1024) catch return;
    defer alloc.free(older_bytes);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    const peers = &[_]PeerConfig{
        .{ .id = 2, .addr = .{ 10, 0, 0, 2 }, .port = 9700 },
    };

    {
        var node = Node.init(alloc, .{
            .id = 1,
            .port = 0,
            .peers = peers,
            .data_dir = tmp_path,
        }) catch return;
        defer node.deinit();

        node.handleMessage(.{
            .from_addr = std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 9700),
            .sender_id = 2,
            .message = .{ .install_snapshot = .{
                .term = 2,
                .leader_id = 2,
                .last_included_index = 5,
                .last_included_term = 2,
                .data = try alloc.dupe(u8, newer_bytes),
            } },
        });

        try std.testing.expectEqual(@as(LogIndex, 5), node.state_machine.last_applied);
        const initial_status = (try getAgentStatusForTest(alloc, &node.state_machine.db, "snapstale")).?;
        defer alloc.free(initial_status);
        try std.testing.expectEqualStrings("active", initial_status);
    }

    var restarted = Node.init(alloc, .{
        .id = 1,
        .port = 0,
        .peers = peers,
        .data_dir = tmp_path,
    }) catch return;
    defer restarted.deinit();

    try std.testing.expectEqual(@as(LogIndex, 5), restarted.raft.commit_index);
    try std.testing.expectEqual(@as(LogIndex, 5), restarted.state_machine.last_applied);

    restarted.handleMessage(.{
        .from_addr = std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 9700),
        .sender_id = 2,
        .message = .{ .install_snapshot = .{
            .term = 2,
            .leader_id = 2,
            .last_included_index = 4,
            .last_included_term = 2,
            .data = try alloc.dupe(u8, older_bytes),
        } },
    });

    try std.testing.expectEqual(@as(LogIndex, 5), restarted.raft.commit_index);
    try std.testing.expectEqual(@as(LogIndex, 5), restarted.state_machine.last_applied);
    const status_after_stale = (try getAgentStatusForTest(alloc, &restarted.state_machine.db, "snapstale")).?;
    defer alloc.free(status_after_stale);
    try std.testing.expectEqualStrings("active", status_after_stale);
}
