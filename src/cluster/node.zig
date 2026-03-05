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
const posix = std.posix;
const sqlite = @import("sqlite");
const raft_mod = @import("raft.zig");
const transport_mod = @import("transport.zig");
const log_mod = @import("log.zig");
const state_machine_mod = @import("state_machine.zig");
const types = @import("raft_types.zig");
const agent_registry = @import("registry.zig");
const scheduler = @import("scheduler.zig");
const logger = @import("../lib/log.zig");

const Raft = raft_mod.Raft;
const Action = raft_mod.Action;
const Transport = transport_mod.Transport;
const Log = log_mod.Log;
const StateMachine = state_machine_mod.StateMachine;
const NodeId = types.NodeId;
const LogIndex = types.LogIndex;
const SnapshotMeta = types.SnapshotMeta;

pub const NodeConfig = struct {
    id: NodeId,
    port: u16,
    peers: []const PeerConfig,
    data_dir: []const u8,
};

pub const PeerConfig = struct {
    id: NodeId,
    addr: [4]u8,
    port: u16,
};

pub const NodeError = error{
    InitFailed,
    AlreadyStarted,
    NotLeader,
};

// how many committed entries between automatic snapshots.
// 1000 entries keeps the raft log bounded while avoiding
// too-frequent snapshot I/O. at ~1 entry/sec this is ~16 min.
const snapshot_threshold: u64 = 1000;

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
    tick_thread: ?std.Thread,
    recv_thread: ?std.Thread,

    // the commit index at the time of the last snapshot.
    // used to decide when a new snapshot is needed.
    last_snapshot_index: LogIndex,

    pub fn init(alloc: std.mem.Allocator, config: NodeConfig) !Node {
        // open persistent log
        var log_path_buf: [512]u8 = undefined;
        const log_path_slice = std.fmt.bufPrint(&log_path_buf, "{s}/raft.db", .{config.data_dir}) catch
            return NodeError.InitFailed;
        // null-terminate for sqlite
        if (log_path_slice.len >= log_path_buf.len) return NodeError.InitFailed;
        log_path_buf[log_path_slice.len] = 0;
        const log_path: [:0]const u8 = log_path_buf[0..log_path_slice.len :0];

        var log = Log.init(log_path) catch return NodeError.InitFailed;
        errdefer log.deinit();

        // open state machine database
        var sm_path_buf: [512]u8 = undefined;
        const sm_path_slice = std.fmt.bufPrint(&sm_path_buf, "{s}/state.db", .{config.data_dir}) catch
            return NodeError.InitFailed;
        if (sm_path_slice.len >= sm_path_buf.len) return NodeError.InitFailed;
        sm_path_buf[sm_path_slice.len] = 0;
        const sm_path: [:0]const u8 = sm_path_buf[0..sm_path_slice.len :0];

        var sm = StateMachine.init(sm_path) catch return NodeError.InitFailed;
        errdefer sm.deinit();

        // collect peer IDs for raft
        const peer_ids = try alloc.alloc(NodeId, config.peers.len);
        for (config.peers, 0..) |p, i| {
            peer_ids[i] = p.id;
        }

        // initialize transport
        var transport = Transport.init(alloc, config.port) catch return NodeError.InitFailed;
        errdefer transport.deinit();

        for (config.peers) |p| {
            transport.addPeer(p.id, p.addr, p.port) catch return NodeError.InitFailed;
        }

        // initialize raft
        var raft = Raft.init(alloc, config.id, peer_ids, &log) catch return NodeError.InitFailed;
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
        };
    }

    pub fn deinit(self: *Node) void {
        self.stop();
        self.raft.deinit();
        self.transport.deinit();
        self.state_machine.deinit();
        self.log.deinit();
        self.alloc.free(self.raft.peers);
    }

    /// fix internal pointers after the node struct is moved in memory.
    /// must be called after init() if the node is stored on the heap
    /// or moved to a different stack frame.
    pub fn fixPointers(self: *Node) void {
        self.raft.log = &self.log;
    }

    pub fn start(self: *Node) !void {
        if (self.running.load(.acquire)) return NodeError.AlreadyStarted;
        self.running.store(true, .release);

        // fix up the raft log pointer now that self is in its final location
        self.raft.log = &self.log;

        self.tick_thread = std.Thread.spawn(.{}, tickLoop, .{self}) catch
            return NodeError.InitFailed;
        self.recv_thread = std.Thread.spawn(.{}, recvLoop, .{self}) catch {
            self.running.store(false, .release);
            return NodeError.InitFailed;
        };
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

    pub fn currentTerm(self: *Node) types.Term {
        self.mu.lock();
        defer self.mu.unlock();
        return self.raft.currentTerm();
    }

    pub fn role(self: *Node) types.Role {
        self.mu.lock();
        defer self.mu.unlock();
        return self.raft.role;
    }

    // -- internal threads --

    fn tickLoop(self: *Node) void {
        while (self.running.load(.acquire)) {
            {
                self.mu.lock();
                defer self.mu.unlock();

                self.raft.tick();
                self.processActions();

                self.tick_count +%= 1;
                if (self.raft.role == .leader) {
                    if (self.tick_count % 300 == 0) self.checkAgentHealth(); // ~30s
                    if (self.tick_count % 100 == 0) self.reconcileOrphanedAssignments(); // ~10s
                    if (self.tick_count % 3600 == 0) self.cleanupDeadAgents(); // ~6 min
                }

                // check if we should take a snapshot. this applies to all
                // roles — followers snapshot their own state too, which
                // keeps the log bounded on every node.
                self.maybeSnapshot();
            }
            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
    }

    /// mark agents as offline if they haven't sent a heartbeat in 30 seconds.
    /// only runs on the leader node. called with self.mu held.
    fn checkAgentHealth(self: *Node) void {
        const agents = agent_registry.listAgents(self.alloc, &self.state_machine.db) catch return;
        defer {
            for (agents) |a| a.deinit(self.alloc);
            self.alloc.free(agents);
        }

        const now = std.time.timestamp();
        const timeout: i64 = 30; // seconds

        for (agents) |agent| {
            // only check active agents — already drained/offline agents are fine
            if (!std.mem.eql(u8, agent.status, "active")) continue;

            if (now - agent.last_heartbeat > timeout) {
                var sql_buf: [256]u8 = undefined;
                const sql = agent_registry.markOfflineSql(&sql_buf, agent.id) catch continue;
                _ = self.raft.propose(sql) catch |e| {
                    logger.warn("failed to propose agent offline status: {}", .{e});
                    continue;
                };

                // orphan the agent's active assignments so they can be rescheduled
                var orphan_buf: [256]u8 = undefined;
                const orphan_sql = agent_registry.orphanAssignmentsSql(&orphan_buf, agent.id) catch continue;
                _ = self.raft.propose(orphan_sql) catch |e| {
                    logger.warn("failed to propose assignment orphaning for agent {s}: {}", .{ agent.id, e });
                };
            }
        }
    }

    /// reschedule orphaned assignments onto active agents.
    /// orphans are assignments with agent_id = '' that were detached
    /// when their agent went offline. called with self.mu held.
    fn reconcileOrphanedAssignments(self: *Node) void {
        const orphans = agent_registry.getOrphanedAssignments(self.alloc, &self.state_machine.db) catch return;
        defer {
            for (orphans) |a| a.deinit(self.alloc);
            self.alloc.free(orphans);
        }

        if (orphans.len == 0) return;

        const agents = agent_registry.listAgents(self.alloc, &self.state_machine.db) catch return;
        defer {
            for (agents) |a| a.deinit(self.alloc);
            self.alloc.free(agents);
        }

        // build placement requests from orphaned assignments
        var requests = self.alloc.alloc(scheduler.PlacementRequest, orphans.len) catch return;
        defer self.alloc.free(requests);

        for (orphans, 0..) |orphan, i| {
            requests[i] = .{
                .image = orphan.image,
                .command = orphan.command,
                .cpu_limit = orphan.cpu_limit,
                .memory_limit_mb = orphan.memory_limit_mb,
            };
        }

        const placements = scheduler.schedule(self.alloc, requests, agents) catch return;
        defer self.alloc.free(placements);

        for (placements, 0..) |placement, i| {
            if (placement) |p| {
                var sql_buf: [256]u8 = undefined;
                const sql = agent_registry.reassignSql(&sql_buf, orphans[i].id, p.agent_id) catch continue;
                _ = self.raft.propose(sql) catch |e| {
                    logger.warn("failed to propose reassignment for {s}: {}", .{ orphans[i].id, e });
                };
            }
        }
    }

    /// remove agents that have been offline for more than 1 hour.
    /// cleans up their remaining terminal assignments, wireguard peers,
    /// and the agent record itself. called with self.mu held.
    fn cleanupDeadAgents(self: *Node) void {
        const agents = agent_registry.listAgents(self.alloc, &self.state_machine.db) catch return;
        defer {
            for (agents) |a| a.deinit(self.alloc);
            self.alloc.free(agents);
        }

        const now = std.time.timestamp();
        const dead_timeout: i64 = 3600; // 1 hour

        for (agents) |agent| {
            if (!std.mem.eql(u8, agent.status, "offline")) continue;
            if (now - agent.last_heartbeat <= dead_timeout) continue;

            // delete remaining terminal assignments
            var assign_buf: [256]u8 = undefined;
            const assign_sql = agent_registry.deleteAgentAssignmentsSql(&assign_buf, agent.id) catch continue;
            _ = self.raft.propose(assign_sql) catch |e| {
                logger.warn("failed to propose assignment cleanup for dead agent {s}: {}", .{ agent.id, e });
                continue;
            };

            // remove wireguard peer entry if the agent had a node_id.
            // this cleans up the wireguard_peers table so other agents
            // won't try to route traffic to a dead node.
            if (agent.node_id) |nid| {
                if (nid >= 1 and nid <= 254) {
                    var wg_buf: [256]u8 = undefined;
                    const wg_sql = agent_registry.removeWireguardPeerSql(&wg_buf, @intCast(nid)) catch continue;
                    _ = self.raft.propose(wg_sql) catch |e| {
                        logger.warn("failed to remove wireguard peer for dead agent {s}: {}", .{ agent.id, e });
                    };
                }
            }

            // remove the agent record
            var remove_buf: [256]u8 = undefined;
            const remove_sql = agent_registry.removeSql(&remove_buf, agent.id) catch continue;
            _ = self.raft.propose(remove_sql) catch |e| {
                logger.warn("failed to propose removal of dead agent {s}: {}", .{ agent.id, e });
            };
        }
    }

    /// check if enough entries have been committed since the last snapshot
    /// to warrant taking a new one. called with self.mu held.
    fn maybeSnapshot(self: *Node) void {
        const commit_index = self.raft.commit_index;
        if (commit_index <= self.last_snapshot_index) return;
        if (commit_index - self.last_snapshot_index < snapshot_threshold) return;

        const term = self.log.termAt(commit_index);
        if (term == 0) return; // shouldn't happen, but be safe

        // build snapshot file path: <data_dir>/snapshot.dat
        var snap_path_buf: [512]u8 = undefined;
        const snap_path = std.fmt.bufPrint(&snap_path_buf, "{s}/snapshot.dat", .{self.config.data_dir}) catch return;

        const meta = SnapshotMeta{
            .last_included_index = commit_index,
            .last_included_term = term,
            .data_len = 0, // filled by takeSnapshot
        };

        self.state_machine.takeSnapshot(snap_path, meta) catch |e| {
            logger.warn("snapshot: failed to take snapshot at index {}: {}", .{ commit_index, e });
            return;
        };

        // tell raft about the snapshot so it can send it to lagging followers
        self.raft.onSnapshotComplete(meta);

        // truncate log entries that are now covered by the snapshot
        self.log.truncateUpTo(commit_index);

        self.last_snapshot_index = commit_index;
        logger.info("snapshot: completed at index {}, term {}", .{ commit_index, term });
    }

    fn recvLoop(self: *Node) void {
        while (self.running.load(.acquire)) {
            const msg = self.transport.receive(self.alloc) catch {
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            };

            if (msg) |received| {
                self.mu.lock();
                defer self.mu.unlock();

                self.handleMessage(received);
                self.processActions();
            } else {
                // no connection pending, sleep briefly
                std.Thread.sleep(10 * std.time.ns_per_ms);
            }
        }
    }

    fn handleMessage(self: *Node, received: transport_mod.ReceivedMessage) void {
        const from_id = self.resolveNodeId(received.from_addr);

        switch (received.message) {
            .request_vote => |args| {
                const reply = self.raft.handleRequestVote(args);
                // send reply back using the candidate_id from the request
                self.transport.send(args.candidate_id, .{
                    .request_vote_reply = reply,
                }) catch |e| {
                    logger.warn("failed to send vote reply to node {}: {}", .{ args.candidate_id, e });
                };
            },
            .request_vote_reply => |reply| {
                // vote replies only matter for counting — raft ignores from_id
                self.raft.handleRequestVoteReply(from_id orelse 0, reply);
            },
            .append_entries => |args| {
                const reply = self.raft.handleAppendEntries(args);
                self.transport.send(args.leader_id, .{
                    .append_entries_reply = reply,
                }) catch |e| {
                    logger.warn("failed to send append entries reply to node {}: {}", .{ args.leader_id, e });
                };
                // free entries data
                for (args.entries) |e| self.alloc.free(e.data);
                self.alloc.free(args.entries);
            },
            .append_entries_reply => |reply| {
                if (from_id) |id| {
                    self.raft.handleAppendEntriesReply(id, reply);
                } else {
                    logger.warn("append_entries_reply from unknown address, dropping", .{});
                }
            },
            .install_snapshot => |args| {
                const commit_before = self.raft.commit_index;
                const reply = self.raft.handleInstallSnapshot(args);
                self.transport.send(args.leader_id, .{
                    .install_snapshot_reply = reply,
                }) catch |e| {
                    logger.warn("failed to send snapshot reply to node {}: {}", .{ args.leader_id, e });
                };

                // ownership: args.data was heap-allocated by transport decode.
                // if the snapshot was accepted (commit_index advanced), the
                // apply_snapshot action will free it during processActions().
                // if rejected (stale term, old snapshot), free it here.
                if (self.raft.commit_index == commit_before) {
                    self.alloc.free(@constCast(args.data));
                }
            },
            .install_snapshot_reply => |reply| {
                if (from_id) |id| {
                    self.raft.handleInstallSnapshotReply(id, reply);
                } else {
                    logger.warn("install_snapshot_reply from unknown address, dropping", .{});
                }
            },
        }
    }

    /// resolve a network address to a peer's NodeId by matching against
    /// the configured peer list. returns null if the address doesn't
    /// match any known peer (e.g. a stale connection from a removed node).
    fn resolveNodeId(self: *const Node, addr: std.net.Address) ?NodeId {
        const from_ip: [4]u8 = @bitCast(addr.in.sa.addr);
        const from_port = std.mem.bigToNative(u16, addr.in.sa.port);

        for (self.config.peers) |peer| {
            if (std.mem.eql(u8, &peer.addr, &from_ip) and peer.port == from_port) {
                return peer.id;
            }
        }
        return null;
    }

    fn processActions(self: *Node) void {
        const actions = self.raft.drainActions();
        defer self.alloc.free(actions);

        for (actions) |action| {
            switch (action) {
                .send_request_vote => |rv| {
                    self.transport.send(rv.target, .{ .request_vote = rv.args }) catch |e| {
                        logger.warn("failed to send vote request to node {}: {}", .{ rv.target, e });
                    };
                },
                .send_append_entries => |ae| {
                    self.transport.send(ae.target, .{ .append_entries = ae.args }) catch |e| {
                        logger.warn("failed to send append entries to node {}: {}", .{ ae.target, e });
                    };
                    // free duplicated entries
                    for (ae.args.entries) |e| self.alloc.free(e.data);
                    if (ae.args.entries.len > 0) self.alloc.free(ae.args.entries);
                },
                .send_request_vote_reply => |rv| {
                    self.transport.send(rv.target, .{ .request_vote_reply = rv.reply }) catch |e| {
                        logger.warn("failed to send vote reply to node {}: {}", .{ rv.target, e });
                    };
                },
                .send_append_entries_reply => |ae| {
                    self.transport.send(ae.target, .{ .append_entries_reply = ae.reply }) catch |e| {
                        logger.warn("failed to send append entries reply to node {}: {}", .{ ae.target, e });
                    };
                },
                .commit_entries => |commit| {
                    self.state_machine.applyUpTo(&self.log, self.alloc, commit.up_to);
                },
                .become_leader => {},
                .become_follower => {},

                .send_install_snapshot => |snap| {
                    // the raft module produces this action with empty data.
                    // we need to read the snapshot file and fill in the data
                    // before sending it over the wire.
                    self.sendSnapshot(snap.target, snap.args);
                },
                .send_install_snapshot_reply => |snap| {
                    self.transport.send(snap.target, .{
                        .install_snapshot_reply = snap.reply,
                    }) catch |e| {
                        logger.warn("failed to send snapshot reply to node {}: {}", .{ snap.target, e });
                    };
                },
                .apply_snapshot => |snap| {
                    // restore the state machine from the received snapshot bytes.
                    // ownership: the data was heap-allocated by transport decode
                    // (via alloc.dupe in the install_snapshot decode path) and
                    // passed through raft's handleInstallSnapshot into this action.
                    // we free it here after restoring.
                    defer self.alloc.free(@constCast(snap.data));

                    const meta = self.state_machine.restoreFromBytes(snap.data) catch |e| {
                        logger.warn("snapshot: failed to restore from bytes: {}", .{e});
                        continue;
                    };

                    // update the raft log to reflect the snapshot
                    self.log.setSnapshotMeta(meta);
                    self.log.truncateUpTo(meta.last_included_index);
                    self.last_snapshot_index = meta.last_included_index;

                    logger.info("snapshot: restored state machine to index {}", .{meta.last_included_index});
                },
                .take_snapshot => |snap| {
                    // build snapshot path
                    var snap_path_buf: [512]u8 = undefined;
                    const snap_path = std.fmt.bufPrint(&snap_path_buf, "{s}/snapshot.dat", .{self.config.data_dir}) catch continue;

                    const meta = SnapshotMeta{
                        .last_included_index = snap.up_to_index,
                        .last_included_term = snap.term,
                        .data_len = 0,
                    };

                    self.state_machine.takeSnapshot(snap_path, meta) catch |e| {
                        logger.warn("snapshot: failed to take snapshot at index {}: {}", .{ snap.up_to_index, e });
                        continue;
                    };

                    self.raft.onSnapshotComplete(meta);
                    self.log.truncateUpTo(snap.up_to_index);
                    self.last_snapshot_index = snap.up_to_index;

                    logger.info("snapshot: completed at index {}, term {}", .{ snap.up_to_index, snap.term });
                },
            }
        }
    }

    /// read the snapshot file from disk and send it to a lagging follower.
    /// the raft module produces send_install_snapshot actions with empty data;
    /// this method fills in the data from the snapshot file on disk.
    fn sendSnapshot(self: *Node, target: NodeId, args: types.InstallSnapshotArgs) void {
        // read the snapshot file. it contains a header + sqlite bytes
        // in the format written by StateMachine.takeSnapshot().
        var snap_path_buf: [512]u8 = undefined;
        const snap_path = std.fmt.bufPrint(&snap_path_buf, "{s}/snapshot.dat", .{self.config.data_dir}) catch return;

        const data = std.fs.cwd().readFileAlloc(
            self.alloc,
            snap_path,
            64 * 1024 * 1024, // 64MB max
        ) catch |e| {
            logger.warn("snapshot: failed to read snapshot file for node {}: {}", .{ target, e });
            return;
        };
        defer self.alloc.free(data);

        // send the snapshot with the actual data
        self.transport.send(target, .{
            .install_snapshot = .{
                .term = args.term,
                .leader_id = args.leader_id,
                .last_included_index = args.last_included_index,
                .last_included_term = args.last_included_term,
                .data = data,
            },
        }) catch |e| {
            logger.warn("failed to send snapshot to node {}: {}", .{ target, e });
        };
    }
};

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
