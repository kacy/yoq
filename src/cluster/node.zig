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
const gossip_mod = @import("gossip.zig");
const heartbeat_batcher_mod = @import("heartbeat_batcher.zig");
const ip_mod = @import("../network/ip.zig");
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
    shared_key: ?[32]u8 = null,
    /// UDP port for gossip protocol. 0 means port + 100 (default: 9800 for port 9700).
    gossip_port: u16 = 0,
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

// how many committed entries between automatic snapshots.
// 1000 entries keeps the raft log bounded while avoiding
// too-frequent snapshot I/O. at ~1 entry/sec this is ~16 min.
const snapshot_threshold: u64 = 1000;

/// default gossip port for agents. used when syncing agent membership
/// into the gossip state machine — agents are expected to bind this port.
const agent_gossip_port: u16 = 9800;

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

    /// SWIM gossip state machine for scalable agent failure detection.
    /// null when gossip failed to initialize (node falls back to
    /// heartbeat-based health checks only).
    gossip: ?*gossip_mod.Gossip,
    gossip_port: u16,
    heartbeat_batcher: heartbeat_batcher_mod.HeartbeatBatcher,

    pub fn init(alloc: std.mem.Allocator, config: NodeConfig) !Node {
        // open persistent log
        var log_path_buf: [512]u8 = undefined;
        const log_path = bufPrintZ(&log_path_buf, "{s}/raft.db", .{config.data_dir}) orelse
            return NodeError.InitFailed;

        var log = Log.init(log_path) catch return NodeError.InitFailed;
        errdefer log.deinit();

        // open state machine database
        var sm_path_buf: [512]u8 = undefined;
        const sm_path = bufPrintZ(&sm_path_buf, "{s}/state.db", .{config.data_dir}) orelse
            return NodeError.InitFailed;

        var sm = StateMachine.init(sm_path) catch return NodeError.InitFailed;
        errdefer sm.deinit();

        // collect peer IDs for raft
        const peer_ids = try alloc.alloc(NodeId, config.peers.len);
        defer alloc.free(peer_ids); // raft dupes internally
        for (config.peers, 0..) |p, i| {
            peer_ids[i] = p.id;
        }

        // initialize transport
        var transport = Transport.init(alloc, config.port) catch {
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
        const gossip_inst: ?*gossip_mod.Gossip = blk: {
            const gossip_state = alloc.create(gossip_mod.Gossip) catch break :blk null;
            gossip_state.* = gossip_mod.Gossip.init(alloc, config.id, .{ .ip = .{ 0, 0, 0, 0 }, .port = gossip_port });
            transport.initUdp(gossip_port) catch {
                logger.warn("gossip: failed to bind UDP port {}, running without gossip", .{gossip_port});
                gossip_state.deinit();
                alloc.destroy(gossip_state);
                break :blk null;
            };
            logger.info("gossip: initialized on UDP port {}", .{gossip_port});
            break :blk gossip_state;
        };

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
            // query DB state outside the lock for leader maintenance tasks.
            // the snapshots may be slightly stale by the time we acquire the
            // lock, but all proposals are idempotent so staleness is safe.
            var health_agents: ?[]agent_registry.AgentRecord = null;
            var reconcile_agents: ?[]agent_registry.AgentRecord = null;
            var reconcile_orphans: ?[]agent_registry.Assignment = null;
            var cleanup_agents: ?[]agent_registry.AgentRecord = null;
            var heartbeat_batch: ?[]const u8 = null;

            {
                self.mu.lock();
                const is_leader = self.raft.role == .leader;
                const tick = self.tick_count +% 1;
                self.mu.unlock();

                if (is_leader) {
                    if (tick % 300 == 0)
                        health_agents = agent_registry.listAgents(self.alloc, &self.state_machine.db) catch null;
                    if (tick % 100 == 0) {
                        reconcile_orphans = agent_registry.getOrphanedAssignments(self.alloc, &self.state_machine.db) catch null;
                        reconcile_agents = agent_registry.listAgents(self.alloc, &self.state_machine.db) catch null;
                    }
                    if (tick % 3600 == 0)
                        cleanup_agents = agent_registry.listAgents(self.alloc, &self.state_machine.db) catch null;
                    if (tick % 20 == 0)
                        heartbeat_batch = self.heartbeat_batcher.flush(self.alloc) catch null;
                }
            }
            defer {
                if (health_agents) |agents| {
                    for (agents) |a| a.deinit(self.alloc);
                    self.alloc.free(agents);
                }
                if (reconcile_agents) |agents| {
                    for (agents) |a| a.deinit(self.alloc);
                    self.alloc.free(agents);
                }
                if (reconcile_orphans) |orphans| {
                    for (orphans) |a| a.deinit(self.alloc);
                    self.alloc.free(orphans);
                }
                if (cleanup_agents) |agents| {
                    for (agents) |a| a.deinit(self.alloc);
                    self.alloc.free(agents);
                }
                if (heartbeat_batch) |batch| self.alloc.free(batch);
            }

            {
                self.mu.lock();
                defer self.mu.unlock();

                self.raft.tick();
                self.processActions();

                self.tick_count +%= 1;
                if (self.raft.role == .leader) {
                    if (health_agents) |agents| self.checkAgentHealth(agents);
                    if (reconcile_orphans) |orphans|
                        self.reconcileOrphanedAssignments(orphans, reconcile_agents orelse &.{});
                    if (cleanup_agents) |agents| self.cleanupDeadAgents(agents);
                    if (heartbeat_batch) |batch| {
                        _ = self.raft.propose(batch) catch |e| {
                            logger.warn("failed to propose heartbeat batch: {}", .{e});
                        };
                    }
                }

                // gossip tick every 500ms (5 × 100ms raft tick)
                if (self.gossip != null and self.tick_count % 5 == 0) {
                    self.tickGossip();
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
    ///
    /// DB queries happen before this call (outside the lock) — the caller
    /// passes the pre-fetched agent list. proposals are idempotent, so
    /// staleness from the unlocked read is safe.
    fn checkAgentHealth(self: *Node, agents: []const agent_registry.AgentRecord) void {
        const now = std.time.timestamp();
        // scale timeout with cluster size to match adaptive agent heartbeat
        const base_timeout: i64 = 30;
        const multiplier: i64 = if (self.gossip) |g| blk: {
            const member_count = g.members.count() + 1;
            break :blk @min(@as(i64, gossip_mod.Gossip.ceilLog2(member_count)), gossip_mod.Gossip.max_interval_multiplier);
        } else 1;
        const timeout: i64 = base_timeout * multiplier;

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
    ///
    /// DB queries happen before this call (outside the lock).
    fn reconcileOrphanedAssignments(
        self: *Node,
        orphans: []const agent_registry.Assignment,
        agents: []const agent_registry.AgentRecord,
    ) void {
        if (orphans.len == 0) return;

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
    ///
    /// DB queries happen before this call (outside the lock).
    fn cleanupDeadAgents(self: *Node, agents: []const agent_registry.AgentRecord) void {
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
                if (nid >= 1 and nid <= 65534) {
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
                // no raft connection pending — check for gossip messages
                self.receiveGossipMessages();
                std.Thread.sleep(10 * std.time.ns_per_ms);
            }
        }
    }

    fn handleMessage(self: *Node, received: transport_mod.ReceivedMessage) void {
        const sender_id = received.sender_id orelse self.resolveNodeId(received.from_addr);

        switch (received.message) {
            .request_vote => |args| {
                const peer_id = sender_id orelse {
                    logger.warn("request_vote from unknown address, dropping", .{});
                    return;
                };
                if (args.candidate_id != peer_id) {
                    logger.warn("request_vote claimed node {} from authenticated peer {}, dropping", .{ args.candidate_id, peer_id });
                    return;
                }

                const reply = self.raft.handleRequestVote(args);
                self.transport.send(peer_id, .{
                    .request_vote_reply = reply,
                }) catch |e| {
                    logger.warn("failed to send vote reply to node {}: {}", .{ peer_id, e });
                };
            },
            .request_vote_reply => |reply| {
                if (sender_id) |peer_id| {
                    self.raft.handleRequestVoteReply(peer_id, reply);
                } else {
                    logger.warn("request_vote_reply from unknown address, dropping", .{});
                }
            },
            .append_entries => |args| {
                const peer_id = sender_id orelse {
                    logger.warn("append_entries from unknown address, dropping", .{});
                    for (args.entries) |e| self.alloc.free(e.data);
                    if (args.entries.len > 0) self.alloc.free(args.entries);
                    return;
                };
                if (args.leader_id != peer_id) {
                    logger.warn("append_entries claimed leader {} from authenticated peer {}, dropping", .{ args.leader_id, peer_id });
                    for (args.entries) |e| self.alloc.free(e.data);
                    if (args.entries.len > 0) self.alloc.free(args.entries);
                    return;
                }

                const reply = self.raft.handleAppendEntries(args);
                self.transport.send(peer_id, .{
                    .append_entries_reply = reply,
                }) catch |e| {
                    logger.warn("failed to send append entries reply to node {}: {}", .{ peer_id, e });
                };
                // free entries data — guard against &.{} (comptime empty slice)
                for (args.entries) |e| self.alloc.free(e.data);
                if (args.entries.len > 0) self.alloc.free(args.entries);
            },
            .append_entries_reply => |reply| {
                if (sender_id) |id| {
                    self.raft.handleAppendEntriesReply(id, reply);
                } else {
                    logger.warn("append_entries_reply from unknown address, dropping", .{});
                }
            },
            .install_snapshot => |args| {
                const peer_id = sender_id orelse {
                    logger.warn("install_snapshot from unknown address, dropping", .{});
                    self.alloc.free(@constCast(args.data));
                    return;
                };
                if (args.leader_id != peer_id) {
                    logger.warn("install_snapshot claimed leader {} from authenticated peer {}, dropping", .{ args.leader_id, peer_id });
                    self.alloc.free(@constCast(args.data));
                    return;
                }

                const commit_before = self.raft.commit_index;
                const reply = self.raft.handleInstallSnapshot(args);
                self.transport.send(peer_id, .{
                    .install_snapshot_reply = reply,
                }) catch |e| {
                    logger.warn("failed to send snapshot reply to node {}: {}", .{ peer_id, e });
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
                if (sender_id) |id| {
                    self.raft.handleInstallSnapshotReply(id, reply);
                } else {
                    logger.warn("install_snapshot_reply from unknown address, dropping", .{});
                }
            },
        }
    }

    // -- gossip integration --

    /// advance gossip state machine, process actions, and sync membership.
    /// called every 5th tick (~500ms) with self.mu held.
    fn tickGossip(self: *Node) void {
        const g = self.gossip orelse return;

        g.tick() catch return;

        const actions = g.drainActions();
        defer g.freeActions(actions);

        for (actions) |action| {
            switch (action) {
                .send_message => |msg| {
                    var encode_buf: [512]u8 = undefined;
                    const len = gossip_mod.Gossip.encode(&encode_buf, msg.message) catch continue;
                    self.transport.sendGossip(msg.addr.ip, msg.addr.port, encode_buf[0..len]) catch {};
                },
                .member_dead => |member_event| {
                    if (self.raft.role != .leader) continue;
                    self.handleGossipMemberDead(member_event.id);
                },
                .member_alive => |member_event| {
                    if (self.raft.role != .leader) continue;
                    self.handleGossipMemberAlive(member_event.id);
                },
                .member_suspect => {},
            }
        }

        // sync gossip membership from agents table every ~10s (100ms × 100 ticks ÷ 5 = 20 gossip ticks)
        if (self.tick_count % 100 == 0 and self.raft.role == .leader) {
            self.syncGossipMembership();
        }
    }

    /// receive and dispatch incoming gossip UDP messages.
    /// called from recvLoop when no raft messages are pending.
    ///
    /// drains all available messages into a local buffer first, then
    /// acquires the lock once to process the entire batch.
    fn receiveGossipMessages(self: *Node) void {
        const g = self.gossip orelse return;

        const GossipMsg = gossip_mod.GossipMessage;
        var msgs: [10]GossipMsg = undefined;
        var msg_count: u32 = 0;
        var buf: [1500]u8 = undefined;

        // drain up to 10 messages without holding the lock
        while (msg_count < 10) {
            const result = self.transport.receiveGossip(&buf) catch break;
            const recv = result orelse break;

            const msg = gossip_mod.Gossip.decode(self.alloc, recv.payload) catch continue;
            msgs[msg_count] = msg;
            msg_count += 1;
        }

        if (msg_count == 0) return;

        // acquire lock once for the entire batch
        self.mu.lock();
        defer self.mu.unlock();

        for (msgs[0..msg_count]) |msg| {
            switch (msg) {
                .ping => |payload| g.handlePing(payload) catch {},
                .ping_ack => |payload| g.handlePingAck(payload) catch {},
                .ping_req => |payload| g.handlePingReq(payload) catch {},
            }
        }

        // process all actions generated by the batch
        const actions = g.drainActions();
        defer g.freeActions(actions);

        for (actions) |action| {
            switch (action) {
                .send_message => |send| {
                    var encode_buf: [512]u8 = undefined;
                    const len = gossip_mod.Gossip.encode(&encode_buf, send.message) catch continue;
                    self.transport.sendGossip(send.addr.ip, send.addr.port, encode_buf[0..len]) catch {};
                },
                .member_dead => |member_event| {
                    if (self.raft.role == .leader) self.handleGossipMemberDead(member_event.id);
                },
                .member_alive => |member_event| {
                    if (self.raft.role == .leader) self.handleGossipMemberAlive(member_event.id);
                },
                .member_suspect => {},
            }
        }
    }

    /// mark an agent offline when gossip detects it as dead.
    /// called with self.mu held, leader only.
    fn handleGossipMemberDead(self: *Node, member_id: u64) void {
        const agent_id = agent_registry.findAgentIdByNodeId(self.alloc, &self.state_machine.db, member_id) orelse return;
        defer self.alloc.free(agent_id);

        logger.info("gossip: member {} dead, marking agent {s} offline", .{ member_id, agent_id });

        var sql_buf: [256]u8 = undefined;
        const sql = agent_registry.markOfflineSql(&sql_buf, agent_id) catch return;
        _ = self.raft.propose(sql) catch |e| {
            logger.warn("gossip: failed to propose offline for agent {s}: {}", .{ agent_id, e });
            return;
        };

        var orphan_buf: [256]u8 = undefined;
        const orphan_sql = agent_registry.orphanAssignmentsSql(&orphan_buf, agent_id) catch return;
        _ = self.raft.propose(orphan_sql) catch |e| {
            logger.warn("gossip: failed to orphan assignments for agent {s}: {}", .{ agent_id, e });
        };
    }

    /// mark an agent active when gossip detects it as alive again.
    /// called with self.mu held, leader only.
    fn handleGossipMemberAlive(self: *Node, member_id: u64) void {
        const agent_id = agent_registry.findAgentIdByNodeId(self.alloc, &self.state_machine.db, member_id) orelse return;
        defer self.alloc.free(agent_id);

        var sql_buf: [256]u8 = undefined;
        const sql = agent_registry.markActiveSql(&sql_buf, agent_id) catch return;
        _ = self.raft.propose(sql) catch |e| {
            logger.warn("gossip: failed to propose active for agent {s}: {}", .{ agent_id, e });
        };
    }

    /// sync gossip membership from the agents table. adds active agents
    /// that have a node_id and removes agents no longer in the table.
    /// called periodically (~10s) on the leader with self.mu held.
    fn syncGossipMembership(self: *Node) void {
        const g = self.gossip orelse return;

        const agents = agent_registry.listAgents(self.alloc, &self.state_machine.db) catch return;
        defer {
            for (agents) |agent| agent.deinit(self.alloc);
            self.alloc.free(agents);
        }

        for (agents) |agent| {
            if (!std.mem.eql(u8, agent.status, "active")) continue;
            const nid = agent.node_id orelse continue;
            if (nid < 1) continue;

            const ip = ip_mod.parseIp(agent.address) orelse continue;
            g.addMember(@intCast(nid), .{ .ip = ip, .port = agent_gossip_port }) catch {};
        }
    }

    /// return the number of members tracked by gossip (for status endpoints).
    pub fn gossipMemberCount(self: *Node) usize {
        self.mu.lock();
        defer self.mu.unlock();
        const g = self.gossip orelse return 0;
        return g.members.count();
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

    /// process raft actions in two phases:
    ///   1. state actions (commits, snapshots, role changes) run under the lock
    ///   2. send actions (vote requests, append entries, etc.) run with the lock
    ///      released so the recv thread can process incoming messages during
    ///      TCP I/O, reducing head-of-line blocking
    ///
    /// callers (tickLoop, recvLoop) hold self.mu when calling this function.
    /// the unlock/re-lock in phase 2 is transparent to them.
    fn processActions(self: *Node) void {
        const actions = self.raft.drainActions();
        defer self.alloc.free(actions);

        // phase 1: process state actions under the lock
        var has_sends = false;
        for (actions) |action| {
            switch (action) {
                .commit_entries => |commit| {
                    self.state_machine.applyUpTo(&self.log, self.alloc, commit.up_to);
                },
                .become_leader => {},
                .become_follower => {},
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
                // send actions — just note that we have some
                else => {
                    has_sends = true;
                },
            }
        }

        if (!has_sends) return;

        // phase 2: release the lock and dispatch sends.
        // this lets the recv thread process incoming messages while we're
        // doing TCP I/O, reducing head-of-line blocking.
        self.mu.unlock();
        defer self.mu.lock();

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
                // state actions already handled in phase 1
                else => {},
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

/// format a string into a buffer and null-terminate it.
/// returns null if the formatted string doesn't fit (needs room for the NUL).
fn bufPrintZ(buf: []u8, comptime fmt: []const u8, args: anytype) ?[:0]const u8 {
    const slice = std.fmt.bufPrint(buf, fmt, args) catch return null;
    if (slice.len >= buf.len) return null;
    buf[slice.len] = 0;
    return buf[0..slice.len :0];
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
