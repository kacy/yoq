const std = @import("std");
const agent_registry = @import("../registry.zig");
const placement = @import("../placement_transaction.zig");
const mutation_session = @import("../mutation_session.zig");
const agent_drain = @import("../agent_drain.zig");
const gossip_mod = @import("../gossip.zig");
const gossip_sender_validation = @import("../gossip_sender_validation.zig");
const ip_mod = @import("../../network/ip.zig");
const service_reconciler = @import("../../network/service_reconciler.zig");
const logger = @import("../../lib/log.zig");

const agent_gossip_port: u16 = 9800;

fn proposeUnderLock(self: anytype, sql: []const u8) !void {
    self.mu.lockUncancelable(std.Options.debug_io);
    defer self.mu.unlock(std.Options.debug_io);
    _ = try self.proposeLocked(sql);
}

pub fn checkAgentHealth(self: anytype, agents: []const agent_registry.AgentRecord) void {
    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    const base_timeout: i64 = 30;
    self.mu.lockUncancelable(std.Options.debug_io);
    const multiplier: i64 = if (self.gossip) |g| blk: {
        const member_count = g.members.count() + 1;
        break :blk @min(@as(i64, gossip_mod.Gossip.ceilLog2(member_count)), gossip_mod.Gossip.max_interval_multiplier);
    } else 1;
    self.mu.unlock(std.Options.debug_io);
    const timeout: i64 = base_timeout * multiplier;

    for (agents) |agent| {
        if (!std.mem.eql(u8, agent.status, "active") and !agent_drain.isDraining(agent.status)) continue;
        if (now - agent.last_heartbeat <= timeout) continue;

        self.mu.lockUncancelable(std.Options.debug_io);
        markOfflineAndOrphanLocked(self, agent.id);
        self.mu.unlock(std.Options.debug_io);
        if (agent.node_id) |node_id| service_reconciler.noteNodeLost(node_id);
    }
}

fn markOfflineAndOrphanLocked(self: anytype, agent_id: []const u8) void {
    const agent = (agent_registry.getAgent(self.alloc, &self.state_machine.db, agent_id) catch return) orelse return;
    defer agent.deinit(self.alloc);
    // blocked host data and unfinished jobs stay with drain reconciliation,
    // even when no replacement has been created yet.
    if (agent_drain.isDraining(agent.status) or std.mem.eql(u8, agent.status, "drained")) return;
    const command = @import("../sql_command.zig").render(
        self.alloc,
        "UPDATE assignments SET agent_id = CASE WHEN (SELECT last_applied FROM state_machine_meta WHERE id = 1) = ? THEN '' ELSE NULL END, status = 'pending' WHERE agent_id = ? AND status IN ('pending', 'running'); UPDATE agents SET status = CASE WHEN status IN ('draining', 'drain_pending', 'drain_blocked', 'drained') THEN status ELSE 'offline' END WHERE id = ?;",
        .{ self.state_machine.last_applied, agent_id, agent_id },
    ) catch return;
    defer self.alloc.free(command);
    // an unapplied drain request may precede this proposal. the placement
    // index guard rejects both updates together, so the next health pass can
    // retry an ordinary worker instead of leaving it offline with stranded work.
    _ = self.proposeLocked(command) catch |err| {
        logger.warn("failed to propose assignment orphaning for agent {s}: {}", .{ agent_id, err });
    };
}

pub fn reconcileOrphanedAssignments(
    self: anytype,
    orphans: []const agent_registry.Assignment,
    agents: []const agent_registry.AgentRecord,
) void {
    _ = agents;
    if (orphans.len == 0) return;
    const session = mutation_session.Session.begin(self) catch return;
    placement.reconcileOrphans(self.alloc, session) catch |err| {
        logger.warn("failed to reconcile assignment capacity: {}", .{err});
    };
}

pub fn reconcileDrainingAgents(self: anytype, agents: []const agent_registry.AgentRecord) void {
    for (agents) |agent| {
        if (!agent_drain.isDraining(agent.status)) continue;
        const session = mutation_session.Session.begin(self) catch return;
        agent_drain.reconcile(self.alloc, session, agent.id) catch |err| {
            logger.warn("failed to advance drain for agent {s}: {}", .{ agent.id, err });
        };
    }
}

pub fn cleanupDeadAgents(self: anytype, agents: []const agent_registry.AgentRecord) void {
    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    const dead_timeout: i64 = 3600;

    for (agents) |agent| {
        if (!std.mem.eql(u8, agent.status, "offline")) continue;
        if (now - agent.last_heartbeat <= dead_timeout) continue;

        var assign_buf: [256]u8 = undefined;
        const assign_sql = agent_registry.deleteAgentAssignmentsSql(&assign_buf, agent.id) catch continue;
        _ = proposeUnderLock(self, assign_sql) catch |e| {
            logger.warn("failed to propose assignment cleanup for dead agent {s}: {}", .{ agent.id, e });
            continue;
        };

        if (agent.node_id) |nid| {
            if (nid >= 1 and nid <= 65534) {
                var wg_buf: [256]u8 = undefined;
                const wg_sql = agent_registry.removeWireguardPeerSql(&wg_buf, @intCast(nid)) catch continue;
                _ = proposeUnderLock(self, wg_sql) catch |e| {
                    logger.warn("failed to remove wireguard peer for dead agent {s}: {}", .{ agent.id, e });
                };
            }
        }

        var remove_buf: [256]u8 = undefined;
        const remove_sql = agent_registry.removeSql(&remove_buf, agent.id) catch continue;
        _ = proposeUnderLock(self, remove_sql) catch |e| {
            logger.warn("failed to propose removal of dead agent {s}: {}", .{ agent.id, e });
        };
    }
}

pub fn tickGossip(self: anytype) void {
    self.mu.lockUncancelable(std.Options.debug_io);
    defer self.mu.unlock(std.Options.debug_io);

    const g = self.gossip orelse return;

    g.tick() catch return;

    const actions = g.drainActions() catch |err| {
        logger.warn("gossip: failed to drain tick actions: {}", .{err});
        return;
    };
    defer g.freeActions(actions);
    processGossipActions(self, actions);

    if (self.tick_count % 100 == 0 and self.raft.role == .leader) {
        syncGossipMembership(self);
    }
}

pub fn receiveGossipMessages(self: anytype) void {
    self.mu.lockUncancelable(std.Options.debug_io);
    defer self.mu.unlock(std.Options.debug_io);

    const g = self.gossip orelse return;
    const GossipMsg = gossip_mod.GossipMessage;
    var msgs: [10]GossipMsg = undefined;
    var msg_count: u32 = 0;
    var buf: [1500]u8 = undefined;

    while (msg_count < 10) {
        const result = self.transport.receiveGossip(&buf) catch break;
        const recv = result orelse break;
        if (!gossip_sender_validation.isTrustedSender(g, recv)) {
            logger.warn("gossip: rejected spoofed sender {} from unexpected source", .{recv.sender_id});
            continue;
        }
        const msg = gossip_mod.Gossip.decode(self.alloc, recv.payload) catch continue;
        msgs[msg_count] = msg;
        msg_count += 1;
    }

    if (msg_count == 0) return;

    for (msgs[0..msg_count]) |msg| {
        switch (msg) {
            .ping => |payload| g.handlePing(payload) catch |e| {
                logger.warn("gossip: handlePing failed: {}", .{e});
            },
            .ping_ack => |payload| g.handlePingAck(payload) catch |e| {
                logger.warn("gossip: handlePingAck failed: {}", .{e});
            },
            .ping_req => |payload| g.handlePingReq(payload) catch |e| {
                logger.warn("gossip: handlePingReq failed: {}", .{e});
            },
        }
    }

    const actions = g.drainActions() catch |err| {
        logger.warn("gossip: failed to drain received-message actions: {}", .{err});
        return;
    };
    defer g.freeActions(actions);
    processGossipActions(self, actions);
}

/// Gossip state and callbacks share the caller's node lock.
pub fn processGossipActions(self: anytype, actions: []gossip_mod.Action) void {
    for (actions) |action| {
        switch (action) {
            .send_message => |msg| {
                var encode_buf: [512]u8 = undefined;
                const len = gossip_mod.Gossip.encode(&encode_buf, msg.message) catch continue;
                self.transport.sendGossip(msg.addr.ip, msg.addr.port, encode_buf[0..len]) catch {};
            },
            .member_dead => |member_event| {
                if (self.raft.role == .leader) handleGossipMemberDead(self, member_event.id);
            },
            .member_alive => |member_event| {
                if (self.raft.role == .leader) handleGossipMemberAlive(self, member_event.id);
            },
            .member_suspect => {},
        }
    }
}

pub fn handleGossipMemberDead(self: anytype, member_id: u64) void {
    const agent_id = agent_registry.findAgentIdByNodeId(self.alloc, &self.state_machine.db, member_id) orelse return;
    defer self.alloc.free(agent_id);

    logger.info("gossip: member {} dead, marking agent {s} offline", .{ member_id, agent_id });

    markOfflineAndOrphanLocked(self, agent_id);
    service_reconciler.noteNodeLost(@intCast(member_id));

    if (member_id >= 1 and member_id <= 65534) {
        var wg_buf: [256]u8 = undefined;
        const wg_sql = agent_registry.removeWireguardPeerSql(&wg_buf, @intCast(member_id)) catch return;
        _ = self.proposeLocked(wg_sql) catch |e| {
            logger.warn("gossip: failed to remove wireguard peer for dead member {}: {}", .{ member_id, e });
        };
    }
}

pub fn handleGossipMemberAlive(self: anytype, member_id: u64) void {
    const agent_id = agent_registry.findAgentIdByNodeId(self.alloc, &self.state_machine.db, member_id) orelse return;
    defer self.alloc.free(agent_id);

    var sql_buf: [256]u8 = undefined;
    const sql = agent_registry.markActiveSql(&sql_buf, agent_id) catch return;
    _ = self.proposeLocked(sql) catch |e| {
        logger.warn("gossip: failed to propose active for agent {s}: {}", .{ agent_id, e });
        return;
    };
    service_reconciler.noteNodeRecovered(@intCast(member_id));
}

pub fn syncGossipMembership(self: anytype) void {
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
