const std = @import("std");
const agent_registry = @import("../registry.zig");
const scheduler = @import("../scheduler.zig");
const gossip_mod = @import("../gossip.zig");
const ip_mod = @import("../../network/ip.zig");
const logger = @import("../../lib/log.zig");

const agent_gossip_port: u16 = 9800;

fn proposeUnderLock(self: anytype, sql: []const u8) !void {
    self.mu.lock();
    defer self.mu.unlock();
    _ = try self.raft.propose(sql);
}

pub fn checkAgentHealth(self: anytype, agents: []const agent_registry.AgentRecord) void {
    const now = std.time.timestamp();
    const base_timeout: i64 = 30;
    const multiplier: i64 = if (self.gossip) |g| blk: {
        const member_count = g.members.count() + 1;
        break :blk @min(@as(i64, gossip_mod.Gossip.ceilLog2(member_count)), gossip_mod.Gossip.max_interval_multiplier);
    } else 1;
    const timeout: i64 = base_timeout * multiplier;

    for (agents) |agent| {
        if (!std.mem.eql(u8, agent.status, "active")) continue;
        if (now - agent.last_heartbeat <= timeout) continue;

        var sql_buf: [256]u8 = undefined;
        const sql = agent_registry.markOfflineSql(&sql_buf, agent.id) catch continue;
        _ = proposeUnderLock(self, sql) catch |e| {
            logger.warn("failed to propose agent offline status: {}", .{e});
            continue;
        };

        var orphan_buf: [256]u8 = undefined;
        const orphan_sql = agent_registry.orphanAssignmentsSql(&orphan_buf, agent.id) catch continue;
        _ = proposeUnderLock(self, orphan_sql) catch |e| {
            logger.warn("failed to propose assignment orphaning for agent {s}: {}", .{ agent.id, e });
        };
    }
}

pub fn reconcileOrphanedAssignments(
    self: anytype,
    orphans: []const agent_registry.Assignment,
    agents: []const agent_registry.AgentRecord,
) void {
    if (orphans.len == 0) return;

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
        if (placement) |picked| {
            var sql_buf: [256]u8 = undefined;
            const sql = agent_registry.reassignSql(&sql_buf, orphans[i].id, picked.agent_id) catch continue;
            _ = proposeUnderLock(self, sql) catch |e| {
                logger.warn("failed to propose reassignment for {s}: {}", .{ orphans[i].id, e });
            };
        }
    }
}

pub fn cleanupDeadAgents(self: anytype, agents: []const agent_registry.AgentRecord) void {
    const now = std.time.timestamp();
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
    const g = self.gossip orelse return;

    g.tick() catch return;

    const actions = g.drainActions();
    defer g.freeActions(actions);
    processGossipActions(self, actions);

    if (self.tick_count % 100 == 0 and self.raft.role == .leader) {
        syncGossipMembership(self);
    }
}

pub fn receiveGossipMessages(self: anytype) void {
    const g = self.gossip orelse return;
    const GossipMsg = gossip_mod.GossipMessage;
    var msgs: [10]GossipMsg = undefined;
    var msg_count: u32 = 0;
    var buf: [1500]u8 = undefined;

    while (msg_count < 10) {
        const result = self.transport.receiveGossip(&buf) catch break;
        const recv = result orelse break;
        const msg = gossip_mod.Gossip.decode(self.alloc, recv.payload) catch continue;
        msgs[msg_count] = msg;
        msg_count += 1;
    }

    if (msg_count == 0) return;

    self.mu.lock();
    defer self.mu.unlock();

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

    const actions = g.drainActions();
    defer g.freeActions(actions);
    processGossipActions(self, actions);
}

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

    var sql_buf: [256]u8 = undefined;
    const sql = agent_registry.markOfflineSql(&sql_buf, agent_id) catch return;
    _ = proposeUnderLock(self, sql) catch |e| {
        logger.warn("gossip: failed to propose offline for agent {s}: {}", .{ agent_id, e });
        return;
    };

    var orphan_buf: [256]u8 = undefined;
    const orphan_sql = agent_registry.orphanAssignmentsSql(&orphan_buf, agent_id) catch return;
    _ = proposeUnderLock(self, orphan_sql) catch |e| {
        logger.warn("gossip: failed to orphan assignments for agent {s}: {}", .{ agent_id, e });
    };

    if (member_id >= 1 and member_id <= 65534) {
        var wg_buf: [256]u8 = undefined;
        const wg_sql = agent_registry.removeWireguardPeerSql(&wg_buf, @intCast(member_id)) catch return;
        _ = proposeUnderLock(self, wg_sql) catch |e| {
            logger.warn("gossip: failed to remove wireguard peer for dead member {}: {}", .{ member_id, e });
        };
    }
}

pub fn handleGossipMemberAlive(self: anytype, member_id: u64) void {
    const agent_id = agent_registry.findAgentIdByNodeId(self.alloc, &self.state_machine.db, member_id) orelse return;
    defer self.alloc.free(agent_id);

    var sql_buf: [256]u8 = undefined;
    const sql = agent_registry.markActiveSql(&sql_buf, agent_id) catch return;
    _ = proposeUnderLock(self, sql) catch |e| {
        logger.warn("gossip: failed to propose active for agent {s}: {}", .{ agent_id, e });
    };
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
