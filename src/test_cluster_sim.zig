const std = @import("std");
const platform = @import("platform");
const raft_mod = @import("cluster/raft.zig");
const log_mod = @import("cluster/log.zig");
const types = @import("cluster/raft_types.zig");

const Raft = raft_mod.Raft;
const Action = raft_mod.Action;
const Log = log_mod.Log;
const NodeId = types.NodeId;

const SimNode = struct {
    id: NodeId,
    raft: Raft,
    log: *Log,

    fn init(alloc: std.mem.Allocator, id: NodeId, peers: []const NodeId) !SimNode {
        const log = try alloc.create(Log);
        errdefer alloc.destroy(log);
        log.* = try Log.initMemory();
        errdefer log.deinit();

        return .{
            .id = id,
            .raft = try Raft.init(alloc, id, peers, log),
            .log = log,
        };
    }

    fn restart(self: *SimNode, peers: []const NodeId) !void {
        const alloc = self.raft.alloc;
        const pending_actions = self.raft.drainActions();
        freeActions(alloc, pending_actions);
        self.raft.deinit();
        self.raft = try Raft.init(alloc, self.id, peers, self.log);
    }

    fn deinit(self: *SimNode) void {
        const alloc = self.raft.alloc;
        const pending_actions = self.raft.drainActions();
        freeActions(alloc, pending_actions);
        self.raft.deinit();
        self.log.deinit();
        alloc.destroy(self.log);
    }
};

fn freeActions(alloc: std.mem.Allocator, actions: []const Action) void {
    for (actions) |action| {
        if (action == .send_append_entries) {
            const entries = action.send_append_entries.args.entries;
            for (entries) |entry| {
                if (entry.data.len > 0) alloc.free(entry.data);
            }
            if (entries.len > 0) alloc.free(entries);
        }
    }
    alloc.free(actions);
}

fn nodeById(node_a: *SimNode, node_b: *SimNode, id: NodeId) !*SimNode {
    if (node_a.raft.id == id) return node_a;
    if (node_b.raft.id == id) return node_b;
    return error.UnexpectedTarget;
}

fn nodeByIdIn(nodes: []const *SimNode, id: NodeId) !*SimNode {
    for (nodes) |node| {
        if (node.raft.id == id) return node;
    }
    return error.UnexpectedTarget;
}

fn isDropped(id: NodeId, dropped_targets: []const NodeId) bool {
    for (dropped_targets) |dropped| {
        if (dropped == id) return true;
    }
    return false;
}

fn deliveryCount(id: NodeId, duplicated_targets: []const NodeId) usize {
    return if (isDropped(id, duplicated_targets)) 2 else 1;
}

fn runElectionWithPeers(candidate: *SimNode, voters: []const *SimNode, dropped_targets: []const NodeId) !void {
    try runElectionWithPeersPlan(candidate, voters, dropped_targets, &.{}, &.{});
}

fn runElectionWithPeersPlan(
    candidate: *SimNode,
    voters: []const *SimNode,
    dropped_targets: []const NodeId,
    dropped_replies: []const NodeId,
    duplicated_targets: []const NodeId,
) !void {
    const alloc = std.testing.allocator;

    for (0..70) |_| {
        candidate.raft.tick();
        if (candidate.raft.role != .follower) break;
    }
    try std.testing.expect(candidate.raft.role != .follower);

    const vote_actions = candidate.raft.drainActions();
    defer alloc.free(vote_actions);

    for (vote_actions) |action| {
        if (action != .send_request_vote) continue;

        const vote = action.send_request_vote;
        if (isDropped(vote.target, dropped_targets)) continue;

        const voter = try nodeByIdIn(voters, vote.target);
        for (0..deliveryCount(vote.target, duplicated_targets)) |_| {
            const reply = voter.raft.handleRequestVote(vote.args);
            if (isDropped(vote.target, dropped_replies)) continue;
            candidate.raft.handleRequestVoteReply(vote.target, reply);
        }
    }
}

fn runElection(candidate: *SimNode, node_a: *SimNode, node_b: *SimNode, dropped_target: ?NodeId) !void {
    if (dropped_target) |target| {
        try runElectionWithPeers(candidate, &.{ node_a, node_b }, &.{target});
    } else {
        try runElectionWithPeers(candidate, &.{ node_a, node_b }, &.{});
    }
}

fn tickHeartbeats(node: *SimNode, count: usize) void {
    for (0..count) |_| {
        node.raft.tick();
    }
}

fn deliverLeaderActions(leader: *SimNode, node_a: *SimNode, node_b: *SimNode, dropped_target: ?NodeId) !void {
    if (dropped_target) |target| {
        try deliverLeaderActionsTo(leader, &.{ node_a, node_b }, &.{target});
    } else {
        try deliverLeaderActionsTo(leader, &.{ node_a, node_b }, &.{});
    }
}

fn deliverLeaderActionsTo(leader: *SimNode, followers: []const *SimNode, dropped_targets: []const NodeId) !void {
    try deliverLeaderActionsToWithPlan(leader, followers, dropped_targets, &.{}, &.{});
}

fn deliverLeaderActionsToWithPlan(
    leader: *SimNode,
    followers: []const *SimNode,
    dropped_targets: []const NodeId,
    dropped_replies: []const NodeId,
    duplicated_targets: []const NodeId,
) !void {
    const alloc = std.testing.allocator;

    for (0..64) |_| {
        const actions = leader.raft.drainActions();
        if (actions.len == 0) {
            alloc.free(actions);
            return;
        }

        for (actions) |action| switch (action) {
            .send_append_entries => |append| {
                if (isDropped(append.target, dropped_targets)) continue;

                const follower = try nodeByIdIn(followers, append.target);
                for (0..deliveryCount(append.target, duplicated_targets)) |_| {
                    const reply = follower.raft.handleAppendEntries(append.args);
                    if (isDropped(append.target, dropped_replies)) continue;
                    leader.raft.handleAppendEntriesReply(append.target, reply);
                }
            },
            .send_install_snapshot => |snapshot| {
                if (isDropped(snapshot.target, dropped_targets)) continue;

                const follower = try nodeByIdIn(followers, snapshot.target);
                for (0..deliveryCount(snapshot.target, duplicated_targets)) |_| {
                    const commit_before = follower.raft.commit_index;
                    const reply = follower.raft.handleInstallSnapshot(snapshot.args);

                    if (snapshot.args.term >= reply.term and snapshot.args.last_included_index > commit_before) {
                        try std.testing.expect(follower.log.truncateUpTo(snapshot.args.last_included_index));
                        try std.testing.expect(follower.raft.finishInstallSnapshot(.{
                            .last_included_index = snapshot.args.last_included_index,
                            .last_included_term = snapshot.args.last_included_term,
                            .data_len = snapshot.args.data.len,
                        }));
                    }

                    if (isDropped(snapshot.target, dropped_replies)) continue;
                    leader.raft.handleInstallSnapshotReply(snapshot.target, reply);
                }
            },
            else => {},
        };

        freeActions(alloc, actions);
    }

    return error.ActionLoopDidNotQuiesce;
}

fn electLeader(node1: *SimNode, node2: *SimNode, node3: *SimNode) !void {
    try runElection(node1, node2, node3, null);
    try std.testing.expectEqual(types.Role.leader, node1.raft.role);
    try deliverLeaderActions(node1, node2, node3, null);
}

const RandomFaultPlan = struct {
    drop_requests: [8]bool = [_]bool{false} ** 8,
    drop_replies: [8]bool = [_]bool{false} ** 8,
    duplicate_targets: [8]bool = [_]bool{false} ** 8,

    fn clear(self: *RandomFaultPlan) void {
        self.* = .{};
    }

    fn toggleDropRequests(self: *RandomFaultPlan, id: NodeId) void {
        self.drop_requests[@intCast(id)] = !self.drop_requests[@intCast(id)];
    }

    fn toggleDropReplies(self: *RandomFaultPlan, id: NodeId) void {
        self.drop_replies[@intCast(id)] = !self.drop_replies[@intCast(id)];
    }

    fn toggleDuplicate(self: *RandomFaultPlan, id: NodeId) void {
        self.duplicate_targets[@intCast(id)] = !self.duplicate_targets[@intCast(id)];
    }

    fn requestTargets(self: *const RandomFaultPlan) []const NodeId {
        return boolFlagsToNodeIds(&self.drop_requests);
    }

    fn replyTargets(self: *const RandomFaultPlan) []const NodeId {
        return boolFlagsToNodeIds(&self.drop_replies);
    }

    fn duplicateTargets(self: *const RandomFaultPlan) []const NodeId {
        return boolFlagsToNodeIds(&self.duplicate_targets);
    }
};

fn boolFlagsToNodeIds(flags: *const [8]bool) []const NodeId {
    var count: usize = 0;
    for (flags[1..]) |flag| {
        if (flag) count += 1;
    }

    return switch (count) {
        0 => &.{},
        1 => switch (firstNodeId(flags, 1).?) {
            1 => &.{1},
            2 => &.{2},
            3 => &.{3},
            4 => &.{4},
            5 => &.{5},
            6 => &.{6},
            7 => &.{7},
            else => &.{},
        },
        2 => blk: {
            const a = firstNodeId(flags, 1).?;
            const b = firstNodeId(flags, a + 1).?;
            break :blk switch (a) {
                1 => switch (b) {
                    2 => &.{ 1, 2 },
                    3 => &.{ 1, 3 },
                    4 => &.{ 1, 4 },
                    5 => &.{ 1, 5 },
                    6 => &.{ 1, 6 },
                    7 => &.{ 1, 7 },
                    else => &.{},
                },
                2 => switch (b) {
                    3 => &.{ 2, 3 },
                    4 => &.{ 2, 4 },
                    5 => &.{ 2, 5 },
                    6 => &.{ 2, 6 },
                    7 => &.{ 2, 7 },
                    else => &.{},
                },
                3 => switch (b) {
                    4 => &.{ 3, 4 },
                    5 => &.{ 3, 5 },
                    6 => &.{ 3, 6 },
                    7 => &.{ 3, 7 },
                    else => &.{},
                },
                4 => switch (b) {
                    5 => &.{ 4, 5 },
                    6 => &.{ 4, 6 },
                    7 => &.{ 4, 7 },
                    else => &.{},
                },
                5 => switch (b) {
                    6 => &.{ 5, 6 },
                    7 => &.{ 5, 7 },
                    else => &.{},
                },
                6 => switch (b) {
                    7 => &.{ 6, 7 },
                    else => &.{},
                },
                else => &.{},
            };
        },
        3 => blk: {
            const a = firstNodeId(flags, 1).?;
            const b = firstNodeId(flags, a + 1).?;
            const c = firstNodeId(flags, b + 1).?;
            break :blk switch (a) {
                1 => switch (b) {
                    2 => switch (c) {
                        3 => &.{ 1, 2, 3 },
                        4 => &.{ 1, 2, 4 },
                        5 => &.{ 1, 2, 5 },
                        6 => &.{ 1, 2, 6 },
                        7 => &.{ 1, 2, 7 },
                        else => &.{},
                    },
                    3 => switch (c) {
                        4 => &.{ 1, 3, 4 },
                        5 => &.{ 1, 3, 5 },
                        6 => &.{ 1, 3, 6 },
                        7 => &.{ 1, 3, 7 },
                        else => &.{},
                    },
                    else => &.{},
                },
                else => &.{},
            };
        },
        else => &.{},
    };
}

fn firstNodeId(flags: *const [8]bool, start: usize) ?NodeId {
    var idx = start;
    while (idx < flags.len) : (idx += 1) {
        if (flags[idx]) return @intCast(idx);
    }
    return null;
}

fn currentLeader(nodes: []const *SimNode) ?*SimNode {
    var leader: ?*SimNode = null;
    for (nodes) |node| {
        if (node.raft.role != .leader) continue;
        if (leader != null) return null;
        leader = node;
    }
    return leader;
}

fn pumpClusterActions(nodes: []const *SimNode, faults: *const RandomFaultPlan) !void {
    const request_targets = faults.requestTargets();
    const reply_targets = faults.replyTargets();
    const duplicate_targets = faults.duplicateTargets();

    for (0..128) |_| {
        var any = false;
        for (nodes) |sender| {
            const actions = sender.raft.drainActions();
            if (actions.len == 0) {
                std.testing.allocator.free(actions);
                continue;
            }
            any = true;

            for (actions) |action| switch (action) {
                .send_request_vote => |vote| {
                    if (isDropped(vote.target, request_targets)) continue;

                    const voter = try nodeByIdIn(nodes, vote.target);
                    for (0..deliveryCount(vote.target, duplicate_targets)) |_| {
                        const reply = voter.raft.handleRequestVote(vote.args);
                        if (isDropped(vote.target, reply_targets)) continue;
                        sender.raft.handleRequestVoteReply(vote.target, reply);
                    }
                },
                .send_append_entries => |append| {
                    if (isDropped(append.target, request_targets)) continue;

                    const follower = try nodeByIdIn(nodes, append.target);
                    for (0..deliveryCount(append.target, duplicate_targets)) |_| {
                        const reply = follower.raft.handleAppendEntries(append.args);
                        if (isDropped(append.target, reply_targets)) continue;
                        sender.raft.handleAppendEntriesReply(append.target, reply);
                    }
                },
                .send_install_snapshot => |snapshot| {
                    if (isDropped(snapshot.target, request_targets)) continue;

                    const follower = try nodeByIdIn(nodes, snapshot.target);
                    for (0..deliveryCount(snapshot.target, duplicate_targets)) |_| {
                        const commit_before = follower.raft.commit_index;
                        const reply = follower.raft.handleInstallSnapshot(snapshot.args);

                        if (snapshot.args.term >= reply.term and snapshot.args.last_included_index > commit_before) {
                            try std.testing.expect(follower.log.truncateUpTo(snapshot.args.last_included_index));
                            try std.testing.expect(follower.raft.finishInstallSnapshot(.{
                                .last_included_index = snapshot.args.last_included_index,
                                .last_included_term = snapshot.args.last_included_term,
                                .data_len = snapshot.args.data.len,
                            }));
                        }

                        if (isDropped(snapshot.target, reply_targets)) continue;
                        sender.raft.handleInstallSnapshotReply(snapshot.target, reply);
                    }
                },
                .send_request_vote_reply => |reply| {
                    if (isDropped(reply.target, reply_targets)) continue;
                    const target = try nodeByIdIn(nodes, reply.target);
                    target.raft.handleRequestVoteReply(sender.id, reply.reply);
                },
                .send_append_entries_reply => |reply| {
                    if (isDropped(reply.target, reply_targets)) continue;
                    const target = try nodeByIdIn(nodes, reply.target);
                    target.raft.handleAppendEntriesReply(sender.id, reply.reply);
                },
                .send_install_snapshot_reply => |reply| {
                    if (isDropped(reply.target, reply_targets)) continue;
                    const target = try nodeByIdIn(nodes, reply.target);
                    target.raft.handleInstallSnapshotReply(sender.id, reply.reply);
                },
                else => {},
            };

            freeActions(std.testing.allocator, actions);
        }
        if (!any) return;
    }

    return error.ActionLoopDidNotQuiesce;
}

fn tickAll(nodes: []const *SimNode, count: usize) void {
    for (0..count) |_| {
        for (nodes) |node| {
            node.raft.tick();
        }
    }
}

fn settleCluster(nodes: []const *SimNode, faults: *RandomFaultPlan, rounds: usize) !void {
    faults.clear();
    for (0..rounds) |_| {
        tickAll(nodes, 1);
        try pumpClusterActions(nodes, faults);
    }
}

fn ensureRandomSimInvariants(nodes: []const *SimNode, prev_commit: *[8]u64) !void {
    for (nodes) |node| {
        const id: usize = @intCast(node.id);
        if (node.raft.commit_index < prev_commit[id]) return error.CommitIndexRegressed;
        prev_commit[id] = node.raft.commit_index;

        if (node.raft.commit_index > node.log.lastIndex()) return error.CommitBeyondLog;
        if (node.raft.snapshot_meta) |meta| {
            if (node.raft.commit_index < meta.last_included_index) {
                return error.CommitBehindSnapshot;
            }
        }
    }

    var i: usize = 0;
    while (i < nodes.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < nodes.len) : (j += 1) {
            const shared = @min(nodes[i].raft.commit_index, nodes[j].raft.commit_index);
            var idx: u64 = 1;
            while (idx <= shared) : (idx += 1) {
                const ti = nodes[i].log.termAt(idx);
                const tj = nodes[j].log.termAt(idx);
                if (ti != 0 and tj != 0 and ti != tj) return error.CommittedTermMismatch;
            }
        }
    }
}

fn appendTrace(trace: *std.ArrayList(u8), comptime fmt: []const u8, args: anytype) !void {
    try platform.arrayListWriter(&trace, std.testing.allocator).print(fmt, args);
}

fn runRandomSeed(seed: u64, trace: *std.ArrayList(u8)) !void {
    const alloc = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2 });
    defer node3.deinit();

    const nodes = [_]*SimNode{ &node1, &node2, &node3 };
    var faults = RandomFaultPlan{};
    var prev_commit: [8]u64 = [_]u64{0} ** 8;
    var command_seq: usize = 0;

    try settleCluster(&nodes, &faults, 24);
    try ensureRandomSimInvariants(&nodes, &prev_commit);

    for (0..32) |step| {
        const event = random.uintLessThan(u8, 7);
        switch (event) {
            0 => {
                const target = random.uintLessThan(usize, nodes.len);
                const ticks = random.uintLessThan(u8, 4) + 1;
                try appendTrace(trace, "step {d}: tick node {d} x{d}\n", .{ step, nodes[target].id, ticks });
                for (0..ticks) |_| nodes[target].raft.tick();
            },
            1 => {
                if (currentLeader(&nodes)) |leader| {
                    var cmd_buf: [64]u8 = undefined;
                    const cmd = try std.fmt.bufPrint(&cmd_buf, "seed-{d}-cmd-{d}", .{ seed, command_seq });
                    command_seq += 1;
                    _ = try leader.raft.propose(cmd);
                    try appendTrace(trace, "step {d}: propose on leader {d} -> {s}\n", .{ step, leader.id, cmd });
                } else {
                    try appendTrace(trace, "step {d}: propose skipped (no single leader)\n", .{step});
                }
            },
            2 => {
                const id: NodeId = @intCast(random.uintLessThan(u8, 3) + 1);
                faults.toggleDropRequests(id);
                try appendTrace(trace, "step {d}: toggle drop requests for {d} -> {}\n", .{ step, id, faults.drop_requests[@intCast(id)] });
            },
            3 => {
                const id: NodeId = @intCast(random.uintLessThan(u8, 3) + 1);
                faults.toggleDropReplies(id);
                try appendTrace(trace, "step {d}: toggle drop replies for {d} -> {}\n", .{ step, id, faults.drop_replies[@intCast(id)] });
            },
            4 => {
                const id: NodeId = @intCast(random.uintLessThan(u8, 3) + 1);
                faults.toggleDuplicate(id);
                try appendTrace(trace, "step {d}: toggle duplicate delivery for {d} -> {}\n", .{ step, id, faults.duplicate_targets[@intCast(id)] });
            },
            5 => {
                const target = random.uintLessThan(usize, nodes.len);
                try nodes[target].restart(switch (nodes[target].id) {
                    1 => &.{ 2, 3 },
                    2 => &.{ 1, 3 },
                    3 => &.{ 1, 2 },
                    else => unreachable,
                });
                try appendTrace(trace, "step {d}: restart node {d}\n", .{ step, nodes[target].id });
            },
            6 => {
                faults.clear();
                try appendTrace(trace, "step {d}: heal all links\n", .{step});
            },
            else => unreachable,
        }

        try pumpClusterActions(&nodes, &faults);
        try ensureRandomSimInvariants(&nodes, &prev_commit);
    }

    try appendTrace(trace, "final: heal and settle\n", .{});
    try settleCluster(&nodes, &faults, 48);
    try ensureRandomSimInvariants(&nodes, &prev_commit);

    const leader = currentLeader(&nodes) orelse return error.NoLeaderAfterHeal;
    var final_cmd_buf: [64]u8 = undefined;
    const final_cmd = try std.fmt.bufPrint(&final_cmd_buf, "seed-{d}-final-sync", .{seed});
    _ = try leader.raft.propose(final_cmd);
    try appendTrace(trace, "final: propose sync command on leader {d} -> {s}\n", .{ leader.id, final_cmd });

    try settleCluster(&nodes, &faults, 24);
    try ensureRandomSimInvariants(&nodes, &prev_commit);

    const expected_commit = leader.raft.commit_index;
    const expected_last = leader.log.lastIndex();
    for (&nodes) |node| {
        if (node.raft.commit_index != expected_commit) return error.FinalCommitDidNotConverge;
        if (node.log.lastIndex() != expected_last) return error.FinalLogDidNotConverge;
        const entry = (try node.log.getEntry(alloc, expected_last)) orelse return error.MissingFinalEntry;
        defer alloc.free(entry.data);
        if (!std.mem.eql(u8, final_cmd, entry.data)) return error.FinalEntryMismatch;
    }
}

test "sim: isolated follower catches up after rejoin" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2 });
    defer node3.deinit();

    try electLeader(&node1, &node2, &node3);

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActions(&node1, &node2, &node3, null);
    if (node1.raft.commit_index != 1 or node2.log.lastIndex() != 1 or node3.log.lastIndex() != 1) {
        std.debug.panic(
            "cmd-1 state commit={d} node2_last={d} node3_last={d}",
            .{ node1.raft.commit_index, node2.log.lastIndex(), node3.log.lastIndex() },
        );
    }
    try std.testing.expectEqual(@as(u64, 1), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node2.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 1), node3.log.lastIndex());

    _ = try node1.raft.propose("cmd-2");
    try deliverLeaderActions(&node1, &node2, &node3, 3);
    if (node1.raft.commit_index != 2 or node2.log.lastIndex() != 2 or node3.log.lastIndex() != 1) {
        std.debug.panic(
            "cmd-2 state commit={d} node2_last={d} node3_last={d}",
            .{ node1.raft.commit_index, node2.log.lastIndex(), node3.log.lastIndex() },
        );
    }
    try std.testing.expectEqual(@as(u64, 2), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 2), node2.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 1), node3.log.lastIndex());

    _ = try node1.raft.propose("cmd-3");
    try deliverLeaderActions(&node1, &node2, &node3, null);
    if (node1.raft.commit_index != 3 or node2.log.lastIndex() != 3 or node3.log.lastIndex() != 3) {
        std.debug.panic(
            "cmd-3 state commit={d} node2_last={d} node3_last={d}",
            .{ node1.raft.commit_index, node2.log.lastIndex(), node3.log.lastIndex() },
        );
    }
    try std.testing.expectEqual(@as(u64, 3), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 3), node2.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 3), node3.log.lastIndex());

    const replayed = (try node3.log.getEntry(alloc, 2)).?;
    defer alloc.free(replayed.data);
    try std.testing.expectEqualStrings("cmd-2", replayed.data);

    const latest = (try node3.log.getEntry(alloc, 3)).?;
    defer alloc.free(latest.data);
    try std.testing.expectEqualStrings("cmd-3", latest.data);
}

test "sim: new leader backtracks and repairs a follower that missed committed entries" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2 });
    defer node3.deinit();

    try electLeader(&node1, &node2, &node3);

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActions(&node1, &node2, &node3, 3);
    try std.testing.expectEqual(@as(u64, 1), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node2.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 0), node3.log.lastIndex());

    try runElection(&node2, &node1, &node3, 1);
    try std.testing.expectEqual(types.Role.leader, node2.raft.role);
    try deliverLeaderActions(&node2, &node1, &node3, 1);

    try std.testing.expectEqual(@as(u64, 1), node3.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 0), node3.raft.commit_index);

    _ = try node2.raft.propose("cmd-2");
    try deliverLeaderActions(&node2, &node1, &node3, 1);
    tickHeartbeats(&node2, 6);
    try deliverLeaderActions(&node2, &node1, &node3, 1);

    try std.testing.expectEqual(@as(u64, 2), node2.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 2), node3.raft.commit_index);

    const repaired = (try node3.log.getEntry(alloc, 1)).?;
    defer alloc.free(repaired.data);
    try std.testing.expectEqualStrings("cmd-1", repaired.data);

    const committed = (try node3.log.getEntry(alloc, 2)).?;
    defer alloc.free(committed.data);
    try std.testing.expectEqualStrings("cmd-2", committed.data);
}

test "sim: stale leader entry is overwritten after higher-term leader rejoins it" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2 });
    defer node3.deinit();

    try electLeader(&node1, &node2, &node3);

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActions(&node1, &node2, &node3, null);
    try std.testing.expectEqual(@as(u64, 1), node1.raft.commit_index);

    _ = try node1.raft.propose("stale-cmd");
    try std.testing.expectEqual(@as(u64, 1), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 2), node1.log.lastIndex());

    try runElection(&node2, &node1, &node3, 1);
    try std.testing.expectEqual(types.Role.leader, node2.raft.role);
    try deliverLeaderActions(&node2, &node1, &node3, 1);

    _ = try node2.raft.propose("new-cmd");
    try deliverLeaderActions(&node2, &node1, &node3, 1);
    try std.testing.expectEqual(@as(u64, 2), node2.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 2), node3.log.lastIndex());

    tickHeartbeats(&node2, 6);
    try deliverLeaderActions(&node2, &node1, &node3, null);

    try std.testing.expectEqual(types.Role.follower, node1.raft.role);
    try std.testing.expectEqual(@as(u64, 2), node1.raft.commit_index);

    const replaced = (try node1.log.getEntry(alloc, 2)).?;
    defer alloc.free(replaced.data);
    try std.testing.expectEqualStrings("new-cmd", replaced.data);
}

test "sim: lagging follower catches up via snapshot and then accepts new entries" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2 });
    defer node3.deinit();

    try electLeader(&node1, &node2, &node3);

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActions(&node1, &node2, &node3, null);

    _ = try node1.raft.propose("cmd-2");
    try deliverLeaderActions(&node1, &node2, &node3, 3);

    _ = try node1.raft.propose("cmd-3");
    try deliverLeaderActions(&node1, &node2, &node3, 3);

    try std.testing.expectEqual(@as(u64, 3), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 3), node2.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 1), node3.log.lastIndex());

    const snapshot_term = node1.log.termAt(3);
    try std.testing.expectEqual(@as(u64, 1), snapshot_term);
    try std.testing.expect(node1.raft.onSnapshotComplete(.{
        .last_included_index = 3,
        .last_included_term = snapshot_term,
        .data_len = 0,
    }));
    try std.testing.expect(node1.log.truncateUpTo(3));

    tickHeartbeats(&node1, 6);
    try deliverLeaderActions(&node1, &node2, &node3, null);

    const snapshot_meta = node3.log.getSnapshotMeta() orelse return error.MissingSnapshotMeta;
    try std.testing.expectEqual(@as(u64, 3), snapshot_meta.last_included_index);
    try std.testing.expectEqual(@as(u64, 3), node3.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 3), node3.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 0), node3.log.termAt(1));

    _ = try node1.raft.propose("cmd-4");
    try deliverLeaderActions(&node1, &node2, &node3, null);

    const latest = (try node3.log.getEntry(alloc, 4)).?;
    defer alloc.free(latest.data);
    try std.testing.expectEqualStrings("cmd-4", latest.data);
    try std.testing.expectEqual(@as(u64, 3), node3.raft.commit_index);

    tickHeartbeats(&node1, 6);
    try deliverLeaderActions(&node1, &node2, &node3, null);
    try std.testing.expectEqual(@as(u64, 4), node3.raft.commit_index);
}

test "sim: 5-node leader commits only with quorum and repairs lagging minority later" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3, 4, 5 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3, 4, 5 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2, 4, 5 });
    defer node3.deinit();
    var node4 = try SimNode.init(alloc, 4, &.{ 1, 2, 3, 5 });
    defer node4.deinit();
    var node5 = try SimNode.init(alloc, 5, &.{ 1, 2, 3, 4 });
    defer node5.deinit();

    try runElectionWithPeers(&node1, &.{ &node2, &node3, &node4, &node5 }, &.{});
    try std.testing.expectEqual(types.Role.leader, node1.raft.role);
    try deliverLeaderActionsTo(&node1, &.{ &node2, &node3, &node4, &node5 }, &.{});

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActionsTo(&node1, &.{ &node2, &node3, &node4, &node5 }, &.{ 4, 5 });
    try std.testing.expectEqual(@as(u64, 1), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node2.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 1), node3.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 0), node4.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 0), node5.log.lastIndex());

    _ = try node1.raft.propose("cmd-2");
    try deliverLeaderActionsTo(&node1, &.{ &node2, &node3, &node4, &node5 }, &.{ 3, 4, 5 });
    try std.testing.expectEqual(@as(u64, 1), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 2), node2.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 1), node3.log.lastIndex());

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsTo(&node1, &.{ &node2, &node3, &node4, &node5 }, &.{ 2, 4, 5 });
    try std.testing.expectEqual(@as(u64, 2), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 2), node3.log.lastIndex());

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsTo(&node1, &.{ &node2, &node3, &node4, &node5 }, &.{});
    try std.testing.expectEqual(@as(u64, 2), node4.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 2), node5.log.lastIndex());
}

test "sim: restarted leader reloads snapshot metadata and catches up lagging follower" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2 });
    defer node3.deinit();

    try electLeader(&node1, &node2, &node3);

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActions(&node1, &node2, &node3, null);
    _ = try node1.raft.propose("cmd-2");
    try deliverLeaderActions(&node1, &node2, &node3, 2);
    _ = try node1.raft.propose("cmd-3");
    try deliverLeaderActions(&node1, &node2, &node3, 2);

    try std.testing.expectEqual(@as(u64, 3), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node2.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 3), node3.log.lastIndex());

    try std.testing.expect(node1.raft.onSnapshotComplete(.{
        .last_included_index = 3,
        .last_included_term = node1.log.termAt(3),
        .data_len = 0,
    }));
    try std.testing.expect(node1.log.truncateUpTo(3));
    try node1.restart(&.{ 2, 3 });
    try std.testing.expect(node1.raft.snapshot_meta != null);
    try std.testing.expectEqual(@as(u64, 3), node1.raft.snapshot_meta.?.last_included_index);

    try runElection(&node1, &node2, &node3, 2);
    try std.testing.expectEqual(types.Role.leader, node1.raft.role);
    try deliverLeaderActions(&node1, &node2, &node3, null);

    const node2_snapshot = node2.log.getSnapshotMeta() orelse return error.MissingSnapshotMeta;
    try std.testing.expectEqual(@as(u64, 3), node2_snapshot.last_included_index);
    try std.testing.expectEqual(@as(u64, 3), node2.raft.commit_index);

    _ = try node1.raft.propose("cmd-4");
    try deliverLeaderActions(&node1, &node2, &node3, null);
    tickHeartbeats(&node1, 6);
    try deliverLeaderActions(&node1, &node2, &node3, null);

    const recovered = (try node2.log.getEntry(alloc, 4)).?;
    defer alloc.free(recovered.data);
    try std.testing.expectEqualStrings("cmd-4", recovered.data);
    try std.testing.expectEqual(@as(u64, 4), node2.raft.commit_index);
}

test "sim: dropped append_entries replies recover on heartbeat retry without duplicating log entries" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2 });
    defer node3.deinit();

    try electLeader(&node1, &node2, &node3);

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActionsToWithPlan(&node1, &.{ &node2, &node3 }, &.{}, &.{ 2, 3 }, &.{});

    try std.testing.expectEqual(@as(u64, 0), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node2.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 1), node3.log.lastIndex());

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsToWithPlan(&node1, &.{ &node2, &node3 }, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u64, 1), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node2.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 1), node3.log.lastIndex());

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsToWithPlan(&node1, &.{ &node2, &node3 }, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u64, 1), node2.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node3.raft.commit_index);

    const follower_entry = (try node2.log.getEntry(alloc, 1)).?;
    defer alloc.free(follower_entry.data);
    try std.testing.expectEqualStrings("cmd-1", follower_entry.data);
}

test "sim: duplicate append_entries delivery is idempotent" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2 });
    defer node3.deinit();

    try electLeader(&node1, &node2, &node3);

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActionsToWithPlan(&node1, &.{ &node2, &node3 }, &.{}, &.{}, &.{ 2, 3 });
    try std.testing.expectEqual(@as(u64, 1), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node2.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 1), node3.log.lastIndex());

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsToWithPlan(&node1, &.{ &node2, &node3 }, &.{}, &.{}, &.{2});
    try std.testing.expectEqual(@as(u64, 1), node2.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node3.raft.commit_index);

    const entry2 = (try node2.log.getEntry(alloc, 1)).?;
    defer alloc.free(entry2.data);
    try std.testing.expectEqualStrings("cmd-1", entry2.data);

    const entry3 = (try node3.log.getEntry(alloc, 1)).?;
    defer alloc.free(entry3.data);
    try std.testing.expectEqualStrings("cmd-1", entry3.data);
}

test "sim: dropped install_snapshot reply recovers on retry without regressing follower state" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2 });
    defer node3.deinit();

    try electLeader(&node1, &node2, &node3);

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActions(&node1, &node2, &node3, null);
    _ = try node1.raft.propose("cmd-2");
    try deliverLeaderActions(&node1, &node2, &node3, 2);
    _ = try node1.raft.propose("cmd-3");
    try deliverLeaderActions(&node1, &node2, &node3, 2);

    try std.testing.expectEqual(@as(u64, 3), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node2.log.lastIndex());

    try std.testing.expect(node1.raft.onSnapshotComplete(.{
        .last_included_index = 3,
        .last_included_term = node1.log.termAt(3),
        .data_len = 0,
    }));
    try std.testing.expect(node1.log.truncateUpTo(3));

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsToWithPlan(&node1, &.{ &node2, &node3 }, &.{}, &.{2}, &.{});

    const first_snapshot = node2.log.getSnapshotMeta() orelse return error.MissingSnapshotMeta;
    try std.testing.expectEqual(@as(u64, 3), first_snapshot.last_included_index);
    try std.testing.expectEqual(@as(u64, 3), node2.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 3), node2.log.lastIndex());

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsToWithPlan(&node1, &.{ &node2, &node3 }, &.{}, &.{}, &.{});

    const retried_snapshot = node2.log.getSnapshotMeta() orelse return error.MissingSnapshotMeta;
    try std.testing.expectEqual(@as(u64, 3), retried_snapshot.last_included_index);
    try std.testing.expectEqual(@as(u64, 3), node2.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 3), node2.log.lastIndex());

    _ = try node1.raft.propose("cmd-4");
    try deliverLeaderActions(&node1, &node2, &node3, null);
    tickHeartbeats(&node1, 6);
    try deliverLeaderActions(&node1, &node2, &node3, null);

    const recovered = (try node2.log.getEntry(alloc, 4)).?;
    defer alloc.free(recovered.data);
    try std.testing.expectEqualStrings("cmd-4", recovered.data);
    try std.testing.expectEqual(@as(u64, 4), node2.raft.commit_index);
}

test "sim: duplicate install_snapshot delivery is idempotent" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2 });
    defer node3.deinit();

    try electLeader(&node1, &node2, &node3);

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActions(&node1, &node2, &node3, null);
    _ = try node1.raft.propose("cmd-2");
    try deliverLeaderActions(&node1, &node2, &node3, 2);
    _ = try node1.raft.propose("cmd-3");
    try deliverLeaderActions(&node1, &node2, &node3, 2);

    try std.testing.expect(node1.raft.onSnapshotComplete(.{
        .last_included_index = 3,
        .last_included_term = node1.log.termAt(3),
        .data_len = 0,
    }));
    try std.testing.expect(node1.log.truncateUpTo(3));

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsToWithPlan(&node1, &.{ &node2, &node3 }, &.{}, &.{}, &.{2});

    const snapshot_meta = node2.log.getSnapshotMeta() orelse return error.MissingSnapshotMeta;
    try std.testing.expectEqual(@as(u64, 3), snapshot_meta.last_included_index);
    try std.testing.expectEqual(@as(u64, 3), node2.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 3), node2.log.lastIndex());

    _ = try node1.raft.propose("cmd-4");
    try deliverLeaderActions(&node1, &node2, &node3, null);
    tickHeartbeats(&node1, 6);
    try deliverLeaderActions(&node1, &node2, &node3, null);

    const recovered = (try node2.log.getEntry(alloc, 4)).?;
    defer alloc.free(recovered.data);
    try std.testing.expectEqualStrings("cmd-4", recovered.data);
    try std.testing.expectEqual(@as(u64, 4), node2.raft.commit_index);
}

test "sim: dropped request_vote replies recover on the next election round" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2 });
    defer node3.deinit();

    try runElectionWithPeersPlan(&node1, &.{ &node2, &node3 }, &.{}, &.{ 2, 3 }, &.{});
    try std.testing.expectEqual(types.Role.candidate, node1.raft.role);
    const first_term = node1.raft.currentTerm();

    for (0..70) |_| {
        node1.raft.tick();
    }
    try runElectionWithPeersPlan(&node1, &.{ &node2, &node3 }, &.{}, &.{}, &.{});
    try std.testing.expectEqual(types.Role.leader, node1.raft.role);
    try std.testing.expect(node1.raft.currentTerm() > first_term);
    try deliverLeaderActions(&node1, &node2, &node3, null);

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActions(&node1, &node2, &node3, null);
    try std.testing.expectEqual(@as(u64, 1), node1.raft.commit_index);
}

test "sim: 5-node mixed transport faults still commit with quorum and repair laggards later" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3, 4, 5 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3, 4, 5 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2, 4, 5 });
    defer node3.deinit();
    var node4 = try SimNode.init(alloc, 4, &.{ 1, 2, 3, 5 });
    defer node4.deinit();
    var node5 = try SimNode.init(alloc, 5, &.{ 1, 2, 3, 4 });
    defer node5.deinit();

    try runElectionWithPeers(&node1, &.{ &node2, &node3, &node4, &node5 }, &.{});
    try std.testing.expectEqual(types.Role.leader, node1.raft.role);
    try deliverLeaderActionsTo(&node1, &.{ &node2, &node3, &node4, &node5 }, &.{});

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActionsToWithPlan(
        &node1,
        &.{ &node2, &node3, &node4, &node5 },
        &.{5},
        &.{2},
        &.{ 3, 4 },
    );

    try std.testing.expectEqual(@as(u64, 1), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node2.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 1), node3.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 1), node4.log.lastIndex());
    try std.testing.expectEqual(@as(u64, 0), node5.log.lastIndex());

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsToWithPlan(
        &node1,
        &.{ &node2, &node3, &node4, &node5 },
        &.{5},
        &.{},
        &.{3},
    );
    try std.testing.expectEqual(@as(u64, 1), node2.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node3.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node4.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 0), node5.raft.commit_index);

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsToWithPlan(
        &node1,
        &.{ &node2, &node3, &node4, &node5 },
        &.{},
        &.{},
        &.{2},
    );
    try std.testing.expectEqual(@as(u64, 1), node5.log.lastIndex());

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsToWithPlan(
        &node1,
        &.{ &node2, &node3, &node4, &node5 },
        &.{},
        &.{},
        &.{},
    );
    try std.testing.expectEqual(@as(u64, 1), node5.raft.commit_index);

    const repaired = (try node5.log.getEntry(alloc, 1)).?;
    defer alloc.free(repaired.data);
    try std.testing.expectEqualStrings("cmd-1", repaired.data);
}

test "sim: snapshot retry after follower restart resumes replication cleanly" {
    const alloc = std.testing.allocator;

    var node1 = try SimNode.init(alloc, 1, &.{ 2, 3 });
    defer node1.deinit();
    var node2 = try SimNode.init(alloc, 2, &.{ 1, 3 });
    defer node2.deinit();
    var node3 = try SimNode.init(alloc, 3, &.{ 1, 2 });
    defer node3.deinit();

    try electLeader(&node1, &node2, &node3);

    _ = try node1.raft.propose("cmd-1");
    try deliverLeaderActions(&node1, &node2, &node3, null);
    _ = try node1.raft.propose("cmd-2");
    try deliverLeaderActions(&node1, &node2, &node3, 2);
    _ = try node1.raft.propose("cmd-3");
    try deliverLeaderActions(&node1, &node2, &node3, 2);

    try std.testing.expectEqual(@as(u64, 3), node1.raft.commit_index);
    try std.testing.expectEqual(@as(u64, 1), node2.log.lastIndex());

    try std.testing.expect(node1.raft.onSnapshotComplete(.{
        .last_included_index = 3,
        .last_included_term = node1.log.termAt(3),
        .data_len = 0,
    }));
    try std.testing.expect(node1.log.truncateUpTo(3));

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsToWithPlan(&node1, &.{ &node2, &node3 }, &.{}, &.{2}, &.{});

    const installed = node2.log.getSnapshotMeta() orelse return error.MissingSnapshotMeta;
    try std.testing.expectEqual(@as(u64, 3), installed.last_included_index);
    try std.testing.expectEqual(@as(u64, 3), node2.raft.commit_index);

    try node2.restart(&.{ 1, 3 });
    try std.testing.expect(node2.raft.snapshot_meta != null);
    try std.testing.expectEqual(@as(u64, 3), node2.raft.snapshot_meta.?.last_included_index);
    try std.testing.expectEqual(@as(u64, 3), node2.raft.commit_index);

    tickHeartbeats(&node1, 6);
    try deliverLeaderActionsToWithPlan(&node1, &.{ &node2, &node3 }, &.{}, &.{}, &.{});
    try std.testing.expectEqual(@as(u64, 3), node2.raft.commit_index);

    _ = try node1.raft.propose("cmd-4");
    try deliverLeaderActions(&node1, &node2, &node3, null);
    tickHeartbeats(&node1, 6);
    try deliverLeaderActions(&node1, &node2, &node3, null);

    const recovered = (try node2.log.getEntry(alloc, 4)).?;
    defer alloc.free(recovered.data);
    try std.testing.expectEqualStrings("cmd-4", recovered.data);
    try std.testing.expectEqual(@as(u64, 4), node2.raft.commit_index);
}

test "sim: randomized fixed seeds preserve raft invariants under transport faults" {
    const seeds = [_]u64{ 1, 2, 3, 4, 5, 7, 11, 13, 17, 19 };

    for (seeds) |seed| {
        var trace = std.ArrayList(u8).empty;
        defer trace.deinit(std.testing.allocator);

        runRandomSeed(seed, &trace) catch |err| {
            std.debug.print("random sim seed {d} failed with {} trace:\n{s}", .{ seed, err, trace.items });
            return err;
        };
    }
}
