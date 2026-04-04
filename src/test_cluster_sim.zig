const std = @import("std");
const raft_mod = @import("cluster/raft.zig");
const log_mod = @import("cluster/log.zig");
const types = @import("cluster/raft_types.zig");

const Raft = raft_mod.Raft;
const Action = raft_mod.Action;
const Log = log_mod.Log;
const NodeId = types.NodeId;

const SimNode = struct {
    raft: Raft,
    log: *Log,

    fn init(alloc: std.mem.Allocator, id: NodeId, peers: []const NodeId) !SimNode {
        const log = try alloc.create(Log);
        errdefer alloc.destroy(log);
        log.* = try Log.initMemory();
        errdefer log.deinit();

        return .{
            .raft = try Raft.init(alloc, id, peers, log),
            .log = log,
        };
    }

    fn deinit(self: *SimNode) void {
        const alloc = self.raft.alloc;
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

fn electLeader(node1: *SimNode, node2: *SimNode, node3: *SimNode) !void {
    const alloc = std.testing.allocator;

    for (0..70) |_| {
        node1.raft.tick();
    }

    const vote_actions = node1.raft.drainActions();
    defer alloc.free(vote_actions);

    for (vote_actions) |action| {
        if (action != .send_request_vote) continue;

        const vote = action.send_request_vote;
        const reply = switch (vote.target) {
            2 => node2.raft.handleRequestVote(vote.args),
            3 => node3.raft.handleRequestVote(vote.args),
            else => return error.UnexpectedTarget,
        };
        node1.raft.handleRequestVoteReply(vote.target, reply);
    }

    try std.testing.expectEqual(types.Role.leader, node1.raft.role);

    const leader_actions = node1.raft.drainActions();
    defer freeActions(alloc, leader_actions);
}

fn deliverLeaderActions(leader: *SimNode, node2: *SimNode, node3: *SimNode, dropped_target: ?NodeId) !void {
    const alloc = std.testing.allocator;
    const actions = leader.raft.drainActions();
    defer freeActions(alloc, actions);

    for (actions) |action| switch (action) {
        .send_append_entries => |append| {
            if (dropped_target != null and append.target == dropped_target.?) continue;

            const reply = switch (append.target) {
                2 => node2.raft.handleAppendEntries(append.args),
                3 => node3.raft.handleAppendEntries(append.args),
                else => return error.UnexpectedTarget,
            };
            leader.raft.handleAppendEntriesReply(append.target, reply);
        },
        .send_install_snapshot => |snapshot| {
            if (dropped_target != null and snapshot.target == dropped_target.?) continue;

            const follower = switch (snapshot.target) {
                2 => &node2.raft,
                3 => &node3.raft,
                else => return error.UnexpectedTarget,
            };
            const reply = follower.handleInstallSnapshot(snapshot.args);
            _ = follower.finishInstallSnapshot(.{
                .last_included_index = snapshot.args.last_included_index,
                .last_included_term = snapshot.args.last_included_term,
                .data_len = snapshot.args.data.len,
            });
            leader.raft.handleInstallSnapshotReply(snapshot.target, reply);
        },
        else => {},
    };
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
