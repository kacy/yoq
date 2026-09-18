const std = @import("std");
const logger = @import("../../lib/log.zig");
const common = @import("common.zig");
const snapshot_runtime = @import("snapshot_runtime.zig");
const types = @import("../raft_types.zig");

const AppendEntriesArgs = types.AppendEntriesArgs;
const AppendEntriesReply = types.AppendEntriesReply;
const LogEntry = types.LogEntry;

pub fn handleAppendEntries(
    self: anytype,
    args: AppendEntriesArgs,
    min_election_ticks: u32,
    max_election_ticks: u32,
) AppendEntriesReply {
    const current_term = self.persistent_state.current_term;
    if (args.term < current_term) {
        return .{ .term = current_term, .success = false, .match_index = 0 };
    }

    if (args.term > current_term) {
        if (!common.stepDown(self, args.term, min_election_ticks, max_election_ticks)) {
            return .{ .term = current_term, .success = false, .match_index = 0 };
        }
    } else if (self.role == .candidate) {
        self.role = .follower;
    }
    // an existing follower also learns the leader after an election. publishing
    // only candidate transitions leaves the api without a usable redirect.
    if (self.role == .follower) {
        self.actions.append(self.alloc, .{ .become_follower = .{ .leader_id = args.leader_id } }) catch |e| {
            logger.warn("raft: failed to queue become_follower action: {}", .{e});
        };
    }
    self.ticks_since_event = 0;

    if (args.prev_log_index > 0) {
        const prev_term = self.log.termAt(args.prev_log_index);
        if (prev_term == 0 or prev_term != args.prev_log_term) {
            return .{ .term = self.persistent_state.current_term, .success = false, .match_index = 0 };
        }
    }

    // validate the entire batch before truncating or appending. a follower
    // may retain a divergent suffix beyond the prefix verified here.
    const verified_index = verifiedPrefix(args.prev_log_index, args.entries) orelse {
        return .{ .term = self.persistent_state.current_term, .success = false, .match_index = 0 };
    };

    for (args.entries) |entry| {
        const existing_term = self.log.termAt(entry.index);
        if (existing_term != 0) {
            if (existing_term == entry.term) continue;
            if (!self.log.truncateFrom(entry.index)) {
                return .{ .term = self.persistent_state.current_term, .success = false, .match_index = 0 };
            }
        }
        self.log.append(entry) catch {
            return .{ .term = self.persistent_state.current_term, .success = false, .match_index = 0 };
        };
    }

    const new_commit = @min(args.leader_commit, verified_index);
    if (new_commit > self.commit_index and !queueCommit(self, new_commit)) {
        return .{ .term = self.persistent_state.current_term, .success = false, .match_index = 0 };
    }

    return .{
        .term = self.persistent_state.current_term,
        .success = true,
        .match_index = verified_index,
    };
}

pub fn handleAppendEntriesReply(
    self: anytype,
    from: anytype,
    reply: AppendEntriesReply,
    min_election_ticks: u32,
    max_election_ticks: u32,
) void {
    const current_term = self.persistent_state.current_term;
    if (reply.term > current_term) {
        _ = common.stepDown(self, reply.term, min_election_ticks, max_election_ticks);
        return;
    }
    if (reply.term != current_term or self.role != .leader) return;

    const peer_idx = common.peerIndex(self, from) orelse return;
    if (reply.success) {
        if (reply.match_index > self.match_index[peer_idx]) {
            self.match_index[peer_idx] = reply.match_index;
            self.next_index[peer_idx] = reply.match_index + 1;
        }
        advanceCommitIndex(self);
        return;
    }

    const backtrack_floor = self.match_index[peer_idx] + 1;
    if (self.next_index[peer_idx] <= backtrack_floor) {
        // a delayed failure may follow a newer success. keep the prefix
        // already acknowledged by the follower.
        return;
    }

    self.next_index[peer_idx] -= 1;
    sendAppendEntries(self, peer_idx);
}

pub fn sendHeartbeats(self: anytype) void {
    for (0..self.peers.len) |i| {
        sendAppendEntries(self, i);
    }
}

pub fn sendAppendEntries(self: anytype, peer_idx: usize) void {
    const next = self.next_index[peer_idx];
    const prev_index = if (next > 0) next - 1 else 0;
    const prev_term = self.log.termAt(prev_index);

    if (prev_index > 0 and prev_term == 0) {
        if (self.snapshot_meta) |meta| {
            if (prev_index <= meta.last_included_index) {
                snapshot_runtime.sendInstallSnapshot(self, peer_idx, meta);
                return;
            }
        }
    }

    const last = self.log.lastIndex();
    var entries_buf: [64]LogEntry = undefined;
    var count: usize = 0;
    var entries_transferred = false;
    defer if (!entries_transferred) {
        for (entries_buf[0..count]) |entry| self.alloc.free(entry.data);
    };

    if (next <= last) {
        var idx = next;
        while (idx <= last and count < entries_buf.len) : (idx += 1) {
            if (self.log.getEntry(self.alloc, idx) catch null) |entry| {
                entries_buf[count] = entry;
                count += 1;
            }
        }
    }

    const entries = if (count > 0)
        self.alloc.dupe(LogEntry, entries_buf[0..count]) catch {
            logger.warn("raft: failed to allocate entries for append_entries to node {}", .{self.peers[peer_idx]});
            return;
        }
    else
        &.{};

    // the queued action owns both the entry slice and its payloads.
    self.actions.append(self.alloc, .{
        .send_append_entries = .{
            .target = self.peers[peer_idx],
            .args = .{
                .term = self.persistent_state.current_term,
                .leader_id = self.id,
                .prev_log_index = prev_index,
                .prev_log_term = prev_term,
                .entries = entries,
                .leader_commit = self.commit_index,
            },
        },
    }) catch |e| {
        logger.warn("raft: failed to queue append entries: {}", .{e});
        if (entries.len > 0) self.alloc.free(entries);
        return;
    };
    entries_transferred = true;
}

pub fn advanceCommitIndex(self: anytype) void {
    const current_term = self.persistent_state.current_term;
    const last = self.log.lastIndex();

    var candidate_index = last;
    while (candidate_index > self.commit_index and candidate_index > 0) : (candidate_index -= 1) {
        if (self.log.termAt(candidate_index) != current_term) continue;

        // the leader's local entry counts toward the majority.
        var replicas: usize = 1;
        for (self.match_index) |matched_index| {
            if (matched_index >= candidate_index) replicas += 1;
        }

        const quorum = (self.peers.len + 1) / 2 + 1;
        if (replicas < quorum) continue;

        _ = queueCommit(self, candidate_index);
        return;
    }
}

pub fn peerIndex(self: anytype, id: anytype) ?usize {
    return common.peerIndex(self, id);
}

fn verifiedPrefix(previous_index: types.LogIndex, entries: []const LogEntry) ?types.LogIndex {
    var verified_index = previous_index;
    for (entries) |entry| {
        const next = @addWithOverflow(verified_index, 1);
        if (next[1] != 0 or entry.index != next[0]) return null;
        verified_index = entry.index;
    }
    return verified_index;
}

fn queueCommit(self: anytype, up_to: types.LogIndex) bool {
    // queue the application work before advancing the index, so a failed
    // allocation leaves the commit available for a later retry.
    self.actions.append(self.alloc, .{
        .commit_entries = .{ .up_to = up_to },
    }) catch |e| {
        logger.warn("raft: failed to queue commit action: {}", .{e});
        return false;
    };
    self.commit_index = up_to;
    return true;
}

test "append entries releases payloads when building or queueing the request fails" {
    const Raft = @import("../raft.zig").Raft;
    const Action = @import("../raft.zig").Action;
    const Log = @import("../log.zig").Log;
    const test_support = @import("test_support.zig");
    const alloc = std.testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();
    try log.append(.{ .index = 1, .term = 1, .data = "first" });
    try log.append(.{ .index = 2, .term = 1, .data = "second" });

    // fail each payload read, the entry slice, and the action queue in turn.
    // the final iteration lets the action take ownership of both payloads.
    for (0..5) |fail_index| {
        var raft = try Raft.init(alloc, 1, &.{2}, &log);
        defer raft.deinit();
        var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = fail_index });
        raft.alloc = failing.allocator();
        sendAppendEntries(&raft, 0);
        raft.alloc = alloc;

        const actions = try raft.drainActions();
        defer test_support.deinitOwnedActions(Action, alloc, actions);
        if (fail_index < 4) {
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(@as(usize, 0), actions.len);
        } else {
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(@as(usize, 1), actions.len);
            const entries = actions[0].send_append_entries.args.entries;
            try std.testing.expectEqual(@as(usize, 2), entries.len);
            try std.testing.expectEqualStrings("first", entries[0].data);
            try std.testing.expectEqualStrings("second", entries[1].data);
        }
    }
}

test "append entries preserves missing log reads and the batch limit" {
    const Raft = @import("../raft.zig").Raft;
    const Action = @import("../raft.zig").Action;
    const Log = @import("../log.zig").Log;
    const test_support = @import("test_support.zig");
    const alloc = std.testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();
    for (1..67) |index| {
        if (index == 2) continue;
        try log.append(.{ .index = index, .term = 1, .data = "entry" });
    }
    var raft = try Raft.init(alloc, 1, &.{2}, &log);
    defer raft.deinit();

    sendAppendEntries(&raft, 0);
    const actions = try raft.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, actions);
    try std.testing.expectEqual(@as(usize, 1), actions.len);
    const request = actions[0].send_append_entries.args;
    try std.testing.expectEqual(@as(types.LogIndex, 0), request.prev_log_index);
    try std.testing.expectEqual(@as(usize, 64), request.entries.len);
    try std.testing.expectEqual(@as(types.LogIndex, 1), request.entries[0].index);
    try std.testing.expectEqual(@as(types.LogIndex, 3), request.entries[1].index);
    try std.testing.expectEqual(@as(types.LogIndex, 65), request.entries[63].index);
}

test "append entries retries commit notification after queue allocation failure" {
    const Raft = @import("../raft.zig").Raft;
    const alloc = std.testing.allocator;
    var log = try @import("../log.zig").Log.initMemory();
    defer log.deinit();
    try std.testing.expect(log.setCurrentTerm(1));
    try log.append(.{ .index = 1, .term = 1, .data = "existing" });
    var raft = try Raft.init(alloc, 2, &.{1}, &log);
    defer raft.deinit();
    const request: AppendEntriesArgs = .{
        .term = 1,
        .leader_id = 1,
        .prev_log_index = 1,
        .prev_log_term = 1,
        .entries = &.{.{ .index = 2, .term = 1, .data = "new" }},
        .leader_commit = 2,
    };

    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    raft.alloc = failing.allocator();
    const rejected = raft.handleAppendEntries(request);
    raft.alloc = alloc;
    try std.testing.expect(!rejected.success);
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(types.LogIndex, 2), log.lastIndex());
    try std.testing.expectEqual(@as(types.LogIndex, 0), raft.commit_index);
    try std.testing.expectEqual(@as(usize, 0), raft.actions.items.len);

    const accepted = raft.handleAppendEntries(request);
    try std.testing.expect(accepted.success);
    try std.testing.expectEqual(@as(types.LogIndex, 2), accepted.match_index);
    try std.testing.expectEqual(@as(types.LogIndex, 2), raft.commit_index);
    const actions = try raft.drainActions();
    defer alloc.free(actions);
    try std.testing.expectEqual(@as(usize, 1), actions.len);
    try std.testing.expectEqual(@as(types.LogIndex, 2), actions[0].commit_entries.up_to);
}

test "leader retries commit notification without another follower acknowledgement" {
    const Raft = @import("../raft.zig").Raft;
    const alloc = std.testing.allocator;
    var log = try @import("../log.zig").Log.initMemory();
    defer log.deinit();
    try std.testing.expect(log.setCurrentTerm(2));
    try log.append(.{ .index = 1, .term = 1, .data = "previous term" });
    try log.append(.{ .index = 2, .term = 2, .data = "current term" });
    var raft = try Raft.init(alloc, 1, &.{2}, &log);
    defer raft.deinit();
    raft.role = .leader;
    raft.match_index[0] = 2;

    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    raft.alloc = failing.allocator();
    advanceCommitIndex(&raft);
    raft.alloc = alloc;
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(types.LogIndex, 0), raft.commit_index);
    try std.testing.expectEqual(@as(usize, 0), raft.actions.items.len);

    advanceCommitIndex(&raft);
    try std.testing.expectEqual(@as(types.LogIndex, 2), raft.commit_index);
    const actions = try raft.drainActions();
    defer alloc.free(actions);
    try std.testing.expectEqual(@as(usize, 1), actions.len);
    try std.testing.expectEqual(@as(types.LogIndex, 2), actions[0].commit_entries.up_to);
}

test "verified prefix rejects an index that wraps around" {
    const last_index = std.math.maxInt(types.LogIndex);
    try std.testing.expectEqual(last_index, verifiedPrefix(last_index, &.{}).?);
    try std.testing.expectEqual(null, verifiedPrefix(last_index, &.{
        .{ .index = 0, .term = 1, .data = "wrapped" },
    }));
}
