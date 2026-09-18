const std = @import("std");
const logger = @import("../../lib/log.zig");
const common = @import("common.zig");
const replication_runtime = @import("replication_runtime.zig");
const types = @import("../raft_types.zig");

const RequestVoteArgs = types.RequestVoteArgs;
const RequestVoteReply = types.RequestVoteReply;

pub fn tick(self: anytype, heartbeat_interval: u32, min_election_ticks: u32, max_election_ticks: u32) void {
    self.ticks_since_event += 1;

    switch (self.role) {
        .follower, .candidate => {
            if (self.ticks_since_event >= self.election_timeout) {
                startElection(self, min_election_ticks, max_election_ticks);
            }
        },
        .leader => {
            self.heartbeat_ticks += 1;
            if (self.heartbeat_ticks >= heartbeat_interval) {
                replication_runtime.sendHeartbeats(self);
                self.heartbeat_ticks = 0;
            }
        },
    }
}

pub fn handleRequestVote(
    self: anytype,
    args: RequestVoteArgs,
    min_election_ticks: u32,
    max_election_ticks: u32,
) RequestVoteReply {
    const current_term = self.persistent_state.current_term;
    if (args.term < current_term) {
        return .{ .term = current_term, .vote_granted = false };
    }

    if (args.term > current_term) {
        if (!common.stepDown(self, args.term, min_election_ticks, max_election_ticks)) {
            return .{ .term = current_term, .vote_granted = false };
        }
    }

    const can_vote = if (self.persistent_state.voted_for) |candidate_id|
        candidate_id == args.candidate_id
    else
        true;
    const log_is_current = candidateLogIsCurrent(self, args);
    if (!can_vote or !log_is_current) {
        return .{ .term = self.persistent_state.current_term, .vote_granted = false };
    }

    // save the vote before granting it or postponing the next election.
    if (!self.persistVote(args.candidate_id)) {
        return .{ .term = self.persistent_state.current_term, .vote_granted = false };
    }
    self.ticks_since_event = 0;
    return .{ .term = self.persistent_state.current_term, .vote_granted = true };
}

fn candidateLogIsCurrent(self: anytype, args: RequestVoteArgs) bool {
    const last_term = self.log.lastTerm();
    const last_index = self.log.lastIndex();

    // compare terms first. length only breaks a tie between equal terms.
    if (args.last_log_term != last_term) return args.last_log_term > last_term;
    return args.last_log_index >= last_index;
}

pub fn handleRequestVoteReply(
    self: anytype,
    from: anytype,
    reply: RequestVoteReply,
    min_election_ticks: u32,
    max_election_ticks: u32,
) void {
    const current_term = self.persistent_state.current_term;
    // every role must learn a newer term, even from a rejected vote.
    if (reply.term > current_term) {
        _ = common.stepDown(self, reply.term, min_election_ticks, max_election_ticks);
        return;
    }
    // only count replies to the election still in progress.
    if (self.role != .candidate) return;
    if (reply.term != current_term) return;

    if (!reply.vote_granted) return;

    const peer_idx = common.peerIndex(self, from) orelse return;
    if (self.votes_granted[peer_idx]) return;

    self.votes_granted[peer_idx] = true;
    self.votes_received += 1;
    const quorum = (self.peers.len + 1) / 2 + 1;
    if (self.votes_received >= quorum) {
        becomeLeader(self);
    }
}

pub fn transferLeadership(self: anytype, min_election_ticks: u32, max_election_ticks: u32) bool {
    if (self.role != .leader) return false;

    const new_term = self.persistent_state.current_term + 1;
    logger.info("raft: leader {d} stepping down, advancing to term {d}", .{ self.id, new_term });

    if (!common.stepDown(self, new_term, min_election_ticks, max_election_ticks)) return false;
    self.actions.append(self.alloc, .{
        .become_follower = .{ .leader_id = 0 },
    }) catch |e| {
        logger.warn("raft: failed to queue become_follower action during transfer: {}", .{e});
        return false;
    };
    return true;
}

pub fn startElection(self: anytype, min_election_ticks: u32, max_election_ticks: u32) void {
    const new_term = self.persistent_state.current_term + 1;
    // persist the term and our own vote before changing role or sending requests.
    if (!self.persistElectionState(new_term, self.id)) return;

    self.role = .candidate;
    @memset(self.votes_granted, false);
    self.votes_received = 1;
    self.ticks_since_event = 0;
    common.resetElectionTimeout(self, min_election_ticks, max_election_ticks);

    if (self.peers.len == 0) {
        becomeLeader(self);
        return;
    }

    sendVoteRequests(self, new_term);
}

fn sendVoteRequests(self: anytype, term: types.Term) void {
    const last_index = self.log.lastIndex();
    const last_term = self.log.lastTerm();
    const args: RequestVoteArgs = .{
        .term = term,
        .candidate_id = self.id,
        .last_log_index = last_index,
        .last_log_term = last_term,
    };
    for (self.peers) |peer| {
        self.actions.append(self.alloc, .{
            .send_request_vote = .{
                .target = peer,
                .args = args,
            },
        }) catch |e| {
            logger.warn("raft: failed to queue vote request: {}", .{e});
        };
    }
}

pub fn becomeLeader(self: anytype) void {
    self.role = .leader;
    self.heartbeat_ticks = 0;

    const last_log_index = self.log.lastIndex();
    for (0..self.peers.len) |peer_index| {
        self.next_index[peer_index] = last_log_index + 1;
        self.match_index[peer_index] = 0;
    }

    self.actions.append(self.alloc, .become_leader) catch |e| {
        logger.warn("raft: failed to queue become_leader action: {}", .{e});
    };

    replication_runtime.sendHeartbeats(self);
}

pub fn resetElectionTimeout(self: anytype, min_election_ticks: u32, max_election_ticks: u32) void {
    common.resetElectionTimeout(self, min_election_ticks, max_election_ticks);
}

const testing = std.testing;
const Raft = @import("../raft.zig").Raft;
const Log = @import("../log.zig").Log;

test "vote eligibility compares snapshot terms before length and permits repeat votes" {
    const Case = struct {
        last_term: types.Term,
        last_index: types.LogIndex,
        voted_for: ?types.NodeId = null,
        granted: bool,
    };
    const cases = [_]Case{
        .{ .last_term = 2, .last_index = 9, .granted = false },
        .{ .last_term = 4, .last_index = 1, .granted = true },
        .{ .last_term = 3, .last_index = 7, .granted = false },
        .{ .last_term = 3, .last_index = 8, .granted = true },
        .{ .last_term = 3, .last_index = 9, .granted = true },
        .{ .last_term = 3, .last_index = 8, .voted_for = 2, .granted = true },
        .{ .last_term = 4, .last_index = 9, .voted_for = 3, .granted = false },
    };
    for (cases) |case| {
        var log = try Log.initMemory();
        defer log.deinit();
        try testing.expect(log.setCurrentTerm(5));
        try testing.expect(log.setVotedFor(case.voted_for));
        try testing.expect(log.setSnapshotMeta(.{
            .last_included_index = 8,
            .last_included_term = 3,
            .data_len = 0,
        }));
        var raft = try Raft.init(testing.allocator, 1, &.{ 2, 3 }, &log);
        defer raft.deinit();
        raft.ticks_since_event = 7;

        const reply = raft.handleRequestVote(.{
            .term = 5,
            .candidate_id = 2,
            .last_log_term = case.last_term,
            .last_log_index = case.last_index,
        });
        try testing.expectEqual(case.granted, reply.vote_granted);
        try testing.expectEqual(@as(types.Term, 5), reply.term);
        try testing.expectEqual(@as(u32, if (case.granted) 0 else 7), raft.ticks_since_event);
        try testing.expectEqual(if (case.granted) @as(?types.NodeId, 2) else case.voted_for, try log.getVotedFor());
    }
}

test "failed vote persistence does not grant a vote or reset the election timer" {
    var log = try Log.initMemory();
    defer log.deinit();
    try testing.expect(log.setCurrentTerm(5));
    var raft = try Raft.init(testing.allocator, 1, &.{ 2, 3 }, &log);
    defer raft.deinit();
    raft.ticks_since_event = 7;
    try log.db.exec("CREATE TRIGGER refuse_vote BEFORE UPDATE OF voted_for ON raft_state BEGIN SELECT RAISE(ABORT, 'vote write failed'); END;", .{}, .{});

    const args: RequestVoteArgs = .{ .term = 5, .candidate_id = 2, .last_log_term = 0, .last_log_index = 0 };
    const failed = raft.handleRequestVote(args);
    try testing.expect(!failed.vote_granted);
    try testing.expectEqual(@as(types.Term, 5), failed.term);
    try testing.expectEqual(@as(?types.NodeId, null), try log.getVotedFor());
    try testing.expectEqual(@as(u32, 7), raft.ticks_since_event);
    try testing.expectEqual(@as(usize, 0), raft.actions.items.len);

    try log.db.exec("DROP TRIGGER refuse_vote;", .{}, .{});
    try testing.expect(raft.handleRequestVote(args).vote_granted);
    try testing.expectEqual(@as(?types.NodeId, 2), try log.getVotedFor());
    try testing.expectEqual(@as(u32, 0), raft.ticks_since_event);
}

test "election persists term and vote together before changing role or sending requests" {
    var log = try Log.initMemory();
    defer log.deinit();
    try testing.expect(log.setCurrentTerm(3));
    try log.append(.{ .index = 1, .term = 3, .data = "command" });
    var raft = try Raft.init(testing.allocator, 1, &.{ 2, 3 }, &log);
    defer raft.deinit();
    raft.ticks_since_event = 7;

    try log.db.exec("CREATE TRIGGER refuse_term BEFORE UPDATE OF current_term ON raft_state BEGIN SELECT RAISE(ABORT, 'term write failed'); END;", .{}, .{});
    startElection(&raft, 10, 10);
    try testing.expectEqual(@as(types.Term, 3), try log.getCurrentTerm());
    try testing.expectEqual(@as(?types.NodeId, null), try log.getVotedFor());
    try testing.expectEqual(types.Role.follower, raft.role);
    try testing.expectEqual(@as(u32, 7), raft.ticks_since_event);
    try testing.expectEqual(@as(usize, 0), raft.actions.items.len);

    try log.db.exec("DROP TRIGGER refuse_term;", .{}, .{});
    try log.db.exec("CREATE TRIGGER refuse_vote BEFORE UPDATE OF voted_for ON raft_state BEGIN SELECT RAISE(ABORT, 'vote write failed'); END;", .{}, .{});
    startElection(&raft, 10, 10);
    // rejecting the vote also leaves the term unchanged.
    try testing.expectEqual(@as(types.Term, 3), try log.getCurrentTerm());
    try testing.expectEqual(@as(?types.NodeId, null), try log.getVotedFor());
    try testing.expectEqual(types.Role.follower, raft.role);
    try testing.expectEqual(@as(u32, 7), raft.ticks_since_event);
    try testing.expectEqual(@as(usize, 0), raft.actions.items.len);

    try log.db.exec("DROP TRIGGER refuse_vote;", .{}, .{});
    startElection(&raft, 10, 10);
    try testing.expectEqual(@as(types.Term, 4), try log.getCurrentTerm());
    try testing.expectEqual(@as(?types.NodeId, 1), try log.getVotedFor());
    try testing.expectEqual(types.Role.candidate, raft.role);
    try testing.expectEqual(@as(u32, 1), raft.votes_received);
    try testing.expectEqual(@as(u32, 0), raft.ticks_since_event);
    try testing.expectEqual(@as(u32, 10), raft.election_timeout);
    try testing.expectEqual(@as(usize, 2), raft.actions.items.len);
    for (raft.actions.items, raft.peers) |action, peer| {
        try testing.expect(action == .send_request_vote);
        try testing.expectEqual(peer, action.send_request_vote.target);
        try testing.expectEqualDeep(RequestVoteArgs{
            .term = 4,
            .candidate_id = 1,
            .last_log_term = 3,
            .last_log_index = 1,
        }, action.send_request_vote.args);
    }
}

test "failed term transition cannot leave a leader in an unelected term" {
    var log = try Log.initMemory();
    defer log.deinit();
    try testing.expect(log.setElectionState(3, 1));
    var raft = try Raft.init(testing.allocator, 1, &.{ 2, 3 }, &log);
    defer raft.deinit();
    raft.role = .leader;
    raft.ticks_since_event = 7;
    try log.db.exec("CREATE TRIGGER refuse_vote BEFORE UPDATE OF voted_for ON raft_state BEGIN SELECT RAISE(ABORT, 'vote write failed'); END;", .{}, .{});

    try testing.expect(!raft.transferLeadership());
    const reply = raft.handleRequestVote(.{ .term = 4, .candidate_id = 2, .last_log_term = 0, .last_log_index = 0 });
    try testing.expect(!reply.vote_granted);
    try testing.expectEqual(@as(types.Term, 3), reply.term);
    raft.handleRequestVoteReply(2, .{ .term = 4, .vote_granted = false });
    try testing.expectEqualDeep(@import("../log.zig").State{ .current_term = 3, .voted_for = 1 }, try log.readState());
    try testing.expectEqualDeep(try log.readState(), raft.persistent_state);
    try testing.expectEqual(types.Role.leader, raft.role);
    try testing.expectEqual(@as(u32, 7), raft.ticks_since_event);
    try testing.expectEqual(@as(usize, 0), raft.actions.items.len);

    try log.db.exec("DROP TRIGGER refuse_vote;", .{}, .{});
    try testing.expect(raft.transferLeadership());
    try testing.expectEqualDeep(@import("../log.zig").State{ .current_term = 4, .voted_for = null }, try log.readState());
    try testing.expectEqualDeep(try log.readState(), raft.persistent_state);
    try testing.expectEqual(types.Role.follower, raft.role);
    try testing.expectEqual(@as(u32, 0), raft.ticks_since_event);
    try testing.expectEqual(@as(usize, 1), raft.actions.items.len);
    try testing.expect(raft.actions.items[0] == .become_follower);
}
