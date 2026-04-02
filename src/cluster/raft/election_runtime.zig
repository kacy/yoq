const std = @import("std");
const logger = @import("../../lib/log.zig");
const common = @import("common.zig");
const replication_runtime = @import("replication_runtime.zig");
const types = @import("../raft_types.zig");

const RequestVoteArgs = types.RequestVoteArgs;
const RequestVoteReply = types.RequestVoteReply;
const Term = types.Term;

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
    const current_term = self.log.getCurrentTerm();
    if (args.term < current_term) {
        return .{ .term = current_term, .vote_granted = false };
    }

    if (args.term > current_term) {
        if (!common.stepDown(self, args.term, min_election_ticks, max_election_ticks)) {
            return .{ .term = current_term, .vote_granted = false };
        }
    }

    const voted_for = self.log.getVotedFor();
    const can_vote = voted_for == null or voted_for.? == args.candidate_id;

    const our_last_term = self.log.lastTerm();
    const our_last_index = self.log.lastIndex();
    const log_ok = (args.last_log_term > our_last_term) or
        (args.last_log_term == our_last_term and args.last_log_index >= our_last_index);

    if (can_vote and log_ok) {
        if (!self.log.setVotedFor(args.candidate_id)) {
            return .{ .term = self.log.getCurrentTerm(), .vote_granted = false };
        }
        self.ticks_since_event = 0;
        return .{ .term = self.log.getCurrentTerm(), .vote_granted = true };
    }

    return .{ .term = self.log.getCurrentTerm(), .vote_granted = false };
}

pub fn handleRequestVoteReply(
    self: anytype,
    from: anytype,
    reply: RequestVoteReply,
    min_election_ticks: u32,
    max_election_ticks: u32,
) void {
    if (self.role != .candidate) return;

    if (reply.term > self.log.getCurrentTerm()) {
        _ = common.stepDown(self, reply.term, min_election_ticks, max_election_ticks);
        return;
    }

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

    const new_term = self.log.getCurrentTerm() + 1;
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
    const new_term = self.log.getCurrentTerm() + 1;
    if (!self.log.setCurrentTerm(new_term)) return;
    if (!self.log.setVotedFor(self.id)) return;
    self.role = .candidate;
    @memset(self.votes_granted, false);
    self.votes_received = 1;
    self.ticks_since_event = 0;
    common.resetElectionTimeout(self, min_election_ticks, max_election_ticks);

    if (self.peers.len == 0) {
        becomeLeader(self);
        return;
    }

    const last_index = self.log.lastIndex();
    const last_term = self.log.lastTerm();
    for (self.peers) |peer| {
        self.actions.append(self.alloc, .{
            .send_request_vote = .{
                .target = peer,
                .args = .{
                    .term = new_term,
                    .candidate_id = self.id,
                    .last_log_index = last_index,
                    .last_log_term = last_term,
                },
            },
        }) catch |e| {
            logger.warn("raft: failed to queue vote request: {}", .{e});
        };
    }
}

pub fn becomeLeader(self: anytype) void {
    self.role = .leader;
    self.heartbeat_ticks = 0;

    const last = self.log.lastIndex();
    for (0..self.peers.len) |i| {
        self.next_index[i] = last + 1;
        self.match_index[i] = 0;
    }

    self.actions.append(self.alloc, .become_leader) catch |e| {
        logger.warn("raft: failed to queue become_leader action: {}", .{e});
    };

    replication_runtime.sendHeartbeats(self);
}

pub fn resetElectionTimeout(self: anytype, min_election_ticks: u32, max_election_ticks: u32) void {
    common.resetElectionTimeout(self, min_election_ticks, max_election_ticks);
}
