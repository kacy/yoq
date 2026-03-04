// raft — pure state machine implementation of the raft consensus protocol
//
// this module implements the core raft algorithm without any I/O.
// all side effects are expressed as Actions that the caller (node.zig)
// must process. this separation makes the algorithm fully testable
// without networking or disk access.
//
// follows the raft paper closely: leader election, log replication,
// and commit advancement via majority agreement.
//
// usage:
//   var raft = try Raft.init(alloc, 1, &.{2, 3}, &log);
//   defer raft.deinit();
//   raft.tick(); // call periodically (every ~100ms)
//   const reply = raft.handleRequestVote(args);
//   const actions = raft.drainActions();
//   // process actions (send messages, apply committed entries)

const std = @import("std");
const types = @import("raft_types.zig");
const persistent_log = @import("log.zig");

const NodeId = types.NodeId;
const Term = types.Term;
const LogIndex = types.LogIndex;
const Role = types.Role;
const LogEntry = types.LogEntry;
const RequestVoteArgs = types.RequestVoteArgs;
const RequestVoteReply = types.RequestVoteReply;
const AppendEntriesArgs = types.AppendEntriesArgs;
const AppendEntriesReply = types.AppendEntriesReply;

pub const Action = union(enum) {
    send_request_vote: struct { target: NodeId, args: RequestVoteArgs },
    send_append_entries: struct { target: NodeId, args: AppendEntriesArgs },
    send_request_vote_reply: struct { target: NodeId, reply: RequestVoteReply },
    send_append_entries_reply: struct { target: NodeId, reply: AppendEntriesReply },
    commit_entries: struct { up_to: LogIndex },
    become_leader: void,
    become_follower: struct { leader_id: NodeId },
};

// election timeout range in ticks. randomized per election to avoid
// split votes. at 100ms per tick this gives 1.5-3s timeouts.
const min_election_ticks: u32 = 15;
const max_election_ticks: u32 = 30;

// heartbeat interval in ticks (100ms per tick = 1s heartbeat)
const heartbeat_interval: u32 = 10;

pub const Raft = struct {
    alloc: std.mem.Allocator,
    id: NodeId,
    role: Role,
    log: *persistent_log.Log,
    peers: []const NodeId,

    // volatile state (lost on restart)
    commit_index: LogIndex,
    last_applied: LogIndex,

    // leader state (valid when role == .leader)
    next_index: []LogIndex,
    match_index: []LogIndex,

    // election state
    ticks_since_event: u32,
    election_timeout: u32,
    votes_received: u32,
    heartbeat_ticks: u32,

    // output queue
    actions: std.ArrayList(Action),

    // rng for election timeouts
    rng: std.Random.DefaultPrng,

    pub fn init(
        alloc: std.mem.Allocator,
        id: NodeId,
        peers: []const NodeId,
        log: *persistent_log.Log,
    ) !Raft {
        const peer_count = peers.len;
        const next_idx = try alloc.alloc(LogIndex, peer_count);
        const match_idx = try alloc.alloc(LogIndex, peer_count);

        // initialize leader state (will be reset when becoming leader)
        for (0..peer_count) |i| {
            next_idx[i] = 1;
            match_idx[i] = 0;
        }

        // seed rng with node id + timestamp for uniqueness
        const seed = @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())))) ^ id;

        var raft = Raft{
            .alloc = alloc,
            .id = id,
            .role = .follower,
            .log = log,
            .peers = peers,
            .commit_index = 0,
            .last_applied = 0,
            .next_index = next_idx,
            .match_index = match_idx,
            .ticks_since_event = 0,
            .election_timeout = 0,
            .votes_received = 0,
            .heartbeat_ticks = 0,
            .actions = .{},
            .rng = std.Random.DefaultPrng.init(seed),
        };

        raft.resetElectionTimeout();
        return raft;
    }

    pub fn deinit(self: *Raft) void {
        self.alloc.free(self.next_index);
        self.alloc.free(self.match_index);
        self.actions.deinit(self.alloc);
    }

    /// call periodically (every ~100ms). drives election timeouts
    /// and heartbeats.
    pub fn tick(self: *Raft) void {
        self.ticks_since_event += 1;

        switch (self.role) {
            .follower, .candidate => {
                if (self.ticks_since_event >= self.election_timeout) {
                    self.startElection();
                }
            },
            .leader => {
                self.heartbeat_ticks += 1;
                if (self.heartbeat_ticks >= heartbeat_interval) {
                    self.sendHeartbeats();
                    self.heartbeat_ticks = 0;
                }
            },
        }
    }

    // -- RPC handlers --

    pub fn handleRequestVote(self: *Raft, args: RequestVoteArgs) RequestVoteReply {
        const current_term = self.log.getCurrentTerm();

        // reject if candidate's term is behind ours
        if (args.term < current_term) {
            return .{ .term = current_term, .vote_granted = false };
        }

        // step down if we see a higher term
        if (args.term > current_term) {
            self.stepDown(args.term);
        }

        const voted_for = self.log.getVotedFor();
        const can_vote = voted_for == null or voted_for.? == args.candidate_id;

        // only grant vote if candidate's log is at least as up-to-date
        const our_last_term = self.log.lastTerm();
        const our_last_index = self.log.lastIndex();
        const log_ok = (args.last_log_term > our_last_term) or
            (args.last_log_term == our_last_term and args.last_log_index >= our_last_index);

        if (can_vote and log_ok) {
            self.log.setVotedFor(args.candidate_id);
            self.ticks_since_event = 0;
            return .{ .term = self.log.getCurrentTerm(), .vote_granted = true };
        }

        return .{ .term = self.log.getCurrentTerm(), .vote_granted = false };
    }

    pub fn handleAppendEntries(self: *Raft, args: AppendEntriesArgs) AppendEntriesReply {
        const current_term = self.log.getCurrentTerm();

        // reject if leader's term is behind ours
        if (args.term < current_term) {
            return .{ .term = current_term, .success = false, .match_index = 0 };
        }

        // step down if we see a higher or equal term from a leader
        if (args.term >= current_term) {
            if (args.term > current_term) {
                self.stepDown(args.term);
            } else if (self.role == .candidate) {
                // another node won the election in our term
                self.role = .follower;
                self.actions.append(self.alloc, .{ .become_follower = .{ .leader_id = args.leader_id } }) catch {};
            }
            self.ticks_since_event = 0;
        }

        // consistency check: verify we have the entry at prev_log_index
        // with the matching term
        if (args.prev_log_index > 0) {
            const prev_term = self.log.termAt(args.prev_log_index);
            if (prev_term == 0 or prev_term != args.prev_log_term) {
                return .{
                    .term = self.log.getCurrentTerm(),
                    .success = false,
                    .match_index = 0,
                };
            }
        }

        // append entries, handling conflicts
        for (args.entries) |entry| {
            const existing_term = self.log.termAt(entry.index);
            if (existing_term != 0 and existing_term != entry.term) {
                // conflict: delete this entry and everything after
                self.log.truncateFrom(entry.index);
            }
            if (existing_term == 0 or existing_term != entry.term) {
                self.log.append(entry) catch {
                    return .{
                        .term = self.log.getCurrentTerm(),
                        .success = false,
                        .match_index = 0,
                    };
                };
            }
        }

        // advance commit index
        if (args.leader_commit > self.commit_index) {
            const last = self.log.lastIndex();
            const new_commit = @min(args.leader_commit, last);
            if (new_commit > self.commit_index) {
                self.commit_index = new_commit;
                self.actions.append(self.alloc, .{
                    .commit_entries = .{ .up_to = new_commit },
                }) catch {};
            }
        }

        return .{
            .term = self.log.getCurrentTerm(),
            .success = true,
            .match_index = self.log.lastIndex(),
        };
    }

    pub fn handleRequestVoteReply(self: *Raft, from: NodeId, reply: RequestVoteReply) void {
        _ = from;
        if (self.role != .candidate) return;

        if (reply.term > self.log.getCurrentTerm()) {
            self.stepDown(reply.term);
            return;
        }

        if (reply.vote_granted) {
            self.votes_received += 1;
            const quorum = (self.peers.len + 1) / 2 + 1;
            if (self.votes_received >= quorum) {
                self.becomeLeader();
            }
        }
    }

    pub fn handleAppendEntriesReply(self: *Raft, from: NodeId, reply: AppendEntriesReply) void {
        if (self.role != .leader) return;

        if (reply.term > self.log.getCurrentTerm()) {
            self.stepDown(reply.term);
            return;
        }

        const peer_idx = self.peerIndex(from) orelse return;

        if (reply.success) {
            self.match_index[peer_idx] = reply.match_index;
            self.next_index[peer_idx] = reply.match_index + 1;
            self.advanceCommitIndex();
        } else {
            // decrement next_index and retry
            if (self.next_index[peer_idx] > 1) {
                self.next_index[peer_idx] -= 1;
            }
            self.sendAppendEntries(peer_idx);
        }
    }

    /// submit a new command through the leader.
    /// returns the log index where the entry will be placed.
    pub fn propose(self: *Raft, data: []const u8) !LogIndex {
        if (self.role != .leader) return error.NotLeader;

        const index = self.log.lastIndex() + 1;
        const term = self.log.getCurrentTerm();

        try self.log.append(.{
            .index = index,
            .term = term,
            .data = data,
        });

        // replicate to all peers
        for (0..self.peers.len) |i| {
            self.sendAppendEntries(i);
        }

        return index;
    }

    /// return all pending actions and clear the queue.
    pub fn drainActions(self: *Raft) []Action {
        const items = self.actions.toOwnedSlice(self.alloc) catch &.{};
        return items;
    }

    // -- internal --

    fn startElection(self: *Raft) void {
        const new_term = self.log.getCurrentTerm() + 1;
        self.log.setCurrentTerm(new_term);
        self.log.setVotedFor(self.id);
        self.role = .candidate;
        self.votes_received = 1; // vote for self
        self.ticks_since_event = 0;
        self.resetElectionTimeout();

        // single-node cluster: become leader immediately
        if (self.peers.len == 0) {
            self.becomeLeader();
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
            }) catch {};
        }
    }

    fn becomeLeader(self: *Raft) void {
        self.role = .leader;
        self.heartbeat_ticks = 0;

        // reinitialize leader state
        const last = self.log.lastIndex();
        for (0..self.peers.len) |i| {
            self.next_index[i] = last + 1;
            self.match_index[i] = 0;
        }

        self.actions.append(self.alloc, .become_leader) catch {};

        // send initial empty append entries (heartbeat) to assert leadership
        self.sendHeartbeats();
    }

    fn stepDown(self: *Raft, new_term: Term) void {
        self.log.setCurrentTerm(new_term);
        self.log.setVotedFor(null);
        self.role = .follower;
        self.ticks_since_event = 0;
        self.resetElectionTimeout();
    }

    fn sendHeartbeats(self: *Raft) void {
        for (0..self.peers.len) |i| {
            self.sendAppendEntries(i);
        }
    }

    fn sendAppendEntries(self: *Raft, peer_idx: usize) void {
        const next = self.next_index[peer_idx];
        const prev_index = if (next > 0) next - 1 else 0;
        const prev_term = self.log.termAt(prev_index);
        const last = self.log.lastIndex();

        // gather entries to send (from next_index to end of log)
        var entries_buf: [64]LogEntry = undefined;
        var count: usize = 0;
        if (next <= last) {
            var idx = next;
            while (idx <= last and count < entries_buf.len) : (idx += 1) {
                const alloc = self.alloc;
                if (self.log.getEntry(alloc, idx) catch null) |entry| {
                    entries_buf[count] = entry;
                    count += 1;
                }
            }
        }

        self.actions.append(self.alloc, .{
            .send_append_entries = .{
                .target = self.peers[peer_idx],
                .args = .{
                    .term = self.log.getCurrentTerm(),
                    .leader_id = self.id,
                    .prev_log_index = prev_index,
                    .prev_log_term = prev_term,
                    .entries = if (count > 0) self.alloc.dupe(LogEntry, entries_buf[0..count]) catch &.{} else &.{},
                    .leader_commit = self.commit_index,
                },
            },
        }) catch {};
    }

    fn advanceCommitIndex(self: *Raft) void {
        // find the highest N such that a majority of match_index[i] >= N
        // and log[N].term == currentTerm
        const current_term = self.log.getCurrentTerm();
        const last = self.log.lastIndex();

        var n = last;
        while (n > self.commit_index) : (n -= 1) {
            if (self.log.termAt(n) != current_term) continue;

            // count peers with match_index >= n (including self)
            var count: usize = 1; // self
            for (self.match_index) |mi| {
                if (mi >= n) count += 1;
            }

            const quorum = (self.peers.len + 1) / 2 + 1;
            if (count >= quorum) {
                self.commit_index = n;
                self.actions.append(self.alloc, .{
                    .commit_entries = .{ .up_to = n },
                }) catch {};
                break;
            }
        }
    }

    fn peerIndex(self: *Raft, id: NodeId) ?usize {
        for (self.peers, 0..) |peer, i| {
            if (peer == id) return i;
        }
        return null;
    }

    fn resetElectionTimeout(self: *Raft) void {
        const range = max_election_ticks - min_election_ticks;
        self.election_timeout = min_election_ticks + self.rng.random().intRangeAtMost(u32, 0, range);
    }

    /// get current term (convenience for external callers)
    pub fn currentTerm(self: *Raft) Term {
        return self.log.getCurrentTerm();
    }
};

// -- tests --

const testing = std.testing;
const Log = persistent_log.Log;

fn setupTestRaft(alloc: std.mem.Allocator, id: NodeId, peers: []const NodeId, log: *Log) !Raft {
    return Raft.init(alloc, id, peers, log);
}

test "single node becomes leader after election timeout" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{};
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    try testing.expectEqual(Role.follower, raft.role);

    // tick past election timeout
    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }

    try testing.expectEqual(Role.leader, raft.role);

    const actions = raft.drainActions();
    defer alloc.free(actions);

    // should have a become_leader action
    var found_leader = false;
    for (actions) |action| {
        if (action == .become_leader) found_leader = true;
    }
    try testing.expect(found_leader);
}

test "candidate becomes leader with majority vote" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // trigger election
    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    try testing.expectEqual(Role.candidate, raft.role);

    // drain the request vote actions
    const election_actions = raft.drainActions();
    defer alloc.free(election_actions);

    // one vote from peer 2 is enough for majority (2/3)
    raft.handleRequestVoteReply(2, .{
        .term = raft.currentTerm(),
        .vote_granted = true,
    });

    try testing.expectEqual(Role.leader, raft.role);

    const leader_actions = raft.drainActions();
    defer {
        for (leader_actions) |action| {
            if (action == .send_append_entries) {
                if (action.send_append_entries.args.entries.len > 0) {
                    alloc.free(action.send_append_entries.args.entries);
                }
            }
        }
        alloc.free(leader_actions);
    }
}

test "reject vote if candidate log is behind" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    // add an entry to our log
    try log.append(.{ .index = 1, .term = 2, .data = "cmd" });

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // candidate with older log asks for vote
    const reply = raft.handleRequestVote(.{
        .term = 3,
        .candidate_id = 2,
        .last_log_index = 0,
        .last_log_term = 0,
    });

    try testing.expect(!reply.vote_granted);
}

test "grant vote if candidate log is up to date" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    try log.append(.{ .index = 1, .term = 1, .data = "cmd" });

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    const reply = raft.handleRequestVote(.{
        .term = 2,
        .candidate_id = 2,
        .last_log_index = 1,
        .last_log_term = 1,
    });

    try testing.expect(reply.vote_granted);
}

test "step down on higher term" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // become candidate
    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    try testing.expectEqual(Role.candidate, raft.role);

    const actions = raft.drainActions();
    defer alloc.free(actions);

    // receive append entries from a leader with higher term
    const reply = raft.handleAppendEntries(.{
        .term = raft.currentTerm() + 1,
        .leader_id = 2,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &.{},
        .leader_commit = 0,
    });

    try testing.expect(reply.success);
    try testing.expectEqual(Role.follower, raft.role);

    const step_actions = raft.drainActions();
    defer alloc.free(step_actions);
}

test "log replication: leader sends entries, follower appends" {
    const alloc = testing.allocator;

    // set up leader
    var leader_log = try Log.initMemory();
    defer leader_log.deinit();
    const leader_peers: []const NodeId = &.{ 2, 3 };
    var leader = try setupTestRaft(alloc, 1, leader_peers, &leader_log);
    defer leader.deinit();

    // force leader
    for (0..max_election_ticks + 1) |_| {
        leader.tick();
    }
    var a1 = leader.drainActions();
    defer alloc.free(a1);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });

    // drain leader actions (become_leader + heartbeats)
    const la = leader.drainActions();
    defer {
        for (la) |action| {
            if (action == .send_append_entries) {
                if (action.send_append_entries.args.entries.len > 0)
                    alloc.free(action.send_append_entries.args.entries);
            }
        }
        alloc.free(la);
    }

    // propose a command
    _ = try leader.propose("SET x 42");

    // get the append entries that were sent
    const propose_actions = leader.drainActions();
    defer {
        for (propose_actions) |action| {
            if (action == .send_append_entries) {
                const entries = action.send_append_entries.args.entries;
                for (entries) |e| alloc.free(e.data);
                if (entries.len > 0) alloc.free(entries);
            }
        }
        alloc.free(propose_actions);
    }

    // set up follower
    var follower_log = try Log.initMemory();
    defer follower_log.deinit();
    const follower_peers: []const NodeId = &.{ 1, 3 };
    var follower = try setupTestRaft(alloc, 2, follower_peers, &follower_log);
    defer follower.deinit();

    // simulate sending the append entries to follower
    const reply = follower.handleAppendEntries(.{
        .term = leader.currentTerm(),
        .leader_id = 1,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &.{.{ .index = 1, .term = leader.currentTerm(), .data = "SET x 42" }},
        .leader_commit = 0,
    });

    try testing.expect(reply.success);
    try testing.expectEqual(@as(LogIndex, 1), reply.match_index);
    try testing.expectEqual(@as(LogIndex, 1), follower_log.lastIndex());

    const fa = follower.drainActions();
    defer alloc.free(fa);
}

test "commit advancement when majority matches" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var leader = try setupTestRaft(alloc, 1, peers, &log);
    defer leader.deinit();

    // force leader
    for (0..max_election_ticks + 1) |_| {
        leader.tick();
    }
    var ea = leader.drainActions();
    defer alloc.free(ea);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
    var la = leader.drainActions();
    defer {
        for (la) |action| {
            if (action == .send_append_entries) {
                if (action.send_append_entries.args.entries.len > 0)
                    alloc.free(action.send_append_entries.args.entries);
            }
        }
        alloc.free(la);
    }

    // propose and replicate
    const idx = try leader.propose("cmd1");
    try testing.expectEqual(@as(LogIndex, 1), idx);

    var pa = leader.drainActions();
    defer {
        for (pa) |action| {
            if (action == .send_append_entries) {
                const entries = action.send_append_entries.args.entries;
                for (entries) |e| alloc.free(e.data);
                if (entries.len > 0) alloc.free(entries);
            }
        }
        alloc.free(pa);
    }

    try testing.expectEqual(@as(LogIndex, 0), leader.commit_index);

    // peer 2 acknowledges
    leader.handleAppendEntriesReply(2, .{
        .term = leader.currentTerm(),
        .success = true,
        .match_index = 1,
    });

    // with self + peer 2 = 2 out of 3, commit should advance
    try testing.expectEqual(@as(LogIndex, 1), leader.commit_index);

    const commit_actions = leader.drainActions();
    defer alloc.free(commit_actions);

    var found_commit = false;
    for (commit_actions) |action| {
        if (action == .commit_entries) {
            try testing.expectEqual(@as(LogIndex, 1), action.commit_entries.up_to);
            found_commit = true;
        }
    }
    try testing.expect(found_commit);
}

test "election timeout triggers new election with higher term" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // first election
    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    const term1 = raft.currentTerm();
    try testing.expectEqual(Role.candidate, raft.role);
    var a1 = raft.drainActions();
    defer alloc.free(a1);

    // no votes received, timeout again -> new election with higher term
    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    const term2 = raft.currentTerm();
    try testing.expect(term2 > term1);
    try testing.expectEqual(Role.candidate, raft.role);

    var a2 = raft.drainActions();
    defer alloc.free(a2);
}

test "log conflict: follower truncates on mismatch" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    // follower has entry at index 1 with term 1
    try log.append(.{ .index = 1, .term = 1, .data = "old" });

    const peers: []const NodeId = &.{ 1, 3 };
    var follower = try setupTestRaft(alloc, 2, peers, &log);
    defer follower.deinit();

    // leader sends entry at index 1 with term 2 (conflict!)
    const reply = follower.handleAppendEntries(.{
        .term = 2,
        .leader_id = 1,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &.{.{ .index = 1, .term = 2, .data = "new" }},
        .leader_commit = 0,
    });

    try testing.expect(reply.success);

    // verify the old entry was replaced
    const entry = (try log.getEntry(alloc, 1)).?;
    defer alloc.free(entry.data);
    try testing.expectEqual(@as(Term, 2), entry.term);
    try testing.expectEqualStrings("new", entry.data);

    var a = follower.drainActions();
    defer alloc.free(a);
}

test "propose fails when not leader" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    const result = raft.propose("cmd");
    try testing.expectError(error.NotLeader, result);
}
