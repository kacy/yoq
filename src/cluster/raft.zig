// raft — pure state machine implementation of the raft consensus protocol
//
// this module implements the core raft algorithm without any I/O.
// all side effects are expressed as Actions that the caller (node.zig)
// must process. this separation makes the algorithm fully testable
// without networking or disk access.
//
// follows the raft paper closely: leader election, log replication,
// commit advancement via majority agreement, and InstallSnapshot RPC
// for bringing far-behind followers up to date.
//
// usage:
//   var raft = try Raft.init(alloc, 1, &.{2, 3}, &log);
//   defer raft.deinit();
//   raft.tick(); // call periodically (every ~100ms)
//   const reply = raft.handleRequestVote(args);
//   const actions = raft.drainActions();
//   // process actions (send messages, apply committed entries)

const std = @import("std");
const action_queue = @import("action_queue.zig");
const common = @import("raft/common.zig");
const election_runtime = @import("raft/election_runtime.zig");
const test_support = @import("raft/test_support.zig");
const types = @import("raft_types.zig");
const replication_runtime = @import("raft/replication_runtime.zig");
const persistent_log = @import("log.zig");
const logger = @import("../lib/log.zig");
const snapshot_runtime = @import("raft/snapshot_runtime.zig");

const NodeId = types.NodeId;
const Term = types.Term;
const LogIndex = types.LogIndex;
const Role = types.Role;
const LogEntry = types.LogEntry;
const SnapshotMeta = types.SnapshotMeta;
const RequestVoteArgs = types.RequestVoteArgs;
const RequestVoteReply = types.RequestVoteReply;
const AppendEntriesArgs = types.AppendEntriesArgs;
const AppendEntriesReply = types.AppendEntriesReply;
const InstallSnapshotArgs = types.InstallSnapshotArgs;
const InstallSnapshotReply = types.InstallSnapshotReply;

pub const Action = union(enum) {
    send_request_vote: struct { target: NodeId, args: RequestVoteArgs },
    send_append_entries: struct { target: NodeId, args: AppendEntriesArgs },
    send_request_vote_reply: struct { target: NodeId, reply: RequestVoteReply },
    send_append_entries_reply: struct { target: NodeId, reply: AppendEntriesReply },
    commit_entries: struct { up_to: LogIndex },
    become_leader: void,
    become_follower: struct { leader_id: NodeId },

    // snapshot actions — the caller (node.zig) handles actual I/O
    send_install_snapshot: struct { target: NodeId, args: InstallSnapshotArgs },
    send_install_snapshot_reply: struct { target: NodeId, reply: InstallSnapshotReply },
    apply_snapshot: struct { data: []u8, meta: SnapshotMeta },
    take_snapshot: struct { up_to_index: LogIndex, term: Term },
};

// election timeout range in ticks. randomized per election to avoid
// split votes. at 100ms per tick this gives 3-6s timeouts.
const min_election_ticks: u32 = 30;
const max_election_ticks: u32 = 60;

// heartbeat interval in ticks (100ms per tick = 600ms heartbeat)
const heartbeat_interval: u32 = 6;

pub const Raft = struct {
    alloc: std.mem.Allocator,
    id: NodeId,
    role: Role,
    log: *persistent_log.Log,
    peers: []const NodeId,

    // volatile state. on restart we recover the snapshot boundary,
    // because any installed snapshot is already durably committed/applied.
    commit_index: LogIndex,
    last_applied: LogIndex,

    // leader state (valid when role == .leader)
    next_index: []LogIndex,
    match_index: []LogIndex,

    // election state
    votes_granted: []bool,
    ticks_since_event: u32,
    election_timeout: u32,
    votes_received: u32,
    heartbeat_ticks: u32,

    // snapshot state — tracks the most recent snapshot so the leader
    // knows when to send InstallSnapshot instead of AppendEntries
    snapshot_meta: ?SnapshotMeta,

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
        const owned_peers = try alloc.dupe(NodeId, peers);
        errdefer alloc.free(owned_peers);
        const next_idx = try alloc.alloc(LogIndex, peer_count);
        errdefer alloc.free(next_idx);
        const match_idx = try alloc.alloc(LogIndex, peer_count);
        errdefer alloc.free(match_idx);
        const votes_granted = try alloc.alloc(bool, peer_count);
        errdefer alloc.free(votes_granted);

        // initialize leader state (will be reset when becoming leader)
        for (0..peer_count) |i| {
            next_idx[i] = 1;
            match_idx[i] = 0;
            votes_granted[i] = false;
        }

        // seed rng with node id + timestamp for uniqueness
        const seed = @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())))) ^ id;

        // load snapshot metadata from persistent storage
        const snap_meta = log.getSnapshotMeta();

        const recovered_index: LogIndex = if (snap_meta) |meta|
            meta.last_included_index
        else
            0;

        var raft = Raft{
            .alloc = alloc,
            .id = id,
            .role = .follower,
            .log = log,
            .peers = owned_peers,
            .commit_index = recovered_index,
            .last_applied = recovered_index,
            .next_index = next_idx,
            .match_index = match_idx,
            .votes_granted = votes_granted,
            .ticks_since_event = 0,
            .election_timeout = 0,
            .votes_received = 0,
            .heartbeat_ticks = 0,
            .snapshot_meta = snap_meta,
            .actions = .{},
            .rng = std.Random.DefaultPrng.init(seed),
        };

        raft.resetElectionTimeout();
        return raft;
    }

    pub fn deinit(self: *Raft) void {
        self.alloc.free(self.next_index);
        self.alloc.free(self.match_index);
        self.alloc.free(self.votes_granted);
        self.alloc.free(self.peers);
        self.actions.deinit(self.alloc);
    }

    /// call periodically (every ~100ms). drives election timeouts
    /// and heartbeats.
    pub fn tick(self: *Raft) void {
        election_runtime.tick(self, heartbeat_interval, min_election_ticks, max_election_ticks);
    }

    // -- RPC handlers --

    pub fn handleRequestVote(self: *Raft, args: RequestVoteArgs) RequestVoteReply {
        return election_runtime.handleRequestVote(self, args, min_election_ticks, max_election_ticks);
    }

    pub fn handleAppendEntries(self: *Raft, args: AppendEntriesArgs) AppendEntriesReply {
        return replication_runtime.handleAppendEntries(self, args, min_election_ticks, max_election_ticks);
    }

    /// validate an InstallSnapshot RPC from the leader and update only
    /// term/role state needed to accept it. the caller must restore the
    /// snapshot bytes synchronously and then call finishInstallSnapshot()
    /// before acknowledging success back to the leader.
    pub fn handleInstallSnapshot(self: *Raft, args: InstallSnapshotArgs) InstallSnapshotReply {
        return snapshot_runtime.handleInstallSnapshot(self, args, min_election_ticks, max_election_ticks);
    }

    pub fn finishInstallSnapshot(self: *Raft, meta: SnapshotMeta) bool {
        return snapshot_runtime.finishInstallSnapshot(self, meta);
    }

    pub fn handleRequestVoteReply(self: *Raft, from: NodeId, reply: RequestVoteReply) void {
        election_runtime.handleRequestVoteReply(self, from, reply, min_election_ticks, max_election_ticks);
    }

    pub fn handleAppendEntriesReply(self: *Raft, from: NodeId, reply: AppendEntriesReply) void {
        replication_runtime.handleAppendEntriesReply(self, from, reply, min_election_ticks, max_election_ticks);
    }

    /// handle a reply to our InstallSnapshot RPC.
    /// if the follower's term is higher, step down. otherwise,
    /// update next_index and match_index for that peer.
    pub fn handleInstallSnapshotReply(self: *Raft, from: NodeId, reply: InstallSnapshotReply) void {
        snapshot_runtime.handleInstallSnapshotReply(self, from, reply, min_election_ticks, max_election_ticks);
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
    /// caller owns the returned slice and must free it with self.alloc.free(actions)
    pub fn drainActions(self: *Raft) []Action {
        return action_queue.drainOwned(Action, self.alloc, &self.actions);
    }

    /// called by the node after a successful snapshot. updates the
    /// in-memory snapshot metadata so the leader knows it can send
    /// snapshots to lagging followers.
    pub fn onSnapshotComplete(self: *Raft, meta: SnapshotMeta) bool {
        return snapshot_runtime.onSnapshotComplete(self, meta);
    }

    /// graceful leader step-down for rolling upgrades.
    ///
    /// the leader voluntarily relinquishes leadership by:
    /// 1. incrementing its term (forces a new election)
    /// 2. transitioning to follower role
    /// 3. clearing its vote (allows it to vote in the next election)
    ///
    /// this avoids the election timeout delay that would occur if the
    /// leader were simply killed. the remaining nodes will start a new
    /// election immediately when they receive the higher term.
    ///
    /// returns true if the node was leader and stepped down,
    /// false if the node was not leader.
    pub fn transferLeadership(self: *Raft) bool {
        return election_runtime.transferLeadership(self, min_election_ticks, max_election_ticks);
    }

    /// returns the protocol version for version negotiation during
    /// rolling upgrades. nodes can check peer versions before
    /// proceeding with an upgrade.
    pub fn protocolVersion() u32 {
        return 1;
    }

    // -- internal --

    fn startElection(self: *Raft) void {
        election_runtime.startElection(self, min_election_ticks, max_election_ticks);
    }

    fn becomeLeader(self: *Raft) void {
        election_runtime.becomeLeader(self);
    }

    fn stepDown(self: *Raft, new_term: Term) bool {
        return common.stepDown(self, new_term, min_election_ticks, max_election_ticks);
    }

    fn sendHeartbeats(self: *Raft) void {
        replication_runtime.sendHeartbeats(self);
    }

    fn sendAppendEntries(self: *Raft, peer_idx: usize) void {
        replication_runtime.sendAppendEntries(self, peer_idx);
    }

    /// queue an InstallSnapshot action for a lagging peer.
    /// the actual snapshot data loading happens in node.zig when
    /// it processes this action — the raft module stays I/O-free.
    fn sendInstallSnapshot(self: *Raft, peer_idx: usize, meta: SnapshotMeta) void {
        snapshot_runtime.sendInstallSnapshot(self, peer_idx, meta);
    }

    fn advanceCommitIndex(self: *Raft) void {
        replication_runtime.advanceCommitIndex(self);
    }

    fn peerIndex(self: *Raft, id: NodeId) ?usize {
        return common.peerIndex(self, id);
    }

    fn resetElectionTimeout(self: *Raft) void {
        common.resetElectionTimeout(self, min_election_ticks, max_election_ticks);
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
    defer test_support.deinitOwnedActions(Action, alloc, leader_actions);
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
    const a1 = leader.drainActions();
    defer alloc.free(a1);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });

    // drain leader actions (become_leader + heartbeats)
    const la = leader.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, la);

    // propose a command
    _ = try leader.propose("SET x 42");

    // get the append entries that were sent
    const propose_actions = leader.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, propose_actions);

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
    const ea = leader.drainActions();
    defer alloc.free(ea);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
    const la = leader.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, la);

    // propose and replicate
    const idx = try leader.propose("cmd1");
    try testing.expectEqual(@as(LogIndex, 1), idx);

    const pa = leader.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, pa);

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
    const a1 = raft.drainActions();
    defer alloc.free(a1);

    // no votes received, timeout again -> new election with higher term
    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    const term2 = raft.currentTerm();
    try testing.expect(term2 > term1);
    try testing.expectEqual(Role.candidate, raft.role);

    const a2 = raft.drainActions();
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

    const actions = follower.drainActions();
    defer alloc.free(actions);
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

// -- snapshot tests --

test "handleInstallSnapshot defers state update until snapshot is finished" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 1, 3 };
    var follower = try setupTestRaft(alloc, 2, peers, &log);
    defer follower.deinit();

    var snap_data = "snapshot data".*;
    const reply = follower.handleInstallSnapshot(.{
        .term = 3,
        .leader_id = 1,
        .last_included_index = 100,
        .last_included_term = 2,
        .data = &snap_data,
    });

    // should accept (term >= ours)
    try testing.expectEqual(@as(Term, 3), reply.term);

    try testing.expectEqual(@as(LogIndex, 0), follower.commit_index);
    try testing.expectEqual(@as(LogIndex, 0), follower.last_applied);

    const actions = follower.drainActions();
    defer alloc.free(actions);
    try testing.expectEqual(@as(usize, 0), actions.len);

    try testing.expect(follower.finishInstallSnapshot(.{
        .last_included_index = 100,
        .last_included_term = 2,
        .data_len = snap_data.len,
    }));
    try testing.expectEqual(@as(LogIndex, 100), follower.commit_index);
    try testing.expectEqual(@as(LogIndex, 100), follower.last_applied);
}

test "init reloads snapshot boundary into commit_index and last_applied" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    _ = log.setSnapshotMeta(.{
        .last_included_index = 42,
        .last_included_term = 7,
        .data_len = 0,
    });

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    try testing.expect(raft.snapshot_meta != null);
    try testing.expectEqual(@as(LogIndex, 42), raft.commit_index);
    try testing.expectEqual(@as(LogIndex, 42), raft.last_applied);
    try testing.expectEqual(@as(LogIndex, 42), raft.snapshot_meta.?.last_included_index);
}

test "handleInstallSnapshot rejects stale term" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    // set our term higher
    _ = log.setCurrentTerm(5);

    const peers: []const NodeId = &.{ 1, 3 };
    var follower = try setupTestRaft(alloc, 2, peers, &log);
    defer follower.deinit();

    var snap_data2 = "snapshot data".*;
    const reply = follower.handleInstallSnapshot(.{
        .term = 3, // behind our term of 5
        .leader_id = 1,
        .last_included_index = 100,
        .last_included_term = 2,
        .data = &snap_data2,
    });

    try testing.expectEqual(@as(Term, 5), reply.term);

    // should NOT have updated commit_index
    try testing.expectEqual(@as(LogIndex, 0), follower.commit_index);

    const actions = follower.drainActions();
    defer alloc.free(actions);
    // no apply_snapshot action
    for (actions) |action| {
        try testing.expect(action != .apply_snapshot);
    }
}

test "handleInstallSnapshot ignores old snapshot" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 1, 3 };
    var follower = try setupTestRaft(alloc, 2, peers, &log);
    defer follower.deinit();

    // pretend we already committed up to 100
    follower.commit_index = 100;

    var snap_data3 = "old snapshot".*;
    const reply = follower.handleInstallSnapshot(.{
        .term = 3,
        .leader_id = 1,
        .last_included_index = 50, // behind our commit_index
        .last_included_term = 2,
        .data = &snap_data3,
    });

    // should accept the RPC (no term issue) but not apply it
    try testing.expectEqual(@as(Term, 3), reply.term);
    try testing.expectEqual(@as(LogIndex, 100), follower.commit_index); // unchanged

    const actions = follower.drainActions();
    defer alloc.free(actions);
    for (actions) |action| {
        try testing.expect(action != .apply_snapshot);
    }
}

test "leader sends install_snapshot when entries are truncated" {
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
    const ea = leader.drainActions();
    defer alloc.free(ea);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
    const la = leader.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, la);

    // simulate: leader has a snapshot at index 50, log truncated
    leader.snapshot_meta = .{
        .last_included_index = 50,
        .last_included_term = 3,
        .data_len = 1024,
    };
    _ = log.setSnapshotMeta(.{
        .last_included_index = 50,
        .last_included_term = 3,
        .data_len = 1024,
    });

    // peer 2's next_index is 2 (one entry behind, but entry 1 is before snapshot).
    // since prev_index would be 1, and entry 1 has been truncated (term=0),
    // the leader should send a snapshot instead of append entries.
    leader.next_index[0] = 2; // peer 2 is at index 0 in peers array

    // trigger a heartbeat
    leader.heartbeat_ticks = heartbeat_interval;
    leader.tick();

    const actions = leader.drainActions();
    defer alloc.free(actions);

    // should have a send_install_snapshot for peer 2
    var found_snapshot = false;
    for (actions) |action| {
        if (action == .send_install_snapshot) {
            try testing.expectEqual(@as(NodeId, 2), action.send_install_snapshot.target);
            try testing.expectEqual(@as(LogIndex, 50), action.send_install_snapshot.args.last_included_index);
            found_snapshot = true;
        }
    }
    try testing.expect(found_snapshot);
}

test "handleInstallSnapshotReply updates peer tracking" {
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
    const ea = leader.drainActions();
    defer alloc.free(ea);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
    const la = leader.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, la);

    leader.snapshot_meta = .{
        .last_included_index = 50,
        .last_included_term = 3,
        .data_len = 1024,
    };

    // peer 2 accepted our snapshot
    leader.handleInstallSnapshotReply(2, .{
        .term = leader.currentTerm(),
    });

    // next_index for peer 2 should be 51 (snapshot index + 1)
    try testing.expectEqual(@as(LogIndex, 51), leader.next_index[0]);
    try testing.expectEqual(@as(LogIndex, 50), leader.match_index[0]);
}

test "leader steps down on higher term in install_snapshot_reply" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var leader = try setupTestRaft(alloc, 1, peers, &log);
    defer leader.deinit();

    for (0..max_election_ticks + 1) |_| {
        leader.tick();
    }
    const election_actions = leader.drainActions();
    defer alloc.free(election_actions);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
    const leader_actions = leader.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, leader_actions);

    try testing.expectEqual(Role.leader, leader.role);
    const original_term = leader.currentTerm();

    leader.handleInstallSnapshotReply(2, .{
        .term = original_term + 1,
    });

    try testing.expectEqual(Role.follower, leader.role);
    try testing.expectEqual(original_term + 1, leader.currentTerm());
    const actions = leader.drainActions();
    defer alloc.free(actions);
}

test "onSnapshotComplete updates metadata" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{};
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    try testing.expect(raft.snapshot_meta == null);

    _ = raft.onSnapshotComplete(.{
        .last_included_index = 100,
        .last_included_term = 5,
        .data_len = 4096,
    });

    try testing.expect(raft.snapshot_meta != null);
    try testing.expectEqual(@as(LogIndex, 100), raft.snapshot_meta.?.last_included_index);

    // should also persist to the log's snapshot_meta table
    const persisted = log.getSnapshotMeta().?;
    try testing.expectEqual(@as(LogIndex, 100), persisted.last_included_index);
}

test "heartbeat with empty entries doesn't crash on free" {
    // verifies the &.{} path in sendAppendEntries works correctly
    // when there are no entries to replicate (heartbeat case)
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
    const ea = leader.drainActions();
    defer alloc.free(ea);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });

    // drain become_leader + initial heartbeats
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

    // trigger another heartbeat — log is empty so entries will be &.{}
    leader.heartbeat_ticks = heartbeat_interval;
    leader.tick();

    const actions = leader.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, actions);

    // verify we got heartbeats with empty entries
    var heartbeat_count: usize = 0;
    for (actions) |action| {
        if (action == .send_append_entries) {
            try testing.expectEqual(@as(usize, 0), action.send_append_entries.args.entries.len);
            heartbeat_count += 1;
        }
    }
    try testing.expectEqual(@as(usize, 2), heartbeat_count); // one per peer
}

test "leader steps down on higher term in append_entries_reply" {
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
    const ea = leader.drainActions();
    defer alloc.free(ea);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
    const la = leader.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, la);

    try testing.expectEqual(Role.leader, leader.role);
    const leader_term = leader.currentTerm();

    // peer replies with a higher term — leader must step down
    leader.handleAppendEntriesReply(2, .{
        .term = leader_term + 5,
        .success = false,
        .match_index = 0,
    });

    try testing.expectEqual(Role.follower, leader.role);
    try testing.expectEqual(leader_term + 5, leader.currentTerm());

    const actions = leader.drainActions();
    defer alloc.free(actions);
}

test "duplicate vote from same peer doesn't double count" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    // 5-node cluster: need 3 votes to win (self + 2 peers)
    const peers: []const NodeId = &.{ 2, 3, 4, 5 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // trigger election
    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    try testing.expectEqual(Role.candidate, raft.role);
    const ea = raft.drainActions();
    defer alloc.free(ea);

    // peer 2 votes yes
    raft.handleRequestVoteReply(2, .{
        .term = raft.currentTerm(),
        .vote_granted = true,
    });
    // self(1) + peer 2 = 2 votes, need 3 — should still be candidate
    try testing.expectEqual(Role.candidate, raft.role);

    // peer 2 votes again (duplicate) — should not count twice
    raft.handleRequestVoteReply(2, .{
        .term = raft.currentTerm(),
        .vote_granted = true,
    });

    const drain = raft.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, drain);
    try testing.expectEqual(Role.candidate, raft.role);
    try testing.expectEqual(@as(usize, 0), drain.len);
}

test "commit index requires majority in 5-node cluster" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    // 5-node cluster: quorum = 3
    const peers: []const NodeId = &.{ 2, 3, 4, 5 };
    var leader = try setupTestRaft(alloc, 1, peers, &log);
    defer leader.deinit();

    // force leader
    for (0..max_election_ticks + 1) |_| {
        leader.tick();
    }
    const ea = leader.drainActions();
    defer alloc.free(ea);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
    leader.handleRequestVoteReply(3, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
    const la = leader.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, la);

    // propose a command
    _ = try leader.propose("cmd1");
    const pa = leader.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, pa);

    try testing.expectEqual(@as(LogIndex, 0), leader.commit_index);

    // only 1 peer acks — self + 1 = 2, need 3. should NOT commit
    leader.handleAppendEntriesReply(2, .{
        .term = leader.currentTerm(),
        .success = true,
        .match_index = 1,
    });
    try testing.expectEqual(@as(LogIndex, 0), leader.commit_index);

    const ca1 = leader.drainActions();
    defer alloc.free(ca1);

    // second peer acks — self + 2 = 3 >= quorum. should commit
    leader.handleAppendEntriesReply(3, .{
        .term = leader.currentTerm(),
        .success = true,
        .match_index = 1,
    });
    try testing.expectEqual(@as(LogIndex, 1), leader.commit_index);

    const ca2 = leader.drainActions();
    defer alloc.free(ca2);
}

// -- multi-instance tests --
//
// these tests create multiple raft instances and route messages between
// them to verify end-to-end consensus behavior. the key insight is that
// raft is a pure state machine — we can simulate a cluster by manually
// delivering drainActions() output to the correct peer.

fn freeActionEntries(alloc: std.mem.Allocator, actions: []const Action) void {
    test_support.freeActionEntries(Action, alloc, actions);
}

test "3-node cluster: election + propose + commit" {
    const alloc = testing.allocator;

    // create 3 in-memory logs
    var log1 = try Log.initMemory();
    defer log1.deinit();
    var log2 = try Log.initMemory();
    defer log2.deinit();
    var log3 = try Log.initMemory();
    defer log3.deinit();

    // create 3 raft instances
    var r1 = try setupTestRaft(alloc, 1, &.{ 2, 3 }, &log1);
    defer r1.deinit();
    var r2 = try setupTestRaft(alloc, 2, &.{ 1, 3 }, &log2);
    defer r2.deinit();
    var r3 = try setupTestRaft(alloc, 3, &.{ 1, 2 }, &log3);
    defer r3.deinit();

    // -- step 1: elect node 1 as leader --

    // tick node 1 past election timeout to trigger election
    for (0..max_election_ticks + 1) |_| {
        r1.tick();
    }
    try testing.expectEqual(Role.candidate, r1.role);

    // drain vote requests, manually deliver to peers and route replies
    const vote_actions = r1.drainActions();
    defer alloc.free(vote_actions);

    for (vote_actions) |action| {
        if (action == .send_request_vote) {
            const rv = action.send_request_vote;
            if (rv.target == 2) {
                const reply = r2.handleRequestVote(rv.args);
                r1.handleRequestVoteReply(2, reply);
            } else if (rv.target == 3) {
                const reply = r3.handleRequestVote(rv.args);
                r1.handleRequestVoteReply(3, reply);
            }
        }
    }

    // node 1 should now be leader (got votes from self + 2 + 3)
    try testing.expectEqual(Role.leader, r1.role);

    // drain the become_leader + heartbeat actions (don't deliver heartbeats)
    const leader_actions = r1.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, leader_actions);

    // verify exactly 1 leader
    var leader_count: u32 = 0;
    if (r1.role == .leader) leader_count += 1;
    if (r2.role == .leader) leader_count += 1;
    if (r3.role == .leader) leader_count += 1;
    try testing.expectEqual(@as(u32, 1), leader_count);

    // -- step 2: propose a command and replicate --

    _ = try r1.propose("INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('test1', 'localhost', 'active', 4, 8192, 0, 0, 0, 1000, 1000);");

    // drain append_entries actions
    const propose_actions = r1.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, propose_actions);

    // deliver to followers manually and route ack replies back to leader
    for (propose_actions) |action| {
        if (action == .send_append_entries) {
            const ae = action.send_append_entries;
            if (ae.target == 2) {
                const reply = r2.handleAppendEntries(ae.args);
                r1.handleAppendEntriesReply(2, reply);
            } else if (ae.target == 3) {
                const reply = r3.handleAppendEntries(ae.args);
                r1.handleAppendEntriesReply(3, reply);
            }
        }
    }

    // -- step 3: verify consensus --

    // commit_index should advance (leader got acks from both followers)
    try testing.expectEqual(@as(LogIndex, 1), r1.commit_index);

    // verify commit_entries action was emitted
    const commit_actions = r1.drainActions();
    defer alloc.free(commit_actions);

    var found_commit = false;
    for (commit_actions) |a| {
        if (a == .commit_entries) {
            try testing.expectEqual(@as(LogIndex, 1), a.commit_entries.up_to);
            found_commit = true;
        }
    }
    try testing.expect(found_commit);

    // followers got the entry (match_index=1 from their reply)
    // but their commit_index only advances when leader sends next
    // heartbeat with leader_commit=1. verify followers have the data:
    try testing.expect(r2.log.lastIndex() >= 1);
    try testing.expect(r3.log.lastIndex() >= 1);
}

test "leader loss triggers re-election with higher term" {
    const alloc = testing.allocator;

    var log1 = try Log.initMemory();
    defer log1.deinit();
    var log2 = try Log.initMemory();
    defer log2.deinit();
    var log3 = try Log.initMemory();
    defer log3.deinit();

    var r1 = try setupTestRaft(alloc, 1, &.{ 2, 3 }, &log1);
    defer r1.deinit();
    var r2 = try setupTestRaft(alloc, 2, &.{ 1, 3 }, &log2);
    defer r2.deinit();
    var r3 = try setupTestRaft(alloc, 3, &.{ 1, 2 }, &log3);
    defer r3.deinit();

    // elect node 1 as leader
    for (0..max_election_ticks + 1) |_| {
        r1.tick();
    }
    const va = r1.drainActions();
    defer alloc.free(va);

    for (va) |action| {
        if (action == .send_request_vote) {
            const rv = action.send_request_vote;
            if (rv.target == 2) {
                const reply = r2.handleRequestVote(rv.args);
                r1.handleRequestVoteReply(2, reply);
            } else if (rv.target == 3) {
                const reply = r3.handleRequestVote(rv.args);
                r1.handleRequestVoteReply(3, reply);
            }
        }
    }
    try testing.expectEqual(Role.leader, r1.role);

    const la = r1.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, la);

    const original_term = r1.currentTerm();

    // stop ticking node 1 (simulate crash). tick node 2 past timeout.
    for (0..max_election_ticks + 1) |_| {
        r2.tick();
    }
    try testing.expectEqual(Role.candidate, r2.role);

    // route node 2's vote requests to node 3 only (node 1 is "dead")
    const v2 = r2.drainActions();
    defer alloc.free(v2);

    for (v2) |action| {
        if (action == .send_request_vote) {
            const rv = action.send_request_vote;
            if (rv.target == 3) {
                const reply = r3.handleRequestVote(rv.args);
                r2.handleRequestVoteReply(3, reply);
            }
            // skip target == 1 (node 1 is dead)
        }
    }

    // node 2 should be the new leader (got vote from self + node 3)
    try testing.expectEqual(Role.leader, r2.role);
    try testing.expect(r2.currentTerm() > original_term);

    // drain new leader's actions (become_leader + heartbeats)
    const nl = r2.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, nl);

    // verify become_leader was emitted
    var found_become_leader = false;
    for (nl) |a| {
        if (a == .become_leader) found_become_leader = true;
    }
    try testing.expect(found_become_leader);

    // old leader still thinks it's leader (we stopped processing it)
    try testing.expectEqual(Role.leader, r1.role);
}

// -- resilience tests --
//
// these tests verify raft correctness under network partitions, split votes,
// log divergence, and stale leader scenarios — the failure modes that cause
// real production incidents.

/// helper: elect a specific node as leader in a 3-node cluster.
/// delivers vote requests to both peers, returns the leader actions (caller must free).
fn electLeader3(alloc: std.mem.Allocator, leader: *Raft, p1: *Raft, p2: *Raft) ![]const Action {
    // tick past election timeout
    for (0..max_election_ticks + 1) |_| {
        leader.tick();
    }

    // deliver vote requests to peers
    const va = leader.drainActions();
    defer alloc.free(va);

    for (va) |action| {
        if (action == .send_request_vote) {
            const rv = action.send_request_vote;
            if (rv.target == p1.id) {
                const reply = p1.handleRequestVote(rv.args);
                leader.handleRequestVoteReply(p1.id, reply);
            } else if (rv.target == p2.id) {
                const reply = p2.handleRequestVote(rv.args);
                leader.handleRequestVoteReply(p2.id, reply);
            }
        }
    }

    // drain become_leader + heartbeat actions
    return leader.drainActions();
}

/// helper: propose a command on the leader and replicate to both peers.
/// returns the commit actions (caller must free).
fn proposeAndReplicate3(alloc: std.mem.Allocator, leader: *Raft, p1: *Raft, p2: *Raft, data: []const u8) ![]const Action {
    _ = try leader.propose(data);
    const pa = leader.drainActions();
    defer test_support.deinitOwnedActions(Action, alloc, pa);

    for (pa) |action| {
        if (action == .send_append_entries) {
            const ae = action.send_append_entries;
            if (ae.target == p1.id) {
                const reply = p1.handleAppendEntries(ae.args);
                leader.handleAppendEntriesReply(p1.id, reply);
            } else if (ae.target == p2.id) {
                const reply = p2.handleAppendEntries(ae.args);
                leader.handleAppendEntriesReply(p2.id, reply);
            }
        }
    }

    return leader.drainActions();
}

test "network partition: old leader steps down on reconnect" {
    const alloc = testing.allocator;

    var log1 = try Log.initMemory();
    defer log1.deinit();
    var log2 = try Log.initMemory();
    defer log2.deinit();
    var log3 = try Log.initMemory();
    defer log3.deinit();

    var r1 = try setupTestRaft(alloc, 1, &.{ 2, 3 }, &log1);
    defer r1.deinit();
    var r2 = try setupTestRaft(alloc, 2, &.{ 1, 3 }, &log2);
    defer r2.deinit();
    var r3 = try setupTestRaft(alloc, 3, &.{ 1, 2 }, &log3);
    defer r3.deinit();

    // step 1: elect r1 as leader, commit "cmd1" to all
    const la = try electLeader3(alloc, &r1, &r2, &r3);
    defer {
        freeActionEntries(alloc, la);
        alloc.free(la);
    }
    try testing.expectEqual(Role.leader, r1.role);

    const ca = try proposeAndReplicate3(alloc, &r1, &r2, &r3, "cmd1");
    defer alloc.free(ca);
    try testing.expectEqual(@as(LogIndex, 1), r1.commit_index);

    // step 2: partition — stop routing between r1 and {r2, r3}

    // step 3: tick r2 past election timeout, deliver r3's vote
    for (0..max_election_ticks + 1) |_| {
        r2.tick();
    }
    try testing.expectEqual(Role.candidate, r2.role);

    const v2 = r2.drainActions();
    defer alloc.free(v2);

    for (v2) |action| {
        if (action == .send_request_vote) {
            const rv = action.send_request_vote;
            if (rv.target == 3) {
                const reply = r3.handleRequestVote(rv.args);
                r2.handleRequestVoteReply(3, reply);
            }
            // don't deliver to r1 (partitioned)
        }
    }
    try testing.expectEqual(Role.leader, r2.role);

    const nl = r2.drainActions();
    defer {
        freeActionEntries(alloc, nl);
        alloc.free(nl);
    }

    // step 4: r1 proposes "stale_cmd" — appends locally but can't commit
    _ = try r1.propose("stale_cmd");
    const stale_actions = r1.drainActions();
    defer {
        freeActionEntries(alloc, stale_actions);
        alloc.free(stale_actions);
    }
    // r1 can't get acks (partitioned), commit_index stays at 1
    try testing.expectEqual(@as(LogIndex, 1), r1.commit_index);

    // step 5: heal partition — deliver r2's AppendEntries to r1
    // r2 sends heartbeats; we need to tick r2 to generate them
    for (0..heartbeat_interval + 1) |_| {
        r2.tick();
    }
    const hb = r2.drainActions();
    defer {
        freeActionEntries(alloc, hb);
        alloc.free(hb);
    }

    for (hb) |action| {
        if (action == .send_append_entries) {
            const ae = action.send_append_entries;
            if (ae.target == 1) {
                _ = r1.handleAppendEntries(ae.args);
            }
        }
    }

    // step 6: assert r1 stepped down
    try testing.expectEqual(Role.follower, r1.role);
    try testing.expectEqual(r2.currentTerm(), r1.currentTerm());
    // committed entry "cmd1" at index 1 is preserved
    try testing.expect(r1.log.lastIndex() >= 1);
}

test "split vote resolves in subsequent election" {
    const alloc = testing.allocator;

    var log1 = try Log.initMemory();
    defer log1.deinit();
    var log2 = try Log.initMemory();
    defer log2.deinit();
    var log3 = try Log.initMemory();
    defer log3.deinit();
    var log4 = try Log.initMemory();
    defer log4.deinit();

    var r1 = try setupTestRaft(alloc, 1, &.{ 2, 3, 4 }, &log1);
    defer r1.deinit();
    var r2 = try setupTestRaft(alloc, 2, &.{ 1, 3, 4 }, &log2);
    defer r2.deinit();
    var r3 = try setupTestRaft(alloc, 3, &.{ 1, 2, 4 }, &log3);
    defer r3.deinit();
    var r4 = try setupTestRaft(alloc, 4, &.{ 1, 2, 3 }, &log4);
    defer r4.deinit();

    // step 1: r1 and r3 both time out simultaneously → both become candidates at same term
    for (0..max_election_ticks + 1) |_| {
        r1.tick();
        r3.tick();
    }
    try testing.expectEqual(Role.candidate, r1.role);
    try testing.expectEqual(Role.candidate, r3.role);

    // step 2: split the votes — r2 votes for r1, r4 votes for r3
    const v1 = r1.drainActions();
    defer alloc.free(v1);
    const v3 = r3.drainActions();
    defer alloc.free(v3);

    for (v1) |action| {
        if (action == .send_request_vote) {
            const rv = action.send_request_vote;
            if (rv.target == 2) {
                const reply = r2.handleRequestVote(rv.args);
                r1.handleRequestVoteReply(2, reply);
            }
            // don't deliver to r3 or r4
        }
    }

    for (v3) |action| {
        if (action == .send_request_vote) {
            const rv = action.send_request_vote;
            if (rv.target == 4) {
                const reply = r4.handleRequestVote(rv.args);
                r3.handleRequestVoteReply(4, reply);
            }
            // don't deliver to r1 or r2
        }
    }

    // neither has quorum of 3 (each has 2: self + one peer)
    try testing.expect(r1.role != .leader);
    try testing.expect(r3.role != .leader);

    // step 3: tick r1 past another election timeout — new term
    for (0..max_election_ticks + 1) |_| {
        r1.tick();
    }
    try testing.expectEqual(Role.candidate, r1.role);

    const v1b = r1.drainActions();
    defer alloc.free(v1b);

    // deliver r1's vote requests to r2, r3, r4 — they see higher term, grant votes
    for (v1b) |action| {
        if (action == .send_request_vote) {
            const rv = action.send_request_vote;
            if (rv.target == 2) {
                const reply = r2.handleRequestVote(rv.args);
                r1.handleRequestVoteReply(2, reply);
            } else if (rv.target == 3) {
                const reply = r3.handleRequestVote(rv.args);
                r1.handleRequestVoteReply(3, reply);
            } else if (rv.target == 4) {
                const reply = r4.handleRequestVote(rv.args);
                r1.handleRequestVoteReply(4, reply);
            }
        }
    }

    // step 4: assert exactly one leader, all at same term
    try testing.expectEqual(Role.leader, r1.role);

    var leader_count: u32 = 0;
    if (r1.role == .leader) leader_count += 1;
    if (r2.role == .leader) leader_count += 1;
    if (r3.role == .leader) leader_count += 1;
    if (r4.role == .leader) leader_count += 1;
    try testing.expectEqual(@as(u32, 1), leader_count);

    // drain the new leader's actions
    const fla = r1.drainActions();
    defer {
        freeActionEntries(alloc, fla);
        alloc.free(fla);
    }
}

test "log divergence after partition resolved by new leader" {
    const alloc = testing.allocator;

    var log1 = try Log.initMemory();
    defer log1.deinit();
    var log2 = try Log.initMemory();
    defer log2.deinit();
    var log3 = try Log.initMemory();
    defer log3.deinit();

    var r1 = try setupTestRaft(alloc, 1, &.{ 2, 3 }, &log1);
    defer r1.deinit();
    var r2 = try setupTestRaft(alloc, 2, &.{ 1, 3 }, &log2);
    defer r2.deinit();
    var r3 = try setupTestRaft(alloc, 3, &.{ 1, 2 }, &log3);
    defer r3.deinit();

    // step 1: elect r1, commit "cmd1" at index 1
    const la = try electLeader3(alloc, &r1, &r2, &r3);
    defer {
        freeActionEntries(alloc, la);
        alloc.free(la);
    }
    const ca = try proposeAndReplicate3(alloc, &r1, &r2, &r3, "cmd1");
    defer alloc.free(ca);
    try testing.expectEqual(@as(LogIndex, 1), r1.commit_index);

    // step 2: partition r1. r1 proposes "uncommitted" at index 2 (can't commit)
    _ = try r1.propose("uncommitted");
    const stale = r1.drainActions();
    defer {
        freeActionEntries(alloc, stale);
        alloc.free(stale);
    }
    // don't deliver to anyone — r1 is partitioned
    try testing.expect(r1.log.lastIndex() == 2);
    try testing.expectEqual(@as(LogIndex, 1), r1.commit_index); // can't advance

    // step 3: elect r2 (r3 votes)
    for (0..max_election_ticks + 1) |_| {
        r2.tick();
    }
    const v2 = r2.drainActions();
    defer alloc.free(v2);

    for (v2) |action| {
        if (action == .send_request_vote) {
            const rv = action.send_request_vote;
            if (rv.target == 3) {
                const reply = r3.handleRequestVote(rv.args);
                r2.handleRequestVoteReply(3, reply);
            }
            // don't deliver to r1 (partitioned)
        }
    }
    try testing.expectEqual(Role.leader, r2.role);

    const nla = r2.drainActions();
    defer {
        freeActionEntries(alloc, nla);
        alloc.free(nla);
    }

    // r2 proposes "new_cmd" at index 2, replicates to r3 — committed
    _ = try r2.propose("new_cmd");
    const pa = r2.drainActions();
    defer {
        freeActionEntries(alloc, pa);
        alloc.free(pa);
    }
    for (pa) |action| {
        if (action == .send_append_entries) {
            const ae = action.send_append_entries;
            if (ae.target == 3) {
                const reply = r3.handleAppendEntries(ae.args);
                r2.handleAppendEntriesReply(3, reply);
            }
            // don't send to r1 (partitioned)
        }
    }
    const ca2 = r2.drainActions();
    defer alloc.free(ca2);
    try testing.expectEqual(@as(LogIndex, 2), r2.commit_index);

    // step 4: heal partition — deliver r2's AppendEntries to r1
    // tick r2 to generate heartbeat with updated log
    for (0..heartbeat_interval + 1) |_| {
        r2.tick();
    }
    const hb = r2.drainActions();
    defer {
        freeActionEntries(alloc, hb);
        alloc.free(hb);
    }

    for (hb) |action| {
        if (action == .send_append_entries) {
            const ae = action.send_append_entries;
            if (ae.target == 1) {
                const reply = r1.handleAppendEntries(ae.args);
                // if prev_log doesn't match, leader decrements next_index and retries
                r2.handleAppendEntriesReply(1, reply);
            }
        }
    }

    // r1 stepped down to follower on seeing higher term
    try testing.expectEqual(Role.follower, r1.role);

    // may need another round for the leader to send the right entries after backtracking
    for (0..heartbeat_interval + 1) |_| {
        r2.tick();
    }
    const hb2 = r2.drainActions();
    defer {
        freeActionEntries(alloc, hb2);
        alloc.free(hb2);
    }
    for (hb2) |action| {
        if (action == .send_append_entries) {
            const ae = action.send_append_entries;
            if (ae.target == 1) {
                _ = r1.handleAppendEntries(ae.args);
            }
        }
    }

    // step 5: verify logs agree — all three should have "cmd1" at index 1 and "new_cmd" at index 2
    try testing.expect(r1.log.lastIndex() >= 2);
    try testing.expect(r2.log.lastIndex() >= 2);
    try testing.expect(r3.log.lastIndex() >= 2);
    // r1 stepped down and caught up — its commit_index may advance via leader's leaderCommit
    // the key invariant: committed entries are preserved (index 1 = "cmd1")
    try testing.expect(r1.commit_index >= 1);
}

test "stale leader cannot commit without quorum" {
    const alloc = testing.allocator;

    var log1 = try Log.initMemory();
    defer log1.deinit();
    var log2 = try Log.initMemory();
    defer log2.deinit();
    var log3 = try Log.initMemory();
    defer log3.deinit();

    var r1 = try setupTestRaft(alloc, 1, &.{ 2, 3 }, &log1);
    defer r1.deinit();
    var r2 = try setupTestRaft(alloc, 2, &.{ 1, 3 }, &log2);
    defer r2.deinit();
    var r3 = try setupTestRaft(alloc, 3, &.{ 1, 2 }, &log3);
    defer r3.deinit();

    // step 1: elect r1, commit "cmd1" at index 1
    const la = try electLeader3(alloc, &r1, &r2, &r3);
    defer {
        freeActionEntries(alloc, la);
        alloc.free(la);
    }
    const ca = try proposeAndReplicate3(alloc, &r1, &r2, &r3, "cmd1");
    defer alloc.free(ca);
    try testing.expectEqual(@as(LogIndex, 1), r1.commit_index);

    // step 2: partition r1 from r2 and r3. r1 proposes "cmd2" — appends but can't commit
    _ = try r1.propose("cmd2");
    const stale = r1.drainActions();
    defer {
        freeActionEntries(alloc, stale);
        alloc.free(stale);
    }
    // don't deliver — partitioned

    // step 3: r1's commit_index stays at 1 despite ticking many times
    for (0..50) |_| {
        r1.tick();
    }
    const tick_actions = r1.drainActions();
    defer {
        freeActionEntries(alloc, tick_actions);
        alloc.free(tick_actions);
    }
    try testing.expectEqual(@as(LogIndex, 1), r1.commit_index);

    // step 4: r2 times out, gets r3's vote, becomes leader at higher term
    for (0..max_election_ticks + 1) |_| {
        r2.tick();
    }
    const v2 = r2.drainActions();
    defer alloc.free(v2);

    for (v2) |action| {
        if (action == .send_request_vote) {
            const rv = action.send_request_vote;
            if (rv.target == 3) {
                const reply = r3.handleRequestVote(rv.args);
                r2.handleRequestVoteReply(3, reply);
            }
        }
    }
    try testing.expectEqual(Role.leader, r2.role);
    try testing.expect(r2.currentTerm() > r1.currentTerm());

    const nla = r2.drainActions();
    defer {
        freeActionEntries(alloc, nla);
        alloc.free(nla);
    }

    // step 5: r2 can advance commit_index with r3's acks
    _ = try r2.propose("cmd_new");
    const pa = r2.drainActions();
    defer {
        freeActionEntries(alloc, pa);
        alloc.free(pa);
    }
    for (pa) |action| {
        if (action == .send_append_entries) {
            const ae = action.send_append_entries;
            if (ae.target == 3) {
                const reply = r3.handleAppendEntries(ae.args);
                r2.handleAppendEntriesReply(3, reply);
            }
        }
    }
    const ca2 = r2.drainActions();
    defer alloc.free(ca2);
    try testing.expect(r2.commit_index > 1);

    // r1 still stuck at commit_index 1
    try testing.expectEqual(@as(LogIndex, 1), r1.commit_index);
}

test "single node propose succeeds without peers" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{};
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // become leader (single node, immediate)
    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    try testing.expectEqual(Role.leader, raft.role);
    const ea = raft.drainActions();
    defer alloc.free(ea);

    // propose should succeed
    const idx = try raft.propose("test-cmd");
    try testing.expectEqual(@as(LogIndex, 1), idx);

    // no append_entries actions since there are no peers
    const actions = raft.drainActions();
    defer alloc.free(actions);
    for (actions) |action| {
        try testing.expect(action != .send_append_entries);
    }
}

test "2-node cluster cannot commit without follower ack" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{2};
    var leader = try setupTestRaft(alloc, 1, peers, &log);
    defer leader.deinit();

    // become leader via single peer granting vote
    for (0..max_election_ticks + 1) |_| {
        leader.tick();
    }
    const ea = leader.drainActions();
    defer alloc.free(ea);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
    try testing.expectEqual(Role.leader, leader.role);
    const la = leader.drainActions();
    defer {
        freeActionEntries(alloc, la);
        alloc.free(la);
    }

    // propose a command
    _ = try leader.propose("cmd1");
    const pa = leader.drainActions();
    defer {
        freeActionEntries(alloc, pa);
        alloc.free(pa);
    }

    // without follower ack, commit_index should NOT advance
    try testing.expectEqual(@as(LogIndex, 0), leader.commit_index);
}

test "advanceCommitIndex skips entries from previous term" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    // manually add an entry from term 1 and set current term to 2
    // so that the election will produce term 3+
    try log.append(.{ .index = 1, .term = 1, .data = "old-term" });
    _ = log.setCurrentTerm(2);

    const peers: []const NodeId = &.{ 2, 3 };
    var leader = try setupTestRaft(alloc, 1, peers, &log);
    defer leader.deinit();

    // force leader — election will bump term from 2 to 3
    for (0..max_election_ticks + 1) |_| {
        leader.tick();
    }
    const ea = leader.drainActions();
    defer alloc.free(ea);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
    const la = leader.drainActions();
    defer {
        freeActionEntries(alloc, la);
        alloc.free(la);
    }

    // leader is now in term 3, entry at index 1 is from term 1
    try testing.expect(leader.currentTerm() >= 3);

    // peer 2 says it has index 1
    leader.handleAppendEntriesReply(2, .{
        .term = leader.currentTerm(),
        .success = true,
        .match_index = 1,
    });

    // entry 1 is from term 1, not current term — should NOT be committed
    // (Raft §5.4.2: leader only commits entries from its own term)
    try testing.expectEqual(@as(LogIndex, 0), leader.commit_index);

    const actions = leader.drainActions();
    defer alloc.free(actions);
}

test "follower rejects vote if already voted in same term" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // candidate A (node 2) requests vote at term 3
    const reply_a = raft.handleRequestVote(.{
        .term = 3,
        .candidate_id = 2,
        .last_log_index = 0,
        .last_log_term = 0,
    });
    try testing.expect(reply_a.vote_granted);

    const a1 = raft.drainActions();
    defer alloc.free(a1);

    // candidate B (node 3) requests vote at same term 3
    const reply_b = raft.handleRequestVote(.{
        .term = 3,
        .candidate_id = 3,
        .last_log_index = 0,
        .last_log_term = 0,
    });

    // should reject — already voted for node 2 in term 3
    try testing.expect(!reply_b.vote_granted);

    const a2 = raft.drainActions();
    defer alloc.free(a2);
}

test "candidate steps down on append_entries from new leader" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // trigger election — become candidate
    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    try testing.expectEqual(Role.candidate, raft.role);
    const candidate_term = raft.currentTerm();

    const ea = raft.drainActions();
    defer alloc.free(ea);

    // receive append_entries from node 2 who won the election in same term
    const reply = raft.handleAppendEntries(.{
        .term = candidate_term, // same term, not higher
        .leader_id = 2,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &.{},
        .leader_commit = 0,
    });

    try testing.expect(reply.success);
    try testing.expectEqual(Role.follower, raft.role);

    // should have a become_follower action
    const actions = raft.drainActions();
    defer alloc.free(actions);
    var found_become_follower = false;
    for (actions) |action| {
        if (action == .become_follower) {
            try testing.expectEqual(@as(NodeId, 2), action.become_follower.leader_id);
            found_become_follower = true;
        }
    }
    try testing.expect(found_become_follower);
}

test "handleAppendEntries rejects stale term" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    // set our term to 5
    _ = log.setCurrentTerm(5);

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // receive append_entries with term 3 (behind our term 5)
    const reply = raft.handleAppendEntries(.{
        .term = 3,
        .leader_id = 2,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &.{},
        .leader_commit = 0,
    });

    try testing.expect(!reply.success);
    try testing.expectEqual(@as(Term, 5), reply.term);

    const actions = raft.drainActions();
    defer alloc.free(actions);
}

test "snapshot boundary: sendAppendEntries triggers install_snapshot" {
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
    const ea = leader.drainActions();
    defer alloc.free(ea);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
    const la = leader.drainActions();
    defer {
        freeActionEntries(alloc, la);
        alloc.free(la);
    }

    // simulate: leader has snapshot at index 100, log truncated before that
    leader.snapshot_meta = .{
        .last_included_index = 100,
        .last_included_term = leader.currentTerm(),
        .data_len = 2048,
    };
    _ = log.setSnapshotMeta(.{
        .last_included_index = 100,
        .last_included_term = leader.currentTerm(),
        .data_len = 2048,
    });

    // peer 2 needs entry at index 5 (way before snapshot)
    leader.next_index[0] = 5; // peer 2 = index 0 in peers

    // trigger heartbeat to peer 2
    leader.heartbeat_ticks = heartbeat_interval;
    leader.tick();

    const actions = leader.drainActions();
    defer {
        freeActionEntries(alloc, actions);
        alloc.free(actions);
    }

    // should send install_snapshot to peer 2, not append_entries
    var found_snapshot = false;
    var found_append_for_peer2 = false;
    for (actions) |action| {
        if (action == .send_install_snapshot and action.send_install_snapshot.target == 2) {
            found_snapshot = true;
            try testing.expectEqual(@as(LogIndex, 100), action.send_install_snapshot.args.last_included_index);
        }
        if (action == .send_append_entries and action.send_append_entries.target == 2) {
            found_append_for_peer2 = true;
        }
    }
    try testing.expect(found_snapshot);
    try testing.expect(!found_append_for_peer2);
}

test "transferLeadership steps down leader and advances term" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // become leader first
    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    const ea = raft.drainActions();
    defer alloc.free(ea);
    raft.handleRequestVoteReply(2, .{
        .term = raft.currentTerm(),
        .vote_granted = true,
    });
    const la = raft.drainActions();
    defer {
        freeActionEntries(alloc, la);
        alloc.free(la);
    }
    try testing.expectEqual(Role.leader, raft.role);

    const term_before = raft.currentTerm();

    // transfer leadership
    const transferred = raft.transferLeadership();
    try testing.expect(transferred);
    try testing.expectEqual(Role.follower, raft.role);
    try testing.expect(raft.currentTerm() > term_before);

    // should have a become_follower action
    const actions = raft.drainActions();
    defer alloc.free(actions);
    var found_follower = false;
    for (actions) |action| {
        if (action == .become_follower) found_follower = true;
    }
    try testing.expect(found_follower);
}

test "transferLeadership returns false when not leader" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{2};
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // not leader — should return false
    try testing.expectEqual(Role.follower, raft.role);
    try testing.expect(!raft.transferLeadership());
}

test "protocolVersion returns 1" {
    try testing.expectEqual(@as(u32, 1), Raft.protocolVersion());
}

test "finishInstallSnapshot preserves higher commit_index" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // simulate: node has already committed up to index 100
    raft.commit_index = 100;
    raft.last_applied = 100;

    // install a snapshot at a lower index — commit_index must not regress
    const result = raft.finishInstallSnapshot(.{
        .last_included_index = 50,
        .last_included_term = 1,
        .data_len = 0,
    });
    try testing.expect(result);
    try testing.expectEqual(@as(LogIndex, 100), raft.commit_index);
    try testing.expectEqual(@as(LogIndex, 100), raft.last_applied);

    const actions = raft.drainActions();
    defer alloc.free(actions);
}

test "finishInstallSnapshot advances commit_index when snapshot is ahead" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    try testing.expectEqual(@as(LogIndex, 0), raft.commit_index);

    const result = raft.finishInstallSnapshot(.{
        .last_included_index = 200,
        .last_included_term = 3,
        .data_len = 0,
    });
    try testing.expect(result);
    try testing.expectEqual(@as(LogIndex, 200), raft.commit_index);
    try testing.expectEqual(@as(LogIndex, 200), raft.last_applied);

    const actions = raft.drainActions();
    defer alloc.free(actions);
}

test "handleAppendEntries advances commit_index from leader_commit" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    // add entries to the log so commit can advance
    try log.append(.{ .index = 1, .term = 1, .data = "a" });
    try log.append(.{ .index = 2, .term = 1, .data = "b" });
    try log.append(.{ .index = 3, .term = 1, .data = "c" });

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    try testing.expectEqual(@as(LogIndex, 0), raft.commit_index);

    // leader says commit up to 2
    const reply = raft.handleAppendEntries(.{
        .term = 1,
        .leader_id = 2,
        .prev_log_index = 3,
        .prev_log_term = 1,
        .entries = &.{},
        .leader_commit = 2,
    });
    try testing.expect(reply.success);
    try testing.expectEqual(@as(LogIndex, 2), raft.commit_index);

    // should have a commit_entries action
    const actions = raft.drainActions();
    defer alloc.free(actions);
    var found_commit = false;
    for (actions) |action| {
        if (action == .commit_entries) {
            try testing.expectEqual(@as(LogIndex, 2), action.commit_entries.up_to);
            found_commit = true;
        }
    }
    try testing.expect(found_commit);
}

test "handleAppendEntries with conflicting entry truncates and appends" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    // existing entries at term 1
    try log.append(.{ .index = 1, .term = 1, .data = "old" });
    try log.append(.{ .index = 2, .term = 1, .data = "old2" });

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // leader sends entry at index 2 with term 2 — conflicts with existing
    const reply = raft.handleAppendEntries(.{
        .term = 2,
        .leader_id = 2,
        .prev_log_index = 1,
        .prev_log_term = 1,
        .entries = &.{.{ .index = 2, .term = 2, .data = "new" }},
        .leader_commit = 0,
    });
    try testing.expect(reply.success);
    try testing.expectEqual(@as(LogIndex, 2), reply.match_index);

    // verify the entry was replaced
    try testing.expectEqual(@as(Term, 2), log.termAt(2));

    const actions = raft.drainActions();
    defer alloc.free(actions);
}

test "handleAppendEntries rejects mismatched prev_log" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    try log.append(.{ .index = 1, .term = 1, .data = "cmd" });

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // leader claims prev_log at index 1 has term 5, but we have term 1
    const reply = raft.handleAppendEntries(.{
        .term = 2,
        .leader_id = 2,
        .prev_log_index = 1,
        .prev_log_term = 5,
        .entries = &.{},
        .leader_commit = 0,
    });
    try testing.expect(!reply.success);

    const actions = raft.drainActions();
    defer alloc.free(actions);
}

test "leader commit advances when majority matches" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // become leader
    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    const ea = raft.drainActions();
    defer alloc.free(ea);
    raft.handleRequestVoteReply(2, .{
        .term = raft.currentTerm(),
        .vote_granted = true,
    });
    const la = raft.drainActions();
    defer {
        freeActionEntries(alloc, la);
        alloc.free(la);
    }
    try testing.expectEqual(Role.leader, raft.role);

    // propose a command
    const idx = try raft.propose("test-cmd");

    // peer 2 confirms replication
    raft.handleAppendEntriesReply(2, .{
        .term = raft.currentTerm(),
        .success = true,
        .match_index = idx,
    });

    // commit should advance (leader + peer 2 = majority of 3)
    try testing.expectEqual(idx, raft.commit_index);

    const actions = raft.drainActions();
    defer {
        freeActionEntries(alloc, actions);
        alloc.free(actions);
    }
}

test "stale append_entries_reply does not regress match_index" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // become leader
    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    const ea = raft.drainActions();
    defer alloc.free(ea);
    raft.handleRequestVoteReply(2, .{
        .term = raft.currentTerm(),
        .vote_granted = true,
    });
    const la = raft.drainActions();
    defer {
        freeActionEntries(alloc, la);
        alloc.free(la);
    }

    // propose two entries
    const idx1 = try raft.propose("cmd1");
    const idx2 = try raft.propose("cmd2");
    const pa = raft.drainActions();
    defer {
        freeActionEntries(alloc, pa);
        alloc.free(pa);
    }

    // peer 2 confirms up to idx2 (newer reply arrives first)
    raft.handleAppendEntriesReply(2, .{
        .term = raft.currentTerm(),
        .success = true,
        .match_index = idx2,
    });
    try testing.expectEqual(idx2, raft.match_index[0]);

    // stale reply for idx1 arrives later — must NOT regress match_index
    raft.handleAppendEntriesReply(2, .{
        .term = raft.currentTerm(),
        .success = true,
        .match_index = idx1,
    });
    try testing.expectEqual(idx2, raft.match_index[0]);

    const actions = raft.drainActions();
    defer {
        freeActionEntries(alloc, actions);
        alloc.free(actions);
    }
}

test "failed append_entries_reply backtracks only above matched prefix" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    const election_actions = raft.drainActions();
    defer alloc.free(election_actions);
    raft.handleRequestVoteReply(2, .{
        .term = raft.currentTerm(),
        .vote_granted = true,
    });
    const leader_actions = raft.drainActions();
    defer {
        freeActionEntries(alloc, leader_actions);
        alloc.free(leader_actions);
    }

    raft.match_index[0] = 1;
    raft.next_index[0] = 3;

    raft.handleAppendEntriesReply(2, .{
        .term = raft.currentTerm(),
        .success = false,
        .match_index = 0,
    });

    try testing.expectEqual(@as(LogIndex, 1), raft.match_index[0]);
    try testing.expectEqual(@as(LogIndex, 2), raft.next_index[0]);

    const actions = raft.drainActions();
    defer {
        freeActionEntries(alloc, actions);
        alloc.free(actions);
    }

    var found_resend = false;
    for (actions) |action| {
        if (action == .send_append_entries and action.send_append_entries.target == 2) {
            found_resend = true;
        }
    }
    try testing.expect(found_resend);
}

test "stale failed append_entries_reply does not regress next_index or trigger resend" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    for (0..max_election_ticks + 1) |_| {
        raft.tick();
    }
    const election_actions = raft.drainActions();
    defer alloc.free(election_actions);
    raft.handleRequestVoteReply(2, .{
        .term = raft.currentTerm(),
        .vote_granted = true,
    });
    const leader_actions = raft.drainActions();
    defer {
        freeActionEntries(alloc, leader_actions);
        alloc.free(leader_actions);
    }

    raft.match_index[0] = 5;
    raft.next_index[0] = 6;

    raft.handleAppendEntriesReply(2, .{
        .term = raft.currentTerm(),
        .success = false,
        .match_index = 0,
    });

    try testing.expectEqual(@as(LogIndex, 5), raft.match_index[0]);
    try testing.expectEqual(@as(LogIndex, 6), raft.next_index[0]);

    const actions = raft.drainActions();
    defer {
        freeActionEntries(alloc, actions);
        alloc.free(actions);
    }
    try testing.expectEqual(@as(usize, 0), actions.len);
}

test "truncation followed by append uses fresh state" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    // follower has entries [1:term1, 2:term1]
    try log.append(.{ .index = 1, .term = 1, .data = "a" });
    try log.append(.{ .index = 2, .term = 1, .data = "b" });

    const peers: []const NodeId = &.{ 2, 3 };
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    // leader sends entry at index 2 with different term — should truncate and replace
    const reply = raft.handleAppendEntries(.{
        .term = 2,
        .leader_id = 2,
        .prev_log_index = 1,
        .prev_log_term = 1,
        .entries = &.{
            .{ .index = 2, .term = 2, .data = "new_b" },
            .{ .index = 3, .term = 2, .data = "c" },
        },
        .leader_commit = 0,
    });
    try testing.expect(reply.success);
    try testing.expectEqual(@as(LogIndex, 3), reply.match_index);

    // verify both entries were written with correct terms
    try testing.expectEqual(@as(Term, 2), log.termAt(2));
    try testing.expectEqual(@as(Term, 2), log.termAt(3));

    const actions = raft.drainActions();
    defer alloc.free(actions);
}

test "snapshot reply does not regress match_index" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 2, 3 };
    var leader = try setupTestRaft(alloc, 1, peers, &log);
    defer leader.deinit();

    // become leader
    for (0..max_election_ticks + 1) |_| {
        leader.tick();
    }
    const ea = leader.drainActions();
    defer alloc.free(ea);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
    const la = leader.drainActions();
    defer {
        freeActionEntries(alloc, la);
        alloc.free(la);
    }

    // manually set peer 2 match_index high (simulating prior replication)
    leader.match_index[0] = 200;
    leader.next_index[0] = 201;

    // set a snapshot at index 100
    leader.snapshot_meta = .{
        .last_included_index = 100,
        .last_included_term = leader.currentTerm(),
        .data_len = 0,
    };

    // snapshot reply arrives — must NOT regress match_index from 200 to 100
    leader.handleInstallSnapshotReply(2, .{ .term = leader.currentTerm() });
    try testing.expectEqual(@as(LogIndex, 200), leader.match_index[0]);
    try testing.expectEqual(@as(LogIndex, 201), leader.next_index[0]);

    const actions = leader.drainActions();
    defer {
        freeActionEntries(alloc, actions);
        alloc.free(actions);
    }
}
