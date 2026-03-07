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
const types = @import("raft_types.zig");
const persistent_log = @import("log.zig");
const logger = @import("../lib/log.zig");

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
    apply_snapshot: struct { data: []const u8, meta: SnapshotMeta },
    take_snapshot: struct { up_to_index: LogIndex, term: Term },
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
        const next_idx = try alloc.alloc(LogIndex, peer_count);
        const match_idx = try alloc.alloc(LogIndex, peer_count);

        // initialize leader state (will be reset when becoming leader)
        for (0..peer_count) |i| {
            next_idx[i] = 1;
            match_idx[i] = 0;
        }

        // seed rng with node id + timestamp for uniqueness
        const seed = @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())))) ^ id;

        // load snapshot metadata from persistent storage
        const snap_meta = log.getSnapshotMeta();

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
        self.alloc.free(self.peers);
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
                self.actions.append(self.alloc, .{ .become_follower = .{ .leader_id = args.leader_id } }) catch |e| {
                    logger.warn("raft: failed to queue become_follower action: {}", .{e});
                };
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
                }) catch |e| {
                    logger.warn("raft: failed to queue commit action: {}", .{e});
                };
            }
        }

        return .{
            .term = self.log.getCurrentTerm(),
            .success = true,
            .match_index = self.log.lastIndex(),
        };
    }

    /// handle an InstallSnapshot RPC from the leader.
    ///
    /// when a follower is far behind and the leader's log has been
    /// truncated past the follower's next_index, the leader sends
    /// a full snapshot instead of individual entries.
    ///
    /// the follower:
    /// 1. steps down if the snapshot has a higher term
    /// 2. rejects if our term is higher
    /// 3. queues an apply_snapshot action for the caller to process
    /// 4. updates commit_index and snapshot_meta
    pub fn handleInstallSnapshot(self: *Raft, args: InstallSnapshotArgs) InstallSnapshotReply {
        const current_term = self.log.getCurrentTerm();

        // reject if leader's term is behind ours
        if (args.term < current_term) {
            return .{ .term = current_term };
        }

        // step down if we see a higher term
        if (args.term > current_term) {
            self.stepDown(args.term);
        }

        self.ticks_since_event = 0;

        // if the snapshot is not more recent than what we have, ignore it
        if (args.last_included_index <= self.commit_index) {
            return .{ .term = self.log.getCurrentTerm() };
        }

        // queue the snapshot for the caller to apply.
        // the caller (node.zig) will:
        //   1. restore the state machine from the snapshot data
        //   2. update the log's snapshot metadata
        //   3. truncate the log up to last_included_index
        const meta = SnapshotMeta{
            .last_included_index = args.last_included_index,
            .last_included_term = args.last_included_term,
            .data_len = @intCast(args.data.len),
        };

        self.actions.append(self.alloc, .{
            .apply_snapshot = .{
                .data = args.data,
                .meta = meta,
            },
        }) catch |e| {
            logger.warn("raft: failed to queue apply_snapshot action: {}", .{e});
        };

        // update our state
        self.snapshot_meta = meta;
        self.commit_index = args.last_included_index;
        self.last_applied = args.last_included_index;

        return .{ .term = self.log.getCurrentTerm() };
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

    /// handle a reply to our InstallSnapshot RPC.
    /// if the follower's term is higher, step down. otherwise,
    /// update next_index and match_index for that peer.
    pub fn handleInstallSnapshotReply(self: *Raft, from: NodeId, reply: InstallSnapshotReply) void {
        if (self.role != .leader) return;

        if (reply.term > self.log.getCurrentTerm()) {
            self.stepDown(reply.term);
            return;
        }

        const peer_idx = self.peerIndex(from) orelse return;

        // the follower accepted the snapshot. update tracking to
        // the snapshot's last_included_index so the next heartbeat
        // sends entries from that point forward.
        if (self.snapshot_meta) |meta| {
            self.match_index[peer_idx] = meta.last_included_index;
            self.next_index[peer_idx] = meta.last_included_index + 1;
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
    /// caller owns the returned slice and must free it with self.alloc.free(actions)
    /// note: returns an empty non-owned slice on allocation failure - caller must NOT free in that case
    pub fn drainActions(self: *Raft) []Action {
        return self.actions.toOwnedSlice(self.alloc) catch blk: {
            // on allocation failure, clear the queue and return empty
            // caller must check if actions.len == 0 before freeing
            self.actions.clearRetainingCapacity();
            break :blk &.{};
        };
    }

    /// called by the node after a successful snapshot. updates the
    /// in-memory snapshot metadata so the leader knows it can send
    /// snapshots to lagging followers.
    pub fn onSnapshotComplete(self: *Raft, meta: SnapshotMeta) void {
        self.snapshot_meta = meta;
        self.log.setSnapshotMeta(meta);
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
            }) catch |e| {
                logger.warn("raft: failed to queue vote request: {}", .{e});
            };
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

        self.actions.append(self.alloc, .become_leader) catch |e| {
            logger.warn("raft: failed to queue become_leader action: {}", .{e});
        };

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

        // if the previous entry has been compacted away (term is 0 for an
        // index that should exist), and we have a snapshot, send the snapshot
        // instead of append entries. this happens when a follower is so far
        // behind that the leader has already truncated the needed entries.
        if (prev_index > 0 and prev_term == 0) {
            if (self.snapshot_meta) |meta| {
                if (prev_index <= meta.last_included_index) {
                    self.sendInstallSnapshot(peer_idx, meta);
                    return;
                }
            }
        }

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
        }) catch |e| {
            logger.warn("raft: failed to queue append entries: {}", .{e});
        };
    }

    /// queue an InstallSnapshot action for a lagging peer.
    /// the actual snapshot data loading happens in node.zig when
    /// it processes this action — the raft module stays I/O-free.
    fn sendInstallSnapshot(self: *Raft, peer_idx: usize, meta: SnapshotMeta) void {
        // we produce the action with empty data here. the caller (node.zig)
        // is responsible for reading the snapshot file and filling in the data
        // before sending it over the wire. this keeps the raft module pure.
        self.actions.append(self.alloc, .{
            .send_install_snapshot = .{
                .target = self.peers[peer_idx],
                .args = .{
                    .term = self.log.getCurrentTerm(),
                    .leader_id = self.id,
                    .last_included_index = meta.last_included_index,
                    .last_included_term = meta.last_included_term,
                    .data = &.{}, // filled by node.zig
                },
            },
        }) catch |e| {
            logger.warn("raft: failed to queue install snapshot: {}", .{e});
        };
    }

    fn advanceCommitIndex(self: *Raft) void {
        // find the highest N such that a majority of match_index[i] >= N
        // and log[N].term == currentTerm
        const current_term = self.log.getCurrentTerm();
        const last = self.log.lastIndex();

        var n = last;
        while (n > self.commit_index and n > 0) : (n -= 1) {
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
                }) catch |e| {
                    logger.warn("raft: failed to queue commit action: {}", .{e});
                };
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
    const a1 = leader.drainActions();
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
    const ea = leader.drainActions();
    defer alloc.free(ea);
    leader.handleRequestVoteReply(2, .{
        .term = leader.currentTerm(),
        .vote_granted = true,
    });
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

    // propose and replicate
    const idx = try leader.propose("cmd1");
    try testing.expectEqual(@as(LogIndex, 1), idx);

    const pa = leader.drainActions();
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

    const a = follower.drainActions();
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

// -- snapshot tests --

test "handleInstallSnapshot updates state and queues apply" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{ 1, 3 };
    var follower = try setupTestRaft(alloc, 2, peers, &log);
    defer follower.deinit();

    const reply = follower.handleInstallSnapshot(.{
        .term = 3,
        .leader_id = 1,
        .last_included_index = 100,
        .last_included_term = 2,
        .data = "snapshot data",
    });

    // should accept (term >= ours)
    try testing.expectEqual(@as(Term, 3), reply.term);

    // commit_index and last_applied should be updated
    try testing.expectEqual(@as(LogIndex, 100), follower.commit_index);
    try testing.expectEqual(@as(LogIndex, 100), follower.last_applied);

    // should have queued an apply_snapshot action
    const actions = follower.drainActions();
    defer alloc.free(actions);

    var found_apply = false;
    for (actions) |action| {
        if (action == .apply_snapshot) {
            try testing.expectEqual(@as(LogIndex, 100), action.apply_snapshot.meta.last_included_index);
            try testing.expectEqualStrings("snapshot data", action.apply_snapshot.data);
            found_apply = true;
        }
    }
    try testing.expect(found_apply);
}

test "handleInstallSnapshot rejects stale term" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    // set our term higher
    log.setCurrentTerm(5);

    const peers: []const NodeId = &.{ 1, 3 };
    var follower = try setupTestRaft(alloc, 2, peers, &log);
    defer follower.deinit();

    const reply = follower.handleInstallSnapshot(.{
        .term = 3, // behind our term of 5
        .leader_id = 1,
        .last_included_index = 100,
        .last_included_term = 2,
        .data = "snapshot data",
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

    const reply = follower.handleInstallSnapshot(.{
        .term = 3,
        .leader_id = 1,
        .last_included_index = 50, // behind our commit_index
        .last_included_term = 2,
        .data = "old snapshot",
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
    defer {
        for (la) |action| {
            if (action == .send_append_entries) {
                if (action.send_append_entries.args.entries.len > 0)
                    alloc.free(action.send_append_entries.args.entries);
            }
        }
        alloc.free(la);
    }

    // simulate: leader has a snapshot at index 50, log truncated
    leader.snapshot_meta = .{
        .last_included_index = 50,
        .last_included_term = 3,
        .data_len = 1024,
    };
    log.setSnapshotMeta(.{
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
    defer {
        for (la) |action| {
            if (action == .send_append_entries) {
                if (action.send_append_entries.args.entries.len > 0)
                    alloc.free(action.send_append_entries.args.entries);
            }
        }
        alloc.free(la);
    }

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

test "onSnapshotComplete updates metadata" {
    const alloc = testing.allocator;
    var log = try Log.initMemory();
    defer log.deinit();

    const peers: []const NodeId = &.{};
    var raft = try setupTestRaft(alloc, 1, peers, &log);
    defer raft.deinit();

    try testing.expect(raft.snapshot_meta == null);

    raft.onSnapshotComplete(.{
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
