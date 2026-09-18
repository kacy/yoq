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
                .term = self.persistent_state.current_term,
                .leader_id = self.id,
                .prev_log_index = prev_index,
                .prev_log_term = prev_term,
                .entries = if (count > 0) self.alloc.dupe(LogEntry, entries_buf[0..count]) catch {
                    logger.warn("raft: failed to allocate entries for append_entries to node {}", .{self.peers[peer_idx]});
                    return;
                } else &.{},
                .leader_commit = self.commit_index,
            },
        },
    }) catch |e| {
        logger.warn("raft: failed to queue append entries: {}", .{e});
    };
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
