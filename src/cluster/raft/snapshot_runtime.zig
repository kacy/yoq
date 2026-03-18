const logger = @import("../../lib/log.zig");
const types = @import("../raft_types.zig");

const InstallSnapshotArgs = types.InstallSnapshotArgs;
const InstallSnapshotReply = types.InstallSnapshotReply;
const SnapshotMeta = types.SnapshotMeta;

pub fn handleInstallSnapshot(
    self: anytype,
    args: InstallSnapshotArgs,
    min_election_ticks: u32,
    max_election_ticks: u32,
) InstallSnapshotReply {
    const current_term = self.log.getCurrentTerm();
    if (args.term < current_term) {
        return .{ .term = current_term };
    }

    if (args.term > current_term) {
        stepDown(self, args.term, min_election_ticks, max_election_ticks);
    }

    self.ticks_since_event = 0;
    if (args.last_included_index <= self.commit_index) {
        return .{ .term = self.log.getCurrentTerm() };
    }

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

    self.snapshot_meta = meta;
    self.commit_index = args.last_included_index;
    self.last_applied = args.last_included_index;
    return .{ .term = self.log.getCurrentTerm() };
}

pub fn handleInstallSnapshotReply(
    self: anytype,
    from: anytype,
    reply: InstallSnapshotReply,
    min_election_ticks: u32,
    max_election_ticks: u32,
) void {
    if (self.role != .leader) return;

    if (reply.term > self.log.getCurrentTerm()) {
        stepDown(self, reply.term, min_election_ticks, max_election_ticks);
        return;
    }

    const peer_idx = peerIndex(self, from) orelse return;
    if (self.snapshot_meta) |meta| {
        self.match_index[peer_idx] = meta.last_included_index;
        self.next_index[peer_idx] = meta.last_included_index + 1;
    }
}

pub fn sendInstallSnapshot(self: anytype, peer_idx: usize, meta: SnapshotMeta) void {
    self.actions.append(self.alloc, .{
        .send_install_snapshot = .{
            .target = self.peers[peer_idx],
            .args = .{
                .term = self.log.getCurrentTerm(),
                .leader_id = self.id,
                .last_included_index = meta.last_included_index,
                .last_included_term = meta.last_included_term,
                .data = @constCast(&.{}),
            },
        },
    }) catch |e| {
        logger.warn("raft: failed to queue install snapshot: {}", .{e});
    };
}

pub fn onSnapshotComplete(self: anytype, meta: SnapshotMeta) void {
    self.snapshot_meta = meta;
    self.log.setSnapshotMeta(meta);
}

fn peerIndex(self: anytype, id: anytype) ?usize {
    for (self.peers, 0..) |peer, i| {
        if (peer == id) return i;
    }
    return null;
}

fn stepDown(self: anytype, new_term: anytype, min_election_ticks: u32, max_election_ticks: u32) void {
    self.log.setCurrentTerm(new_term);
    self.log.setVotedFor(null);
    self.role = .follower;
    self.ticks_since_event = 0;

    const range = max_election_ticks - min_election_ticks;
    self.election_timeout = min_election_ticks + self.rng.random().intRangeAtMost(u32, 0, range);
}
