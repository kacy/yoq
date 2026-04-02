const logger = @import("../../lib/log.zig");
const common = @import("common.zig");
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
        if (!common.stepDown(self, args.term, min_election_ticks, max_election_ticks)) {
            return .{ .term = current_term };
        }
    } else if (self.role == .candidate) {
        self.role = .follower;
        self.actions.append(self.alloc, .{
            .become_follower = .{ .leader_id = args.leader_id },
        }) catch |e| {
            logger.warn("raft: failed to queue become_follower during snapshot install: {}", .{e});
        };
    }

    self.ticks_since_event = 0;
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
        _ = common.stepDown(self, reply.term, min_election_ticks, max_election_ticks);
        return;
    }

    const peer_idx = common.peerIndex(self, from) orelse return;
    if (self.snapshot_meta) |meta| {
        if (meta.last_included_index > self.match_index[peer_idx]) {
            self.match_index[peer_idx] = meta.last_included_index;
            self.next_index[peer_idx] = meta.last_included_index + 1;
        }
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

pub fn finishInstallSnapshot(self: anytype, meta: SnapshotMeta) bool {
    if (!self.log.setSnapshotMeta(meta)) return false;
    self.snapshot_meta = meta;
    self.commit_index = @max(self.commit_index, meta.last_included_index);
    self.last_applied = @max(self.last_applied, meta.last_included_index);
    return true;
}

pub fn onSnapshotComplete(self: anytype, meta: SnapshotMeta) bool {
    if (!self.log.setSnapshotMeta(meta)) return false;
    self.snapshot_meta = meta;
    return true;
}
