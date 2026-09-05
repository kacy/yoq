const std = @import("std");
const types = @import("../raft_types.zig");
const bootstrap = @import("bootstrap.zig");
const logger = @import("../../lib/log.zig");

const LogIndex = types.LogIndex;
const SnapshotMeta = types.SnapshotMeta;
const snapshot_threshold: u64 = 1000;
pub const NodeId = types.NodeId;

pub fn maybeSnapshot(self: anytype) void {
    const applied_index = self.state_machine.last_applied;
    if (applied_index <= self.last_snapshot_index) return;
    if (applied_index - self.last_snapshot_index < snapshot_threshold) return;

    takeSnapshot(self, applied_index, self.log.termAt(applied_index));
}

/// The database contains exactly its last applied prefix. A queued request
/// cannot snapshot an older or newer index without mislabelling those bytes.
/// Call with the node lock held so applying entries cannot move the boundary.
pub fn takeSnapshot(self: anytype, index: LogIndex, term: types.Term) void {
    if (index != self.state_machine.last_applied or index <= self.last_snapshot_index) return;
    if (term == 0 or term != self.log.termAt(index)) return;

    var snap_path_buf: [512]u8 = undefined;
    const snap_path = bootstrap.snapshotPath(&snap_path_buf, self.config.data_dir) orelse return;

    const meta = SnapshotMeta{
        .last_included_index = index,
        .last_included_term = term,
        .data_len = 0,
    };

    self.state_machine.takeSnapshot(snap_path, meta) catch |e| {
        logger.warn("snapshot: failed to take snapshot at index {}: {}", .{ index, e });
        return;
    };

    if (!self.raft.onSnapshotComplete(meta)) {
        logger.warn("snapshot: failed to persist snapshot metadata at index {}", .{index});
        return;
    }
    if (!self.log.truncateUpTo(index)) {
        logger.warn("snapshot: failed to truncate raft log up to index {}", .{index});
        return;
    }
    self.last_snapshot_index = index;
    logger.info("snapshot: completed at index {}, term {}", .{ index, term });
}

pub fn sendSnapshot(self: anytype, target: NodeId, args: types.InstallSnapshotArgs) void {
    var snap_path_buf: [512]u8 = undefined;
    const snap_path = bootstrap.snapshotPath(&snap_path_buf, self.config.data_dir) orelse return;

    const data = std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, snap_path, self.alloc, .limited(64 * 1024 * 1024)) catch |e| {
        logger.warn("snapshot: failed to read snapshot file for node {}: {}", .{ target, e });
        return;
    };
    defer self.alloc.free(data);

    self.transport.send(target, .{
        .install_snapshot = .{
            .term = args.term,
            .leader_id = args.leader_id,
            .last_included_index = args.last_included_index,
            .last_included_term = args.last_included_term,
            .data = data,
        },
    }) catch |e| {
        logger.warn("failed to send snapshot to node {}: {}", .{ target, e });
    };
}
