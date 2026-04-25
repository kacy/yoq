const std = @import("std");
const types = @import("../raft_types.zig");
const bootstrap = @import("bootstrap.zig");
const logger = @import("../../lib/log.zig");

const LogIndex = types.LogIndex;
const SnapshotMeta = types.SnapshotMeta;
const snapshot_threshold: u64 = 1000;
pub const NodeId = types.NodeId;

pub fn maybeSnapshot(self: anytype) void {
    const commit_index = self.raft.commit_index;
    if (commit_index <= self.last_snapshot_index) return;
    if (commit_index - self.last_snapshot_index < snapshot_threshold) return;

    const term = self.log.termAt(commit_index);
    if (term == 0) return;

    var snap_path_buf: [512]u8 = undefined;
    const snap_path = bootstrap.snapshotPath(&snap_path_buf, self.config.data_dir) orelse return;

    const meta = SnapshotMeta{
        .last_included_index = commit_index,
        .last_included_term = term,
        .data_len = 0,
    };

    self.state_machine.takeSnapshot(snap_path, meta) catch |e| {
        logger.warn("snapshot: failed to take snapshot at index {}: {}", .{ commit_index, e });
        return;
    };

    if (!self.raft.onSnapshotComplete(meta)) {
        logger.warn("snapshot: failed to persist snapshot metadata at index {}", .{commit_index});
        return;
    }
    if (!self.log.truncateUpTo(commit_index)) {
        logger.warn("snapshot: failed to truncate raft log up to index {}", .{commit_index});
        return;
    }
    self.last_snapshot_index = commit_index;
    logger.info("snapshot: completed at index {}, term {}", .{ commit_index, term });
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
