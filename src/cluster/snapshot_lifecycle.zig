//! A snapshot moves through three durable states: an immutable published file,
//! selection in the Raft log transaction, and restoration of the state database.
//! Publication alone changes no committed state. Once selected, the generation
//! is the recovery source until the state database reaches its applied boundary.
const std = @import("std");
const artifact = @import("state_machine/snapshot_support.zig");
const SnapshotMeta = @import("raft_types.zig").SnapshotMeta;

pub fn generationPath(buf: []u8, data_dir: []const u8, meta: SnapshotMeta) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/snapshot-{d}-{d}.dat", .{ data_dir, meta.last_included_index, meta.last_included_term });
}

pub fn sameBoundary(a: SnapshotMeta, b: SnapshotMeta) bool {
    return a.last_included_index == b.last_included_index and a.last_included_term == b.last_included_term;
}

/// Read the selected generation, not the newest file in the directory. An
/// unselected generation can be left behind by a crash before activation.
pub fn readSelected(alloc: std.mem.Allocator, data_dir: []const u8, selected: SnapshotMeta) ![]u8 {
    var path_buf: [512]u8 = undefined;
    const path = try generationPath(&path_buf, data_dir, selected);
    const data = std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, path, alloc, .limited(artifact.max_snapshot_file_size)) catch |err| blk: {
        if (err != error.FileNotFound) return err;
        // Older releases wrote one snapshot.dat and recorded a zero length.
        // Only that legacy record may migrate, and its boundary must match.
        if (selected.data_len != 0) return error.MissingSnapshot;
        var legacy_buf: [512]u8 = undefined;
        const legacy = try std.fmt.bufPrint(&legacy_buf, "{s}/snapshot.dat", .{data_dir});
        break :blk try artifact.readBytes(alloc, legacy);
    };
    errdefer alloc.free(data);
    const actual = try artifact.parseSnapshotMeta(data);
    if (!sameBoundary(actual, selected) or (selected.data_len != 0 and selected.data_len != actual.data_len)) return error.SnapshotMismatch;
    return data;
}

pub const Generation = struct {
    prepared: artifact.PreparedSnapshot,
    phase: enum { published, selected, restored } = .published,

    pub fn capture(state_machine: anytype, data_dir: []const u8, meta: SnapshotMeta) !Generation {
        var path_buf: [512]u8 = undefined;
        const path = try generationPath(&path_buf, data_dir, meta);
        return .{ .prepared = try artifact.captureSnapshot(state_machine, path, meta) };
    }

    pub fn receive(data_dir: []const u8, data: []const u8) !Generation {
        const meta = try artifact.parseSnapshotMeta(data);
        var path_buf: [512]u8 = undefined;
        const path = try generationPath(&path_buf, data_dir, meta);
        return .{ .prepared = try artifact.publishSnapshot(path, data) };
    }

    /// Reconstruct progress from durable metadata, never an in-memory marker.
    /// Legacy records first publish the same generation format as new snapshots.
    pub fn recoverSelected(alloc: std.mem.Allocator, data_dir: []const u8, log: anytype) !?Generation {
        const selected = (try log.readSnapshotMeta()) orelse return null;
        const data = try readSelected(alloc, data_dir, selected);
        defer alloc.free(data);
        if (selected.data_len == 0) return try receive(data_dir, data);
        return .{ .prepared = try artifact.PreparedSnapshot.init(data), .phase = .selected };
    }

    pub fn deinit(self: *Generation) void {
        self.prepared.deinit();
    }

    /// Selection and compaction commit together only after durable publication.
    /// A failed transaction leaves the generation published but unselected.
    pub fn select(self: *Generation, log: anytype) !void {
        if (self.phase != .published) return;
        try log.activateSnapshot(self.prepared.meta);
        self.phase = .selected;
    }

    /// Skipping an already applied boundary preserves both local snapshot state
    /// and entries replayed after a selected snapshot on an earlier startup.
    pub fn restore(self: *Generation, state_machine: anytype) !void {
        if (self.phase == .published) return error.SnapshotNotSelected;
        if (self.phase == .restored) return;
        if (state_machine.last_applied < self.prepared.meta.last_included_index) try self.prepared.restore(state_machine);
        self.phase = .restored;
    }

    pub fn finish(self: *Generation, log: anytype, state_machine: anytype) !void {
        try self.select(log);
        try self.restore(state_machine);
    }
};
