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

/// retain the selected recovery source and one older generation. callers hold
/// the node lock and invoke this only after selection and restore complete.
/// snapshot sends read their bytes before handing them to the transport, so
/// removing an older pathname cannot invalidate an in-flight transfer.
pub fn pruneSuperseded(data_dir: []const u8, selected: SnapshotMeta) !void {
    const io = std.Options.debug_io;
    var path_buffer: [512]u8 = undefined;
    const selected_path = try generationPath(&path_buffer, data_dir, selected);
    const actual = try artifact.readSnapshotMeta(selected_path);
    if (!sameBoundary(actual, selected) or (selected.data_len != 0 and actual.data_len != selected.data_len))
        return error.SnapshotMismatch;

    var directory = try std.Io.Dir.cwd().openDir(io, data_dir, .{ .iterate = true });
    defer directory.close(io);
    var previous: ?SnapshotMeta = null;
    var entries = directory.iterate();
    while (try entries.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const meta = parseGenerationName(entry.name) orelse continue;
        if (meta.last_included_index >= selected.last_included_index) continue;
        if (previous == null or newer(meta, previous.?)) previous = meta;
    }
    entries = directory.iterate();
    var removed = false;
    while (try entries.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const meta = parseGenerationName(entry.name) orelse continue;
        if (sameBoundary(meta, selected)) continue;
        if (previous) |keep| if (sameBoundary(meta, keep)) continue;
        try directory.deleteFile(io, entry.name);
        removed = true;
    }
    if (removed) try (@import("linux_platform").File{ .handle = directory.handle }).sync();
}

fn newer(left: SnapshotMeta, right: SnapshotMeta) bool {
    return left.last_included_index > right.last_included_index or
        (left.last_included_index == right.last_included_index and left.last_included_term > right.last_included_term);
}

fn parseGenerationName(name: []const u8) ?SnapshotMeta {
    if (!std.mem.startsWith(u8, name, "snapshot-") or !std.mem.endsWith(u8, name, ".dat")) return null;
    const boundary = name["snapshot-".len .. name.len - ".dat".len];
    const separator = std.mem.indexOfScalar(u8, boundary, '-') orelse return null;
    const index = std.fmt.parseInt(u64, boundary[0..separator], 10) catch return null;
    const term = std.fmt.parseInt(u64, boundary[separator + 1 ..], 10) catch return null;
    var expected: [64]u8 = undefined;
    const canonical = std.fmt.bufPrint(&expected, "snapshot-{d}-{d}.dat", .{ index, term }) catch return null;
    if (!std.mem.eql(u8, name, canonical)) return null;
    return .{ .last_included_index = index, .last_included_term = term, .data_len = 0 };
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

test "snapshot retention keeps the selected generation across cleanup and restart" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var directory_buffer: [512]u8 = undefined;
    const length = try tmp.dir.realPath(std.testing.io, &directory_buffer);
    const directory = directory_buffer[0..length];
    // retention only needs the durable header and boundary; full snapshot
    // validation belongs to capture, selection and restart recovery.
    for ([_]u64{ 1, 2, 3, 4 }) |index| {
        var header: [artifact.snapshot_header_size]u8 = @splat(0);
        std.mem.writeInt(u64, header[0..8], index, .little);
        std.mem.writeInt(u64, header[8..16], 1, .little);
        var path_buffer: [512]u8 = undefined;
        try artifact.publishBytes(try generationPath(&path_buffer, directory, .{
            .last_included_index = index,
            .last_included_term = 1,
            .data_len = 0,
        }), &header);
    }
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "unrelated.dat", .data = "keep" });
    const selected: SnapshotMeta = .{ .last_included_index = 3, .last_included_term = 1, .data_len = 0 };
    try pruneSuperseded(directory, selected);
    try tmp.dir.access(std.testing.io, "snapshot-3-1.dat", .{});
    try tmp.dir.access(std.testing.io, "snapshot-2-1.dat", .{});
    try tmp.dir.access(std.testing.io, "unrelated.dat", .{});
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "snapshot-1-1.dat", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "snapshot-4-1.dat", .{}));
    try pruneSuperseded(directory, selected);
    try tmp.dir.deleteFile(std.testing.io, "snapshot-3-1.dat");
    try std.testing.expectError(error.IoError, pruneSuperseded(directory, selected));
    try tmp.dir.access(std.testing.io, "snapshot-2-1.dat", .{});
}
