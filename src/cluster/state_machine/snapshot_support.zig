const std = @import("std");
const linux_platform = @import("linux_platform");
const sqlite = @import("sqlite");
const types = @import("../raft_types.zig");

const c = sqlite.c;
const SnapshotMeta = types.SnapshotMeta;

pub const SnapshotError = error{
    BackupFailed,
    IoError,
    InvalidSnapshot,
    CorruptSnapshot,
    SnapshotConflict,
};

pub fn parseSnapshotMeta(data: []const u8) SnapshotError!SnapshotMeta {
    return parseHeader(data, data.len);
}

fn parseHeader(data: []const u8, file_size: u64) SnapshotError!SnapshotMeta {
    if (data.len < snapshot_header_size) return SnapshotError.InvalidSnapshot;
    const last_included_index = std.mem.readInt(u64, data[0..8], .little);
    const last_included_term = std.mem.readInt(u64, data[8..16], .little);
    const sqlite_data_len = std.mem.readInt(u64, data[16..24], .little);
    if (last_included_index > std.math.maxInt(i64) or last_included_term > std.math.maxInt(i64)) return SnapshotError.InvalidSnapshot;
    if (sqlite_data_len > max_snapshot_size) return SnapshotError.InvalidSnapshot;
    if (file_size != snapshot_header_size + sqlite_data_len) return SnapshotError.CorruptSnapshot;
    return .{
        .last_included_index = last_included_index,
        .last_included_term = last_included_term,
        .data_len = sqlite_data_len,
    };
}

pub const snapshot_header_size = 24;
pub const max_snapshot_size: u64 = 64 * 1024 * 1024;

pub const max_snapshot_file_size: usize = @intCast(max_snapshot_size + snapshot_header_size);

pub fn readBytes(alloc: std.mem.Allocator, path: []const u8) SnapshotError![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, path, alloc, .limited(max_snapshot_file_size)) catch return SnapshotError.IoError;
}

pub fn readSnapshotMeta(path: []const u8) SnapshotError!SnapshotMeta {
    var file = std.Io.Dir.cwd().openFile(std.Options.debug_io, path, .{}) catch return SnapshotError.IoError;
    defer file.close(std.Options.debug_io);
    const stat = file.stat(std.Options.debug_io) catch return SnapshotError.IoError;
    var header: [snapshot_header_size]u8 = undefined;
    var reader = file.reader(std.Options.debug_io, &.{});
    reader.interface.readSliceAll(&header) catch return SnapshotError.InvalidSnapshot;
    return parseHeader(&header, stat.size);
}

/// A generation is immutable. Its directory entry must be durable before the
/// raft database selects it and deletes the log entries it replaces.
pub fn publishBytes(path: []const u8, data: []const u8) SnapshotError!void {
    _ = try parseSnapshotMeta(data);
    // Request a readable directory descriptor: Linux O_PATH handles cannot
    // be synced, and publication is not durable until the directory is synced.
    var dir = std.Io.Dir.cwd().openDir(std.Options.debug_io, std.fs.path.dirname(path) orelse ".", .{ .iterate = true }) catch return SnapshotError.IoError;
    defer dir.close(std.Options.debug_io);
    var file = dir.createFileAtomic(std.Options.debug_io, std.fs.path.basename(path), .{
        .permissions = std.Io.File.Permissions.fromMode(0o600),
    }) catch return SnapshotError.IoError;
    defer file.deinit(std.Options.debug_io);
    file.file.writeStreamingAll(std.Options.debug_io, data) catch return SnapshotError.IoError;
    file.file.sync(std.Options.debug_io) catch return SnapshotError.IoError;
    file.link(std.Options.debug_io) catch |err| {
        if (err != error.PathAlreadyExists) return SnapshotError.IoError;
        const existing = try readBytes(std.heap.page_allocator, path);
        defer std.heap.page_allocator.free(existing);
        if (!std.mem.eql(u8, existing, data)) return SnapshotError.SnapshotConflict;
    };
    (linux_platform.File{ .handle = dir.handle }).sync() catch return SnapshotError.IoError;
}

/// Raft identifies state by index and term, not SQLite's physical layout. A
/// previous attempt may have published equivalent bytes before activation
/// failed. Keep that validated generation and return its exact database.
pub fn publishSnapshot(path: []const u8, data: []const u8) SnapshotError!PreparedSnapshot {
    var incoming = try PreparedSnapshot.init(data);
    errdefer incoming.deinit();
    publishBytes(path, data) catch |err| {
        if (err != error.SnapshotConflict) return err;
        const existing = try readBytes(std.heap.page_allocator, path);
        defer std.heap.page_allocator.free(existing);
        var retained = try PreparedSnapshot.init(existing);
        errdefer retained.deinit();
        if (retained.meta.last_included_index != incoming.meta.last_included_index or
            retained.meta.last_included_term != incoming.meta.last_included_term)
            return SnapshotError.SnapshotConflict;
        // Retry the durability barrier too: the earlier attempt may have
        // linked the generation but failed to sync its directory.
        try publishBytes(path, existing);
        incoming.deinit();
        return retained;
    };
    return incoming;
}

pub fn takeSnapshot(self: anytype, dest_path: []const u8, meta: SnapshotMeta) SnapshotError!void {
    if (meta.last_included_index != self.last_applied or meta.last_included_index > std.math.maxInt(i64) or meta.last_included_term > std.math.maxInt(i64)) return SnapshotError.InvalidSnapshot;
    var tmp_path_buf: [512]u8 = undefined;
    var tmp = try createUniqueTempFile(&tmp_path_buf, dest_path, ".tmp");
    defer std.Io.Dir.cwd().deleteFile(std.Options.debug_io, tmp.path) catch {};
    tmp.file.close(std.Options.debug_io);

    var dest_db: ?*c.sqlite3 = null;
    defer {
        if (dest_db) |db| _ = c.sqlite3_close(db);
    }

    const open_rc = c.sqlite3_open(tmp.path.ptr, &dest_db);
    if (open_rc != c.SQLITE_OK or dest_db == null) return SnapshotError.BackupFailed;

    const backup = c.sqlite3_backup_init(dest_db, "main", self.db.db, "main");
    if (backup == null) return SnapshotError.BackupFailed;

    const step_rc = c.sqlite3_backup_step(backup, -1);
    const finish_rc = c.sqlite3_backup_finish(backup);
    if (step_rc != c.SQLITE_DONE or finish_rc != c.SQLITE_OK) return SnapshotError.BackupFailed;

    try validateDatabase(dest_db, meta.last_included_index);

    _ = c.sqlite3_close(dest_db);
    dest_db = null;

    const tmp_data = std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, tmp.path, std.heap.page_allocator, .limited(@intCast(max_snapshot_size))) catch {
        return SnapshotError.IoError;
    };
    defer std.heap.page_allocator.free(tmp_data);

    const data = std.heap.page_allocator.alloc(u8, snapshot_header_size + tmp_data.len) catch return SnapshotError.IoError;
    defer std.heap.page_allocator.free(data);
    std.mem.writeInt(u64, data[0..8], meta.last_included_index, .little);
    std.mem.writeInt(u64, data[8..16], meta.last_included_term, .little);
    std.mem.writeInt(u64, data[16..24], @intCast(tmp_data.len), .little);
    @memcpy(data[snapshot_header_size..], tmp_data);
    var published = try publishSnapshot(dest_path, data);
    published.deinit();
}

pub fn restoreFromSnapshot(self: anytype, src_path: []const u8) SnapshotError!SnapshotMeta {
    const data = try readBytes(std.heap.page_allocator, src_path);
    defer std.heap.page_allocator.free(data);
    return restoreFromBytes(self, data);
}

/// Both local and received snapshots must describe an intact database whose
/// replay position agrees with the advertised boundary. Never relabel bytes.
fn validateDatabase(db: ?*c.sqlite3, index: u64) SnapshotError!void {
    var check: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "PRAGMA quick_check;", -1, &check, null) != c.SQLITE_OK) return SnapshotError.CorruptSnapshot;
    defer _ = c.sqlite3_finalize(check);
    if (c.sqlite3_step(check) != c.SQLITE_ROW) return SnapshotError.CorruptSnapshot;
    const result = c.sqlite3_column_text(check, 0);
    if (result == null or !std.mem.eql(u8, std.mem.span(result), "ok")) return SnapshotError.CorruptSnapshot;
    if (c.sqlite3_step(check) != c.SQLITE_DONE) return SnapshotError.CorruptSnapshot;
    var position: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT last_applied FROM state_machine_meta WHERE id = 1;", -1, &position, null) != c.SQLITE_OK) return SnapshotError.CorruptSnapshot;
    defer _ = c.sqlite3_finalize(position);
    if (c.sqlite3_step(position) != c.SQLITE_ROW or c.sqlite3_column_int64(position, 0) != @as(i64, @intCast(index))) return SnapshotError.CorruptSnapshot;
}

/// Validate the complete SQLite image before selecting a received generation.
/// The same staged database is then used for the atomic SQLite backup restore.
pub const PreparedSnapshot = struct {
    db: ?*c.sqlite3 = null,
    path: [128]u8 = undefined,
    path_len: usize = 0,
    meta: SnapshotMeta,

    pub fn init(data: []const u8) SnapshotError!PreparedSnapshot {
        var prepared: PreparedSnapshot = .{ .meta = try parseSnapshotMeta(data) };
        var tmp = try createUniqueTempFile(&prepared.path, "/tmp/yoq_snap_restore", ".db");
        prepared.path_len = tmp.path.len;
        errdefer std.Io.Dir.cwd().deleteFile(std.Options.debug_io, tmp.path) catch {};
        {
            defer tmp.file.close(std.Options.debug_io);
            tmp.file.writeStreamingAll(std.Options.debug_io, data[snapshot_header_size..]) catch return SnapshotError.IoError;
        }
        if (c.sqlite3_open_v2(tmp.path.ptr, &prepared.db, c.SQLITE_OPEN_READONLY, null) != c.SQLITE_OK or prepared.db == null) {
            if (prepared.db) |db| _ = c.sqlite3_close(db);
            return SnapshotError.CorruptSnapshot;
        }
        errdefer _ = c.sqlite3_close(prepared.db);
        try validateDatabase(prepared.db, prepared.meta.last_included_index);
        return prepared;
    }

    pub fn deinit(self: *PreparedSnapshot) void {
        if (self.db) |db| _ = c.sqlite3_close(db);
        std.Io.Dir.cwd().deleteFile(std.Options.debug_io, self.path[0..self.path_len]) catch {};
    }

    pub fn restore(self: *PreparedSnapshot, target: anytype) SnapshotError!void {
        const backup = c.sqlite3_backup_init(target.db.db, "main", self.db, "main") orelse return SnapshotError.BackupFailed;
        const step_rc = c.sqlite3_backup_step(backup, -1);
        const finish_rc = c.sqlite3_backup_finish(backup);
        if (step_rc != c.SQLITE_DONE or finish_rc != c.SQLITE_OK) return SnapshotError.BackupFailed;
        target.last_applied = self.meta.last_included_index;
    }
};

pub fn restoreFromBytes(self: anytype, data: []const u8) SnapshotError!SnapshotMeta {
    var prepared = try PreparedSnapshot.init(data);
    defer prepared.deinit();
    try prepared.restore(self);
    return prepared.meta;
}

fn createUniqueTempFile(buf: []u8, prefix: []const u8, suffix: []const u8) SnapshotError!struct {
    path: [:0]const u8,
    file: std.Io.File,
} {
    var attempts: usize = 0;
    while (attempts < 16) : (attempts += 1) {
        const slice = std.fmt.bufPrint(buf, "{s}.{x}{s}", .{ prefix, randomU64(), suffix }) catch {
            return SnapshotError.IoError;
        };
        if (slice.len >= buf.len) return SnapshotError.IoError;
        buf[slice.len] = 0;
        const path: [:0]const u8 = buf[0..slice.len :0];
        const file = std.Io.Dir.cwd().createFile(std.Options.debug_io, path, .{
            .permissions = std.Io.File.Permissions.fromMode(0o600),
            .exclusive = true,
        }) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => return SnapshotError.IoError,
        };
        return .{ .path = path, .file = file };
    }
    return SnapshotError.IoError;
}

fn randomU64() u64 {
    var bytes: [8]u8 = undefined;
    linux_platform.randomBytes(&bytes);
    return std.mem.readInt(u64, &bytes, .little);
}

test "createUniqueTempFile uses owner-only permissions" {
    var buf: [128]u8 = undefined;
    var tmp = try createUniqueTempFile(&buf, "/tmp/yoq-snapshot-perm-test", ".db");
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, tmp.path) catch {};
    defer tmp.file.close(std.testing.io);

    const stat = try tmp.file.stat(std.testing.io);
    try std.testing.expectEqual(@as(u32, 0), stat.permissions.toMode() & 0o077);
}

test "snapshot generation publication is immutable and leaves no temporary files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [512]u8 = undefined;
    const dir_len = try tmp.dir.realPath(std.testing.io, &dir_buf);
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/generation.dat", .{dir_buf[0..dir_len]});
    var data: [snapshot_header_size + 4]u8 = undefined;
    std.mem.writeInt(u64, data[0..8], 5, .little);
    std.mem.writeInt(u64, data[8..16], 2, .little);
    std.mem.writeInt(u64, data[16..24], 4, .little);
    @memcpy(data[snapshot_header_size..], "old!");
    try publishBytes(path, &data);
    try publishBytes(path, &data);
    @memcpy(data[snapshot_header_size..], "new!");
    try std.testing.expectError(error.SnapshotConflict, publishBytes(path, &data));
    const existing = try readBytes(std.testing.allocator, path);
    defer std.testing.allocator.free(existing);
    try std.testing.expectEqualStrings("old!", existing[snapshot_header_size..]);
    var dir = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer dir.close(std.testing.io);
    var iter = dir.iterate();
    var count: usize = 0;
    while (try iter.next(std.testing.io)) |entry| {
        try std.testing.expectEqualStrings("generation.dat", entry.name);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), count);
}
