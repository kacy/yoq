const std = @import("std");
const platform = @import("platform");
const sqlite = @import("sqlite");
const types = @import("../raft_types.zig");
const db_runtime = @import("db_runtime.zig");

const c = sqlite.c;
const LogIndex = types.LogIndex;
const SnapshotMeta = types.SnapshotMeta;

pub const SnapshotError = error{
    BackupFailed,
    IoError,
    InvalidSnapshot,
    CorruptSnapshot,
};

pub fn parseSnapshotMeta(data: []const u8) SnapshotError!SnapshotMeta {
    if (data.len < snapshot_header_size) return SnapshotError.InvalidSnapshot;
    const last_included_index = std.mem.readInt(u64, data[0..8], .little);
    const last_included_term = std.mem.readInt(u64, data[8..16], .little);
    const sqlite_data_len = std.mem.readInt(u64, data[16..24], .little);
    if (sqlite_data_len > max_snapshot_size) return SnapshotError.InvalidSnapshot;
    if (data.len != snapshot_header_size + sqlite_data_len) return SnapshotError.CorruptSnapshot;
    return .{
        .last_included_index = last_included_index,
        .last_included_term = last_included_term,
        .data_len = sqlite_data_len,
    };
}

pub const snapshot_header_size = 24;
pub const max_snapshot_size: u64 = 64 * 1024 * 1024;

pub fn readSnapshotMeta(path: []const u8) SnapshotError!SnapshotMeta {
    var file = std.Io.Dir.cwd().openFile(std.Options.debug_io, path, .{}) catch return SnapshotError.IoError;
    defer file.close(std.Options.debug_io);

    var header: [snapshot_header_size]u8 = undefined;
    var reader = file.reader(std.Options.debug_io, &.{});
    reader.interface.readSliceAll(&header) catch return SnapshotError.InvalidSnapshot;

    return .{
        .last_included_index = std.mem.readInt(u64, header[0..8], .little),
        .last_included_term = std.mem.readInt(u64, header[8..16], .little),
        .data_len = std.mem.readInt(u64, header[16..24], .little),
    };
}

pub fn takeSnapshot(self: anytype, dest_path: []const u8, meta: SnapshotMeta) SnapshotError!void {
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

    _ = c.sqlite3_close(dest_db);
    dest_db = null;

    const tmp_data = std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, tmp.path, std.heap.page_allocator, .limited(@intCast(max_snapshot_size))) catch {
        return SnapshotError.IoError;
    };
    defer std.heap.page_allocator.free(tmp_data);

    var file = std.Io.Dir.cwd().createFile(std.Options.debug_io, dest_path, .{
        .permissions = std.Io.File.Permissions.fromMode(0o600),
        .truncate = true,
    }) catch return SnapshotError.IoError;
    defer file.close(std.Options.debug_io);

    var header: [snapshot_header_size]u8 = undefined;
    std.mem.writeInt(u64, header[0..8], meta.last_included_index, .little);
    std.mem.writeInt(u64, header[8..16], meta.last_included_term, .little);
    std.mem.writeInt(u64, header[16..24], @intCast(tmp_data.len), .little);

    file.writeStreamingAll(std.Options.debug_io, &header) catch return SnapshotError.IoError;
    file.writeStreamingAll(std.Options.debug_io, tmp_data) catch return SnapshotError.IoError;
}

pub fn restoreFromSnapshot(self: anytype, src_path: []const u8) SnapshotError!SnapshotMeta {
    const data = std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, src_path, std.heap.page_allocator, .limited(@intCast(max_snapshot_size))) catch {
        return SnapshotError.IoError;
    };
    defer std.heap.page_allocator.free(data);
    return restoreFromBytes(self, data);
}

pub fn restoreFromBytes(self: anytype, data: []const u8) SnapshotError!SnapshotMeta {
    if (data.len < snapshot_header_size) return SnapshotError.InvalidSnapshot;

    const last_included_index = std.mem.readInt(u64, data[0..8], .little);
    const last_included_term = std.mem.readInt(u64, data[8..16], .little);
    const sqlite_data_len = std.mem.readInt(u64, data[16..24], .little);
    if (sqlite_data_len > max_snapshot_size) return SnapshotError.InvalidSnapshot;
    if (data.len != snapshot_header_size + sqlite_data_len) return SnapshotError.CorruptSnapshot;

    const sqlite_data = data[snapshot_header_size .. snapshot_header_size + sqlite_data_len];

    var tmp_path_buf: [128]u8 = undefined;
    var tmp = try createUniqueTempFile(&tmp_path_buf, "/tmp/yoq_snap_restore", ".db");
    defer std.Io.Dir.cwd().deleteFile(std.Options.debug_io, tmp.path) catch {};
    tmp.file.writeStreamingAll(std.Options.debug_io, sqlite_data) catch return SnapshotError.IoError;
    tmp.file.close(std.Options.debug_io);

    var src_db: ?*c.sqlite3 = null;
    defer {
        if (src_db) |db| _ = c.sqlite3_close(db);
    }

    const open_rc = c.sqlite3_open(tmp.path.ptr, &src_db);
    if (open_rc != c.SQLITE_OK or src_db == null) return SnapshotError.BackupFailed;

    const backup = c.sqlite3_backup_init(self.db.db, "main", src_db, "main");
    if (backup == null) return SnapshotError.BackupFailed;

    const step_rc = c.sqlite3_backup_step(backup, -1);
    const finish_rc = c.sqlite3_backup_finish(backup);
    if (step_rc != c.SQLITE_DONE or finish_rc != c.SQLITE_OK) return SnapshotError.BackupFailed;

    const meta = SnapshotMeta{
        .last_included_index = last_included_index,
        .last_included_term = last_included_term,
        .data_len = sqlite_data_len,
    };
    db_runtime.setLastApplied(&self.db, last_included_index) catch return SnapshotError.BackupFailed;
    self.last_applied = last_included_index;
    return meta;
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
    platform.randomBytes(&bytes);
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
