// store — persistent container state
//
// stores container metadata to disk so we can list containers,
// check their status, and recover after restarts. uses a simple
// JSON file per container under ~/.local/share/yoq/containers/.
//
// each container gets a file named <id>.json containing its
// config, status, pid, and timestamps.

const std = @import("std");

pub const StoreError = error{
    WriteFailed,
    ReadFailed,
    NotFound,
    InvalidData,
    PathTooLong,
};

/// persisted container record
pub const ContainerRecord = struct {
    id: []const u8,
    rootfs: []const u8,
    command: []const u8,
    hostname: []const u8,
    status: []const u8,
    pid: ?i32,
    exit_code: ?u8,
    created_at: i64,
};

const data_dir = ".local/share/yoq/containers";

/// get the full path to the store directory.
/// creates it if it doesn't exist.
pub fn ensureStoreDir(alloc: std.mem.Allocator) ![]const u8 {
    const home = std.posix.getenv("HOME") orelse "/tmp";
    const path = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ home, data_dir });

    std.fs.cwd().makePath(path) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return StoreError.WriteFailed,
    };

    return path;
}

/// save a container record to disk
pub fn save(alloc: std.mem.Allocator, record: ContainerRecord) StoreError!void {
    const dir_path = ensureStoreDir(alloc) catch return StoreError.WriteFailed;
    defer alloc.free(dir_path);

    var path_buf: [512]u8 = undefined;
    const file_path = std.fmt.bufPrint(&path_buf, "{s}/{s}.json", .{
        dir_path,
        record.id,
    }) catch return StoreError.PathTooLong;

    // build JSON manually to avoid pulling in a full JSON library
    var buf: [2048]u8 = undefined;
    const json = std.fmt.bufPrint(&buf,
        \\{{
        \\  "id": "{s}",
        \\  "rootfs": "{s}",
        \\  "command": "{s}",
        \\  "hostname": "{s}",
        \\  "status": "{s}",
        \\  "pid": {s},
        \\  "exit_code": {s},
        \\  "created_at": {d}
        \\}}
        \\
    , .{
        record.id,
        record.rootfs,
        record.command,
        record.hostname,
        record.status,
        if (record.pid) |p| fmtInt(p) else "null",
        if (record.exit_code) |c| fmtInt(c) else "null",
        record.created_at,
    }) catch return StoreError.WriteFailed;

    const file = std.fs.cwd().createFile(file_path, .{}) catch
        return StoreError.WriteFailed;
    defer file.close();
    file.writeAll(json) catch return StoreError.WriteFailed;
}

/// delete a container record from disk
pub fn remove(alloc: std.mem.Allocator, id: []const u8) StoreError!void {
    const dir_path = ensureStoreDir(alloc) catch return StoreError.WriteFailed;
    defer alloc.free(dir_path);

    var path_buf: [512]u8 = undefined;
    const file_path = std.fmt.bufPrint(&path_buf, "{s}/{s}.json", .{
        dir_path,
        id,
    }) catch return StoreError.PathTooLong;

    std.fs.cwd().deleteFile(file_path) catch return StoreError.NotFound;
}

/// list all container IDs in the store
pub fn listIds(alloc: std.mem.Allocator) !std.ArrayList([]const u8) {
    const dir_path = try ensureStoreDir(alloc);
    defer alloc.free(dir_path);

    var ids: std.ArrayList([]const u8) = .empty;

    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch
        return ids;

    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".json")) continue;

        // strip .json extension to get the id
        const name_len = entry.name.len - 5; // ".json" = 5 chars
        const id = try alloc.dupe(u8, entry.name[0..name_len]);
        try ids.append(alloc, id);
    }

    return ids;
}

/// format a small integer into a static buffer for JSON output
fn fmtInt(value: anytype) []const u8 {
    const S = struct {
        threadlocal var buf: [20]u8 = undefined;
    };
    const result = std.fmt.bufPrint(&S.buf, "{d}", .{value}) catch "0";
    return result;
}

// -- tests --

test "container record defaults" {
    const record = ContainerRecord{
        .id = "abc123",
        .rootfs = "/tmp/rootfs",
        .command = "/bin/sh",
        .hostname = "test",
        .status = "created",
        .pid = null,
        .exit_code = null,
        .created_at = 1234567890,
    };

    try std.testing.expectEqualStrings("abc123", record.id);
    try std.testing.expect(record.pid == null);
    try std.testing.expect(record.exit_code == null);
}

test "fmtInt" {
    const result = fmtInt(@as(i32, 42));
    try std.testing.expectEqualStrings("42", result);
}

test "fmtInt negative" {
    const result = fmtInt(@as(i32, -1));
    try std.testing.expectEqualStrings("-1", result);
}

test "store dir path" {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const path = ensureStoreDir(alloc) catch {
        // may fail in test environments without HOME
        return;
    };
    defer alloc.free(path);

    try std.testing.expect(std.mem.endsWith(u8, path, "yoq/containers"));
}
