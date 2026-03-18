const std = @import("std");
const paths = @import("../../lib/paths.zig");
const container = @import("../container.zig");
const common = @import("common.zig");

pub const LogError = common.LogError;

pub fn logPath(buf: *[paths.max_path]u8, container_id: []const u8) LogError![]const u8 {
    if (!container.isValidContainerId(container_id)) return LogError.InvalidId;
    return paths.dataPathFmt(buf, "{s}/{s}.log", .{ common.logs_subdir, container_id }) catch
        return LogError.PathTooLong;
}

pub fn createLogFile(container_id: []const u8) LogError!std.fs.File {
    if (!container.isValidContainerId(container_id)) return LogError.InvalidId;

    paths.ensureDataDir(common.logs_subdir) catch {};

    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = try logPath(&path_buf, container_id);

    return std.fs.cwd().createFile(file_path, .{}) catch
        return LogError.CreateFailed;
}

pub fn readLogs(alloc: std.mem.Allocator, container_id: []const u8) LogError![]const u8 {
    if (!container.isValidContainerId(container_id)) return LogError.InvalidId;

    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = try logPath(&path_buf, container_id);

    const file = std.fs.cwd().openFile(file_path, .{}) catch
        return LogError.NotFound;
    defer file.close();

    return file.readToEndAlloc(alloc, 10 * 1024 * 1024) catch
        return LogError.ReadFailed;
}

pub fn readTail(alloc: std.mem.Allocator, container_id: []const u8, n: usize) LogError![]const u8 {
    if (!container.isValidContainerId(container_id)) return LogError.InvalidId;
    if (n == 0) return readLogs(alloc, container_id);

    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = try logPath(&path_buf, container_id);

    const file = std.fs.cwd().openFile(file_path, .{}) catch
        return LogError.NotFound;
    defer file.close();

    const file_size = file.getEndPos() catch return LogError.ReadFailed;
    if (file_size == 0) {
        return alloc.dupe(u8, "") catch return LogError.ReadFailed;
    }

    const tail_chunk_size: u64 = 64 * 1024;
    const read_size = @min(file_size, tail_chunk_size);
    const seek_pos = file_size - read_size;

    file.seekTo(seek_pos) catch return LogError.ReadFailed;

    const buf = alloc.alloc(u8, @intCast(read_size)) catch return LogError.ReadFailed;
    const bytes_read = file.readAll(buf) catch {
        alloc.free(buf);
        return LogError.ReadFailed;
    };
    const chunk = buf[0..bytes_read];

    const tail = extractLastNLines(chunk, n);
    if (tail.ptr != chunk.ptr) {
        const result = alloc.dupe(u8, tail) catch {
            alloc.free(buf);
            return LogError.ReadFailed;
        };
        alloc.free(buf);
        return result;
    }

    if (seek_pos == 0) return buf;

    alloc.free(buf);
    return readTailFull(alloc, container_id, n);
}

fn readTailFull(alloc: std.mem.Allocator, container_id: []const u8, n: usize) LogError![]const u8 {
    if (!container.isValidContainerId(container_id)) return LogError.InvalidId;

    const full = try readLogs(alloc, container_id);

    const tail = extractLastNLines(full, n);
    if (tail.ptr != full.ptr) {
        const result = alloc.dupe(u8, tail) catch {
            alloc.free(full);
            return LogError.ReadFailed;
        };
        alloc.free(full);
        return result;
    }

    return full;
}

pub fn extractLastNLines(data: []const u8, n: usize) []const u8 {
    var count: usize = 0;
    var pos: usize = data.len;
    while (pos > 0) {
        pos -= 1;
        if (data[pos] == '\n') {
            count += 1;
            if (count == n + 1) {
                return data[pos + 1 ..];
            }
        }
    }
    return data;
}

pub fn deleteLogFile(container_id: []const u8) void {
    if (!container.isValidContainerId(container_id)) return;

    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = logPath(&path_buf, container_id) catch return;
    std.fs.cwd().deleteFile(file_path) catch {};
}

test "logPath validates container ID" {
    var path_buf: [paths.max_path]u8 = undefined;

    _ = logPath(&path_buf, "abc123def456") catch |e| {
        try std.testing.expect(e != LogError.InvalidId);
    };

    try std.testing.expectError(LogError.InvalidId, logPath(&path_buf, "../etc/passwd"));
    try std.testing.expectError(LogError.InvalidId, logPath(&path_buf, "ABC123DEF456"));
    try std.testing.expectError(LogError.InvalidId, logPath(&path_buf, "short"));
}

test "createLogFile validates container ID" {
    try std.testing.expectError(LogError.InvalidId, createLogFile("../etc/passwd"));
    try std.testing.expectError(LogError.InvalidId, createLogFile("/etc/passwd"));
}

test "readLogs validates container ID" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(LogError.InvalidId, readLogs(alloc, "../etc/passwd"));
    try std.testing.expectError(LogError.InvalidId, readLogs(alloc, "invalid-id"));
}

test "readTail validates container ID" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(LogError.InvalidId, readTail(alloc, "../etc/passwd", 10));
    try std.testing.expectError(LogError.InvalidId, readTail(alloc, "invalid", 10));
}

test "deleteLogFile validates container ID" {
    deleteLogFile("../etc/passwd");
    deleteLogFile("invalid");
}
