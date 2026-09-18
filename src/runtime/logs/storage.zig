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

pub fn createLogFile(container_id: []const u8) LogError!std.Io.File {
    if (!container.isValidContainerId(container_id)) return LogError.InvalidId;

    paths.ensureDataDirWithIo(std.Options.debug_io, common.logs_subdir) catch {};

    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = try logPath(&path_buf, container_id);

    return std.Io.Dir.cwd().createFile(std.Options.debug_io, file_path, .{ .read = true, .truncate = false }) catch
        return LogError.CreateFailed;
}

pub fn readLogs(alloc: std.mem.Allocator, container_id: []const u8) LogError![]const u8 {
    return readLogsWithIo(std.Options.debug_io, alloc, container_id);
}

pub fn readLogsWithIo(io: std.Io, alloc: std.mem.Allocator, container_id: []const u8) LogError![]const u8 {
    if (!container.isValidContainerId(container_id)) return LogError.InvalidId;

    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = try logPath(&path_buf, container_id);

    return std.Io.Dir.cwd().readFileAlloc(io, file_path, alloc, .limited(common.max_log_size)) catch |err| switch (err) {
        error.FileNotFound => return LogError.NotFound,
        else => return LogError.ReadFailed,
    };
}

pub fn readTail(alloc: std.mem.Allocator, container_id: []const u8, n: usize) LogError![]const u8 {
    return readTailWithIo(std.Options.debug_io, alloc, container_id, n);
}

pub fn readTailWithIo(io: std.Io, alloc: std.mem.Allocator, container_id: []const u8, n: usize) LogError![]const u8 {
    if (!container.isValidContainerId(container_id)) return LogError.InvalidId;
    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = try logPath(&path_buf, container_id);
    const file = std.Io.Dir.cwd().openFile(io, file_path, .{}) catch return LogError.NotFound;
    defer file.close(io);
    const end = file.length(io) catch return LogError.ReadFailed;
    const start = try tailStart(io, file, end, n);
    const data = alloc.alloc(u8, @intCast(end - start)) catch return LogError.ReadFailed;
    errdefer alloc.free(data);
    var reader = file.reader(io, &.{});
    reader.seekTo(start) catch return LogError.ReadFailed;
    reader.interface.readSliceAll(data) catch return LogError.ReadFailed;
    return data;
}

/// Stream one snapshot of the current log generation with bounded memory.
/// A missing tail count means all lines; zero means no history.
pub fn streamLogsWithIo(io: std.Io, container_id: []const u8, tail_lines: ?usize) LogError!void {
    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = try logPath(&path_buf, container_id);
    const file = std.Io.Dir.cwd().openFile(io, file_path, .{}) catch return LogError.NotFound;
    defer file.close(io);
    const end = file.length(io) catch return LogError.ReadFailed;
    const start = if (tail_lines) |n| try tailStart(io, file, end, n) else 0;
    var reader = file.reader(io, &.{});
    reader.seekTo(start) catch return LogError.ReadFailed;
    var remaining = end - start;
    var buffer: [64 * 1024]u8 = undefined;
    while (remaining > 0) {
        const count = reader.interface.readSliceShort(buffer[0..@min(buffer.len, remaining)]) catch return LogError.ReadFailed;
        if (count == 0) return LogError.ReadFailed;
        try common.writeToStdoutWithIo(io, buffer[0..count]);
        remaining -= count;
    }
}

/// Scan backwards on the same open file used by the reader. This avoids a
/// second pathname lookup racing with rotation and works for arbitrarily long lines.
pub fn tailStart(io: std.Io, file: std.Io.File, end: u64, n: usize) LogError!u64 {
    if (n == 0) return end;
    var position = end;
    var lines: usize = 0;
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &.{});
    while (position > 0) {
        const count: usize = @intCast(@min(position, buffer.len));
        position -= count;
        reader.seekTo(position) catch return LogError.ReadFailed;
        reader.interface.readSliceAll(buffer[0..count]) catch return LogError.ReadFailed;
        var i = count;
        while (i > 0) {
            i -= 1;
            if (buffer[i] == '\n' and position + i + 1 != end) {
                lines += 1;
                if (lines == n) return position + i + 1;
            }
        }
    }
    return 0;
}

pub fn extractLastNLines(data: []const u8, n: usize) []const u8 {
    if (n == 0) return data[data.len..];
    var count: usize = 0;
    var pos = data.len;
    while (pos > 0) {
        pos -= 1;
        if (data[pos] == '\n' and pos + 1 != data.len) {
            count += 1;
            if (count == n) return data[pos + 1 ..];
        }
    }
    return data;
}

pub fn deleteLogFile(container_id: []const u8) void {
    if (!container.isValidContainerId(container_id)) return;

    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = logPath(&path_buf, container_id) catch return;
    std.Io.Dir.cwd().deleteFile(std.Options.debug_io, file_path) catch {};
    var previous_buf: [paths.max_path]u8 = undefined;
    const previous = std.fmt.bufPrint(&previous_buf, "{s}.1", .{file_path}) catch return;
    std.Io.Dir.cwd().deleteFile(std.Options.debug_io, previous) catch {};
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

test "log tail handles zero, unterminated lines, empty lines, and maximum count" {
    try std.testing.expectEqualStrings("", extractLastNLines("one\ntwo\n", 0));
    try std.testing.expectEqualStrings("two\n", extractLastNLines("one\ntwo\n", 1));
    try std.testing.expectEqualStrings("two", extractLastNLines("one\ntwo", 1));
    try std.testing.expectEqualStrings("\n", extractLastNLines("one\n\n", 1));
    try std.testing.expectEqualStrings("one\ntwo", extractLastNLines("one\ntwo", std.math.maxInt(usize)));
}

test "log tail scans past 64 KiB and the former whole-log size limit" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "large.log", .{ .read = true });
    defer file.close(io);
    try file.writeStreamingAll(io, "first\n");
    const block = "x" ** (64 * 1024);
    for (0..161) |_| try file.writeStreamingAll(io, block);
    try file.writeStreamingAll(io, "\nlast");
    const end = try file.length(io);
    try std.testing.expectEqual(end, try tailStart(io, file, end, 0));
    try std.testing.expectEqual(end - 4, try tailStart(io, file, end, 1));
    try std.testing.expectEqual(@as(u64, 6), try tailStart(io, file, end, 2));
    try std.testing.expectEqual(@as(u64, 0), try tailStart(io, file, end, 3));
}
