const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const paths = @import("../../lib/paths.zig");
const syscall = @import("../../lib/syscall.zig");
const container = @import("../container.zig");
const process = @import("../process.zig");
const common = @import("common.zig");
const storage = @import("storage.zig");

pub const LogError = common.LogError;

pub fn followLogs(container_id: []const u8, tail_lines: usize, pid: ?posix.pid_t) LogError!void {
    return followLogsWithIo(std.Options.debug_io, container_id, tail_lines, pid);
}

pub fn followLogsWithIo(io: std.Io, container_id: []const u8, tail_lines: usize, pid: ?posix.pid_t) LogError!void {
    if (!container.isValidContainerId(container_id)) return LogError.InvalidId;

    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = try storage.logPath(&path_buf, container_id);

    var file = std.Io.Dir.cwd().openFile(io, file_path, .{}) catch return LogError.NotFound;
    defer file.close(io);

    var file_buffer: [4096]u8 = undefined;
    var file_reader = file.reader(io, &file_buffer);
    const tail = try prepareFollowStart(io, &file_reader, container_id, tail_lines);
    defer if (tail) |data| std.heap.page_allocator.free(data);
    if (tail) |data| {
        if (data.len > 0) try common.writeToStdoutWithIo(io, data);
    }

    const fd = @as(posix.fd_t, @intCast(syscall.unwrap(linux.inotify_init1(linux.IN.CLOEXEC)) catch return LogError.ReadFailed));

    var watch_path_buf: [paths.max_path]u8 = undefined;
    const watch_path = sentinelizePath(&watch_path_buf, file_path) catch return LogError.PathTooLong;
    const wd = linux.inotify_add_watch(fd, watch_path, linux.IN.MODIFY | linux.IN.CLOSE_WRITE | linux.IN.MOVE_SELF);
    _ = syscall.unwrap(wd) catch return LogError.ReadFailed;

    defer {
        _ = linux.inotify_rm_watch(fd, @intCast(wd));
        _ = linux.close(fd);
    }

    var event_buf: [4096]u8 align(@alignOf(linux.inotify_event)) = undefined;
    var read_buf: [4096]u8 = undefined;

    while (true) {
        if (drainNewBytes(io, &file_reader, &read_buf) == false and !isContainerPidRunning(io, container_id, pid)) break;
        _ = posix.read(fd, &event_buf) catch break;
    }

    _ = drainNewBytes(io, &file_reader, &read_buf);
}

fn prepareFollowStart(io: std.Io, file_reader: *std.Io.File.Reader, container_id: []const u8, tail_lines: usize) LogError!?[]const u8 {
    if (tail_lines > 0) {
        const tail = try storage.readTailWithIo(io, std.heap.page_allocator, container_id, tail_lines);
        errdefer std.heap.page_allocator.free(tail);

        try seekToEnd(file_reader);
        return tail;
    }

    try seekToEnd(file_reader);
    return null;
}

fn seekToEnd(file_reader: *std.Io.File.Reader) LogError!void {
    const end_pos = file_reader.getSize() catch return LogError.ReadFailed;
    file_reader.seekTo(end_pos) catch return LogError.ReadFailed;
}

fn drainNewBytes(io: std.Io, file_reader: *std.Io.File.Reader, buf: []u8) bool {
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);

    var out_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &out_buf);
    var saw_bytes = false;
    while (true) {
        const bytes_read = file_reader.interface.readSliceShort(buf) catch return saw_bytes;
        if (bytes_read == 0) break;
        saw_bytes = true;
        stdout_writer.interface.writeAll(buf[0..bytes_read]) catch return saw_bytes;
    }
    stdout_writer.interface.flush() catch return saw_bytes;
    return saw_bytes;
}

fn isContainerPidRunning(io: std.Io, container_id: []const u8, pid: ?posix.pid_t) bool {
    const proc_pid = pid orelse return false;
    if (!procCgroupMatchesContainer(io, proc_pid, container_id)) return false;
    process.sendSignal(proc_pid, 0) catch return false;
    return true;
}

fn procCgroupMatchesContainer(io: std.Io, pid: posix.pid_t, container_id: []const u8) bool {
    if (!container.isValidContainerId(container_id)) return false;

    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/cgroup", .{pid}) catch return false;

    var file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return false;
    defer file.close(io);

    var file_buf: [4096]u8 = undefined;
    var reader = file.reader(io, &file_buf);
    var content_buf: [4096]u8 = undefined;
    const bytes_read = reader.interface.readSliceShort(&content_buf) catch return false;
    return procCgroupContentMatchesContainer(content_buf[0..bytes_read], container_id);
}

fn procCgroupContentMatchesContainer(content: []const u8, container_id: []const u8) bool {
    var needle_buf: [32]u8 = undefined;
    const needle = std.fmt.bufPrint(&needle_buf, "/yoq/{s}", .{container_id}) catch return false;

    var start: usize = 0;
    while (std.mem.indexOfPos(u8, content, start, needle)) |idx| {
        const end = idx + needle.len;
        if (end == content.len or content[end] == '\n' or content[end] == '/') return true;
        start = idx + 1;
    }
    return false;
}

fn sentinelizePath(buf: *[paths.max_path]u8, path: []const u8) ![:0]const u8 {
    if (path.len >= buf.len) return error.PathTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0];
}

test "procCgroupContentMatchesContainer matches exact yoq cgroup path" {
    try std.testing.expect(procCgroupContentMatchesContainer("0::/yoq/deadbeefcafe\n", "deadbeefcafe"));
    try std.testing.expect(procCgroupContentMatchesContainer("0::/system.slice/yoq/deadbeefcafe/inner\n", "deadbeefcafe"));
    try std.testing.expect(!procCgroupContentMatchesContainer("0::/yoq/deadbeefcafe123\n", "deadbeefcafe"));
    try std.testing.expect(!procCgroupContentMatchesContainer("0::/user.slice\n", "deadbeefcafe"));
}

test "seekToEnd moves watched file to end" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    var file = tmp_dir.dir.createFile(std.testing.io, "follow.log", .{ .read = true }) catch unreachable;
    defer file.close(std.testing.io);

    try file.writeStreamingAll(std.testing.io, "one\ntwo\nthree\n");
    const end_pos = file.length(std.testing.io) catch unreachable;

    var file_buf: [128]u8 = undefined;
    var reader = file.reader(std.testing.io, &file_buf);
    try reader.seekTo(0);
    try seekToEnd(&reader);
    try std.testing.expectEqual(end_pos, reader.logicalPos());
}

test "followLogs validates container ID" {
    try std.testing.expectError(LogError.InvalidId, followLogs("../etc/passwd", 0, null));
}
