// logs — runtime logs facade
//
// keep the public log API stable while the storage, capture, and follow
// flows live in runtime/logs/.

const std = @import("std");
const common = @import("logs/common.zig");
const storage = @import("logs/storage.zig");
const capture = @import("logs/capture.zig");
const follow = @import("logs/follow.zig");

pub const LogError = common.LogError;

pub fn createLogFile(container_id: []const u8) LogError!std.fs.File {
    return storage.createLogFile(container_id);
}

pub fn readLogs(alloc: std.mem.Allocator, container_id: []const u8) LogError![]const u8 {
    return storage.readLogs(alloc, container_id);
}

pub fn readTail(alloc: std.mem.Allocator, container_id: []const u8, n: usize) LogError![]const u8 {
    return storage.readTail(alloc, container_id, n);
}

pub fn deleteLogFile(container_id: []const u8) void {
    storage.deleteLogFile(container_id);
}

pub fn writeLogLine(log_file: std.fs.File, stream: []const u8, line: []const u8) void {
    capture.writeLogLine(log_file, stream, line);
}

pub fn captureStream(
    log_file: std.fs.File,
    pipe_fd: std.posix.fd_t,
    stream_label: []const u8,
    dev_service: ?[]const u8,
    dev_color: usize,
    mirror_output: bool,
) void {
    capture.captureStream(log_file, pipe_fd, stream_label, dev_service, dev_color, mirror_output);
}

pub fn followLogs(container_id: []const u8, tail_lines: usize, pid: ?std.posix.pid_t) LogError!void {
    return follow.followLogs(container_id, tail_lines, pid);
}
