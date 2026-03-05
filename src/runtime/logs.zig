// logs — container log capture and retrieval
//
// captures stdout/stderr from container processes and writes them
// to log files under ~/.local/share/yoq/logs/<id>.log. each line
// is prefixed with a timestamp and stream identifier so you can
// tell stdout from stderr when reading back.
//
// log format:
//   2026-03-01T23:15:42Z stdout | line content
//   2026-03-01T23:15:42Z stderr | something went wrong

const std = @import("std");
const posix = std.posix;
const paths = @import("../lib/paths.zig");
const log_mux = @import("../dev/log_mux.zig");

pub const LogError = error{
    CreateFailed,
    ReadFailed,
    WriteFailed,
    NotFound,
    PathTooLong,
};

const logs_subdir = "logs";

/// maximum log file size before truncation (50 MB).
/// a container spamming stdout can fill the disk without this limit.
/// when exceeded, the file is truncated and old logs are lost.
/// the read path already caps at 10 MB (readLogs).
const max_log_size: u64 = 50 * 1024 * 1024;

/// resolve the log file path for a container.
/// returns the formatted path within the provided buffer.
fn logPath(buf: *[paths.max_path]u8, container_id: []const u8) LogError![]const u8 {
    return paths.dataPathFmt(buf, "{s}/{s}.log", .{ logs_subdir, container_id }) catch
        return LogError.PathTooLong;
}

/// ensure the log directory exists and return a file handle for
/// the container's log file. creates the file if it doesn't exist.
pub fn createLogFile(container_id: []const u8) LogError!std.fs.File {
    paths.ensureDataDir(logs_subdir) catch {};

    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = try logPath(&path_buf, container_id);

    return std.fs.cwd().createFile(file_path, .{}) catch
        return LogError.CreateFailed;
}

/// read the full log file for a container. caller owns the returned slice.
pub fn readLogs(alloc: std.mem.Allocator, container_id: []const u8) LogError![]const u8 {
    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = try logPath(&path_buf, container_id);

    const file = std.fs.cwd().openFile(file_path, .{}) catch
        return LogError.NotFound;
    defer file.close();

    return file.readToEndAlloc(alloc, 10 * 1024 * 1024) catch // 10MB max
        return LogError.ReadFailed;
}

/// read the last N lines of a container's log file. caller owns the returned slice.
pub fn readTail(alloc: std.mem.Allocator, container_id: []const u8, n: usize) LogError![]const u8 {
    const full = try readLogs(alloc, container_id);

    if (n == 0) return full;

    // walk backwards counting newlines
    var count: usize = 0;
    var pos: usize = full.len;
    while (pos > 0) {
        pos -= 1;
        if (full[pos] == '\n') {
            count += 1;
            // +1 because the last line might not end with \n
            if (count == n + 1) {
                const result = alloc.dupe(u8, full[pos + 1 ..]) catch {
                    alloc.free(full);
                    return LogError.ReadFailed;
                };
                alloc.free(full);
                return result;
            }
        }
    }

    // fewer than n lines — return everything
    return full;
}

/// delete the log file for a container
pub fn deleteLogFile(container_id: []const u8) void {
    var path_buf: [paths.max_path]u8 = undefined;
    const file_path = logPath(&path_buf, container_id) catch return;
    std.fs.cwd().deleteFile(file_path) catch {};
}

/// write a single log line with timestamp and stream label.
/// format: "2026-03-01T23:15:42Z stdout | line content\n"
///
/// builds the entire log line in a single buffer and writes it with one
/// writeAll call. single writes under PIPE_BUF (4096) are atomic on Linux,
/// preventing interleaved output when stdout/stderr threads write concurrently.
pub fn writeLogLine(log_file: std.fs.File, stream: []const u8, line: []const u8) void {
    const ts = std.time.timestamp();
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(ts) };
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    var buf: [8192]u8 = undefined;
    var pos: usize = 0;

    // format header directly into buf
    const header = std.fmt.bufPrint(buf[pos..], "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z {s} | ", .{
        year_day.year,
        @as(u32, @intFromEnum(month_day.month)),
        @as(u32, month_day.day_index) + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
        stream,
    }) catch return;
    pos += header.len;

    // append line content
    const copy_len = @min(line.len, buf.len - pos - 1); // reserve 1 for newline
    @memcpy(buf[pos..][0..copy_len], line[0..copy_len]);
    pos += copy_len;

    // ensure trailing newline
    if (copy_len == 0 or line[copy_len - 1] != '\n') {
        buf[pos] = '\n';
        pos += 1;
    }

    // truncate if the log file has exceeded the size limit.
    // check before writing so we don't grow unboundedly.
    if (log_file.getEndPos()) |end_pos| {
        if (end_pos > max_log_size) {
            log_file.seekTo(0) catch {};
            posix.ftruncate(log_file.handle, 0) catch {};
            log_file.writeAll("--- log truncated (exceeded 50 MB) ---\n") catch {};
        }
    } else |_| {}

    // single atomic write
    log_file.writeAll(buf[0..pos]) catch return;
}

/// blocking read loop that captures output from a pipe fd and writes
/// it to the log file line by line. intended to run in a separate thread.
/// reads until the pipe is closed (EOF).
///
/// when dev_service is non-null, each line is also written to stderr
/// with a colored service name prefix (for dev mode log multiplexing).
pub fn captureStream(
    log_file: std.fs.File,
    pipe_fd: posix.fd_t,
    stream_label: []const u8,
    dev_service: ?[]const u8,
    dev_color: usize,
) void {
    var buf: [4096]u8 = undefined;
    var leftover: [4096]u8 = undefined;
    var leftover_len: usize = 0;

    while (true) {
        const n = posix.read(pipe_fd, &buf) catch break;
        if (n == 0) break; // EOF — pipe closed

        // process complete lines
        var start: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            if (buf[i] == '\n') {
                if (leftover_len > 0) {
                    // combine leftover + current chunk into one line
                    const chunk_len = i - start;
                    if (chunk_len > 0 and leftover_len + chunk_len <= leftover.len) {
                        @memcpy(leftover[leftover_len .. leftover_len + chunk_len], buf[start..i]);
                        const line = leftover[0 .. leftover_len + chunk_len];
                        writeLogLine(log_file, stream_label, line);
                        if (dev_service) |svc| log_mux.writeLine(svc, dev_color, line);
                    } else {
                        // buffer full or no new data — write what we have
                        writeLogLine(log_file, stream_label, leftover[0..leftover_len]);
                        if (dev_service) |svc| log_mux.writeLine(svc, dev_color, leftover[0..leftover_len]);
                        if (chunk_len > 0) {
                            writeLogLine(log_file, stream_label, buf[start..i]);
                            if (dev_service) |svc| log_mux.writeLine(svc, dev_color, buf[start..i]);
                        }
                    }
                    leftover_len = 0;
                } else {
                    const line = buf[start..i];
                    writeLogLine(log_file, stream_label, line);
                    if (dev_service) |svc| log_mux.writeLine(svc, dev_color, line);
                }
                start = i + 1;
            }
        }

        // save any incomplete line for next iteration
        if (start < n) {
            const remaining = n - start;
            if (leftover_len + remaining <= leftover.len) {
                @memcpy(leftover[leftover_len .. leftover_len + remaining], buf[start..n]);
                leftover_len += remaining;
            }
        }
    }

    // flush any remaining data
    if (leftover_len > 0) {
        writeLogLine(log_file, stream_label, leftover[0..leftover_len]);
        if (dev_service) |svc| log_mux.writeLine(svc, dev_color, leftover[0..leftover_len]);
    }

    posix.close(pipe_fd);
}

// -- tests --

test "write and read log line" {
    // use a temp file instead of a real log path
    const tmp_dir = std.testing.tmpDir(.{});
    const file = tmp_dir.dir.createFile("test.log", .{ .read = true }) catch unreachable;
    defer file.close();

    writeLogLine(file, "stdout", "hello world");
    writeLogLine(file, "stderr", "something broke");

    // read back
    file.seekTo(0) catch unreachable;
    var buf: [1024]u8 = undefined;
    const n = file.readAll(&buf) catch unreachable;
    const content = buf[0..n];

    try std.testing.expect(std.mem.indexOf(u8, content, "stdout | hello world\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "stderr | something broke\n") != null);
}

test "log file truncated when exceeding max size" {
    const tmp_dir = std.testing.tmpDir(.{});
    const file = tmp_dir.dir.createFile("test_trunc.log", .{ .read = true }) catch unreachable;
    defer file.close();

    // simulate a file already at the size limit by seeking past it
    file.seekTo(max_log_size + 1) catch unreachable;
    file.writeAll("x") catch unreachable;

    // next writeLogLine should truncate
    writeLogLine(file, "stdout", "after truncation");

    // file should now be small (truncation marker + new line)
    const end = file.getEndPos() catch unreachable;
    try std.testing.expect(end < 1024);

    // verify truncation marker is at the start
    file.seekTo(0) catch unreachable;
    var buf: [512]u8 = undefined;
    const n = file.readAll(&buf) catch unreachable;
    const content = buf[0..n];
    try std.testing.expect(std.mem.startsWith(u8, content, "--- log truncated"));
}

test "write log line adds newline" {
    const tmp_dir = std.testing.tmpDir(.{});
    const file = tmp_dir.dir.createFile("test.log", .{ .read = true }) catch unreachable;
    defer file.close();

    writeLogLine(file, "stdout", "no newline");

    file.seekTo(0) catch unreachable;
    var buf: [512]u8 = undefined;
    const n = file.readAll(&buf) catch unreachable;
    const content = buf[0..n];

    // should end with exactly one newline
    try std.testing.expect(content[content.len - 1] == '\n');
    // but not two
    try std.testing.expect(content[content.len - 2] != '\n');
}
