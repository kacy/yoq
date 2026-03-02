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

pub const LogError = error{
    CreateFailed,
    ReadFailed,
    WriteFailed,
    NotFound,
    PathTooLong,
};

const logs_dir = ".local/share/yoq/logs";

/// ensure the log directory exists and return a file handle for
/// the container's log file. creates the file if it doesn't exist.
pub fn createLogFile(container_id: []const u8) LogError!std.fs.File {
    const home = std.posix.getenv("HOME") orelse "/tmp";

    var dir_buf: [512]u8 = undefined;
    const dir_path = std.fmt.bufPrint(&dir_buf, "{s}/{s}", .{ home, logs_dir }) catch
        return LogError.PathTooLong;
    std.fs.cwd().makePath(dir_path) catch {};

    var path_buf: [512]u8 = undefined;
    const file_path = std.fmt.bufPrint(&path_buf, "{s}/{s}/{s}.log", .{ home, logs_dir, container_id }) catch
        return LogError.PathTooLong;

    return std.fs.cwd().createFile(file_path, .{}) catch
        return LogError.CreateFailed;
}

/// read the full log file for a container. caller owns the returned slice.
pub fn readLogs(alloc: std.mem.Allocator, container_id: []const u8) LogError![]const u8 {
    const home = std.posix.getenv("HOME") orelse "/tmp";

    var path_buf: [512]u8 = undefined;
    const file_path = std.fmt.bufPrint(&path_buf, "{s}/{s}/{s}.log", .{ home, logs_dir, container_id }) catch
        return LogError.PathTooLong;

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
    const home = std.posix.getenv("HOME") orelse return;

    var path_buf: [512]u8 = undefined;
    const file_path = std.fmt.bufPrint(&path_buf, "{s}/{s}/{s}.log", .{ home, logs_dir, container_id }) catch return;

    std.fs.cwd().deleteFile(file_path) catch {};
}

/// write a single log line with timestamp and stream label.
/// format: "2026-03-01T23:15:42Z stdout | line content\n"
pub fn writeLogLine(log_file: std.fs.File, stream: []const u8, line: []const u8) void {
    const ts = std.time.timestamp();
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(ts) };
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    var buf: [4096]u8 = undefined;
    const header = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z {s} | ", .{
        year_day.year,
        @as(u32, @intFromEnum(month_day.month)),
        @as(u32, month_day.day_index) + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
        stream,
    }) catch return;

    log_file.writeAll(header) catch return;
    log_file.writeAll(line) catch return;
    // ensure the line ends with a newline
    if (line.len == 0 or line[line.len - 1] != '\n') {
        log_file.writeAll("\n") catch return;
    }
}

/// blocking read loop that captures output from a pipe fd and writes
/// it to the log file line by line. intended to run in a separate thread.
/// reads until the pipe is closed (EOF).
pub fn captureStream(log_file: std.fs.File, pipe_fd: posix.fd_t, stream_label: []const u8) void {
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
                    // combine leftover + current chunk
                    writeLogLine(log_file, stream_label, leftover[0..leftover_len]);
                    leftover_len = 0;
                    // also write the rest of this line
                    if (start < i) {
                        writeLogLine(log_file, stream_label, buf[start..i]);
                    }
                } else {
                    writeLogLine(log_file, stream_label, buf[start..i]);
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
