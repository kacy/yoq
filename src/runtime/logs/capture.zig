const std = @import("std");
const platform = @import("platform");
const posix = std.posix;
const log_mux = @import("../../dev/log_mux.zig");
const common = @import("common.zig");

pub fn writeLogLine(log_file: platform.File, stream: []const u8, line: []const u8) void {
    const ts = platform.timestamp();
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(ts) };
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    var buf: [8192]u8 = undefined;
    var pos: usize = 0;

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

    const copy_len = @min(line.len, buf.len - pos - 1);
    @memcpy(buf[pos..][0..copy_len], line[0..copy_len]);
    pos += copy_len;

    if (copy_len == 0 or line[copy_len - 1] != '\n') {
        buf[pos] = '\n';
        pos += 1;
    }

    if (log_file.getEndPos()) |end_pos| {
        if (end_pos > common.max_log_size) {
            log_file.seekTo(0) catch {};
            platform.posix.ftruncate(log_file.handle, 0) catch {};
            log_file.writeAll("--- log truncated (exceeded 50 MB) ---\n") catch {};
        }
    } else |_| {}

    log_file.writeAll(buf[0..pos]) catch return;
}

pub fn captureStream(
    log_file: platform.File,
    pipe_fd: posix.fd_t,
    stream_label: []const u8,
    dev_service: ?[]const u8,
    dev_color: usize,
    mirror_output: bool,
) void {
    var buf: [4096]u8 = undefined;
    var leftover: [4096]u8 = undefined;
    var leftover_len: usize = 0;

    while (true) {
        const bytes_read = posix.read(pipe_fd, &buf) catch break;
        if (bytes_read == 0) break;

        var start: usize = 0;
        var i: usize = 0;
        while (i < bytes_read) : (i += 1) {
            if (buf[i] == '\n') {
                if (leftover_len > 0) {
                    const chunk_len = i - start;
                    if (chunk_len > 0 and leftover_len + chunk_len <= leftover.len) {
                        @memcpy(leftover[leftover_len .. leftover_len + chunk_len], buf[start..i]);
                        const line = leftover[0 .. leftover_len + chunk_len];
                        writeLogLine(log_file, stream_label, line);
                        if (mirror_output) writeTerminalLine(stream_label, line);
                        if (dev_service) |svc| log_mux.writeLine(svc, dev_color, line);
                    } else {
                        writeLogLine(log_file, stream_label, leftover[0..leftover_len]);
                        if (mirror_output) writeTerminalLine(stream_label, leftover[0..leftover_len]);
                        if (dev_service) |svc| log_mux.writeLine(svc, dev_color, leftover[0..leftover_len]);
                        if (chunk_len > 0) {
                            writeLogLine(log_file, stream_label, buf[start..i]);
                            if (mirror_output) writeTerminalLine(stream_label, buf[start..i]);
                            if (dev_service) |svc| log_mux.writeLine(svc, dev_color, buf[start..i]);
                        }
                    }
                    leftover_len = 0;
                } else {
                    const line = buf[start..i];
                    writeLogLine(log_file, stream_label, line);
                    if (mirror_output) writeTerminalLine(stream_label, line);
                    if (dev_service) |svc| log_mux.writeLine(svc, dev_color, line);
                }
                start = i + 1;
            }
        }

        if (start < bytes_read) {
            const remaining = bytes_read - start;
            if (leftover_len + remaining <= leftover.len) {
                @memcpy(leftover[leftover_len .. leftover_len + remaining], buf[start..bytes_read]);
                leftover_len += remaining;
            }
        }
    }

    if (leftover_len > 0) {
        writeLogLine(log_file, stream_label, leftover[0..leftover_len]);
        if (mirror_output) writeTerminalLine(stream_label, leftover[0..leftover_len]);
        if (dev_service) |svc| log_mux.writeLine(svc, dev_color, leftover[0..leftover_len]);
    }

    platform.posix.close(pipe_fd);
}

fn writeTerminalLine(stream_label: []const u8, line: []const u8) void {
    const file = if (std.mem.eql(u8, stream_label, "stderr")) platform.File.stderr() else platform.File.stdout();
    file.writeAll(line) catch return;
    file.writeAll("\n") catch {};
}

test "write and read log line" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const file = platform.Dir.from(tmp_dir.dir).createFile("test.log", .{ .read = true }) catch unreachable;
    defer file.close();

    writeLogLine(file, "stdout", "hello world");
    writeLogLine(file, "stderr", "something broke");

    file.seekTo(0) catch unreachable;
    var buf: [1024]u8 = undefined;
    const bytes_read = file.readAll(&buf) catch unreachable;
    const content = buf[0..bytes_read];

    try std.testing.expect(std.mem.indexOf(u8, content, "stdout | hello world\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "stderr | something broke\n") != null);
}

test "log file truncated when exceeding max size" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const file = platform.Dir.from(tmp_dir.dir).createFile("test_trunc.log", .{ .read = true }) catch unreachable;
    defer file.close();

    file.seekTo(common.max_log_size + 1) catch unreachable;
    file.writeAll("x") catch unreachable;

    writeLogLine(file, "stdout", "after truncation");

    const end = file.getEndPos() catch unreachable;
    try std.testing.expect(end < 1024);

    file.seekTo(0) catch unreachable;
    var buf: [512]u8 = undefined;
    const bytes_read = file.readAll(&buf) catch unreachable;
    const content = buf[0..bytes_read];
    try std.testing.expect(std.mem.startsWith(u8, content, "--- log truncated"));
}

test "write log line adds newline" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const file = platform.Dir.from(tmp_dir.dir).createFile("test.log", .{ .read = true }) catch unreachable;
    defer file.close();

    writeLogLine(file, "stdout", "no newline");

    file.seekTo(0) catch unreachable;
    var buf: [512]u8 = undefined;
    const bytes_read = file.readAll(&buf) catch unreachable;
    const content = buf[0..bytes_read];

    try std.testing.expect(content[content.len - 1] == '\n');
    try std.testing.expect(content[content.len - 2] != '\n');
}
