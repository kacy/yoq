const std = @import("std");
const posix = std.posix;
const log_mux = @import("../../dev/log_mux.zig");
const Sink = @import("sink.zig").Sink;
const session = @import("../session.zig");

pub fn writeLogLine(sink: *Sink, stream: []const u8, line: []const u8) void {
    sink.write(stream, line) catch {};
}

pub fn captureStream(sink: *Sink, pipe_fd: posix.fd_t, stream_label: []const u8, dev_service: ?[]const u8, dev_color: usize, mirror_output: bool) void {
    captureSessionStream(sink, pipe_fd, stream_label, dev_service, dev_color, mirror_output, null);
}

pub fn captureSessionStream(sink: *Sink, pipe_fd: posix.fd_t, stream_label: []const u8, dev_service: ?[]const u8, dev_color: usize, mirror_output: bool, output: ?session.Output) void {
    const mirror = if (mirror_output)
        (if (std.mem.eql(u8, stream_label, "stderr")) std.Io.File.stderr() else std.Io.File.stdout())
    else
        null;
    captureStreamToOutput(sink, pipe_fd, stream_label, dev_service, dev_color, mirror, output);
}

fn captureStreamTo(sink: *Sink, pipe_fd: posix.fd_t, stream_label: []const u8, dev_service: ?[]const u8, dev_color: usize, mirror: ?std.Io.File) void {
    captureStreamToOutput(sink, pipe_fd, stream_label, dev_service, dev_color, mirror, null);
}

fn captureStreamToOutput(sink: *Sink, pipe_fd: posix.fd_t, stream_label: []const u8, dev_service: ?[]const u8, dev_color: usize, mirror: ?std.Io.File, output: ?session.Output) void {
    defer _ = std.os.linux.close(pipe_fd);
    var buf: [4096]u8 = undefined;
    var pending: [Sink.chunk_size]u8 = undefined;
    var len: usize = 0;
    while (true) {
        const count = posix.read(pipe_fd, &buf) catch |err| {
            if (err == error.WouldBlock) {
                var polls = [_]std.os.linux.pollfd{.{ .fd = pipe_fd, .events = std.os.linux.POLL.IN, .revents = 0 }};
                _ = std.os.linux.poll(&polls, 1, 100);
                continue;
            }
            break;
        };
        if (count == 0) break;
        // Forward each read immediately, before line-oriented log formatting.
        if (mirror) |file| writeTerminalBytes(file, buf[0..count]);
        if (output) |target| target.send(stream_label, buf[0..count]);
        for (buf[0..count]) |byte| {
            if (byte == '\n') {
                emit(sink, stream_label, pending[0..len], false, dev_service, dev_color);
                len = 0;
            } else {
                // Wait for the next byte before splitting, so a 4 KiB line
                // followed by LF still produces exactly one ordinary record.
                if (len == pending.len) {
                    emit(sink, stream_label, &pending, true, dev_service, dev_color);
                    len = 0;
                }
                pending[len] = byte;
                len += 1;
            }
        }
    }
    if (len != 0) emit(sink, stream_label, pending[0..len], false, dev_service, dev_color);
}

fn emit(sink: *Sink, stream: []const u8, line: []const u8, continued: bool, service: ?[]const u8, color: usize) void {
    sink.writeChunk(stream, line, continued) catch {};
    if (service) |name| log_mux.writeLine(name, color, line);
}

fn writeTerminalBytes(output: std.Io.File, bytes: []const u8) void {
    const io = std.Options.debug_io;
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);
    output.writeStreamingAll(io, bytes) catch {};
}

test "log capture preserves oversized lines and unterminated tails from a real pipe" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &path_buf);
    const path = try std.fmt.allocPrint(alloc, "{s}/capture.log", .{path_buf[0..len]});
    defer alloc.free(path);
    var sink = try Sink.init(try tmp.dir.createFile(std.testing.io, "capture.log", .{ .read = true }), path);
    defer sink.close();
    const mirror = try tmp.dir.createFile(std.testing.io, "raw-output", .{});
    defer mirror.close(std.testing.io);
    const pipes = try @import("linux_platform").posix.pipe();
    var read_owned = true;
    defer if (read_owned) @import("linux_platform").posix.close(pipes[0]);
    const Producer = struct {
        fn run(fd: posix.fd_t, failed: *std.atomic.Value(bool)) void {
            const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
            defer file.close(std.Options.debug_io);
            const input = "x" ** (Sink.chunk_size * 3 + 71) ++ "\n\nlast-byte";
            file.writeStreamingAll(std.Options.debug_io, input) catch failed.store(true, .release);
        }
    };
    var failed = std.atomic.Value(bool).init(false);
    const producer = std.Thread.spawn(.{}, Producer.run, .{ pipes[1], &failed }) catch |err| {
        @import("linux_platform").posix.close(pipes[1]);
        return err;
    };
    captureStreamTo(&sink, pipes[0], "stdout", null, 0, mirror);
    read_owned = false;
    producer.join();
    try std.testing.expect(!failed.load(.acquire));
    const raw = try tmp.dir.readFileAlloc(std.testing.io, "raw-output", alloc, .limited(32 * 1024));
    defer alloc.free(raw);
    try std.testing.expectEqualStrings("x" ** (Sink.chunk_size * 3 + 71) ++ "\n\nlast-byte", raw);
    const data = try tmp.dir.readFileAlloc(std.testing.io, "capture.log", alloc, .limited(32 * 1024));
    defer alloc.free(data);
    try std.testing.expectEqual(@as(usize, Sink.chunk_size * 3 + 71), std.mem.count(u8, data, "x"));
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, data, "stdout [continued] | "));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, data, "stdout | \n"));
    try std.testing.expect(std.mem.endsWith(u8, data, "stdout | last-byte\n"));
}

test "log capture forwards a binary prompt before newline or pipe closure" {
    const linux = std.os.linux;
    const platform = @import("linux_platform").posix;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &path_buffer);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/capture.log", .{path_buffer[0..len]});
    defer std.testing.allocator.free(path);
    var sink = try Sink.init(try tmp.dir.createFile(std.testing.io, "capture.log", .{ .read = true }), path);
    defer sink.close();
    const input = try platform.pipe();
    var input_owned = true;
    defer if (input_owned) {
        platform.close(input[0]);
        platform.close(input[1]);
    };
    const output = try platform.pipe();
    defer platform.close(output[0]);
    defer platform.close(output[1]);
    const mirror: std.Io.File = .{ .handle = output[1], .flags = .{ .nonblocking = false } };
    const worker = try std.Thread.spawn(.{}, captureStreamTo, .{ &sink, input[0], "stdout", @as(?[]const u8, null), @as(usize, 0), @as(?std.Io.File, mirror) });
    input_owned = false;
    defer worker.join();
    defer platform.close(input[1]);
    const prompt = "prompt> \r\x00\x1b[31m";
    _ = try platform.write(input[1], prompt);
    var polls = [_]linux.pollfd{.{ .fd = output[0], .events = linux.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), linux.poll(&polls, 1, 1000));
    var bytes: [128]u8 = undefined;
    const count = try platform.read(output[0], &bytes);
    try std.testing.expectEqualStrings(prompt, bytes[0..count]);
}
