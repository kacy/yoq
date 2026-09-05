const std = @import("std");
const posix = std.posix;
const log_mux = @import("../../dev/log_mux.zig");
const Sink = @import("sink.zig").Sink;

pub fn writeLogLine(sink: *Sink, stream: []const u8, line: []const u8) void {
    sink.write(stream, line) catch {};
}

pub fn captureStream(sink: *Sink, pipe_fd: posix.fd_t, stream_label: []const u8, dev_service: ?[]const u8, dev_color: usize, mirror_output: bool) void {
    defer _ = std.os.linux.close(pipe_fd);
    var buf: [4096]u8 = undefined;
    var pending: [Sink.chunk_size]u8 = undefined;
    var len: usize = 0;
    while (true) {
        const count = posix.read(pipe_fd, &buf) catch break;
        if (count == 0) break;
        for (buf[0..count]) |byte| {
            if (byte == '\n') {
                emit(sink, stream_label, pending[0..len], false, dev_service, dev_color, mirror_output);
                len = 0;
            } else {
                // Wait for the next byte before splitting, so a 4 KiB line
                // followed by LF still produces exactly one ordinary record.
                if (len == pending.len) {
                    emit(sink, stream_label, &pending, true, dev_service, dev_color, mirror_output);
                    len = 0;
                }
                pending[len] = byte;
                len += 1;
            }
        }
    }
    if (len != 0) emit(sink, stream_label, pending[0..len], false, dev_service, dev_color, mirror_output);
}

fn emit(sink: *Sink, stream: []const u8, line: []const u8, continued: bool, service: ?[]const u8, color: usize, mirror: bool) void {
    sink.writeChunk(stream, line, continued) catch {};
    if (mirror) writeTerminalLine(stream, line);
    if (service) |name| log_mux.writeLine(name, color, line);
}

fn writeTerminalLine(stream_label: []const u8, line: []const u8) void {
    const io = std.Options.debug_io;
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);

    var buf: [4096]u8 = undefined;
    var writer = if (std.mem.eql(u8, stream_label, "stderr"))
        std.Io.File.stderr().writer(io, &buf)
    else
        std.Io.File.stdout().writer(io, &buf);
    writer.interface.writeAll(line) catch return;
    writer.interface.writeAll("\n") catch return;
    writer.interface.flush() catch {};
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
    captureStream(&sink, pipes[0], "stdout", null, 0, false);
    read_owned = false;
    producer.join();
    try std.testing.expect(!failed.load(.acquire));
    const data = try tmp.dir.readFileAlloc(std.testing.io, "capture.log", alloc, .limited(32 * 1024));
    defer alloc.free(data);
    try std.testing.expectEqual(@as(usize, Sink.chunk_size * 3 + 71), std.mem.count(u8, data, "x"));
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, data, "stdout [continued] | "));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, data, "stdout | \n"));
    try std.testing.expect(std.mem.endsWith(u8, data, "stdout | last-byte\n"));
}
