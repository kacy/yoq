const std = @import("std");
const common = @import("common.zig");

/// One sink owns both capture streams. Keep at most one previous generation;
/// each generation is capped at 50 MiB, with records split into 4 KiB payloads.
pub const Sink = struct {
    mutex: std.Io.Mutex = .init,
    file: std.Io.File,
    path: [std.fs.max_path_bytes]u8 = undefined,
    path_len: usize,
    max_size: u64 = common.max_log_size,

    pub const chunk_size = 4096;

    pub fn init(file: std.Io.File, path: []const u8) !Sink {
        if (path.len + 5 >= std.fs.max_path_bytes) return error.NameTooLong;
        var self: Sink = .{ .file = file, .path_len = path.len };
        @memcpy(self.path[0..path.len], path);
        return self;
    }

    /// Call only after both capture workers have joined.
    pub fn close(self: *Sink) void {
        self.file.close(std.Options.debug_io);
    }

    pub fn write(self: *Sink, stream: []const u8, line: []const u8) !void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        const payload = if (std.mem.endsWith(u8, line, "\n")) line[0 .. line.len - 1] else line;
        var offset: usize = 0;
        while (true) {
            const end = offset + @min(chunk_size, payload.len - offset);
            try self.writeRecord(stream, payload[offset..end], end < payload.len);
            offset = end;
            if (offset == payload.len) break;
        }
    }

    /// A full buffer without a newline is emitted immediately and explicitly
    /// marked as continued. No input bytes are discarded while waiting for LF.
    pub fn writeChunk(self: *Sink, stream: []const u8, bytes: []const u8, continued: bool) !void {
        std.debug.assert(bytes.len <= chunk_size);
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        try self.writeRecord(stream, bytes, continued);
    }

    fn writeRecord(self: *Sink, stream: []const u8, line: []const u8, continued: bool) !void {
        const io = std.Options.debug_io;
        const ts = std.Io.Clock.real.now(io).toSeconds();
        const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(@max(0, ts)) };
        const day = epoch_seconds.getDaySeconds();
        const year = epoch_seconds.getEpochDay().calculateYearDay();
        const month = year.calculateMonthDay();
        var buf: [chunk_size + 128]u8 = undefined;
        const record = try std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z {s}{s} | {s}\n", .{
            year.year,             @as(u32, @intFromEnum(month.month)),   @as(u32, month.day_index) + 1,
            day.getHoursIntoDay(), day.getMinutesIntoHour(),              day.getSecondsIntoMinute(),
            stream,                if (continued) " [continued]" else "", line,
        });
        if (record.len > self.max_size) return error.RecordTooLarge;
        var end = try self.file.length(io);
        if (end > self.max_size - record.len) {
            try self.rotate();
            end = 0;
        }
        var writer = self.file.writer(io, &.{});
        try writer.seekTo(end);
        try writer.interface.writeAll(record);
        try writer.interface.flush();
    }

    fn rotate(self: *Sink) !void {
        const io = std.Options.debug_io;
        const dir = std.Io.Dir.cwd();
        const path = self.path[0..self.path_len];
        var previous_buf: [std.fs.max_path_bytes]u8 = undefined;
        var next_buf: [std.fs.max_path_bytes]u8 = undefined;
        const previous = try std.fmt.bufPrint(&previous_buf, "{s}.1", .{path});
        const next = try std.fmt.bufPrint(&next_buf, "{s}.next", .{path});
        // Create the replacement first; an open failure leaves the live file
        // and its retained history untouched.
        const replacement = try dir.createFile(io, next, .{ .read = true });
        errdefer replacement.close(io);
        defer dir.deleteFile(io, next) catch {};
        try dir.rename(path, dir, previous, io);
        dir.rename(next, dir, path, io) catch |err| {
            dir.rename(previous, dir, path, io) catch {};
            return err;
        };
        self.file.close(io);
        self.file = replacement;
    }
};

test "log sink concurrent tagged records appear exactly once" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &path_buf);
    const path = try std.fmt.allocPrint(alloc, "{s}/capture.log", .{path_buf[0..len]});
    defer alloc.free(path);
    var sink = try Sink.init(try tmp.dir.createFile(std.testing.io, "capture.log", .{ .read = true }), path);
    defer sink.close();
    const Worker = struct {
        fn run(output: *Sink, stream: []const u8, failed: *std.atomic.Value(bool)) void {
            for (0..200) |i| {
                var buf: [32]u8 = undefined;
                const message = std.fmt.bufPrint(&buf, "record-{d}", .{i}) catch unreachable;
                output.write(stream, message) catch failed.store(true, .release);
            }
        }
    };
    var failed = std.atomic.Value(bool).init(false);
    const stdout = try std.Thread.spawn(.{}, Worker.run, .{ &sink, "stdout", &failed });
    {
        defer stdout.join();
        const stderr = try std.Thread.spawn(.{}, Worker.run, .{ &sink, "stderr", &failed });
        stderr.join();
    }
    try std.testing.expect(!failed.load(.acquire));
    const data = try tmp.dir.readFileAlloc(std.testing.io, "capture.log", alloc, .limited(64 * 1024));
    defer alloc.free(data);
    try std.testing.expectEqual(@as(usize, 400), std.mem.count(u8, data, "\n"));
    for ([_][]const u8{ "stdout", "stderr" }) |stream| {
        for (0..200) |i| {
            var buf: [64]u8 = undefined;
            const needle = try std.fmt.bufPrint(&buf, "{s} | record-{d}\n", .{ stream, i });
            try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, data, needle));
        }
    }
}

test "log sink rotation retains one bounded previous generation" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &path_buf);
    const path = try std.fmt.allocPrint(alloc, "{s}/capture.log", .{path_buf[0..len]});
    defer alloc.free(path);
    var sink = try Sink.init(try tmp.dir.createFile(std.testing.io, "capture.log", .{ .read = true }), path);
    defer sink.close();
    sink.max_size = 80;
    try sink.write("stdout", "first");
    // A follower's existing descriptor remains readable after rotation.
    const old = try tmp.dir.openFile(std.testing.io, "capture.log", .{});
    defer old.close(std.testing.io);
    try sink.write("stdout", "second");
    try sink.write("stdout", "third");
    const previous = try tmp.dir.readFileAlloc(std.testing.io, "capture.log.1", alloc, .limited(80));
    defer alloc.free(previous);
    try std.testing.expect(std.mem.indexOf(u8, previous, "first\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, previous, "second\n") != null);
    try sink.write("stdout", "fourth");
    try sink.write("stdout", "fifth");
    const latest_previous = try tmp.dir.readFileAlloc(std.testing.io, "capture.log.1", alloc, .limited(80));
    defer alloc.free(latest_previous);
    try std.testing.expect(std.mem.indexOf(u8, latest_previous, "third\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, latest_previous, "fourth\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, latest_previous, "first\n") == null);
    const live = try tmp.dir.readFileAlloc(std.testing.io, "capture.log", alloc, .limited(80));
    defer alloc.free(live);
    try std.testing.expect(std.mem.indexOf(u8, live, "fifth\n") != null);
    var old_buf: [80]u8 = undefined;
    var old_reader = old.reader(std.testing.io, &.{});
    const count = try old_reader.interface.readSliceShort(&old_buf);
    try std.testing.expectEqualStrings(previous, old_buf[0..count]);
    try tmp.dir.createDir(std.testing.io, "capture.log.next", .default_dir);
    if (sink.write("stdout", "cannot-rotate-with-blocked-replacement")) |_| {
        return error.ExpectedRotationFailure;
    } else |_| {}
    const unchanged = try tmp.dir.readFileAlloc(std.testing.io, "capture.log", alloc, .limited(80));
    defer alloc.free(unchanged);
    try std.testing.expectEqualStrings(live, unchanged);
    const retained = try tmp.dir.readFileAlloc(std.testing.io, "capture.log.1", alloc, .limited(80));
    defer alloc.free(retained);
    try std.testing.expectEqualStrings(latest_previous, retained);
}
