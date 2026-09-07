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
        try retainCurrent(io, dir, path, previous);
        // Replace the live directory entry atomically. Existing followers keep
        // the old inode; new followers can always open a complete generation.
        try dir.rename(next, dir, path, io);
        self.file.close(io);
        self.file = replacement;
    }
};

/// Preserve history without moving away the live pathname. If replacement
/// later fails, the sink still owns the unchanged live descriptor and can retry.
fn retainCurrent(io: std.Io, dir: std.Io.Dir, path: []const u8, previous: []const u8) !void {
    var retained_buf: [std.fs.max_path_bytes]u8 = undefined;
    const retained = try std.fmt.bufPrint(&retained_buf, "{s}.prev", .{path});
    // A crash can leave this unselected hardlink behind. Removing it cannot
    // affect the live file or the previously published history.
    dir.deleteFile(io, retained) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    try dir.hardLink(path, dir, retained, io, .{});
    defer dir.deleteFile(io, retained) catch {};
    try dir.rename(retained, dir, previous, io);
}

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
                const message = std.fmt.bufPrint(&buf, "record-{d}", .{i}) catch {
                    failed.store(true, .release);
                    return;
                };
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

test "log sink history publication keeps the live pathname and follower inode" {
    const io = std.testing.io;
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &dir_buf);
    const path = try std.fmt.allocPrint(alloc, "{s}/capture.log", .{dir_buf[0..len]});
    defer alloc.free(path);
    const previous = try std.fmt.allocPrint(alloc, "{s}.1", .{path});
    defer alloc.free(previous);
    var sink = try Sink.init(try tmp.dir.createFile(io, "capture.log", .{ .read = true }), path);
    defer sink.close();
    try sink.write("stdout", "retained record");
    const follower = try tmp.dir.openFile(io, "capture.log", .{});
    defer follower.close(io);
    // Exercise the exact publication seam before replacing the live inode.
    // An initial follower open must succeed even when rotation pauses here.
    try retainCurrent(io, std.Io.Dir.cwd(), path, previous);
    const joining_follower = try tmp.dir.openFile(io, "capture.log", .{});
    defer joining_follower.close(io);
    try std.testing.expectEqual((try follower.stat(io)).inode, (try joining_follower.stat(io)).inode);
    const history = try tmp.dir.openFile(io, "capture.log.1", .{});
    defer history.close(io);
    try std.testing.expectEqual((try follower.stat(io)).inode, (try history.stat(io)).inode);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "capture.log.prev", .{}));

    try sink.rotate();
    try sink.write("stderr", "replacement record");
    const current = try tmp.dir.openFile(io, "capture.log", .{});
    defer current.close(io);
    try std.testing.expect((try current.stat(io)).inode != (try follower.stat(io)).inode);
    var buf: [128]u8 = undefined;
    var reader = follower.reader(io, &.{});
    const count = try reader.interface.readSliceShort(&buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..count], "retained record") != null);
    const live = try tmp.dir.readFileAlloc(io, "capture.log", alloc, .limited(128));
    defer alloc.free(live);
    try std.testing.expect(std.mem.indexOf(u8, live, "replacement record") != null);
}

test "log sink failed history publication preserves the live descriptor and retries" {
    const io = std.testing.io;
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &dir_buf);
    const path = try std.fmt.allocPrint(alloc, "{s}/capture.log", .{dir_buf[0..len]});
    defer alloc.free(path);
    var sink = try Sink.init(try tmp.dir.createFile(io, "capture.log", .{ .read = true }), path);
    defer sink.close();
    try sink.write("stdout", "before failure");
    const inode = (try sink.file.stat(io)).inode;
    try tmp.dir.createDir(io, "capture.log.1", .default_dir);
    if (sink.rotate()) |_| return error.ExpectedRotationFailure else |_| {}
    try std.testing.expectEqual(inode, (try sink.file.stat(io)).inode);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "capture.log.prev", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "capture.log.next", .{}));
    try sink.write("stderr", "after failure");
    const live = try tmp.dir.readFileAlloc(io, "capture.log", alloc, .limited(256));
    defer alloc.free(live);
    try std.testing.expect(std.mem.indexOf(u8, live, "before failure") != null);
    try std.testing.expect(std.mem.indexOf(u8, live, "after failure") != null);
    try tmp.dir.deleteDir(io, "capture.log.1");
    // A stale temporary link from a crashed attempt is safe to replace.
    try tmp.dir.hardLink("capture.log", tmp.dir, "capture.log.prev", io, .{});
    try sink.rotate();
    try std.testing.expect((try sink.file.stat(io)).inode != inode);
    const retained = try tmp.dir.readFileAlloc(io, "capture.log.1", alloc, .limited(256));
    defer alloc.free(retained);
    try std.testing.expectEqualStrings(live, retained);
}
