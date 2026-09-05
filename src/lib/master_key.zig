//! The shared encryption key is published only after its complete contents are
//! durable. Concurrent initializers must use the published winner's key.
const std = @import("std");
const platform = @import("linux_platform");
const paths = @import("paths.zig");
const io = std.Options.debug_io;
const linux = std.os.linux;
pub const key_length = 32;
pub const KeyError = error{ HomeDirNotFound, PathTooLong, KeyCreateFailed, KeyLoadFailed };
const ReadError = error{ NotFound, KeyLoadFailed };

pub fn secureZero(bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
}

pub fn loadOrCreateKey() KeyError![key_length]u8 {
    var buf: [paths.max_path]u8 = undefined;
    const path = paths.dataPath(&buf, "secrets.key") catch |err| return err;
    paths.ensureDataDirStrict("") catch |err| return switch (err) {
        error.CreateFailed => error.KeyCreateFailed,
        else => |e| e,
    };
    var dir = std.Io.Dir.cwd().openDir(io, std.fs.path.dirname(path).?, .{ .iterate = true }) catch return error.KeyLoadFailed;
    defer dir.close(io);
    return loadOrCreateAt(dir, std.fs.path.basename(path));
}

fn loadOrCreateAt(dir: std.Io.Dir, name: []const u8) KeyError![key_length]u8 {
    if (readAt(dir, name)) |key| {
        (platform.File{ .handle = dir.handle }).sync() catch return error.KeyCreateFailed;
        return key;
    } else |err| switch (err) {
        error.NotFound => {},
        else => return error.KeyLoadFailed,
    }
    var candidate: [key_length]u8 = undefined;
    platform.randomBytes(&candidate);
    defer secureZero(&candidate);
    var pending = dir.createFileAtomic(io, name, .{ .permissions = .fromMode(0o600) }) catch return error.KeyCreateFailed;
    defer pending.deinit(io);
    pending.file.writeStreamingAll(io, &candidate) catch return error.KeyCreateFailed;
    pending.file.sync(io) catch return error.KeyCreateFailed;
    pending.link(io) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return error.KeyCreateFailed,
    };
    // Also sync when losing the race: the winner may not have synced yet.
    (platform.File{ .handle = dir.handle }).sync() catch return error.KeyCreateFailed;
    return readAt(dir, name) catch return error.KeyLoadFailed;
}

pub fn readKeyFile(path: []const u8) ReadError![key_length]u8 {
    return readAt(std.Io.Dir.cwd(), path);
}

fn readAt(dir: std.Io.Dir, name: []const u8) ReadError![key_length]u8 {
    const path = std.posix.toPosixPath(name) catch return error.KeyLoadFailed;
    // NONBLOCK makes hostile FIFO/device entries fail without blocking startup.
    const rc = linux.openat(dir.handle, &path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true, .NONBLOCK = true }, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .NOENT => return error.NotFound,
        else => return error.KeyLoadFailed,
    }
    const file: std.Io.File = .{ .handle = @intCast(rc), .flags = .{ .nonblocking = true } };
    defer file.close(io);
    var stat: linux.Statx = undefined;
    if (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true, .SIZE = true }, &stat)) != .SUCCESS) return error.KeyLoadFailed;
    if (!stat.mask.TYPE or !stat.mask.MODE or !stat.mask.UID or !stat.mask.SIZE or
        stat.mode & linux.S.IFMT != linux.S.IFREG or stat.mode & 0o077 != 0 or
        stat.uid != linux.geteuid() or stat.size != key_length) return error.KeyLoadFailed;
    var key: [key_length]u8 = undefined;
    errdefer secureZero(&key);
    var reader = file.reader(io, &.{});
    reader.interface.readSliceAll(&key) catch return error.KeyLoadFailed;
    return key;
}

test "master key concurrent initialization converges on one durable private key" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const Worker = struct {
        dir: std.Io.Dir,
        key: ?[key_length]u8 = null,
        fn run(self: *@This()) void {
            self.key = loadOrCreateAt(self.dir, "secrets.key") catch null;
        }
    };
    var workers: [8]Worker = undefined;
    var threads: [8]std.Thread = undefined;
    var started: usize = 0;
    defer for (threads[0..started]) |thread| thread.join();
    for (&workers, &threads) |*worker, *thread| {
        worker.* = .{ .dir = tmp.dir };
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{worker});
        started += 1;
    }
    for (threads) |thread| thread.join();
    started = 0;
    const winner = try readAt(tmp.dir, "secrets.key");
    for (workers) |worker| try std.testing.expectEqualSlices(u8, &winner, &(worker.key orelse return error.TestUnexpectedResult));
    try std.testing.expectEqualSlices(u8, &winner, &(try loadOrCreateAt(tmp.dir, "secrets.key")));
}

test "master key refuses unsafe existing entries without overwriting them" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    for ([_]usize{ 0, 31, 33 }) |size| {
        var file = try tmp.dir.createFile(io, "key", .{ .permissions = .fromMode(0o600) });
        try file.writeStreamingAll(io, ([_]u8{9} ** 33)[0..size]);
        file.close(io);
        try std.testing.expectError(error.KeyLoadFailed, loadOrCreateAt(tmp.dir, "key"));
        try tmp.dir.deleteFile(io, "key");
    }
    var weak = try tmp.dir.createFile(io, "weak", .{ .permissions = .fromMode(0o644) });
    try weak.writeStreamingAll(io, &([_]u8{3} ** key_length));
    try weak.setPermissions(io, .fromMode(0o644));
    weak.close(io);
    try std.testing.expectError(error.KeyLoadFailed, loadOrCreateAt(tmp.dir, "weak"));
    try tmp.dir.symLink(io, "weak", "key", .{});
    try std.testing.expectError(error.KeyLoadFailed, loadOrCreateAt(tmp.dir, "key"));
}

test "master key interrupted unpublished write does not leave a partial key" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    {
        var interrupted = try tmp.dir.createFileAtomic(io, "key", .{ .permissions = .fromMode(0o600) });
        defer interrupted.deinit(io);
        try interrupted.file.writeStreamingAll(io, "partial");
        try std.testing.expectError(error.NotFound, readAt(tmp.dir, "key"));
    }
    _ = try loadOrCreateAt(tmp.dir, "key");
    _ = try readAt(tmp.dir, "key");
}
