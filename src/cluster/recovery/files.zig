const std = @import("std");
const platform = @import("linux_platform");
const linux = std.os.linux;
const io = std.Options.debug_io;

pub const Digest = struct { size: u64, sha256: [64]u8 };
pub const max_database_size: u64 = 4 * 1024 * 1024 * 1024;

pub fn openDir(path: []const u8) !std.Io.Dir {
    const start: [:0]const u8 = if (std.fs.path.isAbsolute(path)) "/" else ".";
    var rc = linux.openat(linux.AT.FDCWD, start, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.UnsafeDirectory;
    var dir: std.Io.Dir = .{ .handle = @intCast(rc) };
    errdefer dir.close(io);
    var components = std.mem.tokenizeScalar(u8, path, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) return error.UnsafeDirectory;
        const terminated = try std.posix.toPosixPath(component);
        rc = linux.openat(dir.handle, &terminated, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        if (linux.errno(rc) != .SUCCESS) return error.UnsafeDirectory;
        dir.close(io);
        dir = .{ .handle = @intCast(rc) };
    }
    return dir;
}

pub fn openRegular(dir: std.Io.Dir, name: []const u8, private: bool) !std.Io.File {
    const terminated = try std.posix.toPosixPath(name);
    const rc = linux.openat(dir.handle, &terminated, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .NONBLOCK = true, .CLOEXEC = true }, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .NOENT => return error.FileNotFound,
        else => return error.UnsafeFile,
    }
    const file: std.Io.File = .{ .handle = @intCast(rc), .flags = .{ .nonblocking = true } };
    errdefer file.close(io);
    var stat: linux.Statx = undefined;
    if (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true, .SIZE = true }, &stat)) != .SUCCESS) return error.UnsafeFile;
    if (!stat.mask.TYPE or !stat.mask.MODE or !stat.mask.UID or !stat.mask.SIZE) return error.UnsafeFile;
    if (stat.mode & linux.S.IFMT != linux.S.IFREG) return error.UnsafeFile;
    if (private and (stat.mode & 0o077 != 0 or stat.uid != linux.geteuid())) return error.UnsafeFile;
    return file;
}

pub fn create(dir: std.Io.Dir, name: []const u8) !std.Io.File {
    return dir.createFile(io, name, .{ .exclusive = true, .permissions = .fromMode(0o600) });
}

pub fn copy(source: std.Io.Dir, name: []const u8, destination: std.Io.Dir, destination_name: []const u8, private_source: bool, limit: u64) !Digest {
    var input = try openRegular(source, name, private_source);
    defer input.close(io);
    var output = try create(destination, destination_name);
    defer output.close(io);
    errdefer destination.deleteFile(io, destination_name) catch {};
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var size: u64 = 0;
    var buffer: [65536]u8 = undefined;
    while (true) {
        const count = try platform.posix.read(input.handle, &buffer);
        if (count == 0) break;
        size = std.math.add(u64, size, count) catch return error.FileTooLarge;
        if (size > limit) return error.FileTooLarge;
        hash.update(buffer[0..count]);
        try output.writeStreamingAll(io, buffer[0..count]);
    }
    try output.sync(io);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .size = size, .sha256 = std.fmt.bytesToHex(digest, .lower) };
}

pub fn digest(dir: std.Io.Dir, name: []const u8, limit: u64) !Digest {
    var input = try openRegular(dir, name, true);
    defer input.close(io);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var size: u64 = 0;
    var buffer: [65536]u8 = undefined;
    while (true) {
        const count = try platform.posix.read(input.handle, &buffer);
        if (count == 0) break;
        size = std.math.add(u64, size, count) catch return error.FileTooLarge;
        if (size > limit) return error.FileTooLarge;
        hash.update(buffer[0..count]);
    }
    var sum: [32]u8 = undefined;
    hash.final(&sum);
    return .{ .size = size, .sha256 = std.fmt.bytesToHex(sum, .lower) };
}

pub fn readSmall(alloc: std.mem.Allocator, dir: std.Io.Dir, name: []const u8, limit: usize) ![]u8 {
    var input = try openRegular(dir, name, true);
    defer input.close(io);
    var reader = input.reader(io, &.{});
    return reader.interface.allocRemaining(alloc, .limited(limit));
}

pub fn write(dir: std.Io.Dir, name: []const u8, data: []const u8) !void {
    var file = try create(dir, name);
    defer file.close(io);
    try file.writeStreamingAll(io, data);
    try file.sync(io);
}

pub fn syncDir(dir: std.Io.Dir) !void {
    try (platform.File{ .handle = dir.handle }).sync();
}

pub const Stage = struct {
    parent: std.Io.Dir,
    dir: std.Io.Dir,
    temporary: [48]u8,
    final_name: [256]u8,
    final_len: usize,
    published: bool = false,

    pub fn init(destination: []const u8) !Stage {
        const name = std.fs.path.basename(destination);
        if (name.len == 0 or name.len >= 256 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidDestination;
        var parent = try openDir(std.fs.path.dirname(destination) orelse ".");
        errdefer parent.close(io);
        var random: [16]u8 = undefined;
        platform.randomBytes(&random);
        var temporary: [48]u8 = @splat(0);
        const staging_name = try std.fmt.bufPrint(temporary[0..47], ".yoq-recovery-{s}", .{std.fmt.bytesToHex(random, .lower)});
        try parent.createDir(io, staging_name, .fromMode(0o700));
        errdefer parent.deleteTree(io, staging_name) catch {};
        var dir = try parent.openDir(io, staging_name, .{ .iterate = true });
        errdefer dir.close(io);
        var stage = Stage{ .parent = parent, .dir = dir, .temporary = temporary, .final_name = undefined, .final_len = name.len };
        @memcpy(stage.final_name[0..name.len], name);
        return stage;
    }

    pub fn name(self: *const Stage) []const u8 {
        return std.mem.sliceTo(&self.temporary, 0);
    }

    pub fn path(self: *const Stage, alloc: std.mem.Allocator) ![]u8 {
        return self.dir.realPathFileAlloc(io, ".", alloc);
    }

    pub fn publish(self: *Stage) !void {
        try syncDir(self.dir);
        const old = try std.posix.toPosixPath(self.name());
        const final = try std.posix.toPosixPath(self.final_name[0..self.final_len]);
        switch (linux.errno(linux.renameat2(self.parent.handle, &old, self.parent.handle, &final, .{ .NOREPLACE = true }))) {
            .SUCCESS => {},
            .EXIST => return error.DestinationExists,
            else => return error.PublishFailed,
        }
        self.published = true;
        try syncDir(self.parent);
    }

    pub fn deinit(self: *Stage) void {
        self.dir.close(io);
        if (!self.published) self.parent.deleteTree(io, self.name()) catch {};
        self.parent.close(io);
    }
};
