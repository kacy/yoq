//! server startup and offline recovery share this lifetime lock. sqlite locks
//! protect individual databases; this lock identifies the process owning them.
const std = @import("std");
const platform = @import("linux_platform");
const linux = std.os.linux;

pub const Lock = struct {
    fd: std.posix.fd_t,

    pub fn acquire(path: []const u8) !Lock {
        var dir = try std.Io.Dir.cwd().openDir(std.Options.debug_io, path, .{});
        defer dir.close(std.Options.debug_io);
        return acquireAt(dir);
    }

    pub fn acquireAt(dir: std.Io.Dir) !Lock {
        const opened = linux.openat(dir.handle, ".server.lock", .{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true, .NOFOLLOW = true, .NONBLOCK = true }, 0o600);
        if (linux.errno(opened) != .SUCCESS) return error.LockFailed;
        const fd: std.posix.fd_t = @intCast(opened);
        errdefer platform.posix.close(fd);
        var stat: linux.Statx = undefined;
        if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true }, &stat)) != .SUCCESS) return error.LockFailed;
        if (stat.mode & linux.S.IFMT != linux.S.IFREG or stat.mode & 0o077 != 0 or stat.uid != linux.geteuid()) return error.UnsafeLock;
        switch (linux.errno(linux.flock(fd, 2 | 4))) {
            .SUCCESS => {},
            .AGAIN => return error.ServerRunning,
            else => return error.LockFailed,
        }
        return .{ .fd = fd };
    }

    pub fn release(self: Lock) void {
        platform.posix.close(self.fd);
    }
};

test "cluster bundle lifetime lock excludes idle servers and releases after close" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const first = try Lock.acquireAt(tmp.dir);
    try std.testing.expectError(error.ServerRunning, Lock.acquireAt(tmp.dir));
    first.release();
    const next = try Lock.acquireAt(tmp.dir);
    next.release();
}
