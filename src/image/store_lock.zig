// producers keep a shared lease until their blobs have a durable reference.
// pruning takes the exclusive lease for its entire mark and sweep. keep this
// lock file in place so every process always locks the same inode.
const std = @import("std");
const linux = std.os.linux;
const platform = @import("linux_platform");
const paths = @import("../lib/paths.zig");

pub const Mode = enum { shared, exclusive };

pub const Lock = struct {
    fd: ?std.posix.fd_t,

    pub fn acquire(mode: Mode) !Lock {
        return acquireWithWait(mode, true);
    }

    fn acquireWithWait(mode: Mode, wait: bool) !Lock {
        try paths.ensureDataDirStrict("locks");
        var buffer: [paths.max_path]u8 = undefined;
        const path = try paths.dataPath(&buffer, "locks/image-store.lock");
        if (path.len == buffer.len) return error.PathTooLong;
        buffer[path.len] = 0;
        const opened = linux.open(buffer[0..path.len :0], .{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true }, 0o600);
        if (linux.errno(opened) != .SUCCESS) return error.LockFailed;
        const fd: std.posix.fd_t = @intCast(opened);
        errdefer platform.posix.close(fd);
        const operation: i32 = (if (mode == .shared) @as(i32, 1) else 2) | (if (wait) @as(i32, 0) else 4);
        while (true) {
            switch (linux.errno(linux.flock(fd, operation))) {
                .SUCCESS => return .{ .fd = fd },
                .INTR => continue,
                .AGAIN => return error.Busy,
                else => return error.LockFailed,
            }
        }
    }

    pub fn deinit(self: *Lock) void {
        if (self.fd) |fd| {
            _ = linux.flock(fd, 8);
            platform.posix.close(fd);
            self.fd = null;
        }
    }
};

test "image store leases allow producers together and exclude pruning" {
    var first = try Lock.acquireWithWait(.shared, false);
    defer first.deinit();
    var second = try Lock.acquireWithWait(.shared, false);
    defer second.deinit();
    try std.testing.expectError(error.Busy, Lock.acquireWithWait(.exclusive, false));
    first.deinit();
    try std.testing.expectError(error.Busy, Lock.acquireWithWait(.exclusive, false));
    second.deinit();
    var prune = try Lock.acquireWithWait(.exclusive, false);
    defer prune.deinit();
    try std.testing.expectError(error.Busy, Lock.acquireWithWait(.shared, false));
    try std.testing.expectError(error.Busy, Lock.acquireWithWait(.exclusive, false));
}
