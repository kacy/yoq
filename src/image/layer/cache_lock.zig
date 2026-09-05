const std = @import("std");
const platform = @import("linux_platform");
const linux = std.os.linux;

/// Locks live outside immutable entries and are never unlinked: unlinking a
/// lock file could let two processes lock different inodes for the same digest.
pub const Lock = struct {
    fd: std.posix.fd_t,

    pub fn acquire(parent: std.Io.Dir, hex: []const u8) !Lock {
        if (hex.len != 64) return error.InvalidDigest;
        for (hex) |c| if (!std.ascii.isDigit(c) and !(c >= 'a' and c <= 'f')) return error.InvalidDigest;
        parent.createDir(std.Options.debug_io, ".locks", .fromMode(0o700)) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
        var path: [80]u8 = undefined;
        const name = try std.fmt.bufPrintZ(&path, ".locks/{s}", .{hex});
        const opened = linux.openat(parent.handle, name, .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o600);
        if (linux.errno(opened) != .SUCCESS) return error.LockFailed;
        const fd: std.posix.fd_t = @intCast(opened);
        errdefer platform.posix.close(fd);
        while (true) {
            switch (linux.errno(linux.flock(fd, 2))) { // LOCK_EX
                .SUCCESS => return .{ .fd = fd },
                .INTR => continue,
                else => return error.LockFailed,
            }
        }
    }

    pub fn deinit(self: Lock) void {
        platform.posix.close(self.fd);
    }
};
