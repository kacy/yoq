const std = @import("std");
const linux = std.os.linux;
const platform = @import("linux_platform");
const mount_ops = @import("mount_ops.zig");
const cli = @import("../../lib/cli.zig");

pub const default_size: u64 = 64 * 1024 * 1024;

pub const TmpfsMount = struct {
    target: []const u8,
    size_bytes: u64 = default_size,
    mode: u16 = 0o1777,
    read_only: bool = false,
    noexec: bool = false,
    nosuid: bool = true,
    nodev: bool = true,

    pub fn validate(self: TmpfsMount) !void {
        if (self.target.len < 2 or self.target[0] != '/' or std.mem.indexOfScalar(u8, self.target, 0) != null) return error.InvalidTmpfs;
        var components = std.mem.splitScalar(u8, self.target[1..], '/');
        while (components.next()) |component| {
            if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return error.InvalidTmpfs;
        }
        if (self.target.len > 4095 or self.size_bytes == 0 or self.size_bytes > std.math.maxInt(i64) or self.mode > 0o7777) return error.InvalidTmpfs;
        // These mounts provide the runtime's process and device interfaces.
        for ([_][]const u8{ "/proc", "/sys", "/dev/pts" }) |reserved| {
            if (std.mem.eql(u8, self.target, reserved) or (std.mem.startsWith(u8, self.target, reserved) and self.target.len > reserved.len and self.target[reserved.len] == '/')) return error.InvalidTmpfs;
        }
        if (std.mem.eql(u8, self.target, "/dev")) return error.InvalidTmpfs;
    }

    /// The returned target borrows the input until the saved config duplicates it.
    pub fn parse(value: []const u8) !TmpfsMount {
        var parts = std.mem.splitScalar(u8, value, ':');
        var result: TmpfsMount = .{ .target = parts.next().? };
        if (parts.next()) |options| {
            var items = std.mem.splitScalar(u8, options, ',');
            while (items.next()) |option| {
                if (std.mem.startsWith(u8, option, "size=")) {
                    result.size_bytes = cli.parseMemorySize(option[5..]) orelse return error.InvalidTmpfs;
                } else if (std.mem.startsWith(u8, option, "mode=")) {
                    result.mode = std.fmt.parseUnsigned(u16, option[5..], 8) catch return error.InvalidTmpfs;
                } else if (std.mem.eql(u8, option, "ro")) {
                    result.read_only = true;
                } else if (std.mem.eql(u8, option, "rw")) {
                    result.read_only = false;
                } else if (std.mem.eql(u8, option, "noexec")) {
                    result.noexec = true;
                } else if (std.mem.eql(u8, option, "exec")) {
                    result.noexec = false;
                } else if (std.mem.eql(u8, option, "nosuid")) {
                    result.nosuid = true;
                } else if (std.mem.eql(u8, option, "suid")) {
                    result.nosuid = false;
                } else if (std.mem.eql(u8, option, "nodev")) {
                    result.nodev = true;
                } else if (std.mem.eql(u8, option, "dev")) {
                    result.nodev = false;
                } else return error.InvalidTmpfs;
            }
        }
        if (parts.next() != null) return error.InvalidTmpfs;
        try result.validate();
        return result;
    }
};

pub fn mountAt(root: []const u8, config: TmpfsMount) !void {
    try config.validate();
    const root_fd = try platform.posix.open(root, .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    defer platform.posix.close(root_fd);
    const target_fd = try mount_ops.prepareDirectory(root_fd, config.target);
    defer platform.posix.close(target_fd);
    var path_buffer: [64]u8 = undefined;
    const target = try std.fmt.bufPrintZ(&path_buffer, "/proc/self/fd/{d}", .{target_fd});
    var options_buffer: [96]u8 = undefined;
    const options = try std.fmt.bufPrintZ(&options_buffer, "size={d},mode={o}", .{ config.size_bytes, config.mode });
    var flags: u32 = 0;
    if (config.read_only) flags |= linux.MS.RDONLY;
    if (config.noexec) flags |= linux.MS.NOEXEC;
    if (config.nosuid) flags |= linux.MS.NOSUID;
    if (config.nodev) flags |= linux.MS.NODEV;
    if (linux.errno(linux.mount("tmpfs", target.ptr, "tmpfs", flags, @intFromPtr(options.ptr))) != .SUCCESS) return error.MountFailed;
}

test "tmpfs parses typed options and rejects invalid mount settings" {
    const mount = try TmpfsMount.parse("/cache:size=32m,mode=750,ro,noexec");
    try std.testing.expectEqual(@as(u64, 32 * 1024 * 1024), mount.size_bytes);
    try std.testing.expectEqual(@as(u16, 0o750), mount.mode);
    try std.testing.expect(mount.read_only and mount.noexec and mount.nosuid and mount.nodev);
    for ([_][]const u8{ "/", "relative", "/cache/../data", "/cache:size=0", "/cache:size=bad", "/cache:mode=888", "/cache:mode=10000", "/cache:unknown", "/cache:", "/cache:ro:rw", "/proc", "/dev", "/sys/foo" }) |value|
        try std.testing.expectError(error.InvalidTmpfs, TmpfsMount.parse(value));
}
