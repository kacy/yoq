const std = @import("std");
const platform = @import("linux_platform");
const linux = std.os.linux;
const io = std.Options.debug_io;

/// firewall chains are shared by the network namespace, even when callers
/// use different data directories. one namespace therefore has one authority.
/// the owner marker remains until reboot or explicit offline recovery.
pub fn acquire(owner: []const u8) !std.posix.fd_t {
    var namespace_buf: [80]u8 = undefined;
    const namespace_len = try std.Io.Dir.cwd().readLink(io, "/proc/self/ns/net", &namespace_buf);
    const namespace_hash = std.hash.Wyhash.hash(0, namespace_buf[0..namespace_len]);
    try std.Io.Dir.cwd().createDirPath(io, "/run/yoq");
    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "/run/yoq/published-{x}.lock", .{namespace_hash});
    const opened = linux.open(path, .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o600);
    if (linux.errno(opened) != .SUCCESS) return error.LockFailed;
    const fd: std.posix.fd_t = @intCast(opened);
    errdefer platform.posix.close(fd);
    while (true) switch (linux.errno(linux.flock(fd, 2))) {
        .SUCCESS => break,
        .INTR => continue,
        else => return error.LockFailed,
    };
    try checkOwner(.{ .handle = fd }, owner);
    return fd;
}

fn checkOwner(file: platform.File, owner: []const u8) !void {
    var stored: [4096]u8 = undefined;
    try file.seekTo(0);
    const len = try file.readAll(&stored);
    if (len == 0) {
        if (owner.len == 0 or owner.len >= stored.len) return error.InvalidOwner;
        try file.writeAll(owner);
        try file.sync();
    } else if (!std.mem.eql(u8, stored[0..len], owner)) return error.NetworkNamespaceOwned;
}

test "published ports reject another data directory in the same namespace" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(std.testing.io, "owner", .{ .read = true });
    defer file.close(std.testing.io);
    try checkOwner(platform.File.from(file), "/root/.local/share/yoq");
    try checkOwner(platform.File.from(file), "/root/.local/share/yoq");
    try std.testing.expectError(error.NetworkNamespaceOwned, checkOwner(platform.File.from(file), "/different/state"));
    try checkOwner(platform.File.from(file), "/root/.local/share/yoq");
}
