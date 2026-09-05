//! A child must finish isolation before startup is committed. EOF or a bad
//! message always aborts; closing a channel never grants permission to exec.
const std = @import("std");
const platform = @import("linux_platform");
const posix = std.posix;
const linux = std.os.linux;

pub const Error = error{ ChannelFailed, StartupAborted };
pub const Stage = enum(u8) { filesystem_ready = 1, prepared = 2, execute = 3 };
pub const NetworkFiles = struct {
    enabled: bool = false,
    address: [4]u8 = .{ 0, 0, 0, 0 },
    gateway: [4]u8 = .{ 0, 0, 0, 0 },
};

pub const Channel = struct {
    parent: posix.fd_t,
    child: posix.fd_t,

    pub fn init() Error!Channel {
        var fds: [2]i32 = undefined;
        if (linux.errno(linux.socketpair(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0, &fds)) != .SUCCESS) return error.ChannelFailed;
        errdefer for (fds) |fd| platform.posix.close(fd);
        const timeout: posix.timeval = .{ .sec = 30, .usec = 0 };
        for (fds) |fd| {
            posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch return error.ChannelFailed;
            posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch return error.ChannelFailed;
        }
        return .{ .parent = fds[0], .child = fds[1] };
    }

    pub fn deinit(self: *Channel) void {
        closeOwned(&self.parent);
        closeOwned(&self.child);
    }
};

pub fn closeOwned(fd: *posix.fd_t) void {
    if (fd.* >= 0) platform.posix.close(fd.*);
    fd.* = -1;
}

fn send(fd: posix.fd_t, bytes: []const u8) Error!void {
    const count = platform.posix.send(fd, bytes, posix.MSG.NOSIGNAL) catch return error.ChannelFailed;
    if (count != bytes.len) return error.ChannelFailed;
}

fn receive(fd: posix.fd_t, bytes: []u8) Error!void {
    // MSG_TRUNC exposes oversized packets rather than accepting a prefix.
    const count = platform.posix.recv(fd, bytes, posix.MSG.TRUNC) catch return error.ChannelFailed;
    if (count != bytes.len) return error.StartupAborted;
}

pub fn notify(fd: posix.fd_t, stage: Stage) Error!void {
    try send(fd, &.{@intFromEnum(stage)});
}

pub fn expect(fd: posix.fd_t, stage: Stage) Error!void {
    var byte: [1]u8 = undefined;
    try receive(fd, &byte);
    if (byte[0] != @intFromEnum(stage)) return error.StartupAborted;
}

pub fn sendNetwork(fd: posix.fd_t, files: NetworkFiles) Error!void {
    var packet: [9]u8 = undefined;
    packet[0] = @intFromBool(files.enabled);
    @memcpy(packet[1..5], &files.address);
    @memcpy(packet[5..9], &files.gateway);
    try send(fd, &packet);
}

pub fn receiveNetwork(fd: posix.fd_t) Error!NetworkFiles {
    var packet: [9]u8 = undefined;
    try receive(fd, &packet);
    if (packet[0] > 1) return error.StartupAborted;
    return .{ .enabled = packet[0] == 1, .address = packet[1..5].*, .gateway = packet[5..9].* };
}

test "startup channel enforces stages and preserves generated network data" {
    var channel = try Channel.init();
    defer channel.deinit();
    try notify(channel.child, .filesystem_ready);
    try expect(channel.parent, .filesystem_ready);
    const files: NetworkFiles = .{ .enabled = true, .address = .{ 10, 42, 0, 7 }, .gateway = .{ 10, 42, 0, 1 } };
    try sendNetwork(channel.parent, files);
    try std.testing.expectEqualDeep(files, try receiveNetwork(channel.child));
    try notify(channel.child, .prepared);
    try expect(channel.parent, .prepared);
    try notify(channel.parent, .execute);
    try expect(channel.child, .execute);
}

test "startup channel closure and wrong stages never authorize execution" {
    var channel = try Channel.init();
    defer channel.deinit();
    try notify(channel.parent, .filesystem_ready);
    try std.testing.expectError(error.StartupAborted, expect(channel.child, .execute));
    try sendNetwork(channel.parent, .{});
    try std.testing.expectError(error.StartupAborted, expect(channel.child, .execute));
    closeOwned(&channel.parent);
    try std.testing.expectError(error.StartupAborted, expect(channel.child, .execute));
}
