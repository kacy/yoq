const std = @import("std");
const posix = std.posix;
const platform = @import("linux_platform").posix;

pub const max_payload = 4096;
pub const Kind = enum(u8) { hello = 1, ready, stdin, stdout, stderr, resize, signal, eof, exit, failure, detach };
pub const Packet = struct {
    bytes: [max_payload + 1]u8 = undefined,
    len: usize = 0,

    pub fn kind(self: *const Packet) !Kind {
        if (self.len == 0) return error.Disconnected;
        return std.enums.fromInt(Kind, self.bytes[0]) orelse error.InvalidPacket;
    }
    pub fn payload(self: *const Packet) []const u8 {
        return self.bytes[1..self.len];
    }
};

pub fn send(fd: posix.fd_t, kind: Kind, data: []const u8, nonblocking: bool) !void {
    if (data.len > max_payload) return error.InvalidPacket;
    var buffer: [max_payload + 1]u8 = undefined;
    buffer[0] = @intFromEnum(kind);
    @memcpy(buffer[1..][0..data.len], data);
    const count = try platform.send(fd, buffer[0 .. data.len + 1], posix.MSG.NOSIGNAL | @as(u32, if (nonblocking) posix.MSG.DONTWAIT else 0));
    if (count != data.len + 1) return error.Disconnected;
}

pub fn receive(fd: posix.fd_t, packet: *Packet, nonblocking: bool) !void {
    const count = try platform.recv(fd, &packet.bytes, posix.MSG.TRUNC | @as(u32, if (nonblocking) posix.MSG.DONTWAIT else 0));
    if (count == 0) return error.Disconnected;
    if (count > packet.bytes.len) return error.InvalidPacket;
    packet.len = count;
    _ = try packet.kind();
}

pub const DetachKeys = struct {
    pending: bool = false,

    /// detach keys (Ctrl-P Ctrl-Q) may span reads. a lone Ctrl-P waits for the
    /// next byte or EOF; unrelated bytes are forwarded unchanged.
    pub fn consume(self: *DetachKeys, input: []const u8, output: []u8) struct { count: usize, detached: bool } {
        var count: usize = 0;
        for (input) |byte| {
            if (self.pending) {
                self.pending = false;
                if (byte == 0x11) return .{ .count = count, .detached = true };
                output[count] = 0x10;
                count += 1;
            }
            if (byte == 0x10) {
                self.pending = true;
            } else {
                output[count] = byte;
                count += 1;
            }
        }
        return .{ .count = count, .detached = false };
    }
};

test "session detach keys survive split reads and preserve unrelated control bytes" {
    var keys: DetachKeys = .{};
    var output: [32]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), keys.consume("\x10", &output).count);
    const ordinary = keys.consume("x\x00", &output);
    try std.testing.expectEqualStrings("\x10x\x00", output[0..ordinary.count]);
    try std.testing.expect(!ordinary.detached);
    _ = keys.consume("\x10", &output);
    try std.testing.expect(keys.consume("\x11", &output).detached);
}

test "session packets preserve stream tags and binary bytes" {
    var fds: [2]posix.fd_t = undefined;
    if (std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0, &fds) != 0) return error.SocketFailed;
    defer platform.close(fds[0]);
    defer platform.close(fds[1]);
    try send(fds[0], .stderr, "prompt\x00\r", false);
    var packet: Packet = .{};
    try receive(fds[1], &packet, false);
    try std.testing.expectEqual(Kind.stderr, try packet.kind());
    try std.testing.expectEqualStrings("prompt\x00\r", packet.payload());
    try std.testing.expectError(error.InvalidPacket, send(fds[0], .stdin, "x" ** (max_payload + 1), false));
}
