const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const types = @import("../raft_types.zig");
const common = @import("common.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const NodeId = types.NodeId;
const GossipReceiveResult = common.GossipReceiveResult;
const TransportError = common.TransportError;

pub fn initUdp(self: anytype, port: u16) !void {
    if (self.udp_fd != null) return;

    const fd = try linux_platform.posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    errdefer linux_platform.posix.close(fd);

    const one: i32 = 1;
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));

    const addr = linux_platform.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
    try linux_platform.posix.bind(fd, &addr.any, addr.getOsSockLen());
    self.udp_fd = fd;
}

pub fn deinitUdp(self: anytype) void {
    if (self.udp_fd) |fd| {
        linux_platform.posix.close(fd);
        self.udp_fd = null;
    }
}

pub fn sendGossip(self: anytype, ip: [4]u8, port: u16, payload: []const u8) TransportError!void {
    const fd = self.udp_fd orelse return TransportError.SendFailed;
    const key = self.shared_key orelse return TransportError.AuthenticationFailed;
    const local_id = self.local_id orelse return TransportError.SendFailed;

    var frame_buf: [1500]u8 = undefined;
    const frame_len = 8 + 32 + payload.len;
    if (frame_len > frame_buf.len) return TransportError.SendFailed;

    var sender_bytes: [8]u8 = undefined;
    common.writeU64(&sender_bytes, local_id);
    @memcpy(frame_buf[0..8], &sender_bytes);
    @memcpy(frame_buf[40..][0..payload.len], payload);

    var tag: [32]u8 = undefined;
    var hmac = HmacSha256.init(&key);
    hmac.update(&sender_bytes);
    hmac.update(payload);
    hmac.final(&tag);
    @memcpy(frame_buf[8..40], &tag);

    const dest = linux_platform.net.Address.initIp4(ip, port);
    _ = linux_platform.posix.sendto(fd, frame_buf[0..frame_len], 0, &dest.any, dest.getOsSockLen()) catch {
        return TransportError.SendFailed;
    };
}

pub fn receiveGossip(self: anytype, buf: []u8) TransportError!?GossipReceiveResult {
    const fd = self.udp_fd orelse return TransportError.ReceiveFailed;
    const key = self.shared_key orelse return TransportError.AuthenticationFailed;

    var from_addr: posix.sockaddr = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    const recv_len = linux_platform.posix.recvfrom(fd, buf, 0, &from_addr, &addr_len) catch |err| {
        return switch (err) {
            error.WouldBlock => null,
            else => TransportError.ReceiveFailed,
        };
    };
    if (recv_len < 40) return TransportError.AuthenticationFailed;

    const sender_bytes = buf[0..8];
    const received_hmac = buf[8..40];
    const payload = buf[40..recv_len];

    var expected: [32]u8 = undefined;
    var hmac = HmacSha256.init(&key);
    hmac.update(sender_bytes);
    hmac.update(payload);
    hmac.final(&expected);

    if (!std.crypto.timing_safe.eql([32]u8, received_hmac[0..32].*, expected)) {
        return TransportError.AuthenticationFailed;
    }

    return .{
        .sender_id = common.readU64(sender_bytes),
        .from_addr = linux_platform.net.Address{ .any = from_addr },
        .payload = payload,
    };
}

pub fn resolvePeerId(self: anytype, addr: linux_platform.net.Address) ?NodeId {
    var iter = self.peers.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.addr.any.family != addr.any.family) continue;
        if (std.mem.eql(u8, std.mem.asBytes(&entry.value_ptr.addr.in.addr), std.mem.asBytes(&addr.in.addr)) and
            entry.value_ptr.addr.in.port == addr.in.port)
        {
            return entry.key_ptr.*;
        }
    }
    return null;
}
