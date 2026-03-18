const std = @import("std");
const posix = std.posix;
const types = @import("../raft_types.zig");
const common = @import("common.zig");
const auth_support = @import("auth_support.zig");
const codec_support = @import("codec_support.zig");

const NodeId = types.NodeId;
const PeerAddr = common.PeerAddr;
const ReceivedMessage = common.ReceivedMessage;
const TransportError = common.TransportError;
const VerifiedBody = common.VerifiedBody;

pub fn sendBytes(self: anytype, peer_id: NodeId, peer: PeerAddr, data: []const u8) !void {
    const fd = self.pool.getOrConnect(peer_id, peer.addr) catch return TransportError.ConnectFailed;

    var total: usize = 0;
    while (total < data.len) {
        const bytes_written = posix.write(fd, data[total..]) catch {
            self.pool.removeConn(peer_id);
            return TransportError.SendFailed;
        };
        if (bytes_written == 0) {
            self.pool.removeConn(peer_id);
            return TransportError.SendFailed;
        }
        total += bytes_written;
    }
}

pub fn receive(self: anytype, alloc: std.mem.Allocator) TransportError!?ReceivedMessage {
    var client_addr: posix.sockaddr = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);

    const client_fd = posix.accept(self.listen_fd, &client_addr, &addr_len, 0) catch |err| {
        return switch (err) {
            error.WouldBlock => null,
            else => TransportError.ReceiveFailed,
        };
    };
    defer posix.close(client_fd);

    const from_addr = std.net.Address{ .any = client_addr };
    const timeout = posix.timeval{ .sec = 5, .usec = 0 };
    posix.setsockopt(client_fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

    var len_buf: [4]u8 = undefined;
    common.readExact(client_fd, &len_buf) catch return TransportError.ReceiveFailed;
    const msg_len = std.mem.readInt(u32, &len_buf, .little);
    if (msg_len > common.max_receive_size or msg_len < 1) return TransportError.InvalidMessage;

    var stack_buf: [8192]u8 = undefined;
    const body = if (msg_len <= stack_buf.len)
        stack_buf[0..msg_len]
    else
        alloc.alloc(u8, msg_len) catch return TransportError.ReceiveFailed;
    defer if (msg_len > stack_buf.len) alloc.free(body);

    common.readExact(client_fd, body) catch return TransportError.ReceiveFailed;

    const verified = if (self.shared_key) |key|
        try auth_support.verifyAuthenticatedBody(body, key, from_addr, &self.peers)
    else
        VerifiedBody{ .sender_id = null, .payload = body };

    const msg = codec_support.decode(alloc, verified.payload) catch return TransportError.InvalidMessage;
    return .{
        .from_addr = from_addr,
        .sender_id = verified.sender_id,
        .message = msg,
    };
}
