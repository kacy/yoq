const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const common = @import("common.zig");
const auth_support = @import("auth_support.zig");
const codec_support = @import("codec_support.zig");

const PeerAddr = common.PeerAddr;
const ReceivedMessage = common.ReceivedMessage;
const TransportError = common.TransportError;
const VerifiedBody = common.VerifiedBody;

pub fn sendBytes(peer: PeerAddr, data: []const u8) !void {
    const fd = linux_platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return TransportError.ConnectFailed;
    defer linux_platform.posix.close(fd);

    const timeout = posix.timeval{ .sec = 1, .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};

    linux_platform.posix.connect(fd, &peer.addr.any, peer.addr.getOsSockLen()) catch return TransportError.ConnectFailed;

    var total: usize = 0;
    while (total < data.len) {
        const bytes_written = linux_platform.posix.write(fd, data[total..]) catch return TransportError.SendFailed;
        if (bytes_written == 0) return TransportError.SendFailed;
        total += bytes_written;
    }
}

pub fn receive(self: anytype, alloc: std.mem.Allocator) TransportError!?ReceivedMessage {
    var client_addr: posix.sockaddr = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);

    const client_fd = linux_platform.posix.accept(self.listen_fd, &client_addr, &addr_len, 0) catch |err| {
        return switch (err) {
            error.WouldBlock => null,
            else => TransportError.ReceiveFailed,
        };
    };
    defer linux_platform.posix.close(client_fd);

    const from_addr = linux_platform.net.Address{ .any = client_addr };
    const timeout = posix.timeval{ .sec = 5, .usec = 0 };
    posix.setsockopt(client_fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

    return readMessage(self, alloc, client_fd, from_addr);
}

// the socket frame is temporary. decoding copies entry and snapshot data
// before the stack buffer or allocated body is released.
fn readMessage(self: anytype, alloc: std.mem.Allocator, client_fd: linux_platform.posix.socket_t, from_addr: linux_platform.net.Address) TransportError!ReceivedMessage {
    var len_buf: [4]u8 = undefined;
    common.readExact(client_fd, &len_buf) catch return TransportError.ReceiveFailed;
    const body_len = std.mem.readInt(u32, &len_buf, .little);
    if (body_len > common.max_receive_size or body_len < 1) return TransportError.InvalidMessage;

    var stack_buf: [8192]u8 = undefined;
    const body_is_allocated = body_len > stack_buf.len;
    const body = if (!body_is_allocated)
        stack_buf[0..body_len]
    else
        alloc.alloc(u8, body_len) catch return TransportError.ReceiveFailed;
    defer if (body_is_allocated) alloc.free(body);

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
