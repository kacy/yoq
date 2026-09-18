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

    return try readMessage(self, alloc, client_fd, from_addr);
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

fn readTestFrame(transport: anytype, alloc: std.mem.Allocator, frame: []const u8) !ReceivedMessage {
    var sockets: [2]posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &sockets) != 0) return error.SocketPairFailed;
    defer linux_platform.posix.close(sockets[1]);
    {
        defer linux_platform.posix.close(sockets[0]);
        var sent: usize = 0;
        while (sent < frame.len) {
            const count = try linux_platform.posix.write(sockets[0], frame[sent..]);
            if (count == 0) return error.WriteFailed;
            sent += count;
        }
    }
    // closing the writer lets truncated frames reach eof without a timeout.
    return readMessage(transport, alloc, sockets[1], linux_platform.net.Address.initIp4(.{ 127, 0, 0, 1 }, 43210));
}

test "tcp frame receive rejects invalid lengths and distinguishes truncated input" {
    const Transport = @import("../transport.zig").Transport;
    const alloc = std.testing.allocator;
    var transport = try Transport.initForTests(alloc);
    defer transport.deinit();
    const cases = [_]struct { frame: []const u8, expected: TransportError }{
        .{ .frame = &.{}, .expected = error.ReceiveFailed },
        .{ .frame = &.{ 1, 0 }, .expected = error.ReceiveFailed },
        .{ .frame = &.{ 0, 0, 0, 0 }, .expected = error.InvalidMessage },
        .{ .frame = &.{ 1, 0, 0, 4 }, .expected = error.InvalidMessage },
        .{ .frame = &.{ 1, 0, 0, 0 }, .expected = error.ReceiveFailed },
        .{ .frame = &.{ 1, 0, 0, 0, 0xff }, .expected = error.InvalidMessage },
    };
    for (cases) |case| {
        try std.testing.expectError(case.expected, readTestFrame(&transport, alloc, case.frame));
    }
}

test "tcp frame receive owns snapshot data across the stack buffer boundary" {
    const Transport = @import("../transport.zig").Transport;
    const alloc = std.testing.allocator;
    var transport = try Transport.initForTests(alloc);
    defer transport.deinit();
    // a snapshot body has 37 header bytes before its data.
    for ([_]usize{ 8192, 8193 }) |body_len| {
        const data = try alloc.alloc(u8, body_len - 37);
        defer alloc.free(data);
        @memset(data, 0x5a);
        const frame = try codec_support.encodeSnapshot(alloc, .{
            .term = 3,
            .leader_id = 7,
            .last_included_index = 12,
            .last_included_term = 2,
            .data = data,
        });
        defer alloc.free(frame);
        try std.testing.expectEqual(body_len, frame.len - 4);

        const received = try readTestFrame(&transport, alloc, frame);
        defer alloc.free(received.message.install_snapshot.data);
        try std.testing.expect(received.sender_id == null);
        try std.testing.expectEqual(@as(u64, 12), received.message.install_snapshot.last_included_index);
        try std.testing.expectEqualSlices(u8, data, received.message.install_snapshot.data);
        try std.testing.expect(received.message.install_snapshot.data.ptr != frame[41..].ptr);

        if (body_len > 8192) {
            for (0..2) |fail_index| {
                var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = fail_index });
                const expected: TransportError = if (fail_index == 0) error.ReceiveFailed else error.InvalidMessage;
                try std.testing.expectError(expected, readTestFrame(&transport, failing.allocator(), frame));
                try std.testing.expect(failing.has_induced_failure);
                try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            }
            try std.testing.expectError(error.ReceiveFailed, readTestFrame(&transport, alloc, frame[0 .. frame.len - 1]));
        }
    }
}

test "tcp frame receive verifies authentication before decoding and permits ephemeral source ports" {
    const Transport = @import("../transport.zig").Transport;
    const alloc = std.testing.allocator;
    var transport = try Transport.initForTests(alloc);
    defer transport.deinit();
    const key = [_]u8{7} ** 32;
    transport.shared_key = key;
    try transport.addPeer(7, .{ 127, 0, 0, 1 }, 9700);

    var buf: [32]u8 = undefined;
    const len = try codec_support.encode(&buf, .{ .install_snapshot_reply = .{ .term = 3 } });
    const signed = try auth_support.applyHmac(alloc, key, 7, buf[0..len]);
    defer alloc.free(signed);
    const received = try readTestFrame(&transport, alloc, signed);
    try std.testing.expectEqual(@as(?u64, 7), received.sender_id);
    try std.testing.expectEqual(@as(u64, 3), received.message.install_snapshot_reply.term);

    const malformed = [_]u8{ 1, 0, 0, 0, 0xff };
    const bad_signature = try auth_support.applyHmac(alloc, [_]u8{8} ** 32, 7, &malformed);
    defer alloc.free(bad_signature);
    try std.testing.expectError(error.AuthenticationFailed, readTestFrame(&transport, alloc, bad_signature));
    const bad_message = try auth_support.applyHmac(alloc, key, 7, &malformed);
    defer alloc.free(bad_message);
    try std.testing.expectError(error.InvalidMessage, readTestFrame(&transport, alloc, bad_message));
}
