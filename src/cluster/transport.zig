// transport — TCP and UDP transport for raft and gossip traffic.
//
// The top-level module keeps the public transport surface stable. The
// implementation now lives behind small support modules so HMAC handling,
// message codec logic, and UDP gossip I/O are easier to audit.

const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const types = @import("raft_types.zig");
const common = @import("transport/common.zig");
const auth_support = @import("transport/auth_support.zig");
const codec_support = @import("transport/codec_support.zig");
const io_support = @import("transport/io_support.zig");
const udp_support = @import("transport/udp_support.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const NodeId = types.NodeId;
const LogEntry = types.LogEntry;
const RequestVoteArgs = types.RequestVoteArgs;
const RequestVoteReply = types.RequestVoteReply;
const AppendEntriesArgs = types.AppendEntriesArgs;
const AppendEntriesReply = types.AppendEntriesReply;
const InstallSnapshotArgs = types.InstallSnapshotArgs;
const InstallSnapshotReply = types.InstallSnapshotReply;

pub const TransportError = common.TransportError;
pub const Message = common.Message;
pub const ReceivedMessage = common.ReceivedMessage;
pub const GossipReceiveResult = common.GossipReceiveResult;

const PeerAddr = common.PeerAddr;
const msg_request_vote = common.msg_request_vote;
const msg_request_vote_reply = common.msg_request_vote_reply;
const msg_append_entries = common.msg_append_entries;
const msg_append_entries_reply = common.msg_append_entries_reply;
const msg_install_snapshot = common.msg_install_snapshot;
const msg_install_snapshot_reply = common.msg_install_snapshot_reply;

const invalid_socket: @import("compat").posix.socket_t = -1;

pub const Transport = struct {
    alloc: std.mem.Allocator,
    listen_fd: @import("compat").posix.socket_t,
    peers: std.AutoHashMap(NodeId, PeerAddr),
    local_id: ?NodeId,

    /// optional shared key for HMAC authentication on raft messages.
    /// when null, messages are sent/received without authentication
    /// (single-node mode or during initial bootstrap).
    /// when set, all messages include a 32-byte HMAC-SHA256 tag.
    shared_key: ?[32]u8,

    /// optional UDP socket for gossip protocol messages.
    /// initialized separately from the TCP listener since gossip is
    /// only active when the cluster exceeds a size threshold.
    udp_fd: ?@import("compat").posix.socket_t,

    pub fn init(alloc: std.mem.Allocator, port: u16) !Transport {
        const fd = try @import("compat").posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        errdefer @import("compat").posix.close(fd);

        // allow address reuse
        const one: i32 = 1;
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));

        const addr = @import("compat").net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        try @import("compat").posix.bind(fd, &addr.any, addr.getOsSockLen());
        try @import("compat").posix.listen(fd, 16);

        return .{
            .alloc = alloc,
            .listen_fd = fd,
            .peers = std.AutoHashMap(NodeId, PeerAddr).init(alloc),
            .local_id = null,
            .shared_key = null,
            .udp_fd = null,
        };
    }

    /// test-only initializer that avoids binding a TCP listener.
    /// useful for route-flow and state-machine tests that need a node
    /// shell but do not start transport threads or accept network I/O.
    pub fn initForTests(alloc: std.mem.Allocator) !Transport {
        return .{
            .alloc = alloc,
            .listen_fd = invalid_socket,
            .peers = std.AutoHashMap(NodeId, PeerAddr).init(alloc),
            .local_id = null,
            .shared_key = null,
            .udp_fd = null,
        };
    }

    pub fn deinit(self: *Transport) void {
        self.deinitUdp();
        if (self.listen_fd != invalid_socket) @import("compat").posix.close(self.listen_fd);
        self.peers.deinit();
    }

    pub fn addPeer(self: *Transport, id: NodeId, addr: [4]u8, port: u16) !void {
        try self.peers.put(id, .{
            .addr = @import("compat").net.Address.initIp4(addr, port),
        });
    }

    pub fn setLocalNodeId(self: *Transport, id: NodeId) void {
        self.local_id = id;
    }

    /// cluster mode must authenticate raft messages. single-node mode
    /// (no peers) is the only valid unauthenticated configuration.
    pub fn requireAuth(self: *const Transport) TransportError!void {
        if (self.shared_key == null and self.peers.count() > 0) {
            return TransportError.AuthenticationFailed;
        }
    }

    pub fn send(self: *Transport, target: NodeId, msg: Message) TransportError!void {
        const peer = self.peers.get(target) orelse return TransportError.PeerNotFound;

        if (msg == .install_snapshot) {
            const encoded = encodeSnapshot(self.alloc, msg.install_snapshot) catch return TransportError.SendFailed;
            defer self.alloc.free(encoded);

            const final = self.applyHmac(encoded) catch return TransportError.SendFailed;
            defer if (final.ptr != encoded.ptr) self.alloc.free(final);

            self.sendBytes(target, peer, final) catch return TransportError.SendFailed;
            return;
        }

        var buf: [8192]u8 = undefined;
        const len = encode(&buf, msg) catch return TransportError.SendFailed;

        const final = self.applyHmac(buf[0..len]) catch return TransportError.SendFailed;
        defer if (final.ptr != buf[0..len].ptr) self.alloc.free(final);

        self.sendBytes(target, peer, final) catch return TransportError.SendFailed;
    }

    fn applyHmac(self: *Transport, data: []const u8) ![]const u8 {
        return auth_support.applyHmac(self.alloc, self.shared_key, self.local_id, data);
    }

    fn sendBytes(self: *Transport, peer_id: NodeId, peer: PeerAddr, data: []const u8) !void {
        return io_support.sendBytes(self, peer_id, peer, data);
    }

    pub fn receive(self: *Transport, alloc: std.mem.Allocator) TransportError!?ReceivedMessage {
        return io_support.receive(self, alloc);
    }

    // --- UDP gossip transport ---
    //
    // gossip messages use UDP for low-overhead, fire-and-forget delivery.
    // the protocol handles message loss through redundant probing (SWIM).
    //
    // UDP frame: [8B sender_id] [32B HMAC-SHA256] [gossip payload...]
    // HMAC is computed over [sender_id + payload].

    pub fn initUdp(self: *Transport, port: u16) !void {
        return udp_support.initUdp(self, port);
    }

    pub fn deinitUdp(self: *Transport) void {
        udp_support.deinitUdp(self);
    }

    pub fn sendGossip(self: *Transport, ip: [4]u8, port: u16, payload: []const u8) TransportError!void {
        return udp_support.sendGossip(self, ip, port, payload);
    }

    pub fn receiveGossip(self: *Transport, buf: []u8) TransportError!?GossipReceiveResult {
        return udp_support.receiveGossip(self, buf);
    }

    fn resolvePeerId(self: *const Transport, addr: @import("compat").net.Address) ?NodeId {
        return udp_support.resolvePeerId(self, addr);
    }
};

const verifyAuthenticatedBody = auth_support.verifyAuthenticatedBody;
const samePeerIp = common.samePeerIp;
const encode = codec_support.encode;
const encodeSnapshot = codec_support.encodeSnapshot;
pub const decode = codec_support.decode;
const writeU64 = common.writeU64;
const writeU32 = common.writeU32;
const readU64 = common.readU64;
const readU32 = common.readU32;
const readExact = common.readExact;

// -- tests --

test "encode/decode round-trip: request vote" {
    const alloc = std.testing.allocator;
    const args = RequestVoteArgs{
        .term = 5,
        .candidate_id = 42,
        .last_log_index = 10,
        .last_log_term = 3,
    };

    var buf: [256]u8 = undefined;
    const len = try encode(&buf, .{ .request_vote = args });

    // skip 4-byte length prefix
    const decoded = try decode(alloc, buf[4..len]);
    try std.testing.expectEqual(args.term, decoded.request_vote.term);
    try std.testing.expectEqual(args.candidate_id, decoded.request_vote.candidate_id);
    try std.testing.expectEqual(args.last_log_index, decoded.request_vote.last_log_index);
    try std.testing.expectEqual(args.last_log_term, decoded.request_vote.last_log_term);
}

test "encode/decode round-trip: request vote reply" {
    const alloc = std.testing.allocator;
    const reply = RequestVoteReply{ .term = 7, .vote_granted = true };

    var buf: [256]u8 = undefined;
    const len = try encode(&buf, .{ .request_vote_reply = reply });

    const decoded = try decode(alloc, buf[4..len]);
    try std.testing.expectEqual(reply.term, decoded.request_vote_reply.term);
    try std.testing.expect(decoded.request_vote_reply.vote_granted);
}

test "encode/decode round-trip: append entries with entries" {
    const alloc = std.testing.allocator;
    const entries = [_]LogEntry{
        .{ .index = 1, .term = 2, .data = "hello" },
        .{ .index = 2, .term = 2, .data = "world" },
    };

    const args = AppendEntriesArgs{
        .term = 3,
        .leader_id = 1,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &entries,
        .leader_commit = 0,
    };

    var buf: [1024]u8 = undefined;
    const len = try encode(&buf, .{ .append_entries = args });

    const decoded = try decode(alloc, buf[4..len]);
    defer {
        for (decoded.append_entries.entries) |e| alloc.free(e.data);
        alloc.free(decoded.append_entries.entries);
    }

    try std.testing.expectEqual(args.term, decoded.append_entries.term);
    try std.testing.expectEqual(args.leader_id, decoded.append_entries.leader_id);
    try std.testing.expectEqual(@as(usize, 2), decoded.append_entries.entries.len);
    try std.testing.expectEqualStrings("hello", decoded.append_entries.entries[0].data);
    try std.testing.expectEqualStrings("world", decoded.append_entries.entries[1].data);
}

test "encode/decode round-trip: append entries reply" {
    const alloc = std.testing.allocator;
    const reply = AppendEntriesReply{ .term = 5, .success = true, .match_index = 10 };

    var buf: [256]u8 = undefined;
    const len = try encode(&buf, .{ .append_entries_reply = reply });

    const decoded = try decode(alloc, buf[4..len]);
    try std.testing.expectEqual(reply.term, decoded.append_entries_reply.term);
    try std.testing.expect(decoded.append_entries_reply.success);
    try std.testing.expectEqual(reply.match_index, decoded.append_entries_reply.match_index);
}

test "encode/decode round-trip: empty append entries (heartbeat)" {
    const alloc = std.testing.allocator;
    const args = AppendEntriesArgs{
        .term = 10,
        .leader_id = 3,
        .prev_log_index = 5,
        .prev_log_term = 8,
        .entries = &.{},
        .leader_commit = 4,
    };

    var buf: [256]u8 = undefined;
    const len = try encode(&buf, .{ .append_entries = args });

    const decoded = try decode(alloc, buf[4..len]);
    defer alloc.free(decoded.append_entries.entries);

    try std.testing.expectEqual(args.term, decoded.append_entries.term);
    try std.testing.expectEqual(args.leader_commit, decoded.append_entries.leader_commit);
    try std.testing.expectEqual(@as(usize, 0), decoded.append_entries.entries.len);
}

test "decode rejects invalid message type" {
    const alloc = std.testing.allocator;
    const buf = [_]u8{0xFF} ++ [_]u8{0} ** 32;
    const result = decode(alloc, &buf);
    try std.testing.expectError(error.InvalidMessage, result);
}

test "decode rejects truncated message" {
    const alloc = std.testing.allocator;
    const buf = [_]u8{msg_request_vote} ++ [_]u8{0} ** 10; // need 32, only 10
    const result = decode(alloc, &buf);
    try std.testing.expectError(error.InvalidMessage, result);
}

test "decode append_entries with zero entries produces safe slice" {
    const alloc = std.testing.allocator;
    // build an append_entries with entry_count = 0
    var buf: [256]u8 = undefined;
    const args = AppendEntriesArgs{
        .term = 5,
        .leader_id = 1,
        .prev_log_index = 10,
        .prev_log_term = 4,
        .entries = &.{},
        .leader_commit = 9,
    };

    const len = try encode(&buf, .{ .append_entries = args });
    const decoded = try decode(alloc, buf[4..len]);

    // entries should be an allocated zero-length slice, safe to free
    try std.testing.expectEqual(@as(usize, 0), decoded.append_entries.entries.len);

    // the slice is heap-allocated (alloc.alloc with count 0),
    // so freeing it must not crash
    alloc.free(decoded.append_entries.entries);
}

test "decode rejects inflated entry_count" {
    const alloc = std.testing.allocator;
    // build a minimal append_entries message with entry_count far exceeding
    // what the payload could actually contain
    var buf: [45]u8 = undefined;
    buf[0] = msg_append_entries;
    // term, leader_id, prev_log_index, prev_log_term, leader_commit (5 x 8 bytes)
    @memset(buf[1..41], 0);
    // entry_count = 1000 but remaining payload is 0 bytes
    std.mem.writeInt(u32, buf[41..45], 1000, .little);

    const result = decode(alloc, &buf);
    try std.testing.expectError(error.InvalidMessage, result);
}

test "decode empty buffer returns error" {
    const alloc = std.testing.allocator;
    const result = decode(alloc, &[_]u8{});
    try std.testing.expectError(error.InvalidMessage, result);
}

test "decode truncated entry data" {
    const alloc = std.testing.allocator;
    // append_entries header (1 type + 40 fields + 4 entry_count = 45 bytes)
    // then one entry header claiming data_len=100 but only 5 bytes of data
    var buf: [45 + 20 + 5]u8 = undefined;
    buf[0] = msg_append_entries;
    @memset(buf[1..41], 0); // term, leader_id, etc.
    std.mem.writeInt(u32, buf[41..45], 1, .little); // entry_count = 1
    // entry: index=1, term=1, data_len=100
    std.mem.writeInt(u64, buf[45..53], 1, .little);
    std.mem.writeInt(u64, buf[53..61], 1, .little);
    std.mem.writeInt(u32, buf[61..65], 100, .little); // claims 100 bytes
    @memset(buf[65..70], 0); // but only 5 bytes available

    const result = decode(alloc, &buf);
    try std.testing.expectError(error.InvalidMessage, result);
}

test "encode buffer too small returns error" {
    var buf: [4]u8 = undefined;
    const msg = Message{ .request_vote = .{
        .term = 1,
        .candidate_id = 1,
        .last_log_index = 0,
        .last_log_term = 0,
    } };
    const result = encode(&buf, msg);
    try std.testing.expectError(error.BufferTooSmall, result);
}

// -- snapshot message tests --

test "encode/decode round-trip: install snapshot" {
    const alloc = std.testing.allocator;
    var snapshot_data = "this is a fake snapshot payload with some data in it".*;
    const args = InstallSnapshotArgs{
        .term = 7,
        .leader_id = 1,
        .last_included_index = 100,
        .last_included_term = 5,
        .data = &snapshot_data,
    };

    // use encodeSnapshot since install_snapshot needs dynamic allocation
    const encoded = try encodeSnapshot(alloc, args);
    defer alloc.free(encoded);

    // skip 4-byte length prefix
    const decoded = try decode(alloc, encoded[4..]);
    defer alloc.free(decoded.install_snapshot.data);

    try std.testing.expectEqual(args.term, decoded.install_snapshot.term);
    try std.testing.expectEqual(args.leader_id, decoded.install_snapshot.leader_id);
    try std.testing.expectEqual(args.last_included_index, decoded.install_snapshot.last_included_index);
    try std.testing.expectEqual(args.last_included_term, decoded.install_snapshot.last_included_term);
    try std.testing.expectEqualStrings(&snapshot_data, decoded.install_snapshot.data);
}

test "encode/decode round-trip: install snapshot reply" {
    const alloc = std.testing.allocator;
    const reply = InstallSnapshotReply{ .term = 12 };

    var buf: [256]u8 = undefined;
    const len = try encode(&buf, .{ .install_snapshot_reply = reply });

    const decoded = try decode(alloc, buf[4..len]);
    try std.testing.expectEqual(reply.term, decoded.install_snapshot_reply.term);
}

test "encode/decode round-trip: install snapshot with empty data" {
    const alloc = std.testing.allocator;
    const args = InstallSnapshotArgs{
        .term = 3,
        .leader_id = 2,
        .last_included_index = 50,
        .last_included_term = 2,
        .data = @constCast(""),
    };

    const encoded = try encodeSnapshot(alloc, args);
    defer alloc.free(encoded);

    const decoded = try decode(alloc, encoded[4..]);
    defer alloc.free(decoded.install_snapshot.data);

    try std.testing.expectEqual(args.term, decoded.install_snapshot.term);
    try std.testing.expectEqual(args.last_included_index, decoded.install_snapshot.last_included_index);
    try std.testing.expectEqual(@as(usize, 0), decoded.install_snapshot.data.len);
}

test "encode/decode round-trip: install snapshot with large payload" {
    const alloc = std.testing.allocator;

    // simulate a realistic snapshot size (64KB)
    const data = try alloc.alloc(u8, 65536);
    defer alloc.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i);

    const args = InstallSnapshotArgs{
        .term = 10,
        .leader_id = 1,
        .last_included_index = 500,
        .last_included_term = 8,
        .data = data,
    };

    const encoded = try encodeSnapshot(alloc, args);
    defer alloc.free(encoded);

    const decoded = try decode(alloc, encoded[4..]);
    defer alloc.free(decoded.install_snapshot.data);

    try std.testing.expectEqual(args.term, decoded.install_snapshot.term);
    try std.testing.expectEqual(args.last_included_index, decoded.install_snapshot.last_included_index);
    try std.testing.expectEqual(data.len, decoded.install_snapshot.data.len);
    try std.testing.expectEqualSlices(u8, data, decoded.install_snapshot.data);
}

test "decode rejects truncated install snapshot" {
    const alloc = std.testing.allocator;
    // type byte + only 20 bytes of header (need 36 minimum)
    var buf: [21]u8 = undefined;
    buf[0] = msg_install_snapshot;
    @memset(buf[1..], 0);

    const result = decode(alloc, &buf);
    try std.testing.expectError(error.InvalidMessage, result);
}

test "decode rejects install snapshot with truncated data" {
    const alloc = std.testing.allocator;
    // header claims 1000 bytes of snapshot data but only provides 5
    var buf: [1 + 36 + 5]u8 = undefined;
    buf[0] = msg_install_snapshot;
    @memset(buf[1..33], 0); // term, leader_id, last_included_index, last_included_term
    std.mem.writeInt(u32, buf[33..37], 1000, .little); // claims 1000 bytes
    @memset(buf[37..], 0); // but only 5 bytes available

    const result = decode(alloc, &buf);
    try std.testing.expectError(error.InvalidMessage, result);
}

test "decode rejects truncated install snapshot reply" {
    const alloc = std.testing.allocator;
    // type byte + only 4 bytes (need 8)
    var buf: [5]u8 = undefined;
    buf[0] = msg_install_snapshot_reply;
    @memset(buf[1..], 0);

    const result = decode(alloc, &buf);
    try std.testing.expectError(error.InvalidMessage, result);
}

// -- HMAC authentication tests --

test "hmac round-trip: compute and verify succeeds" {
    const key: [32]u8 = "test-key-for-hmac-verification!!".*;
    const message = [_]u8{msg_request_vote} ++ [_]u8{0} ** 32;

    // compute HMAC
    var tag: [32]u8 = undefined;
    HmacSha256.create(&tag, &message, &key);

    // verify should succeed
    var expected: [32]u8 = undefined;
    HmacSha256.create(&expected, &message, &key);
    try std.testing.expect(std.crypto.timing_safe.eql([32]u8, tag, expected));
}

test "hmac rejects message with wrong key" {
    const key_a: [32]u8 = "key-aaaaaaaaaaaaaaaaaaaaaaaaaaaa".*;
    const key_b: [32]u8 = "key-bbbbbbbbbbbbbbbbbbbbbbbbbbbb".*;
    const message = [_]u8{msg_append_entries} ++ [_]u8{1} ** 44;

    var tag_a: [32]u8 = undefined;
    HmacSha256.create(&tag_a, &message, &key_a);
    var tag_b: [32]u8 = undefined;
    HmacSha256.create(&tag_b, &message, &key_b);

    // tags from different keys must not match
    try std.testing.expect(!std.crypto.timing_safe.eql([32]u8, tag_a, tag_b));
}

test "applyHmac produces correct authenticated format" {
    const alloc = std.testing.allocator;

    // build a small message: [4B length] [1B type] [data]
    var plain: [10]u8 = undefined;
    std.mem.writeInt(u32, plain[0..4], 6, .little); // body len = 6
    plain[4] = msg_request_vote_reply;
    @memset(plain[5..], 0xAB);

    var transport = Transport{
        .alloc = alloc,
        .listen_fd = -1,
        .peers = std.AutoHashMap(NodeId, PeerAddr).init(alloc),
        .local_id = 7,
        .shared_key = "test-key-32-bytes-exactly-here!!".*,

        .udp_fd = null,
    };
    defer transport.peers.deinit();

    const authenticated = try transport.applyHmac(&plain);
    defer alloc.free(authenticated);

    // result should be: [4B new_length] [8B sender_id] [32B HMAC] [original body]
    try std.testing.expectEqual(@as(usize, 4 + 8 + 32 + 6), authenticated.len);

    // the new length should be 8 + 32 + 6 = 46
    const new_len = std.mem.readInt(u32, authenticated[0..4], .little);
    try std.testing.expectEqual(@as(u32, 46), new_len);

    try std.testing.expectEqual(@as(NodeId, 7), readU64(authenticated[4..12]));

    // verify the HMAC matches what we expect
    const body = plain[4..]; // type + payload
    var expected_hmac: [32]u8 = undefined;
    var hmac = HmacSha256.init(&transport.shared_key.?);
    hmac.update(authenticated[4..12]);
    hmac.update(body);
    hmac.final(&expected_hmac);
    try std.testing.expectEqualSlices(u8, &expected_hmac, authenticated[12..44]);

    try std.testing.expectEqualSlices(u8, body, authenticated[44..]);
}

test "applyHmac returns data unchanged when no key" {
    const alloc = std.testing.allocator;

    var plain = [_]u8{ 0x06, 0x00, 0x00, 0x00, msg_request_vote, 0, 0, 0, 0, 0 };

    var transport = Transport{
        .alloc = alloc,
        .listen_fd = -1,
        .peers = std.AutoHashMap(NodeId, PeerAddr).init(alloc),
        .local_id = null,
        .shared_key = null,

        .udp_fd = null,
    };
    defer transport.peers.deinit();

    const result = try transport.applyHmac(&plain);
    // should return the same pointer — no allocation
    try std.testing.expectEqual(@as(*const u8, &plain[0]), &result[0]);
}

test "verifyAuthenticatedBody rejects mismatched sender id" {
    const alloc = std.testing.allocator;
    const key: [32]u8 = "test-key-32-bytes-exactly-here!!".*;
    var sender_buf: [8]u8 = undefined;
    writeU64(&sender_buf, 2);
    const payload = [_]u8{ msg_request_vote_reply, 0, 0, 0, 0, 0 };

    var tag: [32]u8 = undefined;
    var hmac = HmacSha256.init(&key);
    hmac.update(&sender_buf);
    hmac.update(&payload);
    hmac.final(&tag);

    var body: [8 + 32 + payload.len]u8 = undefined;
    @memcpy(body[0..8], &sender_buf);
    @memcpy(body[8..40], &tag);
    @memcpy(body[40..], &payload);

    // empty peer map — sender_id=2 is not a known peer
    var peers = std.AutoHashMap(NodeId, PeerAddr).init(alloc);
    defer peers.deinit();

    try std.testing.expectError(
        TransportError.AuthenticationFailed,
        verifyAuthenticatedBody(&body, key, @import("compat").net.Address.initIp4(.{ 10, 0, 0, 2 }, 9000), &peers),
    );
}

test "verifyAuthenticatedBody rejects sender from wrong ip" {
    const alloc = std.testing.allocator;
    const key: [32]u8 = "test-key-32-bytes-exactly-here!!".*;
    var sender_buf: [8]u8 = undefined;
    writeU64(&sender_buf, 2);
    const payload = [_]u8{ msg_request_vote_reply, 0, 0, 0, 0, 0 };

    var tag: [32]u8 = undefined;
    var hmac = HmacSha256.init(&key);
    hmac.update(&sender_buf);
    hmac.update(&payload);
    hmac.final(&tag);

    var body: [8 + 32 + payload.len]u8 = undefined;
    @memcpy(body[0..8], &sender_buf);
    @memcpy(body[8..40], &tag);
    @memcpy(body[40..], &payload);

    var peers = std.AutoHashMap(NodeId, PeerAddr).init(alloc);
    defer peers.deinit();
    try peers.put(2, .{ .addr = @import("compat").net.Address.initIp4(.{ 10, 0, 0, 2 }, 9700) });

    try std.testing.expectError(
        TransportError.AuthenticationFailed,
        verifyAuthenticatedBody(&body, key, @import("compat").net.Address.initIp4(.{ 10, 0, 0, 99 }, 40000), &peers),
    );
}

test "resolvePeerId matches configured peer" {
    const alloc = std.testing.allocator;

    var transport = Transport{
        .alloc = alloc,
        .listen_fd = -1,
        .peers = std.AutoHashMap(NodeId, PeerAddr).init(alloc),
        .local_id = 1,
        .shared_key = null,

        .udp_fd = null,
    };
    defer transport.peers.deinit();

    try transport.addPeer(2, .{ 10, 0, 0, 2 }, 9700);

    try std.testing.expectEqual(
        @as(?NodeId, 2),
        transport.resolvePeerId(@import("compat").net.Address.initIp4(.{ 10, 0, 0, 2 }, 9700)),
    );
    try std.testing.expect(
        transport.resolvePeerId(@import("compat").net.Address.initIp4(.{ 10, 0, 0, 3 }, 9700)) == null,
    );
}

fn waitForGossipResult(receiver: *Transport, buf: []u8) !?GossipReceiveResult {
    var attempts: usize = 0;
    while (attempts < 50) : (attempts += 1) {
        const result = try receiver.receiveGossip(buf);
        if (result != null) return result;
        @import("compat").sleep(10 * std.time.ns_per_ms);
    }
    return null;
}

fn waitForGossipError(receiver: *Transport, buf: []u8) !void {
    var attempts: usize = 0;
    while (attempts < 50) : (attempts += 1) {
        const result = receiver.receiveGossip(buf);
        if (result) |_| {
            @import("compat").sleep(10 * std.time.ns_per_ms);
            continue;
        } else |err| switch (err) {
            TransportError.AuthenticationFailed => return,
            else => return err,
        }
    }
    return error.TestExpectedError;
}

fn requireUdpGossipTestHost() !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const fd = @import("compat").posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0) catch
        return error.SkipZigTest;
    @import("compat").posix.close(fd);
}

// -- UDP gossip transport tests --

test "udp gossip: send and receive with HMAC" {
    try requireUdpGossipTestHost();
    const alloc = std.testing.allocator;
    const key: [32]u8 = "gossip-test-key-32bytes-exactly!".*;

    // create two transports on different UDP ports
    var sender = Transport{
        .alloc = alloc,
        .listen_fd = -1,
        .peers = std.AutoHashMap(NodeId, PeerAddr).init(alloc),
        .local_id = 1,
        .shared_key = key,

        .udp_fd = null,
    };
    defer sender.peers.deinit();

    defer sender.deinitUdp();

    var receiver = Transport{
        .alloc = alloc,
        .listen_fd = -1,
        .peers = std.AutoHashMap(NodeId, PeerAddr).init(alloc),
        .local_id = 2,
        .shared_key = key,

        .udp_fd = null,
    };
    defer receiver.peers.deinit();

    defer receiver.deinitUdp();

    try sender.initUdp(0); // OS assigns port
    try receiver.initUdp(0);

    // get the receiver's assigned port
    var recv_addr: posix.sockaddr.storage = undefined;
    var recv_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try @import("compat").posix.getsockname(receiver.udp_fd.?, @ptrCast(&recv_addr), &recv_len);
    const recv_in: *const posix.sockaddr.in = @ptrCast(@alignCast(&recv_addr));
    const recv_port = std.mem.bigToNative(u16, recv_in.port);

    // send a gossip payload
    const payload = "hello-gossip";
    try sender.sendGossip(.{ 127, 0, 0, 1 }, recv_port, payload);

    // receive and verify
    var buf: [1500]u8 = undefined;
    const result = try waitForGossipResult(&receiver, &buf);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u64, 1), result.?.sender_id);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, @as([4]u8, @bitCast(result.?.from_addr.in.addr)));
    try std.testing.expectEqualSlices(u8, payload, result.?.payload);
}

test "udp gossip: wrong key rejected" {
    try requireUdpGossipTestHost();
    const alloc = std.testing.allocator;

    var sender = Transport{
        .alloc = alloc,
        .listen_fd = -1,
        .peers = std.AutoHashMap(NodeId, PeerAddr).init(alloc),
        .local_id = 1,
        .shared_key = "sender-key-aaaaaaaaaaaaaaaaaaaaa".*,

        .udp_fd = null,
    };
    defer sender.peers.deinit();

    defer sender.deinitUdp();

    var receiver = Transport{
        .alloc = alloc,
        .listen_fd = -1,
        .peers = std.AutoHashMap(NodeId, PeerAddr).init(alloc),
        .local_id = 2,
        .shared_key = "receiver-key-bbbbbbbbbbbbbbbbbbb".*,

        .udp_fd = null,
    };
    defer receiver.peers.deinit();

    defer receiver.deinitUdp();

    try sender.initUdp(0);
    try receiver.initUdp(0);

    var recv_addr: posix.sockaddr.storage = undefined;
    var recv_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try @import("compat").posix.getsockname(receiver.udp_fd.?, @ptrCast(&recv_addr), &recv_len);
    const recv_in: *const posix.sockaddr.in = @ptrCast(@alignCast(&recv_addr));
    const recv_port = std.mem.bigToNative(u16, recv_in.port);

    try sender.sendGossip(.{ 127, 0, 0, 1 }, recv_port, "secret-data");

    var buf: [1500]u8 = undefined;
    try waitForGossipError(&receiver, &buf);
}
