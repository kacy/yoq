// transport — TCP transport for raft RPC messages
//
// simple binary protocol over TCP. raft is management-plane traffic
// (low volume heartbeats + occasional log entries) so blocking TCP
// with short timeouts is fine — no need for io_uring here.
//
// wire format (unauthenticated):
//   [4B length] [1B type] [payload...]
//
// wire format (authenticated, when shared_key is set):
//   [4B length] [8B sender_id] [32B HMAC-SHA256] [1B type] [payload...]
//
// the HMAC is computed over [sender_id + type byte + payload]. the 32-byte
// tag is inserted after sender_id. the length prefix covers sender_id + hmac
// + type + payload. on receive, the HMAC is verified and sender_id must match
// the configured peer for the remote socket address.
//
// message types:
//   0x01 = RequestVote
//   0x02 = RequestVoteReply
//   0x03 = AppendEntries
//   0x04 = AppendEntriesReply
//   0x05 = InstallSnapshot
//   0x06 = InstallSnapshotReply
//
// all integers are little-endian. entries in AppendEntries are
// serialized inline: [8B index][8B term][4B data_len][data bytes]
//
// InstallSnapshot payloads can be megabytes (full state machine database),
// so encoding/decoding uses dynamic allocation instead of the fixed 8KB
// stack buffer used for other RPCs.

const std = @import("std");
const posix = std.posix;
const types = @import("raft_types.zig");

const NodeId = types.NodeId;
const Term = types.Term;
const LogIndex = types.LogIndex;
const LogEntry = types.LogEntry;
const RequestVoteArgs = types.RequestVoteArgs;
const RequestVoteReply = types.RequestVoteReply;
const AppendEntriesArgs = types.AppendEntriesArgs;
const AppendEntriesReply = types.AppendEntriesReply;
const InstallSnapshotArgs = types.InstallSnapshotArgs;
const InstallSnapshotReply = types.InstallSnapshotReply;

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const TransportError = error{
    /// TCP connection to a peer could not be established
    ConnectFailed,
    /// failed to write the full message to the peer socket
    SendFailed,
    /// failed to read a complete message from an incoming connection
    ReceiveFailed,
    /// received data could not be decoded as a valid raft message
    InvalidMessage,
    /// HMAC verification failed — shared key mismatch or tampered message
    AuthenticationFailed,
    /// the target NodeId has no known address in the peer table
    PeerNotFound,
};

pub const Message = union(enum) {
    request_vote: RequestVoteArgs,
    request_vote_reply: RequestVoteReply,
    append_entries: AppendEntriesArgs,
    append_entries_reply: AppendEntriesReply,
    install_snapshot: InstallSnapshotArgs,
    install_snapshot_reply: InstallSnapshotReply,
};

pub const ReceivedMessage = struct {
    from_addr: std.net.Address,
    sender_id: ?NodeId,
    message: Message,
    // entries data owned by the allocator passed to receive()
};

const PeerAddr = struct {
    addr: std.net.Address,
};

// message type tags
const msg_request_vote: u8 = 0x01;
const msg_request_vote_reply: u8 = 0x02;
const msg_append_entries: u8 = 0x03;
const msg_append_entries_reply: u8 = 0x04;
const msg_install_snapshot: u8 = 0x05;
const msg_install_snapshot_reply: u8 = 0x06;

// max receive size: 64MB. snapshot payloads (full sqlite databases)
// can be several megabytes. normal RPCs are a few hundred bytes.
const max_receive_size: u32 = 64 * 1024 * 1024;

pub const Transport = struct {
    alloc: std.mem.Allocator,
    listen_fd: posix.socket_t,
    peers: std.AutoHashMap(NodeId, PeerAddr),
    local_id: ?NodeId,

    /// optional shared key for HMAC authentication on raft messages.
    /// when null, messages are sent/received without authentication
    /// (single-node mode or during initial bootstrap).
    /// when set, all messages include a 32-byte HMAC-SHA256 tag.
    shared_key: ?[32]u8,

    pub fn init(alloc: std.mem.Allocator, port: u16) !Transport {
        const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(fd);

        // allow address reuse
        const one: i32 = 1;
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));

        const addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        try posix.bind(fd, &addr.any, addr.getOsSockLen());
        try posix.listen(fd, 16);

        return .{
            .alloc = alloc,
            .listen_fd = fd,
            .peers = std.AutoHashMap(NodeId, PeerAddr).init(alloc),
            .local_id = null,
            .shared_key = null,
        };
    }

    pub fn deinit(self: *Transport) void {
        posix.close(self.listen_fd);
        self.peers.deinit();
    }

    pub fn addPeer(self: *Transport, id: NodeId, addr: [4]u8, port: u16) !void {
        try self.peers.put(id, .{
            .addr = std.net.Address.initIp4(addr, port),
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

    /// send a message to a peer. opens a new TCP connection each time.
    /// raft heartbeats are ~1/sec so connection overhead is negligible.
    ///
    /// snapshot messages use dynamic allocation since they can be megabytes.
    /// all other RPCs use a fixed stack buffer.
    ///
    /// when shared_key is set, computes HMAC-SHA256 over [type + payload]
    /// and prepends the 32-byte tag to the body before sending.
    pub fn send(self: *Transport, target: NodeId, msg: Message) TransportError!void {
        const peer = self.peers.get(target) orelse return TransportError.PeerNotFound;

        // snapshot messages need dynamic allocation — they can be megabytes
        if (msg == .install_snapshot) {
            const encoded = encodeSnapshot(self.alloc, msg.install_snapshot) catch
                return TransportError.SendFailed;
            defer self.alloc.free(encoded);

            const final = self.applyHmac(encoded) catch return TransportError.SendFailed;
            defer if (final.ptr != encoded.ptr) self.alloc.free(final);

            self.sendBytes(peer, final) catch return TransportError.SendFailed;
            return;
        }

        // all other RPCs fit in the 8KB stack buffer
        var buf: [8192]u8 = undefined;
        const len = encode(&buf, msg) catch return TransportError.SendFailed;

        const final = self.applyHmac(buf[0..len]) catch return TransportError.SendFailed;
        defer if (final.ptr != buf[0..len].ptr) self.alloc.free(final);

        self.sendBytes(peer, final) catch return TransportError.SendFailed;
    }

    /// if shared_key is set, compute HMAC over [sender_id + type + payload]
    /// and produce a new buffer with the sender id and HMAC inserted:
    /// [4B new_length] [8B sender_id] [32B HMAC] [type + payload].
    /// returns `data` unchanged if no key is configured.
    fn applyHmac(self: *Transport, data: []const u8) ![]const u8 {
        const key = self.shared_key orelse return data;
        const local_id = self.local_id orelse return TransportError.SendFailed;
        if (data.len < 5) return TransportError.SendFailed;

        const body = data[4..]; // type + payload
        var sender_buf: [8]u8 = undefined;
        writeU64(&sender_buf, local_id);
        var hmac_tag: [32]u8 = undefined;
        var hmac = HmacSha256.init(&key);
        hmac.update(&sender_buf);
        hmac.update(body);
        hmac.final(&hmac_tag);

        const new_len: u32 = @intCast(body.len + 8 + 32); // sender + hmac + original body
        const out = try self.alloc.alloc(u8, 4 + 8 + 32 + body.len);
        std.mem.writeInt(u32, out[0..4], new_len, .little);
        @memcpy(out[4..12], &sender_buf);
        @memcpy(out[12..44], &hmac_tag);
        @memcpy(out[44..], body);
        return out;
    }

    /// open a TCP connection to a peer and send the bytes.
    fn sendBytes(_: *Transport, peer: PeerAddr, data: []const u8) !void {
        const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch
            return TransportError.ConnectFailed;
        defer posix.close(fd);

        // set send/receive timeout (1 second for normal RPCs).
        // snapshot sends get a longer timeout since they can be megabytes.
        const timeout = posix.timeval{ .sec = 5, .usec = 0 };
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

        posix.connect(fd, &peer.addr.any, peer.addr.getOsSockLen()) catch
            return TransportError.ConnectFailed;

        // write all bytes, handling partial writes
        var total: usize = 0;
        while (total < data.len) {
            const n = posix.write(fd, data[total..]) catch return TransportError.SendFailed;
            if (n == 0) return TransportError.SendFailed;
            total += n;
        }
    }

    /// accept a connection and read one message. non-blocking on accept.
    /// returns null if no connection is pending.
    ///
    /// when shared_key is set, verifies HMAC before decoding. drops the
    /// connection (returns AuthenticationFailed) on mismatch.
    pub fn receive(self: *Transport, alloc: std.mem.Allocator) TransportError!?ReceivedMessage {
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
        const expected_peer_id = if (self.shared_key != null)
            self.resolvePeerId(from_addr) orelse return TransportError.AuthenticationFailed
        else
            null;

        // set receive timeout — longer to accommodate snapshot transfers
        const timeout = posix.timeval{ .sec = 5, .usec = 0 };
        posix.setsockopt(client_fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

        // read length prefix (4 bytes)
        var len_buf: [4]u8 = undefined;
        readExact(client_fd, &len_buf) catch return TransportError.ReceiveFailed;
        const msg_len = std.mem.readInt(u32, &len_buf, .little);

        if (msg_len > max_receive_size or msg_len < 1) return TransportError.InvalidMessage;

        // read message body
        const body = alloc.alloc(u8, msg_len) catch return TransportError.ReceiveFailed;
        defer alloc.free(body);

        readExact(client_fd, body) catch return TransportError.ReceiveFailed;

        const verified = if (self.shared_key) |key|
            try verifyAuthenticatedBody(body, expected_peer_id.?, key)
        else
            VerifiedBody{ .sender_id = null, .payload = body };

        const msg = decode(alloc, verified.payload) catch return TransportError.InvalidMessage;

        return ReceivedMessage{
            .from_addr = from_addr,
            .sender_id = verified.sender_id,
            .message = msg,
        };
    }

    fn resolvePeerId(self: *const Transport, addr: std.net.Address) ?NodeId {
        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.addr.any.family != addr.any.family) continue;
            if (std.mem.eql(u8, std.mem.asBytes(&entry.value_ptr.addr.in.sa.addr), std.mem.asBytes(&addr.in.sa.addr)) and
                entry.value_ptr.addr.in.sa.port == addr.in.sa.port)
            {
                return entry.key_ptr.*;
            }
        }
        return null;
    }
};

const VerifiedBody = struct {
    sender_id: ?NodeId,
    payload: []const u8,
};

fn verifyAuthenticatedBody(body: []const u8, expected_peer_id: NodeId, key: [32]u8) TransportError!VerifiedBody {
    if (body.len < 41) return TransportError.AuthenticationFailed;

    const sender_bytes = body[0..8];
    const received_hmac = body[8..40];
    const signed_data = body[40..];

    var expected: [32]u8 = undefined;
    var hmac = HmacSha256.init(&key);
    hmac.update(sender_bytes);
    hmac.update(signed_data);
    hmac.final(&expected);

    if (!std.crypto.timing_safe.eql([32]u8, received_hmac[0..32].*, expected)) {
        return TransportError.AuthenticationFailed;
    }

    const sender_id = readU64(sender_bytes);
    if (sender_id != expected_peer_id) return TransportError.AuthenticationFailed;

    return .{
        .sender_id = sender_id,
        .payload = signed_data,
    };
}

// -- encoding --

fn encode(buf: []u8, msg: Message) !usize {
    if (buf.len < 5) return error.BufferTooSmall;

    // leave 4 bytes for length prefix, write type byte
    var offset: usize = 4;

    switch (msg) {
        .request_vote => |args| {
            buf[offset] = msg_request_vote;
            offset += 1;
            writeU64(buf[offset..], args.term);
            offset += 8;
            writeU64(buf[offset..], args.candidate_id);
            offset += 8;
            writeU64(buf[offset..], args.last_log_index);
            offset += 8;
            writeU64(buf[offset..], args.last_log_term);
            offset += 8;
        },
        .request_vote_reply => |reply| {
            buf[offset] = msg_request_vote_reply;
            offset += 1;
            writeU64(buf[offset..], reply.term);
            offset += 8;
            buf[offset] = if (reply.vote_granted) 1 else 0;
            offset += 1;
        },
        .append_entries => |args| {
            buf[offset] = msg_append_entries;
            offset += 1;
            writeU64(buf[offset..], args.term);
            offset += 8;
            writeU64(buf[offset..], args.leader_id);
            offset += 8;
            writeU64(buf[offset..], args.prev_log_index);
            offset += 8;
            writeU64(buf[offset..], args.prev_log_term);
            offset += 8;
            writeU64(buf[offset..], args.leader_commit);
            offset += 8;
            // entry count
            writeU32(buf[offset..], @intCast(args.entries.len));
            offset += 4;
            // entries
            for (args.entries) |entry| {
                if (offset + 20 + entry.data.len > buf.len) return error.BufferTooSmall;
                writeU64(buf[offset..], entry.index);
                offset += 8;
                writeU64(buf[offset..], entry.term);
                offset += 8;
                writeU32(buf[offset..], @intCast(entry.data.len));
                offset += 4;
                @memcpy(buf[offset..][0..entry.data.len], entry.data);
                offset += entry.data.len;
            }
        },
        .append_entries_reply => |reply| {
            buf[offset] = msg_append_entries_reply;
            offset += 1;
            writeU64(buf[offset..], reply.term);
            offset += 8;
            buf[offset] = if (reply.success) 1 else 0;
            offset += 1;
            writeU64(buf[offset..], reply.match_index);
            offset += 8;
        },
        .install_snapshot => {
            // snapshot payloads are variable-length and can be megabytes.
            // use encodeSnapshot() instead — this case should not be reached
            // since Transport.send() handles it separately.
            return error.BufferTooSmall;
        },
        .install_snapshot_reply => |reply| {
            buf[offset] = msg_install_snapshot_reply;
            offset += 1;
            writeU64(buf[offset..], reply.term);
            offset += 8;
        },
    }

    // write length prefix (excludes the 4-byte length itself)
    const body_len: u32 = @intCast(offset - 4);
    std.mem.writeInt(u32, buf[0..4], body_len, .little);

    return offset;
}

/// encode an InstallSnapshot message with dynamic allocation.
///
/// wire format:
///   [4B length][1B type=0x05][8B term][8B leader_id]
///   [8B last_included_index][8B last_included_term]
///   [4B data_len][data bytes]
///
/// returns an owned slice that the caller must free.
fn encodeSnapshot(alloc: std.mem.Allocator, args: InstallSnapshotArgs) ![]u8 {
    // header: 4B length + 1B type + 8*4 fields + 4B data_len = 41 bytes
    const header_size = 4 + 1 + 32 + 4;
    const total = header_size + args.data.len;

    const buf = try alloc.alloc(u8, total);
    errdefer alloc.free(buf);

    var offset: usize = 4; // skip length prefix

    buf[offset] = msg_install_snapshot;
    offset += 1;
    writeU64(buf[offset..], args.term);
    offset += 8;
    writeU64(buf[offset..], args.leader_id);
    offset += 8;
    writeU64(buf[offset..], args.last_included_index);
    offset += 8;
    writeU64(buf[offset..], args.last_included_term);
    offset += 8;
    writeU32(buf[offset..], @intCast(args.data.len));
    offset += 4;
    @memcpy(buf[offset..][0..args.data.len], args.data);
    offset += args.data.len;

    // write length prefix
    const body_len: u32 = @intCast(offset - 4);
    std.mem.writeInt(u32, buf[0..4], body_len, .little);

    return buf;
}

fn decode(alloc: std.mem.Allocator, buf: []const u8) !Message {
    if (buf.len < 1) return error.InvalidMessage;

    const msg_type = buf[0];
    const payload = buf[1..];

    switch (msg_type) {
        msg_request_vote => {
            if (payload.len < 32) return error.InvalidMessage;
            return .{ .request_vote = .{
                .term = readU64(payload[0..]),
                .candidate_id = readU64(payload[8..]),
                .last_log_index = readU64(payload[16..]),
                .last_log_term = readU64(payload[24..]),
            } };
        },
        msg_request_vote_reply => {
            if (payload.len < 9) return error.InvalidMessage;
            return .{ .request_vote_reply = .{
                .term = readU64(payload[0..]),
                .vote_granted = payload[8] != 0,
            } };
        },
        msg_append_entries => {
            if (payload.len < 44) return error.InvalidMessage;
            const term = readU64(payload[0..]);
            const leader_id = readU64(payload[8..]);
            const prev_log_index = readU64(payload[16..]);
            const prev_log_term = readU64(payload[24..]);
            const leader_commit = readU64(payload[32..]);
            const entry_count = readU32(payload[40..]);

            // each entry needs at least 20 bytes (8 index + 8 term + 4 data_len).
            // cap entry_count against remaining payload to prevent allocation spikes
            // from malicious or corrupt messages.
            const remaining_payload = payload.len - 44;
            const max_possible_entries = remaining_payload / 20;
            if (entry_count > max_possible_entries) return error.InvalidMessage;

            var entries = try alloc.alloc(LogEntry, entry_count);
            var offset: usize = 44;
            for (0..entry_count) |i| {
                if (offset + 20 > payload.len) {
                    alloc.free(entries);
                    return error.InvalidMessage;
                }
                const index = readU64(payload[offset..]);
                offset += 8;
                const e_term = readU64(payload[offset..]);
                offset += 8;
                const data_len = readU32(payload[offset..]);
                offset += 4;

                if (offset + data_len > payload.len) {
                    alloc.free(entries);
                    return error.InvalidMessage;
                }
                const data = try alloc.dupe(u8, payload[offset..][0..data_len]);
                offset += data_len;

                entries[i] = .{
                    .index = index,
                    .term = e_term,
                    .data = data,
                };
            }

            return .{ .append_entries = .{
                .term = term,
                .leader_id = leader_id,
                .prev_log_index = prev_log_index,
                .prev_log_term = prev_log_term,
                .entries = entries,
                .leader_commit = leader_commit,
            } };
        },
        msg_append_entries_reply => {
            if (payload.len < 17) return error.InvalidMessage;
            return .{ .append_entries_reply = .{
                .term = readU64(payload[0..]),
                .success = payload[8] != 0,
                .match_index = readU64(payload[9..]),
            } };
        },
        msg_install_snapshot => {
            // 8B term + 8B leader_id + 8B last_included_index +
            // 8B last_included_term + 4B data_len = 36 bytes minimum
            if (payload.len < 36) return error.InvalidMessage;
            const term = readU64(payload[0..]);
            const leader_id = readU64(payload[8..]);
            const last_included_index = readU64(payload[16..]);
            const last_included_term = readU64(payload[24..]);
            const data_len = readU32(payload[32..]);

            if (payload.len < 36 + data_len) return error.InvalidMessage;

            // duplicate the snapshot data so the caller owns it
            const data = try alloc.dupe(u8, payload[36..][0..data_len]);

            return .{ .install_snapshot = .{
                .term = term,
                .leader_id = leader_id,
                .last_included_index = last_included_index,
                .last_included_term = last_included_term,
                .data = data,
            } };
        },
        msg_install_snapshot_reply => {
            if (payload.len < 8) return error.InvalidMessage;
            return .{ .install_snapshot_reply = .{
                .term = readU64(payload[0..]),
            } };
        },
        else => return error.InvalidMessage,
    }
}

// -- helpers --

fn writeU64(buf: []u8, val: u64) void {
    std.mem.writeInt(u64, buf[0..8], val, .little);
}

fn writeU32(buf: []u8, val: u32) void {
    std.mem.writeInt(u32, buf[0..4], val, .little);
}

fn readU64(buf: []const u8) u64 {
    return std.mem.readInt(u64, buf[0..8], .little);
}

fn readU32(buf: []const u8) u32 {
    return std.mem.readInt(u32, buf[0..4], .little);
}

fn readExact(fd: posix.socket_t, buf: []u8) !void {
    var total: usize = 0;
    while (total < buf.len) {
        const n = posix.read(fd, buf[total..]) catch return error.ReadFailed;
        if (n == 0) return error.ReadFailed; // connection closed
        total += n;
    }
}

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
    const snapshot_data = "this is a fake snapshot payload with some data in it";
    const args = InstallSnapshotArgs{
        .term = 7,
        .leader_id = 1,
        .last_included_index = 100,
        .last_included_term = 5,
        .data = snapshot_data,
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
    try std.testing.expectEqualStrings(snapshot_data, decoded.install_snapshot.data);
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
        .data = "",
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
    };
    defer transport.peers.deinit();

    const result = try transport.applyHmac(&plain);
    // should return the same pointer — no allocation
    try std.testing.expectEqual(@as(*const u8, &plain[0]), &result[0]);
}

test "verifyAuthenticatedBody rejects mismatched sender id" {
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

    try std.testing.expectError(
        TransportError.AuthenticationFailed,
        verifyAuthenticatedBody(&body, 3, key),
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
    };
    defer transport.peers.deinit();

    try transport.addPeer(2, .{ 10, 0, 0, 2 }, 9700);

    try std.testing.expectEqual(
        @as(?NodeId, 2),
        transport.resolvePeerId(std.net.Address.initIp4(.{ 10, 0, 0, 2 }, 9700)),
    );
    try std.testing.expect(
        transport.resolvePeerId(std.net.Address.initIp4(.{ 10, 0, 0, 3 }, 9700)) == null,
    );
}
