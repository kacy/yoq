// transport — TCP transport for raft RPC messages
//
// simple binary protocol over TCP. raft is management-plane traffic
// (low volume heartbeats + occasional log entries) so blocking TCP
// with short timeouts is fine — no need for io_uring here.
//
// wire format:
//   [4B length] [1B type] [payload...]
//
// message types:
//   0x01 = RequestVote
//   0x02 = RequestVoteReply
//   0x03 = AppendEntries
//   0x04 = AppendEntriesReply
//
// all integers are little-endian. entries in AppendEntries are
// serialized inline: [8B index][8B term][4B data_len][data bytes]

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

pub const TransportError = error{
    ConnectFailed,
    SendFailed,
    ReceiveFailed,
    InvalidMessage,
    PeerNotFound,
};

pub const Message = union(enum) {
    request_vote: RequestVoteArgs,
    request_vote_reply: RequestVoteReply,
    append_entries: AppendEntriesArgs,
    append_entries_reply: AppendEntriesReply,
};

pub const ReceivedMessage = struct {
    from_addr: std.net.Address,
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

pub const Transport = struct {
    alloc: std.mem.Allocator,
    listen_fd: posix.socket_t,
    peers: std.AutoHashMap(NodeId, PeerAddr),

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

    /// send a message to a peer. opens a new TCP connection each time.
    /// raft heartbeats are ~1/sec so connection overhead is negligible.
    pub fn send(self: *Transport, target: NodeId, msg: Message) TransportError!void {
        const peer = self.peers.get(target) orelse return TransportError.PeerNotFound;

        // encode message
        var buf: [8192]u8 = undefined;
        const len = encode(&buf, msg) catch return TransportError.SendFailed;

        // connect with blocking socket
        const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch
            return TransportError.ConnectFailed;
        defer posix.close(fd);

        // set send/receive timeout (1 second)
        const timeout = posix.timeval{ .sec = 1, .usec = 0 };
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

        posix.connect(fd, &peer.addr.any, peer.addr.getOsSockLen()) catch
            return TransportError.ConnectFailed;

        // send the encoded message
        _ = posix.write(fd, buf[0..len]) catch return TransportError.SendFailed;
    }

    /// accept a connection and read one message. non-blocking on accept.
    /// returns null if no connection is pending.
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

        // set receive timeout
        const timeout = posix.timeval{ .sec = 1, .usec = 0 };
        posix.setsockopt(client_fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

        // read length prefix (4 bytes)
        var len_buf: [4]u8 = undefined;
        readExact(client_fd, &len_buf) catch return TransportError.ReceiveFailed;
        const msg_len = std.mem.readInt(u32, &len_buf, .little);

        if (msg_len > 65536 or msg_len < 1) return TransportError.InvalidMessage;

        // read message body
        const body = alloc.alloc(u8, msg_len) catch return TransportError.ReceiveFailed;
        defer alloc.free(body);

        readExact(client_fd, body) catch return TransportError.ReceiveFailed;

        const msg = decode(alloc, body) catch return TransportError.InvalidMessage;

        return ReceivedMessage{
            .from_addr = std.net.Address{ .any = client_addr },
            .message = msg,
        };
    }
};

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
    }

    // write length prefix (excludes the 4-byte length itself)
    const body_len: u32 = @intCast(offset - 4);
    std.mem.writeInt(u32, buf[0..4], body_len, .little);

    return offset;
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
