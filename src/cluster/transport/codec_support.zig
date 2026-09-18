const std = @import("std");
const common = @import("common.zig");

const Message = common.Message;
const LogEntry = common.LogEntry;
const AppendEntriesArgs = common.AppendEntriesArgs;
const InstallSnapshotArgs = common.InstallSnapshotArgs;

const frame_prefix_size = 4;
const message_tag_size = 1;
// payload sizes exclude the length prefix and message tag.
const vote_payload_size = 32;
const vote_reply_payload_size = 9;
const append_entries_header_size = 44;
const append_reply_payload_size = 17;
const entry_header_size = 20;
const snapshot_header_size = 36;
const snapshot_reply_payload_size = 8;

// check the whole frame before writing fields or narrowing lengths to u32.
pub fn encodedSize(msg: Message) !usize {
    var payload_size: usize = switch (msg) {
        .request_vote => vote_payload_size,
        .request_vote_reply => vote_reply_payload_size,
        .append_entries => append_entries_header_size,
        .append_entries_reply => append_reply_payload_size,
        .install_snapshot => return error.BufferTooSmall,
        .install_snapshot_reply => snapshot_reply_payload_size,
    };
    if (msg == .append_entries) {
        const entries = msg.append_entries.entries;
        if (entries.len > std.math.maxInt(u32)) return error.BufferTooSmall;
        for (entries) |entry| {
            payload_size = std.math.add(usize, payload_size, entry_header_size) catch return error.BufferTooSmall;
            payload_size = std.math.add(usize, payload_size, entry.data.len) catch return error.BufferTooSmall;
        }
    }
    if (payload_size > std.math.maxInt(u32) - message_tag_size) return error.BufferTooSmall;
    return std.math.add(usize, frame_prefix_size + message_tag_size, payload_size) catch error.BufferTooSmall;
}

pub fn encode(buf: []u8, msg: Message) !usize {
    const frame_size = try encodedSize(msg);
    if (buf.len < frame_size) return error.BufferTooSmall;

    var offset: usize = frame_prefix_size;
    switch (msg) {
        .request_vote => |args| {
            buf[offset] = common.msg_request_vote;
            offset += 1;
            common.writeU64(buf[offset..], args.term);
            offset += 8;
            common.writeU64(buf[offset..], args.candidate_id);
            offset += 8;
            common.writeU64(buf[offset..], args.last_log_index);
            offset += 8;
            common.writeU64(buf[offset..], args.last_log_term);
            offset += 8;
        },
        .request_vote_reply => |reply| {
            buf[offset] = common.msg_request_vote_reply;
            offset += 1;
            common.writeU64(buf[offset..], reply.term);
            offset += 8;
            buf[offset] = if (reply.vote_granted) 1 else 0;
            offset += 1;
        },
        .append_entries => |args| encodeAppendEntries(buf, &offset, args),
        .append_entries_reply => |reply| {
            buf[offset] = common.msg_append_entries_reply;
            offset += 1;
            common.writeU64(buf[offset..], reply.term);
            offset += 8;
            buf[offset] = if (reply.success) 1 else 0;
            offset += 1;
            common.writeU64(buf[offset..], reply.match_index);
            offset += 8;
        },
        .install_snapshot => return error.BufferTooSmall,
        .install_snapshot_reply => |reply| {
            buf[offset] = common.msg_install_snapshot_reply;
            offset += 1;
            common.writeU64(buf[offset..], reply.term);
            offset += 8;
        },
    }

    std.mem.writeInt(u32, buf[0..frame_prefix_size], @intCast(frame_size - frame_prefix_size), .little);
    return offset;
}

fn encodeAppendEntries(buf: []u8, offset: *usize, args: AppendEntriesArgs) void {
    buf[offset.*] = common.msg_append_entries;
    offset.* += 1;
    common.writeU64(buf[offset.*..], args.term);
    offset.* += 8;
    common.writeU64(buf[offset.*..], args.leader_id);
    offset.* += 8;
    common.writeU64(buf[offset.*..], args.prev_log_index);
    offset.* += 8;
    common.writeU64(buf[offset.*..], args.prev_log_term);
    offset.* += 8;
    common.writeU64(buf[offset.*..], args.leader_commit);
    offset.* += 8;
    common.writeU32(buf[offset.*..], @intCast(args.entries.len));
    offset.* += 4;

    for (args.entries) |entry| {
        common.writeU64(buf[offset.*..], entry.index);
        offset.* += 8;
        common.writeU64(buf[offset.*..], entry.term);
        offset.* += 8;
        common.writeU32(buf[offset.*..], @intCast(entry.data.len));
        offset.* += 4;
        @memcpy(buf[offset.*..][0..entry.data.len], entry.data);
        offset.* += entry.data.len;
    }
}

pub fn encodeSnapshot(alloc: std.mem.Allocator, args: InstallSnapshotArgs) ![]u8 {
    const body_header_size = message_tag_size + snapshot_header_size;
    if (args.data.len > std.math.maxInt(u32) - body_header_size) return error.OutOfMemory;
    const total = std.math.add(usize, frame_prefix_size + body_header_size, args.data.len) catch return error.OutOfMemory;
    const buf = try alloc.alloc(u8, total);

    var offset: usize = frame_prefix_size;
    buf[offset] = common.msg_install_snapshot;
    offset += 1;
    common.writeU64(buf[offset..], args.term);
    offset += 8;
    common.writeU64(buf[offset..], args.leader_id);
    offset += 8;
    common.writeU64(buf[offset..], args.last_included_index);
    offset += 8;
    common.writeU64(buf[offset..], args.last_included_term);
    offset += 8;
    common.writeU32(buf[offset..], @intCast(args.data.len));
    offset += 4;
    @memcpy(buf[offset..][0..args.data.len], args.data);

    std.mem.writeInt(u32, buf[0..frame_prefix_size], @intCast(total - frame_prefix_size), .little);
    return buf;
}

pub fn decode(alloc: std.mem.Allocator, buf: []const u8) !Message {
    if (buf.len < 1) return error.InvalidMessage;

    const msg_type = buf[0];
    const payload = buf[1..];

    switch (msg_type) {
        common.msg_request_vote => {
            if (payload.len < vote_payload_size) return error.InvalidMessage;
            return .{ .request_vote = .{
                .term = common.readU64(payload[0..]),
                .candidate_id = common.readU64(payload[8..]),
                .last_log_index = common.readU64(payload[16..]),
                .last_log_term = common.readU64(payload[24..]),
            } };
        },
        common.msg_request_vote_reply => {
            if (payload.len < vote_reply_payload_size) return error.InvalidMessage;
            return .{ .request_vote_reply = .{
                .term = common.readU64(payload[0..]),
                .vote_granted = payload[8] != 0,
            } };
        },
        common.msg_append_entries => return decodeAppendEntries(alloc, payload),
        common.msg_append_entries_reply => {
            if (payload.len < append_reply_payload_size) return error.InvalidMessage;
            return .{ .append_entries_reply = .{
                .term = common.readU64(payload[0..]),
                .success = payload[8] != 0,
                .match_index = common.readU64(payload[9..]),
            } };
        },
        common.msg_install_snapshot => {
            if (payload.len < snapshot_header_size) return error.InvalidMessage;
            const data_len = common.readU32(payload[32..]);
            const snapshot_data = payload[snapshot_header_size..];
            if (data_len > snapshot_data.len) return error.InvalidMessage;
            const data = try alloc.dupe(u8, snapshot_data[0..data_len]);
            return .{ .install_snapshot = .{
                .term = common.readU64(payload[0..]),
                .leader_id = common.readU64(payload[8..]),
                .last_included_index = common.readU64(payload[16..]),
                .last_included_term = common.readU64(payload[24..]),
                .data = data,
            } };
        },
        common.msg_install_snapshot_reply => {
            if (payload.len < snapshot_reply_payload_size) return error.InvalidMessage;
            return .{ .install_snapshot_reply = .{
                .term = common.readU64(payload[0..]),
            } };
        },
        else => return error.InvalidMessage,
    }
}

fn decodeAppendEntries(alloc: std.mem.Allocator, payload: []const u8) !Message {
    if (payload.len < append_entries_header_size) return error.InvalidMessage;
    const entry_count = common.readU32(payload[40..]);
    const remaining_payload = payload.len - append_entries_header_size;
    const max_possible_entries = remaining_payload / entry_header_size;
    if (entry_count > max_possible_entries) return error.InvalidMessage;

    const entries = try alloc.alloc(LogEntry, entry_count);
    var decoded_count: usize = 0;
    errdefer {
        // only completed entries own a payload when decoding fails.
        for (entries[0..decoded_count]) |entry| alloc.free(entry.data);
        alloc.free(entries);
    }

    var offset: usize = append_entries_header_size;
    for (entries) |*entry| {
        if (payload.len - offset < entry_header_size) return error.InvalidMessage;

        const data_len = common.readU32(payload[offset + 16 ..]);
        const data_start = offset + entry_header_size;
        if (data_len > payload.len - data_start) return error.InvalidMessage;

        const data = try alloc.dupe(u8, payload[data_start..][0..data_len]);
        entry.* = .{
            .index = common.readU64(payload[offset..]),
            .term = common.readU64(payload[offset + 8 ..]),
            .data = data,
        };
        decoded_count += 1;
        offset = data_start + data_len;
    }

    return .{ .append_entries = .{
        .term = common.readU64(payload[0..]),
        .leader_id = common.readU64(payload[8..]),
        .prev_log_index = common.readU64(payload[16..]),
        .prev_log_term = common.readU64(payload[24..]),
        .entries = entries,
        .leader_commit = common.readU64(payload[32..]),
    } };
}

test "encode rejects every short buffer before writing the frame" {
    const entries = [_]LogEntry{
        .{ .index = 2, .term = 1, .data = "abc" },
        .{ .index = 3, .term = 1, .data = "" },
    };
    const cases = [_]struct { message: Message, frame_size: usize }{
        .{ .message = .{ .request_vote = .{ .term = 1, .candidate_id = 2, .last_log_index = 3, .last_log_term = 4 } }, .frame_size = 37 },
        .{ .message = .{ .request_vote_reply = .{ .term = 1, .vote_granted = true } }, .frame_size = 14 },
        .{ .message = .{ .append_entries = .{ .term = 1, .leader_id = 2, .prev_log_index = 3, .prev_log_term = 4, .leader_commit = 5, .entries = &.{} } }, .frame_size = 49 },
        .{ .message = .{ .append_entries = .{ .term = 1, .leader_id = 2, .prev_log_index = 3, .prev_log_term = 4, .leader_commit = 5, .entries = &entries } }, .frame_size = 92 },
        .{ .message = .{ .append_entries_reply = .{ .term = 1, .success = true, .match_index = 2 } }, .frame_size = 22 },
        .{ .message = .{ .install_snapshot_reply = .{ .term = 1 } }, .frame_size = 13 },
    };
    var buf: [128]u8 = undefined;
    for (cases) |case| {
        for (0..case.frame_size) |length| {
            @memset(&buf, 0xaa);
            try std.testing.expectError(error.BufferTooSmall, encode(buf[0..length], case.message));
            try std.testing.expect(std.mem.allEqual(u8, &buf, 0xaa));
        }
        try std.testing.expectEqual(case.frame_size, try encode(buf[0..case.frame_size], case.message));
        try std.testing.expectEqual(case.frame_size - 4, common.readU32(&buf));
    }
}

test "decode releases earlier entries when a later header or payload is truncated" {
    const entries = [_]LogEntry{
        .{ .index = 1, .term = 1, .data = "first" },
        .{ .index = 2, .term = 1, .data = "second" },
    };
    const message: Message = .{ .append_entries = .{
        .term = 2,
        .leader_id = 3,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .leader_commit = 0,
        .entries = &entries,
    } };
    var buf: [128]u8 = undefined;
    const size = try encode(&buf, message);
    const second_header = 4 + 1 + 44 + 20 + entries[0].data.len;
    try std.testing.expectError(error.InvalidMessage, decode(std.testing.allocator, buf[4 .. second_header + 19]));
    try std.testing.expectError(error.InvalidMessage, decode(std.testing.allocator, buf[4 .. size - 1]));
    common.writeU32(buf[second_header + 16 ..], std.math.maxInt(u32));
    try std.testing.expectError(error.InvalidMessage, decode(std.testing.allocator, buf[4..size]));
}

fn decodeEntriesWithAllocator(alloc: std.mem.Allocator, body: []const u8) !void {
    const decoded = try decode(alloc, body);
    defer {
        for (decoded.append_entries.entries) |entry| alloc.free(entry.data);
        alloc.free(decoded.append_entries.entries);
    }
    try std.testing.expectEqual(@as(usize, 3), decoded.append_entries.entries.len);
    try std.testing.expectEqualStrings("first", decoded.append_entries.entries[0].data);
    try std.testing.expectEqualStrings("second", decoded.append_entries.entries[1].data);
    try std.testing.expectEqualStrings("", decoded.append_entries.entries[2].data);
}

test "decode releases entries and payloads after any allocation failure" {
    const entries = [_]LogEntry{
        .{ .index = 1, .term = 1, .data = "first" },
        .{ .index = 2, .term = 1, .data = "second" },
        .{ .index = 3, .term = 1, .data = "" },
    };
    var buf: [128]u8 = undefined;
    const size = try encode(&buf, .{ .append_entries = .{
        .term = 2,
        .leader_id = 3,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .leader_commit = 0,
        .entries = &entries,
    } });
    try std.testing.checkAllAllocationFailures(std.testing.allocator, decodeEntriesWithAllocator, .{buf[4..size]});
}

test "decode rejects snapshot lengths near the u32 limit" {
    var body = [_]u8{0} ** 37;
    body[0] = common.msg_install_snapshot;
    for ([_]u32{ 1, std.math.maxInt(u32) - 36, std.math.maxInt(u32) - 35, std.math.maxInt(u32) }) |length| {
        common.writeU32(body[33..], length);
        try std.testing.expectError(error.InvalidMessage, decode(std.testing.allocator, &body));
    }
}

test "append entries keeps the wire layout and accepts trailing bytes" {
    const frame =
        "\x44\x00\x00\x00" ++ // body length
        "\x03" ++ // append entries
        "\x01\x00\x00\x00\x00\x00\x00\x00" ++ // term
        "\x02\x00\x00\x00\x00\x00\x00\x00" ++ // leader
        "\x03\x00\x00\x00\x00\x00\x00\x00" ++ // previous index
        "\x04\x00\x00\x00\x00\x00\x00\x00" ++ // previous term
        "\x05\x00\x00\x00\x00\x00\x00\x00" ++ // committed index
        "\x01\x00\x00\x00" ++ // entry count
        "\x06\x00\x00\x00\x00\x00\x00\x00" ++ // entry index
        "\x07\x00\x00\x00\x00\x00\x00\x00" ++ // entry term
        "\x03\x00\x00\x00abc"; // entry data
    var buf: [72]u8 = undefined;
    const size = try encode(&buf, .{ .append_entries = .{
        .term = 1,
        .leader_id = 2,
        .prev_log_index = 3,
        .prev_log_term = 4,
        .leader_commit = 5,
        .entries = &.{.{ .index = 6, .term = 7, .data = "abc" }},
    } });
    try std.testing.expectEqualSlices(u8, frame, buf[0..size]);

    const alloc = std.testing.allocator;
    const body_with_trailing_bytes = frame[4..] ++ "trailing";
    const decoded = try decode(alloc, body_with_trailing_bytes);
    defer {
        for (decoded.append_entries.entries) |entry| alloc.free(entry.data);
        alloc.free(decoded.append_entries.entries);
    }
    const args = decoded.append_entries;
    try std.testing.expectEqual(@as(u64, 1), args.term);
    try std.testing.expectEqual(@as(u64, 2), args.leader_id);
    try std.testing.expectEqual(@as(u64, 3), args.prev_log_index);
    try std.testing.expectEqual(@as(u64, 4), args.prev_log_term);
    try std.testing.expectEqual(@as(u64, 5), args.leader_commit);
    try std.testing.expectEqual(@as(usize, 1), args.entries.len);
    try std.testing.expectEqual(@as(u64, 6), args.entries[0].index);
    try std.testing.expectEqual(@as(u64, 7), args.entries[0].term);
    try std.testing.expectEqualStrings("abc", args.entries[0].data);
}
