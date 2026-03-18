const std = @import("std");
const common = @import("common.zig");

const Message = common.Message;
const LogEntry = common.LogEntry;
const AppendEntriesArgs = common.AppendEntriesArgs;
const InstallSnapshotArgs = common.InstallSnapshotArgs;

pub fn encode(buf: []u8, msg: Message) !usize {
    if (buf.len < 5) return error.BufferTooSmall;

    var offset: usize = 4;
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
        .append_entries => |args| try encodeAppendEntries(buf, &offset, args),
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

    if (offset - 4 > std.math.maxInt(u32)) return error.BufferTooSmall;
    std.mem.writeInt(u32, buf[0..4], @intCast(offset - 4), .little);
    return offset;
}

fn encodeAppendEntries(buf: []u8, offset: *usize, args: AppendEntriesArgs) !void {
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
    if (args.entries.len > std.math.maxInt(u32)) return error.BufferTooSmall;
    common.writeU32(buf[offset.*..], @intCast(args.entries.len));
    offset.* += 4;

    for (args.entries) |entry| {
        if (offset.* + 20 + entry.data.len > buf.len) return error.BufferTooSmall;
        common.writeU64(buf[offset.*..], entry.index);
        offset.* += 8;
        common.writeU64(buf[offset.*..], entry.term);
        offset.* += 8;
        if (entry.data.len > std.math.maxInt(u32)) return error.BufferTooSmall;
        common.writeU32(buf[offset.*..], @intCast(entry.data.len));
        offset.* += 4;
        @memcpy(buf[offset.*..][0..entry.data.len], entry.data);
        offset.* += entry.data.len;
    }
}

pub fn encodeSnapshot(alloc: std.mem.Allocator, args: InstallSnapshotArgs) ![]u8 {
    const header_size = 4 + 1 + 32 + 4;
    const total = header_size + args.data.len;
    const buf = try alloc.alloc(u8, total);
    errdefer alloc.free(buf);

    var offset: usize = 4;
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
    if (args.data.len > std.math.maxInt(u32)) return error.OutOfMemory;
    common.writeU32(buf[offset..], @intCast(args.data.len));
    offset += 4;
    @memcpy(buf[offset..][0..args.data.len], args.data);
    offset += args.data.len;

    if (offset - 4 > std.math.maxInt(u32)) return error.OutOfMemory;
    std.mem.writeInt(u32, buf[0..4], @intCast(offset - 4), .little);
    return buf;
}

pub fn decode(alloc: std.mem.Allocator, buf: []const u8) !Message {
    if (buf.len < 1) return error.InvalidMessage;

    const msg_type = buf[0];
    const payload = buf[1..];

    switch (msg_type) {
        common.msg_request_vote => {
            if (payload.len < 32) return error.InvalidMessage;
            return .{ .request_vote = .{
                .term = common.readU64(payload[0..]),
                .candidate_id = common.readU64(payload[8..]),
                .last_log_index = common.readU64(payload[16..]),
                .last_log_term = common.readU64(payload[24..]),
            } };
        },
        common.msg_request_vote_reply => {
            if (payload.len < 9) return error.InvalidMessage;
            return .{ .request_vote_reply = .{
                .term = common.readU64(payload[0..]),
                .vote_granted = payload[8] != 0,
            } };
        },
        common.msg_append_entries => return decodeAppendEntries(alloc, payload),
        common.msg_append_entries_reply => {
            if (payload.len < 17) return error.InvalidMessage;
            return .{ .append_entries_reply = .{
                .term = common.readU64(payload[0..]),
                .success = payload[8] != 0,
                .match_index = common.readU64(payload[9..]),
            } };
        },
        common.msg_install_snapshot => {
            if (payload.len < 36) return error.InvalidMessage;
            const data_len = common.readU32(payload[32..]);
            if (payload.len < 36 + data_len) return error.InvalidMessage;
            const data = try alloc.dupe(u8, payload[36..][0..data_len]);
            return .{ .install_snapshot = .{
                .term = common.readU64(payload[0..]),
                .leader_id = common.readU64(payload[8..]),
                .last_included_index = common.readU64(payload[16..]),
                .last_included_term = common.readU64(payload[24..]),
                .data = data,
            } };
        },
        common.msg_install_snapshot_reply => {
            if (payload.len < 8) return error.InvalidMessage;
            return .{ .install_snapshot_reply = .{
                .term = common.readU64(payload[0..]),
            } };
        },
        else => return error.InvalidMessage,
    }
}

fn decodeAppendEntries(alloc: std.mem.Allocator, payload: []const u8) !Message {
    if (payload.len < 44) return error.InvalidMessage;
    const entry_count = common.readU32(payload[40..]);
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

        const data_len = common.readU32(payload[offset + 16 ..]);
        const data_start = offset + 20;
        if (data_start + data_len > payload.len) {
            alloc.free(entries);
            return error.InvalidMessage;
        }

        const data = try alloc.dupe(u8, payload[data_start..][0..data_len]);
        entries[i] = .{
            .index = common.readU64(payload[offset..]),
            .term = common.readU64(payload[offset + 8 ..]),
            .data = data,
        };
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
