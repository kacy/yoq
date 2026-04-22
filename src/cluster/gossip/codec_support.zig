const std = @import("std");
const platform = @import("platform");

pub fn encode(buf: []u8, msg: anytype, max_piggyback_updates: usize) !usize {
    var pos: usize = 0;

    switch (msg) {
        .ping => |p| {
            const updates = p.updates.slice();
            if (buf.len < 18 + updates.len * 23) return error.BufferTooSmall;
            buf[pos] = 0x10;
            pos += 1;
            writeU64(buf[pos..], p.from);
            pos += 8;
            writeU64(buf[pos..], p.sequence);
            pos += 8;
            buf[pos] = @intCast(updates.len);
            pos += 1;
            pos = encodeUpdates(buf, pos, updates);
        },
        .ping_ack => |p| {
            const updates = p.updates.slice();
            if (buf.len < 18 + updates.len * 23) return error.BufferTooSmall;
            buf[pos] = 0x11;
            pos += 1;
            writeU64(buf[pos..], p.from);
            pos += 8;
            writeU64(buf[pos..], p.sequence);
            pos += 8;
            buf[pos] = @intCast(updates.len);
            pos += 1;
            pos = encodeUpdates(buf, pos, updates);
        },
        .ping_req => |p| {
            const updates = p.updates.slice();
            if (buf.len < 26 + updates.len * 23) return error.BufferTooSmall;
            buf[pos] = 0x12;
            pos += 1;
            writeU64(buf[pos..], p.from);
            pos += 8;
            writeU64(buf[pos..], p.target);
            pos += 8;
            writeU64(buf[pos..], p.sequence);
            pos += 8;
            buf[pos] = @intCast(updates.len);
            pos += 1;
            pos = encodeUpdates(buf, pos, updates);
        },
    }

    _ = max_piggyback_updates;
    return pos;
}

pub fn decode(data: []const u8, GossipMessage: type, BoundedUpdates: type, MemberState: type, max_piggyback_updates: u8) !@TypeOf(@as(GossipMessage, undefined)) {
    if (data.len < 1) return error.InvalidMessage;
    const msg_type = data[0];

    switch (msg_type) {
        0x10, 0x11 => {
            if (data.len < 18) return error.InvalidMessage;
            const from = readU64(data[1..]);
            const sequence = readU64(data[9..]);
            const count = data[17];
            if (count > max_piggyback_updates) return error.InvalidMessage;
            if (data.len < 18 + @as(usize, count) * 23) return error.InvalidMessage;

            const updates = decodeUpdates(data[18..], count, BoundedUpdates, MemberState);
            if (msg_type == 0x10) {
                return .{ .ping = .{ .from = from, .sequence = sequence, .updates = updates } };
            }
            return .{ .ping_ack = .{ .from = from, .sequence = sequence, .updates = updates } };
        },
        0x12 => {
            if (data.len < 26) return error.InvalidMessage;
            const from = readU64(data[1..]);
            const target = readU64(data[9..]);
            const sequence = readU64(data[17..]);
            const count = data[25];
            if (count > max_piggyback_updates) return error.InvalidMessage;
            if (data.len < 26 + @as(usize, count) * 23) return error.InvalidMessage;

            const updates = decodeUpdates(data[26..], count, BoundedUpdates, MemberState);
            return .{ .ping_req = .{ .from = from, .target = target, .sequence = sequence, .updates = updates } };
        },
        else => return error.InvalidMessage,
    }
}

pub fn encodeUpdates(buf: []u8, start: usize, updates: anytype) usize {
    var pos = start;
    for (updates) |u| {
        writeU64(buf[pos..], u.id);
        pos += 8;
        @memcpy(buf[pos..][0..4], &u.addr.ip);
        pos += 4;
        buf[pos] = @intCast(u.addr.port & 0xFF);
        buf[pos + 1] = @intCast((u.addr.port >> 8) & 0xFF);
        pos += 2;
        buf[pos] = @intFromEnum(u.state);
        pos += 1;
        writeU64(buf[pos..], u.incarnation);
        pos += 8;
    }
    return pos;
}

pub fn decodeUpdates(data: []const u8, count: u8, BoundedUpdates: type, MemberState: type) BoundedUpdates {
    var result: BoundedUpdates = .{};
    result.len = count;

    var pos: usize = 0;
    for (0..count) |i| {
        result.buf[i] = .{
            .id = readU64(data[pos..]),
            .addr = .{
                .ip = data[pos + 8 ..][0..4].*,
                .port = @as(u16, data[pos + 12]) | (@as(u16, data[pos + 13]) << 8),
            },
            .state = platform.intToEnum(MemberState, data[pos + 14]) catch return .{},
            .incarnation = readU64(data[pos + 15 ..]),
        };
        pos += 23;
    }

    return result;
}

pub fn writeU64(buf: []u8, val: u64) void {
    buf[0..8].* = @bitCast(val);
}

pub fn readU64(buf: []const u8) u64 {
    return @bitCast(buf[0..8].*);
}
