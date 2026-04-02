const std = @import("std");

pub const client_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const frame_header_len: usize = 9;
pub const Error = error{
    BufferTooSmall,
    LengthTooLarge,
    InvalidStreamId,
};

pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    unknown = 0xff,

    pub fn fromByte(value: u8) FrameType {
        return switch (value) {
            0x0 => .data,
            0x1 => .headers,
            0x2 => .priority,
            0x3 => .rst_stream,
            0x4 => .settings,
            0x5 => .push_promise,
            0x6 => .ping,
            0x7 => .goaway,
            0x8 => .window_update,
            0x9 => .continuation,
            else => .unknown,
        };
    }
};

pub const FrameHeader = struct {
    length: u32,
    frame_type: FrameType,
    flags: u8,
    stream_id: u32,

    pub fn isConnectionFrame(self: FrameHeader) bool {
        return self.stream_id == 0;
    }
};

pub fn hasClientPrefacePrefix(buf: []const u8) bool {
    if (buf.len > client_preface.len) return false;
    return std.mem.eql(u8, client_preface[0..buf.len], buf);
}

pub fn startsWithClientPreface(buf: []const u8) bool {
    if (buf.len < client_preface.len) return false;
    return std.mem.eql(u8, buf[0..client_preface.len], client_preface);
}

pub fn parseFrameHeader(buf: []const u8) ?FrameHeader {
    if (buf.len < frame_header_len) return null;

    const length = (@as(u32, buf[0]) << 16) | (@as(u32, buf[1]) << 8) | @as(u32, buf[2]);
    const stream_id = std.mem.readInt(u32, buf[5..9], .big) & 0x7fff_ffff;
    return .{
        .length = length,
        .frame_type = FrameType.fromByte(buf[3]),
        .flags = buf[4],
        .stream_id = stream_id,
    };
}

pub fn writeFrameHeader(dest: []u8, header: FrameHeader) Error!void {
    if (dest.len < frame_header_len) return error.BufferTooSmall;
    if (header.length > 0x00ff_ffff) return error.LengthTooLarge;
    if ((header.stream_id & 0x8000_0000) != 0) return error.InvalidStreamId;

    dest[0] = @intCast((header.length >> 16) & 0xff);
    dest[1] = @intCast((header.length >> 8) & 0xff);
    dest[2] = @intCast(header.length & 0xff);
    dest[3] = @intFromEnum(header.frame_type);
    dest[4] = header.flags;
    std.mem.writeInt(u32, dest[5..9], header.stream_id, .big);
}

pub fn buildFrame(alloc: std.mem.Allocator, header: FrameHeader, payload: []const u8) ![]u8 {
    const buf = try alloc.alloc(u8, frame_header_len + payload.len);
    errdefer alloc.free(buf);
    try writeFrameHeader(buf[0..frame_header_len], header);
    @memcpy(buf[frame_header_len..], payload);
    return buf;
}

pub fn isInitialServerSettingsFrame(header: FrameHeader) bool {
    return header.frame_type == .settings and header.stream_id == 0;
}

test "hasClientPrefacePrefix matches complete preface" {
    try std.testing.expect(hasClientPrefacePrefix(client_preface));
}

test "hasClientPrefacePrefix matches partial preface" {
    try std.testing.expect(hasClientPrefacePrefix(client_preface[0..8]));
}

test "hasClientPrefacePrefix rejects wrong bytes" {
    try std.testing.expect(!hasClientPrefacePrefix("PRI * HTTP/1."));
}

test "startsWithClientPreface matches request buffer with full preface" {
    try std.testing.expect(startsWithClientPreface(client_preface ++ "rest"));
}

test "startsWithClientPreface rejects partial preface" {
    try std.testing.expect(!startsWithClientPreface(client_preface[0..8]));
}

test "parseFrameHeader parses settings header" {
    const header = parseFrameHeader(&[_]u8{
        0x00, 0x00, 0x00,
        0x04, 0x00, 0x00,
        0x00, 0x00, 0x00,
    }).?;

    try std.testing.expectEqual(@as(u32, 0), header.length);
    try std.testing.expectEqual(FrameType.settings, header.frame_type);
    try std.testing.expectEqual(@as(u8, 0), header.flags);
    try std.testing.expectEqual(@as(u32, 0), header.stream_id);
    try std.testing.expect(header.isConnectionFrame());
}

test "parseFrameHeader masks reserved stream bit" {
    const header = parseFrameHeader(&[_]u8{
        0x00, 0x00, 0x05,
        0x01, 0x04, 0x80,
        0x00, 0x00, 0x01,
    }).?;

    try std.testing.expectEqual(FrameType.headers, header.frame_type);
    try std.testing.expectEqual(@as(u32, 1), header.stream_id);
}

test "writeFrameHeader round trips through parseFrameHeader" {
    var buf: [frame_header_len]u8 = undefined;
    try writeFrameHeader(&buf, .{
        .length = 42,
        .frame_type = .headers,
        .flags = 0x05,
        .stream_id = 3,
    });

    const parsed = parseFrameHeader(&buf).?;
    try std.testing.expectEqual(@as(u32, 42), parsed.length);
    try std.testing.expectEqual(FrameType.headers, parsed.frame_type);
    try std.testing.expectEqual(@as(u8, 0x05), parsed.flags);
    try std.testing.expectEqual(@as(u32, 3), parsed.stream_id);
}

test "writeFrameHeader rejects oversized payload length" {
    var buf: [frame_header_len]u8 = undefined;
    try std.testing.expectError(error.LengthTooLarge, writeFrameHeader(&buf, .{
        .length = 0x0100_0000,
        .frame_type = .data,
        .flags = 0,
        .stream_id = 1,
    }));
}

test "isInitialServerSettingsFrame accepts connection-scoped settings" {
    try std.testing.expect(isInitialServerSettingsFrame(.{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }));
}

test "isInitialServerSettingsFrame rejects stream-scoped frames" {
    try std.testing.expect(!isInitialServerSettingsFrame(.{
        .length = 0,
        .frame_type = .headers,
        .flags = 0,
        .stream_id = 1,
    }));
}
