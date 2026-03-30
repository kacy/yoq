const std = @import("std");
const hpack = @import("hpack.zig");
const http2 = @import("http2.zig");

const Flag = struct {
    const end_stream: u8 = 0x1;
    const end_headers: u8 = 0x4;
};

pub const Error = http2.Error || std.mem.Allocator.Error;

pub fn formatSimpleResponse(
    alloc: std.mem.Allocator,
    stream_id: u32,
    status_code: u16,
    content_type: []const u8,
    body: []const u8,
) Error![]u8 {
    return formatSimpleResponseWithSettings(alloc, stream_id, status_code, content_type, body, true);
}

pub fn formatSimpleStreamResponse(
    alloc: std.mem.Allocator,
    stream_id: u32,
    status_code: u16,
    content_type: []const u8,
    body: []const u8,
) Error![]u8 {
    return formatSimpleResponseWithSettings(alloc, stream_id, status_code, content_type, body, false);
}

fn formatSimpleResponseWithSettings(
    alloc: std.mem.Allocator,
    stream_id: u32,
    status_code: u16,
    content_type: []const u8,
    body: []const u8,
    include_settings: bool,
) Error![]u8 {
    var status_buf: [3]u8 = undefined;
    const status = std.fmt.bufPrint(&status_buf, "{d:0>3}", .{status_code}) catch unreachable;

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);
    try appendLiteralHeaderWithIndexedName(&header_block, alloc, 8, status);
    try appendLiteralHeaderWithIndexedName(&header_block, alloc, 31, content_type);

    var content_length_buf: [20]u8 = undefined;
    const content_length = std.fmt.bufPrint(&content_length_buf, "{d}", .{body.len}) catch unreachable;
    try appendLiteralHeaderWithIndexedName(&header_block, alloc, 28, content_length);

    const headers = try buildFrame(alloc, .{
        .length = @intCast(header_block.items.len),
        .frame_type = .headers,
        .flags = Flag.end_headers | if (body.len == 0) Flag.end_stream else 0,
        .stream_id = stream_id,
    }, header_block.items);
    defer alloc.free(headers);

    const data = if (body.len == 0) null else try buildFrame(alloc, .{
        .length = @intCast(body.len),
        .frame_type = .data,
        .flags = Flag.end_stream,
        .stream_id = stream_id,
    }, body);
    defer if (data) |frame| alloc.free(frame);

    const settings_len: usize = if (include_settings) http2.frame_header_len else 0;
    const total_len = settings_len + headers.len + if (data) |frame| frame.len else 0;
    var response = try alloc.alloc(u8, total_len);
    errdefer alloc.free(response);

    var pos: usize = 0;
    if (include_settings) {
        try http2.writeFrameHeader(response[pos .. pos + http2.frame_header_len], .{
            .length = 0,
            .frame_type = .settings,
            .flags = 0,
            .stream_id = 0,
        });
        pos += http2.frame_header_len;
    }

    @memcpy(response[pos .. pos + headers.len], headers);
    pos += headers.len;
    if (data) |frame| {
        @memcpy(response[pos .. pos + frame.len], frame);
        pos += frame.len;
    }

    return response[0..pos];
}

fn appendLiteralHeaderWithIndexedName(
    buf: *std.ArrayList(u8),
    alloc: std.mem.Allocator,
    name_index: u8,
    value: []const u8,
) !void {
    try appendInteger(buf, alloc, 0, 4, name_index);
    try appendString(buf, alloc, value);
}

fn appendString(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, value: []const u8) !void {
    try appendInteger(buf, alloc, 0, 7, value.len);
    try buf.appendSlice(alloc, value);
}

fn appendInteger(
    buf: *std.ArrayList(u8),
    alloc: std.mem.Allocator,
    first_byte_prefix: u8,
    comptime prefix_bits: u8,
    value: usize,
) !void {
    const max_prefix_value: usize = (@as(usize, 1) << prefix_bits) - 1;
    if (value < max_prefix_value) {
        try buf.append(alloc, first_byte_prefix | @as(u8, @intCast(value)));
        return;
    }

    try buf.append(alloc, first_byte_prefix | @as(u8, @intCast(max_prefix_value)));
    var remaining = value - max_prefix_value;
    while (remaining >= 128) {
        try buf.append(alloc, @as(u8, @intCast((remaining & 0x7f) | 0x80)));
        remaining >>= 7;
    }
    try buf.append(alloc, @intCast(remaining));
}

fn buildFrame(alloc: std.mem.Allocator, header: http2.FrameHeader, payload: []const u8) ![]u8 {
    const buf = try alloc.alloc(u8, http2.frame_header_len + payload.len);
    errdefer alloc.free(buf);
    try http2.writeFrameHeader(buf[0..http2.frame_header_len], header);
    @memcpy(buf[http2.frame_header_len..], payload);
    return buf;
}

fn parseNextFrame(buf: []const u8, pos: usize) ?struct { header: http2.FrameHeader, payload: []const u8, next: usize } {
    if (pos + http2.frame_header_len > buf.len) return null;
    const header = http2.parseFrameHeader(buf[pos .. pos + http2.frame_header_len]) orelse return null;
    const payload_start = pos + http2.frame_header_len;
    const payload_end = payload_start + header.length;
    if (payload_end > buf.len) return null;
    return .{
        .header = header,
        .payload = buf[payload_start..payload_end],
        .next = payload_end,
    };
}

test "formatSimpleResponse emits settings, headers, and data frames" {
    const alloc = std.testing.allocator;
    const body = "{\"error\":\"route not found\"}";

    const response = try formatSimpleResponse(alloc, 1, 404, "application/json", body);
    defer alloc.free(response);

    const settings = parseNextFrame(response, 0).?;
    try std.testing.expect(http2.isInitialServerSettingsFrame(settings.header));

    const headers = parseNextFrame(response, settings.next).?;
    try std.testing.expectEqual(http2.FrameType.headers, headers.header.frame_type);
    try std.testing.expectEqual(@as(u32, 1), headers.header.stream_id);
    try std.testing.expectEqual(@as(u8, Flag.end_headers), headers.header.flags);

    var decoded_headers = try hpack.decodeHeaderBlock(alloc, headers.payload);
    defer {
        for (decoded_headers.items) |header| header.deinit(alloc);
        decoded_headers.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 3), decoded_headers.items.len);
    try std.testing.expectEqualStrings(":status", decoded_headers.items[0].name);
    try std.testing.expectEqualStrings("404", decoded_headers.items[0].value);
    try std.testing.expectEqualStrings("content-type", decoded_headers.items[1].name);
    try std.testing.expectEqualStrings("application/json", decoded_headers.items[1].value);
    try std.testing.expectEqualStrings("content-length", decoded_headers.items[2].name);

    const data = parseNextFrame(response, headers.next).?;
    try std.testing.expectEqual(http2.FrameType.data, data.header.frame_type);
    try std.testing.expectEqual(@as(u8, Flag.end_stream), data.header.flags);
    try std.testing.expectEqualStrings(body, data.payload);
    try std.testing.expectEqual(@as(usize, response.len), data.next);
}

test "formatSimpleResponse can end stream in headers without body" {
    const alloc = std.testing.allocator;

    const response = try formatSimpleResponse(alloc, 3, 204, "application/json", "");
    defer alloc.free(response);

    const settings = parseNextFrame(response, 0).?;
    try std.testing.expect(http2.isInitialServerSettingsFrame(settings.header));

    const headers = parseNextFrame(response, settings.next).?;
    try std.testing.expectEqual(http2.FrameType.headers, headers.header.frame_type);
    try std.testing.expectEqual(@as(u32, 3), headers.header.stream_id);
    try std.testing.expectEqual(@as(u8, Flag.end_headers | Flag.end_stream), headers.header.flags);
    try std.testing.expectEqual(@as(usize, response.len), headers.next);
}

test "formatSimpleStreamResponse omits connection settings frame" {
    const alloc = std.testing.allocator;

    const response = try formatSimpleStreamResponse(alloc, 5, 200, "application/grpc", "ok");
    defer alloc.free(response);

    const first = parseNextFrame(response, 0).?;
    try std.testing.expectEqual(http2.FrameType.headers, first.header.frame_type);
    try std.testing.expectEqual(@as(u32, 5), first.header.stream_id);
}
