const std = @import("std");
const hpack = @import("hpack.zig");
const http2 = @import("http2.zig");

pub const ParseError = error{
    MissingClientPreface,
    MissingHeaders,
    MissingMethod,
    MissingAuthority,
    MissingPath,
    InvalidFrameSequence,
    InvalidHeadersFrame,
} || http2.Error || hpack.Error || std.mem.Allocator.Error;

pub const RequestHead = struct {
    stream_id: u32,
    method: []u8,
    authority: []u8,
    path: []u8,
    end_stream: bool,

    pub fn deinit(self: RequestHead, alloc: std.mem.Allocator) void {
        alloc.free(self.method);
        alloc.free(self.authority);
        alloc.free(self.path);
    }
};

pub const ParseResult = struct {
    request: RequestHead,
    consumed: usize,

    pub fn deinit(self: ParseResult, alloc: std.mem.Allocator) void {
        self.request.deinit(alloc);
    }
};

const Flag = struct {
    const end_stream: u8 = 0x1;
    const end_headers: u8 = 0x4;
    const padded: u8 = 0x8;
    const priority: u8 = 0x20;
};

pub fn parseClientConnectionPreface(alloc: std.mem.Allocator, buf: []const u8) ParseError!ParseResult {
    if (buf.len < http2.client_preface.len or !std.mem.eql(u8, buf[0..http2.client_preface.len], http2.client_preface)) {
        return error.MissingClientPreface;
    }

    var pos: usize = http2.client_preface.len;
    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);

    var request_stream_id: ?u32 = null;
    var request_end_stream = false;

    while (pos + http2.frame_header_len <= buf.len) {
        const frame = http2.parseFrameHeader(buf[pos .. pos + http2.frame_header_len]).?;
        pos += http2.frame_header_len;

        if (pos + frame.length > buf.len) return error.BufferTooShort;
        const payload = buf[pos .. pos + frame.length];
        pos += frame.length;

        switch (frame.frame_type) {
            .settings, .window_update, .ping => continue,
            .headers => {
                if (frame.stream_id == 0) return error.InvalidHeadersFrame;
                if (request_stream_id != null) return error.InvalidFrameSequence;
                request_stream_id = frame.stream_id;
                request_end_stream = (frame.flags & Flag.end_stream) != 0;
                const fragment = try headerBlockFragment(payload, frame.flags);
                try header_block.appendSlice(alloc, fragment);
                if ((frame.flags & Flag.end_headers) != 0) break;
            },
            .continuation => {
                if (request_stream_id == null or frame.stream_id != request_stream_id.?) return error.InvalidFrameSequence;
                try header_block.appendSlice(alloc, payload);
                if ((frame.flags & Flag.end_headers) != 0) break;
            },
            else => {
                if (request_stream_id == null) continue;
                return error.InvalidFrameSequence;
            },
        }
    }

    if (request_stream_id == null or header_block.items.len == 0) return error.MissingHeaders;

    var headers = try hpack.decodeHeaderBlock(alloc, header_block.items);
    defer {
        for (headers.items) |header| header.deinit(alloc);
        headers.deinit(alloc);
    }

    var method: ?[]u8 = null;
    var authority: ?[]u8 = null;
    var path: ?[]u8 = null;

    for (headers.items) |header| {
        if (std.mem.eql(u8, header.name, ":method")) {
            method = try alloc.dupe(u8, header.value);
        } else if (std.mem.eql(u8, header.name, ":authority")) {
            authority = try alloc.dupe(u8, header.value);
        } else if (std.mem.eql(u8, header.name, ":path")) {
            path = try alloc.dupe(u8, header.value);
        }
    }

    errdefer {
        if (method) |value| alloc.free(value);
        if (authority) |value| alloc.free(value);
        if (path) |value| alloc.free(value);
    }

    return .{
        .request = .{
            .stream_id = request_stream_id.?,
            .method = method orelse return error.MissingMethod,
            .authority = authority orelse return error.MissingAuthority,
            .path = path orelse return error.MissingPath,
            .end_stream = request_end_stream,
        },
        .consumed = pos,
    };
}

fn headerBlockFragment(payload: []const u8, flags: u8) ParseError![]const u8 {
    var pos: usize = 0;
    var padded_len: usize = 0;

    if ((flags & Flag.padded) != 0) {
        if (payload.len == 0) return error.InvalidHeadersFrame;
        padded_len = payload[0];
        pos += 1;
    }

    if ((flags & Flag.priority) != 0) {
        if (pos + 5 > payload.len) return error.InvalidHeadersFrame;
        pos += 5;
    }

    if (padded_len > payload.len - pos) return error.InvalidHeadersFrame;
    return payload[pos .. payload.len - padded_len];
}

fn appendLiteralWithIndexedName(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, name_index: u8, value: []const u8) !void {
    try buf.append(alloc, name_index);
    try buf.append(alloc, @intCast(value.len));
    try buf.appendSlice(alloc, value);
}

fn buildFrame(alloc: std.mem.Allocator, header: http2.FrameHeader, payload: []const u8) ![]u8 {
    var buf = try alloc.alloc(u8, http2.frame_header_len + payload.len);
    errdefer alloc.free(buf);
    try http2.writeFrameHeader(buf[0..http2.frame_header_len], header);
    @memcpy(buf[http2.frame_header_len..], payload);
    return buf;
}

test "parseClientConnectionPreface parses initial HEADERS request" {
    const alloc = std.testing.allocator;

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);
    try header_block.append(alloc, 0x83); // :method POST
    try header_block.append(alloc, 0x86); // :scheme http
    try appendLiteralWithIndexedName(&header_block, alloc, 0x01, "api.internal"); // :authority
    try appendLiteralWithIndexedName(&header_block, alloc, 0x04, "/pkg.Service/Call"); // :path

    const settings = try buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try buildFrame(alloc, .{
        .length = @intCast(header_block.items.len),
        .frame_type = .headers,
        .flags = Flag.end_headers | Flag.end_stream,
        .stream_id = 1,
    }, header_block.items);
    defer alloc.free(headers);

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(alloc);
    try request_bytes.appendSlice(alloc, http2.client_preface);
    try request_bytes.appendSlice(alloc, settings);
    try request_bytes.appendSlice(alloc, headers);

    const parsed = try parseClientConnectionPreface(alloc, request_bytes.items);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(u32, 1), parsed.request.stream_id);
    try std.testing.expectEqualStrings("POST", parsed.request.method);
    try std.testing.expectEqualStrings("api.internal", parsed.request.authority);
    try std.testing.expectEqualStrings("/pkg.Service/Call", parsed.request.path);
    try std.testing.expect(parsed.request.end_stream);
    try std.testing.expectEqual(@as(usize, request_bytes.items.len), parsed.consumed);
}

test "parseClientConnectionPreface parses HEADERS plus CONTINUATION" {
    const alloc = std.testing.allocator;

    const first_fragment = [_]u8{ 0x82, 0x86 };
    var second_fragment: std.ArrayList(u8) = .empty;
    defer second_fragment.deinit(alloc);
    try appendLiteralWithIndexedName(&second_fragment, alloc, 0x01, "api.internal");
    try appendLiteralWithIndexedName(&second_fragment, alloc, 0x04, "/v1/users");

    const settings = try buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try buildFrame(alloc, .{
        .length = first_fragment.len,
        .frame_type = .headers,
        .flags = 0,
        .stream_id = 3,
    }, &first_fragment);
    defer alloc.free(headers);

    const continuation = try buildFrame(alloc, .{
        .length = @intCast(second_fragment.items.len),
        .frame_type = .continuation,
        .flags = Flag.end_headers,
        .stream_id = 3,
    }, second_fragment.items);
    defer alloc.free(continuation);

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(alloc);
    try request_bytes.appendSlice(alloc, http2.client_preface);
    try request_bytes.appendSlice(alloc, settings);
    try request_bytes.appendSlice(alloc, headers);
    try request_bytes.appendSlice(alloc, continuation);

    const parsed = try parseClientConnectionPreface(alloc, request_bytes.items);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(u32, 3), parsed.request.stream_id);
    try std.testing.expectEqualStrings("GET", parsed.request.method);
    try std.testing.expectEqualStrings("api.internal", parsed.request.authority);
    try std.testing.expectEqualStrings("/v1/users", parsed.request.path);
    try std.testing.expect(!parsed.request.end_stream);
}

test "parseClientConnectionPreface rejects missing preface" {
    try std.testing.expectError(error.MissingClientPreface, parseClientConnectionPreface(std.testing.allocator, "GET / HTTP/1.1\r\n"));
}

test "parseClientConnectionPreface rejects header block without authority" {
    const alloc = std.testing.allocator;

    const settings = try buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const header_block = [_]u8{ 0x82, 0x84 };
    const headers = try buildFrame(alloc, .{
        .length = header_block.len,
        .frame_type = .headers,
        .flags = Flag.end_headers,
        .stream_id = 1,
    }, &header_block);
    defer alloc.free(headers);

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(alloc);
    try request_bytes.appendSlice(alloc, http2.client_preface);
    try request_bytes.appendSlice(alloc, settings);
    try request_bytes.appendSlice(alloc, headers);

    try std.testing.expectError(error.MissingAuthority, parseClientConnectionPreface(alloc, request_bytes.items));
}
