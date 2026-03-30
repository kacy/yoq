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
    headers: []const hpack.HeaderField,
    consumed: usize,

    pub fn deinit(self: ParseResult, alloc: std.mem.Allocator) void {
        self.request.deinit(alloc);
        for (self.headers) |header| header.deinit(alloc);
        alloc.free(self.headers);
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
    errdefer {
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

    const method_value = method orelse return error.MissingMethod;
    const authority_value = authority orelse return error.MissingAuthority;
    const path_value = path orelse return error.MissingPath;
    const owned_headers = try headers.toOwnedSlice(alloc);

    return .{
        .request = .{
            .stream_id = request_stream_id.?,
            .method = method_value,
            .authority = authority_value,
            .path = path_value,
            .end_stream = request_end_stream,
        },
        .headers = owned_headers,
        .consumed = pos,
    };
}

pub fn rewriteClientConnectionPreface(
    alloc: std.mem.Allocator,
    buf: []const u8,
    outbound_authority: ?[]const u8,
    outbound_path: ?[]const u8,
    forwarded_proto: ?[]const u8,
) (ParseError || hpack.Error)![]u8 {
    if (outbound_authority == null and outbound_path == null and forwarded_proto == null) return alloc.dupe(u8, buf);
    if (buf.len < http2.client_preface.len or !std.mem.eql(u8, buf[0..http2.client_preface.len], http2.client_preface)) {
        return error.MissingClientPreface;
    }

    var pos: usize = http2.client_preface.len;
    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.appendSlice(alloc, http2.client_preface);

    var request_stream_id: ?u32 = null;
    var request_flags: u8 = 0;

    while (pos + http2.frame_header_len <= buf.len) {
        const frame_start = pos;
        const frame = http2.parseFrameHeader(buf[pos .. pos + http2.frame_header_len]).?;
        pos += http2.frame_header_len;

        if (pos + frame.length > buf.len) return error.BufferTooShort;
        const payload = buf[pos .. pos + frame.length];
        pos += frame.length;
        const frame_end = pos;

        switch (frame.frame_type) {
            .settings, .window_update, .ping => {
                if (request_stream_id == null) try out.appendSlice(alloc, buf[frame_start..frame_end]);
            },
            .headers => {
                if (frame.stream_id == 0) return error.InvalidHeadersFrame;
                if (request_stream_id != null) return error.InvalidFrameSequence;
                request_stream_id = frame.stream_id;
                request_flags = frame.flags;
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
                if (request_stream_id == null) {
                    try out.appendSlice(alloc, buf[frame_start..frame_end]);
                } else {
                    return error.InvalidFrameSequence;
                }
            },
        }
    }

    if (request_stream_id == null or header_block.items.len == 0) return error.MissingHeaders;

    var headers = try hpack.decodeHeaderBlock(alloc, header_block.items);
    defer {
        for (headers.items) |header| header.deinit(alloc);
        headers.deinit(alloc);
    }

    var saw_forwarded_proto = false;
    for (headers.items) |*header| {
        if (outbound_authority != null and std.mem.eql(u8, header.name, ":authority")) {
            alloc.free(header.value);
            header.value = try alloc.dupe(u8, outbound_authority.?);
        } else if (outbound_path != null and std.mem.eql(u8, header.name, ":path")) {
            alloc.free(header.value);
            header.value = try alloc.dupe(u8, outbound_path.?);
        } else if (forwarded_proto != null and std.mem.eql(u8, header.name, "x-forwarded-proto")) {
            alloc.free(header.value);
            header.value = try alloc.dupe(u8, forwarded_proto.?);
            saw_forwarded_proto = true;
        }
    }

    if (forwarded_proto != null and !saw_forwarded_proto) {
        try headers.append(alloc, .{
            .name = try alloc.dupe(u8, "x-forwarded-proto"),
            .value = try alloc.dupe(u8, forwarded_proto.?),
        });
    }

    const rewritten_block = try hpack.encodeHeaderBlockLiteral(alloc, headers.items);
    defer alloc.free(rewritten_block);

    const rewritten_headers = try buildFrame(alloc, .{
        .length = @intCast(rewritten_block.len),
        .frame_type = .headers,
        .flags = (request_flags & Flag.end_stream) | Flag.end_headers,
        .stream_id = request_stream_id.?,
    }, rewritten_block);
    defer alloc.free(rewritten_headers);

    try out.appendSlice(alloc, rewritten_headers);
    try out.appendSlice(alloc, buf[pos..]);
    return out.toOwnedSlice(alloc);
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

test "parseClientConnectionPreface parses huffman-encoded authority" {
    const alloc = std.testing.allocator;

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);
    try header_block.append(alloc, 0x83); // :method POST
    try header_block.append(alloc, 0x86); // :scheme http
    try header_block.append(alloc, 0x01); // literal :authority without indexing
    try header_block.appendSlice(alloc, &[_]u8{
        0x8c,
        0xf1,
        0xe3,
        0xc2,
        0xe5,
        0xf2,
        0x3a,
        0x6b,
        0xa0,
        0xab,
        0x90,
        0xf4,
        0xff,
    });
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

    try std.testing.expectEqualStrings("POST", parsed.request.method);
    try std.testing.expectEqualStrings("www.example.com", parsed.request.authority);
    try std.testing.expectEqualStrings("/pkg.Service/Call", parsed.request.path);
    try std.testing.expect(parsed.request.end_stream);
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

test "rewriteClientConnectionPreface rewrites authority and path" {
    const alloc = std.testing.allocator;

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);
    try header_block.append(alloc, 0x83);
    try header_block.append(alloc, 0x86);
    try appendLiteralWithIndexedName(&header_block, alloc, 0x01, "api.internal");
    try appendLiteralWithIndexedName(&header_block, alloc, 0x04, "/api/users?id=7");

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

    const rewritten = try rewriteClientConnectionPreface(alloc, request_bytes.items, "api", "/users?id=7", null);
    defer alloc.free(rewritten);

    const parsed = try parseClientConnectionPreface(alloc, rewritten);
    defer parsed.deinit(alloc);

    try std.testing.expectEqualStrings("api", parsed.request.authority);
    try std.testing.expectEqualStrings("/users?id=7", parsed.request.path);
}

test "rewriteClientConnectionPreface injects forwarded proto header" {
    const alloc = std.testing.allocator;

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);
    try header_block.append(alloc, 0x83);
    try header_block.append(alloc, 0x86);
    try appendLiteralWithIndexedName(&header_block, alloc, 0x01, "api.internal");
    try appendLiteralWithIndexedName(&header_block, alloc, 0x04, "/pkg.Service/Call");

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

    const rewritten = try rewriteClientConnectionPreface(alloc, request_bytes.items, null, null, "https");
    defer alloc.free(rewritten);

    const parsed = try parseClientConnectionPreface(alloc, rewritten);
    defer parsed.deinit(alloc);

    var found = false;
    for (parsed.headers) |header| {
        if (std.mem.eql(u8, header.name, "x-forwarded-proto")) {
            try std.testing.expectEqualStrings("https", header.value);
            found = true;
        }
    }
    try std.testing.expect(found);
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
