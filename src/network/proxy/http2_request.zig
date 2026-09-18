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
    DuplicatePseudoheader,
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

pub const StreamRewriteState = struct {
    saw_client_preface: bool = false,
    decoder: hpack.Decoder = .{},

    pub fn deinit(self: *StreamRewriteState, alloc: std.mem.Allocator) void {
        self.decoder.deinit(alloc);
        self.* = .{};
    }
};

pub const StreamRewriteResult = struct {
    bytes: []u8,
    consumed: usize,

    pub fn deinit(self: StreamRewriteResult, alloc: std.mem.Allocator) void {
        alloc.free(self.bytes);
    }
};

pub const RewriteOptions = struct {
    outbound_authority: ?[]const u8 = null,
    outbound_path: ?[]const u8 = null,
    forwarded_proto: ?[]const u8 = null,
    stream_id: ?u32 = null,
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

    while (pos + http2.frame_header_len <= buf.len) {
        const frame = http2.parseFrameHeader(buf[pos .. pos + http2.frame_header_len]).?;
        if (frame.frame_type == .headers) break;
        pos += http2.frame_header_len;
        if (pos + frame.length > buf.len) return error.BufferTooShort;
        if (frame.frame_type != .settings and frame.frame_type != .window_update and frame.frame_type != .ping) {
            return error.InvalidFrameSequence;
        }
        pos += frame.length;
    }

    const parsed = try parseRequestHeaderSequence(alloc, buf, pos);
    return .{
        .request = parsed.request,
        .headers = parsed.headers,
        .consumed = pos + parsed.consumed,
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

    var decoder: hpack.Decoder = .{};
    defer decoder.deinit(alloc);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.appendSlice(alloc, http2.client_preface);
    var pos: usize = http2.client_preface.len;
    var first_headers = true;
    while (pos + http2.frame_header_len <= buf.len) {
        const frame = http2.parseFrameHeader(buf[pos..]).?;
        if (frame.frame_type == .headers) {
            // buffered requests can include trailers whose indices were added
            // by the initial headers. translate every block in the same context.
            var sequence = try decodeHeaderSequence(alloc, &decoder, buf, pos);
            defer sequence.deinit(alloc);
            try appendForwardedHeaders(&out, alloc, sequence.headers.items, frame.flags & Flag.end_stream != 0, .{
                .outbound_authority = if (first_headers) outbound_authority else null,
                .outbound_path = if (first_headers) outbound_path else null,
                .forwarded_proto = if (first_headers) forwarded_proto else null,
                .stream_id = frame.stream_id,
            });
            pos += sequence.consumed;
            first_headers = false;
        } else {
            if (first_headers and frame.frame_type != .settings and frame.frame_type != .window_update and frame.frame_type != .ping) return error.InvalidFrameSequence;
            const length = http2.frame_header_len + frame.length;
            if (length > buf.len - pos) return error.BufferTooShort;
            try out.appendSlice(alloc, buf[pos..][0..length]);
            pos += length;
        }
    }
    if (first_headers) return error.MissingHeaders;
    try out.appendSlice(alloc, buf[pos..]);
    return out.toOwnedSlice(alloc);
}

pub const HeaderSequence = struct {
    frame: http2.FrameHeader,
    headers: std.ArrayList(hpack.HeaderField),
    consumed: usize,

    pub fn deinit(self: *HeaderSequence, alloc: std.mem.Allocator) void {
        for (self.headers.items) |header| header.deinit(alloc);
        self.headers.deinit(alloc);
    }
};

// consume a complete block once. callers must wait for every continuation
// before calling, because decoding advances the connection's dynamic table.
pub fn decodeHeaderSequence(
    alloc: std.mem.Allocator,
    decoder: *hpack.Decoder,
    buf: []const u8,
    start: usize,
) ParseError!HeaderSequence {
    var pos = start;
    if (pos + http2.frame_header_len > buf.len) return error.BufferTooShort;
    const first = http2.parseFrameHeader(buf[pos .. pos + http2.frame_header_len]).?;
    if (first.frame_type != .headers or first.stream_id == 0) return error.InvalidHeadersFrame;
    pos += http2.frame_header_len;
    if (pos + first.length > buf.len) return error.BufferTooShort;

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);
    try header_block.appendSlice(alloc, try headerBlockFragment(buf[pos .. pos + first.length], first.flags));
    pos += first.length;

    while ((first.flags & Flag.end_headers) == 0) {
        if (pos + http2.frame_header_len > buf.len) return error.BufferTooShort;
        const continuation = http2.parseFrameHeader(buf[pos .. pos + http2.frame_header_len]).?;
        if (continuation.frame_type != .continuation or continuation.stream_id != first.stream_id)
            return error.InvalidFrameSequence;
        pos += http2.frame_header_len;
        if (pos + continuation.length > buf.len) return error.BufferTooShort;
        try header_block.appendSlice(alloc, buf[pos .. pos + continuation.length]);
        pos += continuation.length;
        if ((continuation.flags & Flag.end_headers) != 0) break;
    }

    return .{
        .frame = first,
        .headers = try decoder.decode(alloc, header_block.items),
        .consumed = pos - start,
    };
}

pub fn parseRequestHeaderSequence(
    alloc: std.mem.Allocator,
    buf: []const u8,
    start: usize,
) ParseError!ParseResult {
    var decoder: hpack.Decoder = .{};
    defer decoder.deinit(alloc);
    return parseRequestHeaderSequenceWithDecoder(alloc, &decoder, buf, start);
}

pub fn parseRequestHeaderSequenceWithDecoder(
    alloc: std.mem.Allocator,
    decoder: *hpack.Decoder,
    buf: []const u8,
    start: usize,
) ParseError!ParseResult {
    const sequence = try decodeHeaderSequence(alloc, decoder, buf, start);
    var headers = sequence.headers;
    errdefer {
        for (headers.items) |header| header.deinit(alloc);
        headers.deinit(alloc);
    }
    var method: ?[]u8 = null;
    var authority: ?[]u8 = null;
    var path: ?[]u8 = null;
    var saw_scheme = false;
    // each allocation is owned as soon as it succeeds, including while later
    // pseudoheaders are validated or duplicated into the request head.
    errdefer {
        if (method) |value| alloc.free(value);
        if (authority) |value| alloc.free(value);
        if (path) |value| alloc.free(value);
    }
    for (headers.items) |header| {
        if (std.mem.eql(u8, header.name, ":method")) {
            if (method != null) return error.DuplicatePseudoheader;
            method = try alloc.dupe(u8, header.value);
        } else if (std.mem.eql(u8, header.name, ":authority")) {
            if (authority != null) return error.DuplicatePseudoheader;
            authority = try alloc.dupe(u8, header.value);
        } else if (std.mem.eql(u8, header.name, ":path")) {
            if (path != null) return error.DuplicatePseudoheader;
            path = try alloc.dupe(u8, header.value);
        } else if (std.mem.eql(u8, header.name, ":scheme")) {
            if (saw_scheme) return error.DuplicatePseudoheader;
            saw_scheme = true;
        }
    }

    return .{
        .request = .{
            .stream_id = sequence.frame.stream_id,
            .method = method orelse return error.MissingMethod,
            .authority = authority orelse return error.MissingAuthority,
            .path = path orelse return error.MissingPath,
            .end_stream = (sequence.frame.flags & Flag.end_stream) != 0,
        },
        .headers = try headers.toOwnedSlice(alloc),
        .consumed = sequence.consumed,
    };
}

pub fn encodeForwardedHeaders(
    alloc: std.mem.Allocator,
    headers: []const hpack.HeaderField,
    end_stream: bool,
    options: RewriteOptions,
) ![]u8 {
    var outgoing: std.ArrayList(hpack.HeaderField) = .empty;
    defer outgoing.deinit(alloc);
    var saw_forwarded_proto = false;
    for (headers) |header| {
        var value: []const u8 = header.value;
        if (options.outbound_authority != null and std.mem.eql(u8, header.name, ":authority")) {
            value = options.outbound_authority.?;
        } else if (options.outbound_path != null and std.mem.eql(u8, header.name, ":path")) {
            value = options.outbound_path.?;
        } else if (options.forwarded_proto != null and std.mem.eql(u8, header.name, "x-forwarded-proto")) {
            value = options.forwarded_proto.?;
            saw_forwarded_proto = true;
        }
        try outgoing.append(alloc, .{ .name = header.name, .value = @constCast(value) });
    }
    if (options.forwarded_proto != null and !saw_forwarded_proto) {
        try outgoing.append(alloc, .{ .name = @constCast("x-forwarded-proto"), .value = @constCast(options.forwarded_proto.?) });
    }
    const block = try hpack.encodeHeaderBlockIndependent(alloc, outgoing.items);
    defer alloc.free(block);
    return http2.buildFrame(alloc, .{
        .length = @intCast(block.len),
        .frame_type = .headers,
        .flags = Flag.end_headers | (if (end_stream) Flag.end_stream else @as(u8, 0)),
        .stream_id = options.stream_id orelse 1,
    }, block);
}

pub fn rewriteRequestHeaderSequence(
    alloc: std.mem.Allocator,
    buf: []const u8,
    start: usize,
    options: RewriteOptions,
) (ParseError || hpack.Error)!StreamRewriteResult {
    var decoder: hpack.Decoder = .{};
    defer decoder.deinit(alloc);
    var sequence = try decodeHeaderSequence(alloc, &decoder, buf, start);
    defer sequence.deinit(alloc);
    var outbound = options;
    outbound.stream_id = options.stream_id orelse sequence.frame.stream_id;
    return .{
        .bytes = try encodeForwardedHeaders(alloc, sequence.headers.items, sequence.frame.flags & Flag.end_stream != 0, outbound),
        .consumed = sequence.consumed,
    };
}

pub fn rewriteClientStreamChunk(
    alloc: std.mem.Allocator,
    buf: []const u8,
    state: *StreamRewriteState,
    forwarded_proto: []const u8,
) (ParseError || hpack.Error)!?StreamRewriteResult {
    var pos: usize = 0;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    if (!state.saw_client_preface) {
        if (!http2.hasClientPrefacePrefix(buf[0..@min(buf.len, http2.client_preface.len)])) {
            return error.MissingClientPreface;
        }
        if (buf.len < http2.client_preface.len) return null;
        try out.appendSlice(alloc, http2.client_preface);
        pos = http2.client_preface.len;
        state.saw_client_preface = true;
    }

    while (pos + http2.frame_header_len <= buf.len) {
        const frame_start = pos;
        const frame = http2.parseFrameHeader(buf[pos .. pos + http2.frame_header_len]).?;
        pos += http2.frame_header_len;
        if (pos + frame.length > buf.len) {
            pos = frame_start;
            break;
        }

        if (frame.frame_type != .headers) {
            pos += frame.length;
            try out.appendSlice(alloc, buf[frame_start..pos]);
            continue;
        }

        var sequence = decodeHeaderSequence(alloc, &state.decoder, buf, frame_start) catch |err| switch (err) {
            error.BufferTooShort => {
                pos = frame_start;
                break;
            },
            else => return err,
        };
        defer sequence.deinit(alloc);
        var initial_headers = false;
        for (sequence.headers.items) |header| {
            if (std.mem.eql(u8, header.name, ":method")) initial_headers = true;
        }
        try appendForwardedHeaders(&out, alloc, sequence.headers.items, frame.flags & Flag.end_stream != 0, .{
            // routing metadata belongs to the initial headers, not trailers.
            .forwarded_proto = if (initial_headers) forwarded_proto else null,
            .stream_id = frame.stream_id,
        });
        pos = frame_start + sequence.consumed;
    }

    if (pos == 0) return null;
    return .{
        .bytes = try out.toOwnedSlice(alloc),
        .consumed = pos,
    };
}

fn appendForwardedHeaders(out: *std.ArrayList(u8), alloc: std.mem.Allocator, headers: []const hpack.HeaderField, end_stream: bool, options: RewriteOptions) !void {
    const rewritten = try encodeForwardedHeaders(alloc, headers, end_stream, options);
    defer alloc.free(rewritten);
    var fragments: @import("http2_flow.zig").Queue = .{};
    defer fragments.deinit(alloc);
    fragments.appendHeaders(alloc, rewritten) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidFrameSequence,
    };
    try out.appendSlice(alloc, fragments.bytes.items);
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
    if (padded_len > payload.len) return error.InvalidHeadersFrame;
    return payload[pos .. payload.len - padded_len];
}

fn appendLiteralWithIndexedName(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, name_index: u8, value: []const u8) !void {
    if (value.len > 127) return error.HeaderTooLong;
    try buf.append(alloc, name_index);
    try buf.append(alloc, @intCast(value.len));
    try buf.appendSlice(alloc, value);
}

test "parseClientConnectionPreface parses initial HEADERS request" {
    const alloc = std.testing.allocator;

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);
    try header_block.append(alloc, 0x83); // :method POST
    try header_block.append(alloc, 0x86); // :scheme http
    try appendLiteralWithIndexedName(&header_block, alloc, 0x01, "api.internal"); // :authority
    try appendLiteralWithIndexedName(&header_block, alloc, 0x04, "/pkg.Service/Call"); // :path

    const settings = try http2.buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try http2.buildFrame(alloc, .{
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

    const settings = try http2.buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try http2.buildFrame(alloc, .{
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

    const settings = try http2.buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try http2.buildFrame(alloc, .{
        .length = first_fragment.len,
        .frame_type = .headers,
        .flags = 0,
        .stream_id = 3,
    }, &first_fragment);
    defer alloc.free(headers);

    const continuation = try http2.buildFrame(alloc, .{
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

    const settings = try http2.buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try http2.buildFrame(alloc, .{
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

    const settings = try http2.buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try http2.buildFrame(alloc, .{
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

test "rewriteClientStreamChunk injects forwarded proto on later streams" {
    const alloc = std.testing.allocator;

    const settings = try http2.buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    var stream1_block: std.ArrayList(u8) = .empty;
    defer stream1_block.deinit(alloc);
    try stream1_block.append(alloc, 0x83);
    try stream1_block.append(alloc, 0x86);
    try appendLiteralWithIndexedName(&stream1_block, alloc, 0x01, "svc.internal");
    try appendLiteralWithIndexedName(&stream1_block, alloc, 0x04, "/pkg.Service/Call");

    const stream1_headers = try http2.buildFrame(alloc, .{
        .length = @intCast(stream1_block.items.len),
        .frame_type = .headers,
        .flags = Flag.end_headers,
        .stream_id = 1,
    }, stream1_block.items);
    defer alloc.free(stream1_headers);

    var stream3_block: std.ArrayList(u8) = .empty;
    defer stream3_block.deinit(alloc);
    try stream3_block.append(alloc, 0x83);
    try stream3_block.append(alloc, 0x86);
    try appendLiteralWithIndexedName(&stream3_block, alloc, 0x01, "svc.internal");
    try appendLiteralWithIndexedName(&stream3_block, alloc, 0x04, "/pkg.Service/Stream");

    const stream3_headers = try http2.buildFrame(alloc, .{
        .length = @intCast(stream3_block.items.len),
        .frame_type = .headers,
        .flags = Flag.end_headers,
        .stream_id = 3,
    }, stream3_block.items);
    defer alloc.free(stream3_headers);

    var initial_chunk: std.ArrayList(u8) = .empty;
    defer initial_chunk.deinit(alloc);
    try initial_chunk.appendSlice(alloc, http2.client_preface);
    try initial_chunk.appendSlice(alloc, settings);
    try initial_chunk.appendSlice(alloc, stream1_headers);

    var state = StreamRewriteState{};
    defer state.deinit(alloc);
    const initial = (try rewriteClientStreamChunk(alloc, initial_chunk.items, &state, "https")).?;
    defer initial.deinit(alloc);
    try std.testing.expectEqual(initial_chunk.items.len, initial.consumed);

    const later = (try rewriteClientStreamChunk(alloc, stream3_headers, &state, "https")).?;
    defer later.deinit(alloc);
    try std.testing.expectEqual(stream3_headers.len, later.consumed);

    const header = http2.parseFrameHeader(later.bytes[0..http2.frame_header_len]).?;
    try std.testing.expectEqual(http2.FrameType.headers, header.frame_type);
    var decoded = try hpack.decodeHeaderBlock(alloc, later.bytes[http2.frame_header_len .. http2.frame_header_len + header.length]);
    defer {
        for (decoded.items) |field| field.deinit(alloc);
        decoded.deinit(alloc);
    }

    var found = false;
    for (decoded.items) |field| {
        if (std.mem.eql(u8, field.name, "x-forwarded-proto")) {
            try std.testing.expectEqualStrings("https", field.value);
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

    const settings = try http2.buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const header_block = [_]u8{ 0x82, 0x84 };
    const headers = try http2.buildFrame(alloc, .{
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

fn pseudoheaderFixture(alloc: std.mem.Allocator, duplicate: ?[]const u8) ![]u8 {
    var fields: std.ArrayList(hpack.HeaderField) = .empty;
    defer fields.deinit(alloc);
    for ([_]hpack.HeaderField{
        .{ .name = @constCast(":method"), .value = @constCast("GET") },
        .{ .name = @constCast(":scheme"), .value = @constCast("http") },
        .{ .name = @constCast(":authority"), .value = @constCast("example.test") },
        .{ .name = @constCast(":path"), .value = @constCast("/") },
    }) |field| {
        try fields.append(alloc, field);
        if (duplicate) |name| if (std.mem.eql(u8, name, field.name)) try fields.append(alloc, field);
    }
    const block = try hpack.encodeHeaderBlockLiteral(alloc, fields.items);
    defer alloc.free(block);
    return http2.buildFrame(alloc, .{
        .length = @intCast(block.len),
        .frame_type = .headers,
        .flags = Flag.end_headers | Flag.end_stream,
        .stream_id = 1,
    }, block);
}

test "http2 request rejects duplicate pseudoheaders without losing earlier allocations" {
    for ([_][]const u8{ ":method", ":scheme", ":authority", ":path" }) |name| {
        const frame = try pseudoheaderFixture(std.testing.allocator, name);
        defer std.testing.allocator.free(frame);
        try std.testing.expectError(error.DuplicatePseudoheader, parseRequestHeaderSequence(std.testing.allocator, frame, 0));
    }
}

test "http2 request releases partial pseudoheader allocations on every allocation failure" {
    const frame = try pseudoheaderFixture(std.testing.allocator, null);
    defer std.testing.allocator.free(frame);
    const Probe = struct {
        fn parse(alloc: std.mem.Allocator, bytes: []const u8) !void {
            const result = try parseRequestHeaderSequence(alloc, bytes, 0);
            defer result.deinit(alloc);
            try std.testing.expectEqualStrings("example.test", result.request.authority);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Probe.parse, .{frame});
}

test "http2 compression reuses request indices without decoding again for rewrites" {
    const alloc = std.testing.allocator;
    var decoder: hpack.Decoder = .{};
    defer decoder.deinit(alloc);
    const first_block = [_]u8{ 0x82, 0x86, 0x84, 0x41, 3, 'a', 'p', 'i' };
    const second_block = [_]u8{ 0x82, 0x86, 0x84, 0xbe };
    for ([_][]const u8{ &first_block, &second_block }, 0..) |block, index| {
        const frame = try http2.buildFrame(alloc, .{ .length = @intCast(block.len), .frame_type = .headers, .flags = 5, .stream_id = @intCast(1 + 2 * index) }, block);
        defer alloc.free(frame);
        const parsed = try parseRequestHeaderSequenceWithDecoder(alloc, &decoder, frame, 0);
        defer parsed.deinit(alloc);
        try std.testing.expectEqualStrings("api", parsed.request.authority);
        // retries and mirrors use the decoded fields, without inserting them
        // into the inbound table again or changing the original route fields.
        for ([_][]const u8{ "primary", "mirror" }) |target| {
            const rewritten = try encodeForwardedHeaders(alloc, parsed.headers, true, .{ .outbound_authority = target });
            defer alloc.free(rewritten);
            const forwarded = try parseRequestHeaderSequence(alloc, rewritten, 0);
            defer forwarded.deinit(alloc);
            try std.testing.expectEqualStrings(target, forwarded.request.authority);
            try std.testing.expectEqualStrings("api", parsed.request.authority);
        }
    }
}

test "http2 compression incomplete continuation leaves decoder unchanged" {
    const alloc = std.testing.allocator;
    var decoder: hpack.Decoder = .{};
    defer decoder.deinit(alloc);
    const block = [_]u8{ 0x40, 1, 'x', 1, 'a' };
    const partial = try http2.buildFrame(alloc, .{ .length = block.len, .frame_type = .headers, .flags = 0, .stream_id = 1 }, &block);
    defer alloc.free(partial);
    try std.testing.expectError(error.BufferTooShort, decodeHeaderSequence(alloc, &decoder, partial, 0));
    try std.testing.expectError(error.InvalidIndex, decoder.decode(alloc, &.{0xbe}));
}

test "http2 compression buffered rewrite retains indexed request trailers" {
    const alloc = std.testing.allocator;
    const block = [_]u8{ 0x82, 0x86, 0x84, 0x41, 3, 'a', 'p', 'i', 0x40, 1, 'x', 1, 'a' };
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(alloc);
    try input.appendSlice(alloc, http2.client_preface);
    const head = try http2.buildFrame(alloc, .{ .length = block.len, .frame_type = .headers, .flags = 4, .stream_id = 1 }, &block);
    defer alloc.free(head);
    const data = try http2.buildFrame(alloc, .{ .length = 4, .frame_type = .data, .flags = 0, .stream_id = 1 }, "body");
    defer alloc.free(data);
    const trailer = try http2.buildFrame(alloc, .{ .length = 1, .frame_type = .headers, .flags = 5, .stream_id = 1 }, &.{0xbe});
    defer alloc.free(trailer);
    try input.appendSlice(alloc, head);
    try input.appendSlice(alloc, data);
    try input.appendSlice(alloc, trailer);
    const rewritten = try rewriteClientConnectionPreface(alloc, input.items, "backend", null, null);
    defer alloc.free(rewritten);
    var decoder: hpack.Decoder = .{};
    defer decoder.deinit(alloc);
    const parsed = try parseRequestHeaderSequenceWithDecoder(alloc, &decoder, rewritten, http2.client_preface.len);
    defer parsed.deinit(alloc);
    try std.testing.expectEqualStrings("backend", parsed.request.authority);
    const body_offset = http2.client_preface.len + parsed.consumed;
    try std.testing.expectEqualSlices(u8, data, rewritten[body_offset..][0..data.len]);
    var trailers = try decodeHeaderSequence(alloc, &decoder, rewritten, body_offset + data.len);
    defer trailers.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), trailers.headers.items.len);
    try std.testing.expectEqualStrings("x", trailers.headers.items[0].name);
    try std.testing.expectEqualStrings("a", trailers.headers.items[0].value);
    try std.testing.expectEqual(@as(u8, 5), trailers.frame.flags);
}

test "http2 compression streaming rewrite retains indices across streams and trailers" {
    const alloc = std.testing.allocator;
    var state: StreamRewriteState = .{};
    defer state.deinit(alloc);
    const first_block = [_]u8{ 0x82, 0x86, 0x84, 0x41, 3, 'a', 'p', 'i', 0x40, 1, 'x', 1, 'a' };
    const first_frame = try http2.buildFrame(alloc, .{ .length = first_block.len, .frame_type = .headers, .flags = 4, .stream_id = 1 }, &first_block);
    defer alloc.free(first_frame);
    const first_input = try std.mem.concat(alloc, u8, &.{ http2.client_preface, first_frame });
    defer alloc.free(first_input);
    const first = (try rewriteClientStreamChunk(alloc, first_input, &state, "http")).?;
    defer first.deinit(alloc);
    const parsed_first = try parseClientConnectionPreface(alloc, first.bytes);
    defer parsed_first.deinit(alloc);
    try std.testing.expectEqualStrings("api", parsed_first.request.authority);

    // the new stream references the first stream's authority, then inserts z.
    const second_block = [_]u8{ 0x82, 0x86, 0x84, 0xbf, 0x40, 1, 'z', 1, 'b' };
    const second_frame = try http2.buildFrame(alloc, .{ .length = second_block.len, .frame_type = .headers, .flags = 0, .stream_id = 3 }, &second_block);
    defer alloc.free(second_frame);
    // an incomplete block must not insert z until the continuation arrives.
    try std.testing.expect((try rewriteClientStreamChunk(alloc, second_frame, &state, "http")) == null);
    const continuation = try http2.buildFrame(alloc, .{ .length = 1, .frame_type = .continuation, .flags = 4, .stream_id = 3 }, &.{0xbf});
    defer alloc.free(continuation);
    const second_input = try std.mem.concat(alloc, u8, &.{ second_frame, continuation });
    defer alloc.free(second_input);
    const second = (try rewriteClientStreamChunk(alloc, second_input, &state, "http")).?;
    defer second.deinit(alloc);
    const parsed_second = try parseRequestHeaderSequence(alloc, second.bytes, 0);
    defer parsed_second.deinit(alloc);
    try std.testing.expectEqualStrings("api", parsed_second.request.authority);
    try std.testing.expectEqual(@as(u32, 3), parsed_second.request.stream_id);
    var saw_forwarded = false;
    for (parsed_second.headers) |header| {
        if (std.mem.eql(u8, header.name, "x")) try std.testing.expectEqualStrings("a", header.value);
        if (std.mem.eql(u8, header.name, "x-forwarded-proto")) {
            try std.testing.expectEqualStrings("http", header.value);
            saw_forwarded = true;
        }
    }
    try std.testing.expect(saw_forwarded);

    // the original stream's trailer uses the connection's updated index 63.
    const trailer_frame = try http2.buildFrame(alloc, .{ .length = 1, .frame_type = .headers, .flags = 5, .stream_id = 1 }, &.{0xbf});
    defer alloc.free(trailer_frame);
    const trailer = (try rewriteClientStreamChunk(alloc, trailer_frame, &state, "http")).?;
    defer trailer.deinit(alloc);
    var output_decoder: hpack.Decoder = .{};
    defer output_decoder.deinit(alloc);
    var fields = try decodeHeaderSequence(alloc, &output_decoder, trailer.bytes, 0);
    defer fields.deinit(alloc);
    try std.testing.expectEqual(@as(u32, 1), fields.frame.stream_id);
    try std.testing.expectEqual(@as(u8, 5), fields.frame.flags);
    try std.testing.expectEqual(@as(usize, 1), fields.headers.items.len);
    try std.testing.expectEqualStrings("x", fields.headers.items[0].name);
    try std.testing.expectEqualStrings("a", fields.headers.items[0].value);
}
