const std = @import("std");
const posix = std.posix;
const hpack = @import("../../network/proxy/hpack.zig");
const http2 = @import("../../network/proxy/http2.zig");

const grpc_health_path = "/grpc.health.v1.Health/Check";
const grpc_stream_id: u32 = 1;
const max_http2_frame_payload: usize = 16 * 1024;
const max_header_block_len: usize = 8 * 1024;
const max_grpc_message_len: usize = 8 * 1024;

pub fn runCheck(container_ip: [4]u8, config: anytype) bool {
    return switch (config.check_type) {
        .http => |http| runHttpCheck(container_ip, http.port, http.path, config.timeout),
        .tcp => |tcp| runTcpCheck(container_ip, tcp.port, config.timeout),
        .grpc => |grpc| runGrpcCheck(container_ip, grpc.port, grpc.service, config.timeout),
        .exec => false,
    };
}

pub fn runHttpCheck(container_ip: [4]u8, port: u16, path: []const u8, timeout: u32) bool {
    const sock = tcpConnect(container_ip, port, timeout) orelse return false;
    defer posix.close(sock);

    var request_buf: [512]u8 = undefined;
    const request = std.fmt.bufPrint(
        &request_buf,
        "GET {s} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        .{path},
    ) catch return false;

    _ = posix.write(sock, request) catch return false;

    var response_buf: [256]u8 = undefined;
    const bytes_read = posix.read(sock, &response_buf) catch return false;
    if (bytes_read < 12) return false;

    return isHttp2xx(response_buf[0..bytes_read]);
}

pub fn isHttp2xx(response: []const u8) bool {
    if (response.len < 12) return false;
    if (!std.mem.startsWith(u8, response, "HTTP/1.")) return false;
    return response[9] == '2';
}

pub fn runTcpCheck(container_ip: [4]u8, port: u16, timeout: u32) bool {
    const sock = tcpConnect(container_ip, port, timeout) orelse return false;
    posix.close(sock);
    return true;
}

pub fn runGrpcCheck(container_ip: [4]u8, port: u16, service: ?[]const u8, timeout: u32) bool {
    const sock = tcpConnect(container_ip, port, timeout) orelse return false;
    defer posix.close(sock);

    writeGrpcHealthRequest(sock, service orelse "") catch return false;
    return readGrpcHealthResponse(sock);
}

pub fn isHttp2SettingsFrame(frame_header: []const u8) bool {
    if (frame_header.len < 9) return false;
    if (frame_header[3] != 0x4) return false;
    const stream_id = std.mem.readInt(u32, frame_header[5..9], .big) & 0x7fff_ffff;
    return stream_id == 0;
}

fn writeGrpcHealthRequest(sock: posix.socket_t, service: []const u8) !void {
    try writeAll(sock, http2.client_preface);
    try writeFrame(sock, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");

    var header_storage: [1024]u8 = undefined;
    var header_alloc = std.heap.FixedBufferAllocator.init(&header_storage);
    const alloc = header_alloc.allocator();
    const headers = try buildGrpcRequestHeaders(alloc);
    const header_block = try hpack.encodeHeaderBlockLiteral(alloc, &headers);
    try writeFrame(sock, .{
        .length = @intCast(header_block.len),
        .frame_type = .headers,
        .flags = 0x04,
        .stream_id = grpc_stream_id,
    }, header_block);

    var body_buf: [512]u8 = undefined;
    const body = try buildGrpcHealthRequestBody(service, &body_buf);
    try writeFrame(sock, .{
        .length = @intCast(body.len),
        .frame_type = .data,
        .flags = 0x01,
        .stream_id = grpc_stream_id,
    }, body);
}

fn readGrpcHealthResponse(sock: posix.socket_t) bool {
    var payload_storage: [max_http2_frame_payload]u8 = undefined;
    var header_block_storage: [max_header_block_len]u8 = undefined;
    var grpc_payload_storage: [max_grpc_message_len]u8 = undefined;
    var grpc_payload_len: usize = 0;
    var http_status_ok = false;
    var saw_grpc_status = false;
    var grpc_status_ok = false;
    var stream_ended = false;
    var frames_seen: usize = 0;

    while (!stream_ended and frames_seen < 64) : (frames_seen += 1) {
        const frame = readFrame(sock, &payload_storage) orelse return false;
        switch (frame.header.frame_type) {
            .settings => {
                if (frame.header.stream_id != 0) return false;
                if ((frame.header.flags & 0x01) == 0) {
                    writeSettingsAck(sock) catch {};
                }
            },
            .ping => {
                if (frame.payload.len != 8) return false;
                if ((frame.header.flags & 0x01) == 0) {
                    writePingAck(sock, frame.payload) catch {};
                }
            },
            .headers => {
                if (frame.header.stream_id != grpc_stream_id) return false;
                const header_block = collectHeaderBlock(
                    sock,
                    frame.header,
                    frame.payload,
                    &payload_storage,
                    &header_block_storage,
                ) orelse return false;
                if (!applyGrpcHeaderBlock(header_block.block, &http_status_ok, &saw_grpc_status, &grpc_status_ok)) {
                    return false;
                }
                stream_ended = header_block.end_stream;
            },
            .data => {
                if (frame.header.stream_id != grpc_stream_id) return false;
                const payload = extractDataPayload(frame.header.flags, frame.payload) orelse return false;
                if (grpc_payload_len + payload.len > grpc_payload_storage.len) return false;
                @memcpy(grpc_payload_storage[grpc_payload_len .. grpc_payload_len + payload.len], payload);
                grpc_payload_len += payload.len;
                stream_ended = (frame.header.flags & 0x01) != 0;
            },
            .continuation => return false,
            .rst_stream, .goaway => return false,
            else => {},
        }
    }

    if (!stream_ended) return false;
    if (!http_status_ok or !saw_grpc_status or !grpc_status_ok) return false;
    return parseGrpcHealthResponseMessages(grpc_payload_storage[0..grpc_payload_len]);
}

fn applyGrpcHeaderBlock(
    block: []const u8,
    http_status_ok: *bool,
    saw_grpc_status: *bool,
    grpc_status_ok: *bool,
) bool {
    var decode_storage: [4096]u8 = undefined;
    var decode_alloc = std.heap.FixedBufferAllocator.init(&decode_storage);
    var headers = hpack.decodeHeaderBlock(decode_alloc.allocator(), block) catch return false;
    defer {
        for (headers.items) |header| header.deinit(decode_alloc.allocator());
        headers.deinit(decode_alloc.allocator());
    }

    for (headers.items) |header| {
        if (std.mem.eql(u8, header.name, ":status")) {
            http_status_ok.* = std.mem.eql(u8, header.value, "200");
        } else if (std.mem.eql(u8, header.name, "grpc-status")) {
            saw_grpc_status.* = true;
            grpc_status_ok.* = std.mem.eql(u8, header.value, "0");
        }
    }
    return true;
}

const HeaderBlockResult = struct {
    block: []const u8,
    end_stream: bool,
};

fn collectHeaderBlock(
    sock: posix.socket_t,
    initial_header: http2.FrameHeader,
    initial_payload: []const u8,
    payload_storage: *[max_http2_frame_payload]u8,
    block_storage: *[max_header_block_len]u8,
) ?HeaderBlockResult {
    var block_len: usize = 0;
    const initial_fragment = extractHeaderBlockFragment(initial_header.frame_type, initial_header.flags, initial_payload) orelse
        return null;
    if (initial_fragment.len > block_storage.len) return null;
    @memcpy(block_storage[0..initial_fragment.len], initial_fragment);
    block_len = initial_fragment.len;

    var current = initial_header;
    while ((current.flags & 0x04) == 0) {
        const next = readFrame(sock, payload_storage) orelse return null;
        if (next.header.frame_type != .continuation or next.header.stream_id != initial_header.stream_id) return null;
        const fragment = extractHeaderBlockFragment(next.header.frame_type, next.header.flags, next.payload) orelse
            return null;
        if (block_len + fragment.len > block_storage.len) return null;
        @memcpy(block_storage[block_len .. block_len + fragment.len], fragment);
        block_len += fragment.len;
        current = next.header;
    }

    return .{
        .block = block_storage[0..block_len],
        .end_stream = (initial_header.flags & 0x01) != 0,
    };
}

fn extractHeaderBlockFragment(frame_type: http2.FrameType, flags: u8, payload: []const u8) ?[]const u8 {
    return switch (frame_type) {
        .headers => blk: {
            var pos: usize = 0;
            var padding: usize = 0;
            if ((flags & 0x08) != 0) {
                if (payload.len == 0) return null;
                padding = payload[0];
                pos = 1;
            }
            if ((flags & 0x20) != 0) {
                if (pos + 5 > payload.len) return null;
                pos += 5;
            }
            if (padding > payload.len or payload.len < pos + padding) return null;
            break :blk payload[pos .. payload.len - padding];
        },
        .continuation => payload,
        else => null,
    };
}

fn extractDataPayload(flags: u8, payload: []const u8) ?[]const u8 {
    if ((flags & 0x08) == 0) return payload;
    if (payload.len == 0) return null;
    const padding: usize = payload[0];
    if (padding > payload.len - 1) return null;
    return payload[1 .. payload.len - padding];
}

fn parseGrpcHealthResponseMessages(payload: []const u8) bool {
    var pos: usize = 0;
    while (pos < payload.len) {
        if (payload.len - pos < 5) return false;
        if (payload[pos] != 0) return false;
        const message_len = std.mem.readInt(u32, @ptrCast(payload[pos + 1 .. pos + 5]), .big);
        pos += 5;
        if (payload.len - pos < message_len) return false;
        if (parseGrpcHealthResponseMessage(payload[pos .. pos + message_len])) return true;
        pos += message_len;
    }
    return false;
}

fn parseGrpcHealthResponseMessage(message: []const u8) bool {
    var pos: usize = 0;
    while (pos < message.len) {
        const tag = readVarint(message[pos..]) orelse return false;
        pos += tag.consumed;
        const field_number = tag.value >> 3;
        const wire_type = tag.value & 0x7;
        if (field_number == 1 and wire_type == 0) {
            const status = readVarint(message[pos..]) orelse return false;
            return status.value == 1;
        }
        pos = skipProtoField(message, pos, wire_type) orelse return false;
    }
    return false;
}

fn parseGrpcHealthRequestService(payload: []const u8) ?[]const u8 {
    if (payload.len < 5 or payload[0] != 0) return null;
    const message_len = std.mem.readInt(u32, payload[1..5], .big);
    if (payload.len < 5 + message_len) return null;
    const message = payload[5 .. 5 + message_len];
    var pos: usize = 0;
    while (pos < message.len) {
        const tag = readVarint(message[pos..]) orelse return null;
        pos += tag.consumed;
        const field_number = tag.value >> 3;
        const wire_type = tag.value & 0x7;
        if (field_number == 1 and wire_type == 2) {
            const string_len = readVarint(message[pos..]) orelse return null;
            pos += string_len.consumed;
            if (message.len - pos < string_len.value) return null;
            return message[pos .. pos + string_len.value];
        }
        pos = skipProtoField(message, pos, wire_type) orelse return null;
    }
    return "";
}

const Varint = struct {
    value: usize,
    consumed: usize,
};

fn readVarint(buf: []const u8) ?Varint {
    var value: usize = 0;
    var shift: usize = 0;
    var pos: usize = 0;
    while (pos < buf.len and shift < @bitSizeOf(usize)) : (pos += 1) {
        const byte = buf[pos];
        value |= @as(usize, byte & 0x7f) << @intCast(shift);
        if ((byte & 0x80) == 0) {
            return .{ .value = value, .consumed = pos + 1 };
        }
        shift += 7;
    }
    return null;
}

fn skipProtoField(message: []const u8, pos: usize, wire_type: usize) ?usize {
    return switch (wire_type) {
        0 => blk: {
            const value = readVarint(message[pos..]) orelse return null;
            break :blk pos + value.consumed;
        },
        1 => if (message.len - pos >= 8) pos + 8 else null,
        2 => blk: {
            const len = readVarint(message[pos..]) orelse return null;
            const start = pos + len.consumed;
            if (message.len - start < len.value) return null;
            break :blk start + len.value;
        },
        5 => if (message.len - pos >= 4) pos + 4 else null,
        else => null,
    };
}

fn buildGrpcRequestHeaders(alloc: std.mem.Allocator) ![6]hpack.HeaderField {
    return .{
        .{ .name = try alloc.dupe(u8, ":method"), .value = try alloc.dupe(u8, "POST") },
        .{ .name = try alloc.dupe(u8, ":scheme"), .value = try alloc.dupe(u8, "http") },
        .{ .name = try alloc.dupe(u8, ":path"), .value = try alloc.dupe(u8, grpc_health_path) },
        .{ .name = try alloc.dupe(u8, ":authority"), .value = try alloc.dupe(u8, "localhost") },
        .{ .name = try alloc.dupe(u8, "content-type"), .value = try alloc.dupe(u8, "application/grpc") },
        .{ .name = try alloc.dupe(u8, "te"), .value = try alloc.dupe(u8, "trailers") },
    };
}

fn buildGrpcHealthRequestBody(service: []const u8, buf: []u8) ![]const u8 {
    if (buf.len < 6 + service.len) return error.BufferTooShort;
    buf[5] = 0x0a;
    var proto_len: usize = 1;
    proto_len += try writeVarint(buf[6..], service.len);
    if (buf.len < 5 + proto_len + service.len) return error.BufferTooShort;
    @memcpy(buf[5 + proto_len .. 5 + proto_len + service.len], service);
    proto_len += service.len;
    if (buf.len < 5 + proto_len) return error.BufferTooShort;
    buf[0] = 0;
    std.mem.writeInt(u32, buf[1..5], @intCast(proto_len), .big);
    return buf[0 .. 5 + proto_len];
}

fn writeVarint(buf: []u8, value: usize) !usize {
    var remaining = value;
    var pos: usize = 0;
    while (true) {
        if (pos >= buf.len) return error.BufferTooShort;
        var byte: u8 = @intCast(remaining & 0x7f);
        remaining >>= 7;
        if (remaining != 0) byte |= 0x80;
        buf[pos] = byte;
        pos += 1;
        if (remaining == 0) return pos;
    }
}

fn writeFrame(sock: posix.socket_t, header: http2.FrameHeader, payload: []const u8) !void {
    var header_buf: [http2.frame_header_len]u8 = undefined;
    try http2.writeFrameHeader(&header_buf, header);
    try writeAll(sock, &header_buf);
    if (payload.len > 0) try writeAll(sock, payload);
}

const ReadFrame = struct {
    header: http2.FrameHeader,
    payload: []u8,
};

fn readFrame(sock: posix.socket_t, payload_storage: []u8) ?ReadFrame {
    var header_buf: [http2.frame_header_len]u8 = undefined;
    readExact(sock, &header_buf) catch return null;
    const header = http2.parseFrameHeader(&header_buf) orelse return null;
    if (header.length > payload_storage.len) return null;
    const payload = payload_storage[0..header.length];
    readExact(sock, payload) catch return null;
    return .{ .header = header, .payload = payload };
}

fn writeSettingsAck(sock: posix.socket_t) !void {
    try writeFrame(sock, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0x01,
        .stream_id = 0,
    }, "");
}

fn writePingAck(sock: posix.socket_t, opaque_data: []const u8) !void {
    try writeFrame(sock, .{
        .length = @intCast(opaque_data.len),
        .frame_type = .ping,
        .flags = 0x01,
        .stream_id = 0,
    }, opaque_data);
}

fn tcpConnect(container_ip: [4]u8, port: u16, timeout: u32) ?posix.socket_t {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch return null;
    errdefer posix.close(sock);

    const tv = posix.timeval{
        .sec = @intCast(timeout),
        .usec = 0,
    };
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};

    const addr = posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(container_ip),
    };

    posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch return null;
    return sock;
}

fn writeAll(sock: posix.socket_t, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const chunk = try posix.write(sock, bytes[written..]);
        if (chunk == 0) return error.WriteFailed;
        written += chunk;
    }
}

fn readExact(sock: posix.socket_t, buf: []u8) !void {
    var read_total: usize = 0;
    while (read_total < buf.len) {
        const chunk = try posix.read(sock, buf[read_total..]);
        if (chunk == 0) return error.ReadFailed;
        read_total += chunk;
    }
}

const TestServerMode = enum {
    capture_only,
};

const BoundTestListener = struct {
    fd: posix.socket_t,
    port: u16,
};

fn initTestListenerSocket() !BoundTestListener {
    const reuseaddr: i32 = 1;
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);

    var attempt: usize = 0;
    while (attempt < 50) : (attempt += 1) {
        const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch {
            if (attempt + 1 == 50) return error.SkipZigTest;
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };
        errdefer posix.close(fd);

        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuseaddr)) catch {};

        posix.bind(fd, &addr.any, addr.getOsSockLen()) catch {
            if (attempt + 1 == 50) return error.SkipZigTest;
            posix.close(fd);
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };
        posix.listen(fd, 1) catch {
            if (attempt + 1 == 50) return error.SkipZigTest;
            posix.close(fd);
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };

        var bound_addr: posix.sockaddr.in = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        posix.getsockname(fd, @ptrCast(&bound_addr), &bound_len) catch {
            if (attempt + 1 == 50) return error.SkipZigTest;
            posix.close(fd);
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };

        return .{
            .fd = fd,
            .port = std.mem.bigToNative(u16, bound_addr.port),
        };
    }

    unreachable;
}

const TestServer = struct {
    listen_fd: posix.socket_t,
    port: u16,
    mode: TestServerMode,
    thread: ?std.Thread = null,
    requested_service: [128]u8 = undefined,
    requested_service_len: usize = 0,

    fn init(mode: TestServerMode) !TestServer {
        const listener = try initTestListenerSocket();
        return .{
            .listen_fd = listener.fd,
            .port = listener.port,
            .mode = mode,
        };
    }

    fn start(self: *TestServer) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn deinit(self: *TestServer) void {
        if (self.thread) |thread| thread.join();
        posix.close(self.listen_fd);
    }

    fn requestedService(self: *const TestServer) []const u8 {
        return self.requested_service[0..self.requested_service_len];
    }

    fn run(self: *TestServer) void {
        const client_fd = posix.accept(self.listen_fd, null, null, posix.SOCK.CLOEXEC) catch return;
        defer posix.close(client_fd);

        switch (self.mode) {
            .capture_only => {
                self.requested_service_len = readGrpcHealthRequestService(client_fd, &self.requested_service) orelse return;
            },
        }
    }
};

fn readGrpcHealthRequestService(sock: posix.socket_t, service_storage: []u8) ?usize {
    var preface: [http2.client_preface.len]u8 = undefined;
    readExact(sock, &preface) catch return null;
    if (!std.mem.eql(u8, &preface, http2.client_preface)) return null;

    var payload_storage: [max_http2_frame_payload]u8 = undefined;
    var grpc_payload_storage: [max_grpc_message_len]u8 = undefined;
    var grpc_payload_len: usize = 0;
    var stream_ended = false;
    var frames_seen: usize = 0;

    while (!stream_ended and frames_seen < 16) : (frames_seen += 1) {
        const frame = readFrame(sock, &payload_storage) orelse return null;
        switch (frame.header.frame_type) {
            .settings => {
                if (frame.header.stream_id != 0) return null;
            },
            .headers => {
                if (frame.header.stream_id != grpc_stream_id) return null;
                stream_ended = (frame.header.flags & 0x01) != 0;
                if ((frame.header.flags & 0x04) == 0) {
                    while (true) {
                        const continuation = readFrame(sock, &payload_storage) orelse return null;
                        if (continuation.header.frame_type != .continuation or continuation.header.stream_id != grpc_stream_id) {
                            return null;
                        }
                        if ((continuation.header.flags & 0x04) != 0) break;
                    }
                }
            },
            .data => {
                if (frame.header.stream_id != grpc_stream_id) return null;
                const payload = extractDataPayload(frame.header.flags, frame.payload) orelse return null;
                if (grpc_payload_len + payload.len > grpc_payload_storage.len) return null;
                @memcpy(grpc_payload_storage[grpc_payload_len .. grpc_payload_len + payload.len], payload);
                grpc_payload_len += payload.len;
                stream_ended = (frame.header.flags & 0x01) != 0;
            },
            else => {},
        }
    }

    const service = parseGrpcHealthRequestService(grpc_payload_storage[0..grpc_payload_len]) orelse return null;
    if (service.len > service_storage.len) return null;
    @memcpy(service_storage[0..service.len], service);
    return service.len;
}

fn writeGrpcHealthTestResponse(sock: posix.socket_t, serving_status: u8, grpc_status: []const u8) !void {
    try writeFrame(sock, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");

    var header_storage: [1024]u8 = undefined;
    var header_alloc = std.heap.FixedBufferAllocator.init(&header_storage);
    const alloc = header_alloc.allocator();

    const response_headers = [_]hpack.HeaderField{
        .{ .name = try alloc.dupe(u8, ":status"), .value = try alloc.dupe(u8, "200") },
        .{ .name = try alloc.dupe(u8, "content-type"), .value = try alloc.dupe(u8, "application/grpc") },
    };
    const response_header_block = try hpack.encodeHeaderBlockLiteral(alloc, &response_headers);
    try writeFrame(sock, .{
        .length = @intCast(response_header_block.len),
        .frame_type = .headers,
        .flags = 0x04,
        .stream_id = grpc_stream_id,
    }, response_header_block);

    var body_buf: [32]u8 = undefined;
    const body = try buildGrpcHealthTestResponseBody(serving_status, &body_buf);
    try writeFrame(sock, .{
        .length = @intCast(body.len),
        .frame_type = .data,
        .flags = 0,
        .stream_id = grpc_stream_id,
    }, body);

    const trailers = [_]hpack.HeaderField{
        .{ .name = try alloc.dupe(u8, "grpc-status"), .value = try alloc.dupe(u8, grpc_status) },
    };
    const trailer_block = try hpack.encodeHeaderBlockLiteral(alloc, &trailers);
    try writeFrame(sock, .{
        .length = @intCast(trailer_block.len),
        .frame_type = .headers,
        .flags = 0x05,
        .stream_id = grpc_stream_id,
    }, trailer_block);
}

fn buildGrpcHealthTestResponseBody(serving_status: u8, buf: []u8) ![]const u8 {
    if (buf.len < 7) return error.BufferTooShort;
    buf[0] = 0;
    std.mem.writeInt(u32, buf[1..5], 2, .big);
    buf[5] = 0x08;
    buf[6] = serving_status;
    return buf[0..7];
}

test "isHttp2SettingsFrame accepts server settings frame" {
    try std.testing.expect(isHttp2SettingsFrame(&[_]u8{
        0,   0, 0,
        0x4, 0, 0,
        0,   0, 0,
    }));
}

test "isHttp2SettingsFrame rejects non-settings frame" {
    try std.testing.expect(!isHttp2SettingsFrame(&[_]u8{
        0,   0, 0,
        0x0, 0, 0,
        0,   0, 0,
    }));
}

test "writeGrpcHealthRequest sends grpc service name" {
    var server = try TestServer.init(.capture_only);
    try server.start();

    const sock = tcpConnect(.{ 127, 0, 0, 1 }, server.port, 1) orelse return error.SkipZigTest;
    defer posix.close(sock);
    try writeGrpcHealthRequest(sock, "pkg.Health");

    server.deinit();
    try std.testing.expectEqualStrings("pkg.Health", server.requestedService());
}

test "writeGrpcHealthRequest sends empty grpc service name by default" {
    var server = try TestServer.init(.capture_only);
    try server.start();

    const sock = tcpConnect(.{ 127, 0, 0, 1 }, server.port, 1) orelse return error.SkipZigTest;
    defer posix.close(sock);
    try writeGrpcHealthRequest(sock, "");

    server.deinit();
    try std.testing.expectEqualStrings("", server.requestedService());
}

test "parseGrpcHealthResponseMessages accepts serving response body" {
    var body_buf: [32]u8 = undefined;
    const body = try buildGrpcHealthTestResponseBody(1, &body_buf);
    try std.testing.expect(parseGrpcHealthResponseMessages(body));
}

test "applyGrpcHeaderBlock accepts grpc response headers and trailers" {
    var storage: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&storage);
    const alloc = fba.allocator();

    const response_headers = [_]hpack.HeaderField{
        .{ .name = try alloc.dupe(u8, ":status"), .value = try alloc.dupe(u8, "200") },
        .{ .name = try alloc.dupe(u8, "content-type"), .value = try alloc.dupe(u8, "application/grpc") },
    };
    const header_block = try hpack.encodeHeaderBlockLiteral(alloc, &response_headers);

    var http_status_ok = false;
    var saw_grpc_status = false;
    var grpc_status_ok = false;
    try std.testing.expect(applyGrpcHeaderBlock(header_block, &http_status_ok, &saw_grpc_status, &grpc_status_ok));
    try std.testing.expect(http_status_ok);
    try std.testing.expect(!saw_grpc_status);

    const trailers = [_]hpack.HeaderField{
        .{ .name = try alloc.dupe(u8, "grpc-status"), .value = try alloc.dupe(u8, "0") },
    };
    const trailer_block = try hpack.encodeHeaderBlockLiteral(alloc, &trailers);
    try std.testing.expect(applyGrpcHeaderBlock(trailer_block, &http_status_ok, &saw_grpc_status, &grpc_status_ok));
    try std.testing.expect(saw_grpc_status);
    try std.testing.expect(grpc_status_ok);
}
