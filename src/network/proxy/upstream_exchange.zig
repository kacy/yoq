// One buffered upstream exchange: service identity, transport deadlines,
// response framing and socket ownership. Routing, retries and metrics belong
// to the caller, regardless of HTTP version or TLS mode.
const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const http = @import("../../api/http.zig");
const log = @import("../../lib/log.zig");
const socket_helpers = @import("socket_helpers.zig");
const upstream_pool = @import("upstream_pool.zig");
const upstream_mod = @import("upstream.zig");
const client_dial = @import("../../tls/client_dial.zig");
const transport = @import("../../tls/client_transport.zig");
const store_mod = @import("../../state/store.zig");
const peer_identity = @import("../../tls/peer_identity.zig");
const proxy_credentials = @import("../../tls/proxy_credentials.zig");
const http2_passthrough = @import("http2_passthrough.zig");

pub const Protocol = enum { http1, http2 };
pub const Options = struct { connect_timeout_ms: u32, request_timeout_ms: u32, head: bool = false, protocol: Protocol = .http1 };

pub const Client = struct {
    allocator: std.mem.Allocator,
    peer_key: ?proxy_credentials.Key = null,
    max_response_bytes: usize = 64 * 1024,

    pub fn forward(self: *const Client, request: []const u8, options: Options, upstream: *const upstream_mod.Upstream) ![]u8 {
        return if (upstream.peer_mode == .off)
            self.forwardPlain(request, options, upstream)
        else
            self.forwardTls(request, options, upstream);
    }

    /// TLS connections own their encryption state and never enter the bare
    /// socket pool. Identity and credentials are derived from service state.
    pub fn forwardTls(
        self: *const Client,
        request: []const u8,
        timeouts: Options,
        upstream: *const upstream_mod.Upstream,
    ) ![]u8 {
        const ca_rec_opt = store_mod.getClusterCa(self.allocator) catch null;
        const ca_rec = ca_rec_opt orelse {
            if (upstream.peer_mode == .require) return error.ClusterCaMissing;
            log.warn("mtls upstream {s}: cluster CA not seeded, downgrading to plain dial", .{upstream.address});
            return self.forwardPlain(request, timeouts, upstream);
        };
        defer ca_rec.deinit(self.allocator);

        const expected_identity = try peer_identity.service(self.allocator, upstream.service);
        defer self.allocator.free(expected_identity);
        const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
        const credentials: ?proxy_credentials.Credentials = credentials: {
            const key = self.peer_key orelse {
                if (upstream.peer_mode == .require) return error.ProxyCredentialsMissing;
                log.warn("mtls upstream {s}: proxy credentials unavailable, continuing without client authentication", .{upstream.service});
                break :credentials null;
            };
            break :credentials proxy_credentials.load(self.allocator, key, ca_rec.cert_pem, now) catch |err| switch (err) {
                error.ProxyCredentialsMissing, error.ReadFailed, error.DbOpenFailed => {
                    if (upstream.peer_mode == .require) return err;
                    log.warn("mtls upstream {s}: proxy credentials unavailable ({}), continuing without client authentication", .{ upstream.service, err });
                    break :credentials null;
                },
                else => return err,
            };
        };
        defer if (credentials) |owned| owned.deinit(self.allocator);

        var outcome = client_dial.dial(std.Options.debug_io, self.allocator, .{
            .address = upstream.address,
            .port = upstream.port,
            .connect_timeout_ms = timeouts.connect_timeout_ms,
            .request_timeout_ms = timeouts.request_timeout_ms,
            .ca_cert_pem = ca_rec.cert_pem,
            .server_name = upstream.service,
            .expected_server_identity = expected_identity,
            .client_cert_pem = if (credentials) |owned| owned.cert_pem else null,
            .client_key_pem = if (credentials) |owned| owned.key_pem else null,
            .now_unix = std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
        }) catch |err| return err;

        switch (outcome) {
            .bare => |fd| {
                // dial returned plaintext somehow (shouldn't happen when
                // ca_cert_pem is set, but be defensive).
                defer linux_platform.posix.close(fd);
                return error.HandshakeFailed;
            },
            .session => |*sess| {
                defer {
                    sess.deinit();
                    linux_platform.posix.close(sess.fd);
                }

                _ = sess.write(request) catch return error.SendFailed;
                return (try readProtocolResponse(self.allocator, sess, self.max_response_bytes, timeouts)).bytes;
            },
        }
    }

    /// Primary, mirror, and permissive fallback traffic share one plaintext
    /// exchange budget. Retries belong to the routing policy above this layer.
    pub fn forwardPlain(
        self: *const Client,
        request: []const u8,
        timeouts: Options,
        upstream: *const upstream_mod.Upstream,
    ) ![]u8 {
        const deadline = transport.Deadline.afterMilliseconds(timeouts.request_timeout_ms);
        const fd = upstream_pool.checkout(upstream.endpoint_id, upstream.address, upstream.port) orelse blk: {
            const dialed = try socket_helpers.connectToUpstreamUntil(timeouts.connect_timeout_ms, deadline, upstream);
            upstream_pool.noteDialed();
            break :blk dialed;
        };

        // A failed pooled write may already have sent request bytes. Only the
        // caller's method-aware retry policy may issue another request.
        (transport.Stream{ .fd = fd, .deadline = deadline }).writeAll(request) catch |err| {
            upstream_pool.discard(fd);
            return if (err == error.TimedOut) err else error.SendFailed;
        };

        const result = readProtocolResponse(self.allocator, transport.Stream{ .fd = fd, .deadline = deadline }, self.max_response_bytes, timeouts) catch |err| {
            upstream_pool.discard(fd);
            return err;
        };

        if (result.reusable) {
            upstream_pool.release(upstream.endpoint_id, upstream.address, upstream.port, fd);
        } else {
            upstream_pool.discard(fd);
        }
        return result.bytes;
    }
};

const max_informational_responses = 16;

/// Response accounting and retries use the final status, not an interim hint.
fn parseUpstreamStatusCode(response: []const u8) !u16 {
    var start: usize = 0;
    var interim: usize = 0;
    while (true) {
        const status = try parseResponseStatusLine(response[start..]);
        if (status < 100 or status >= 200 or status == 101) return status;
        if (interim == max_informational_responses) return error.InvalidResponse;
        interim += 1;
        const end = std.mem.indexOfPos(u8, response, start, "\r\n\r\n") orelse return error.InvalidResponse;
        start = end + 4;
    }
}

fn parseResponseStatusLine(response: []const u8) !u16 {
    if (response.len < 12) return error.InvalidResponse;
    if (!std.mem.startsWith(u8, response, "HTTP/")) return error.InvalidResponse;

    const first_space = std.mem.indexOfScalar(u8, response, ' ') orelse return error.InvalidResponse;
    const status_start = first_space + 1;
    if (status_start + 3 > response.len) return error.InvalidResponse;
    return std.fmt.parseInt(u16, response[status_start .. status_start + 3], 10) catch error.InvalidResponse;
}

pub fn parseStatusCode(alloc: std.mem.Allocator, protocol: Protocol, response: []const u8) !u16 {
    return switch (protocol) {
        .http1 => parseUpstreamStatusCode(response),
        .http2 => http2_passthrough.parseStatusCode(alloc, response),
    };
}

/// an upstream response plus whether its connection can be returned to the pool.
const UpstreamResponse = struct {
    bytes: []u8,
    /// true only when the response body was fully delimited by Content-Length
    /// or chunked framing and the upstream did not ask to close the connection.
    /// connection-close-delimited (read-to-EOF) responses are never reusable.
    reusable: bool,
};

/// how the upstream response body is delimited.
const BodyFraming = union(enum) {
    /// no body at all (HEAD, interim responses, 204, 304).
    empty,
    /// A protocol switch needs a tunnel, which this buffered path does not own.
    upgrade,
    /// exactly `len` bytes of body.
    fixed: usize,
    /// chunked transfer-encoding, terminated by the zero-length chunk.
    chunked,
    /// delimited by connection close — read until EOF, not reusable.
    eof,
};

/// read a full upstream response. unlike a naive read-until-EOF, this honors
/// HTTP/1.1 framing so a kept-alive connection can be returned promptly without
/// waiting for the peer to close. Responses without a body length use EOF
/// framing and cannot reuse the connection.
fn readResponse(
    alloc: std.mem.Allocator,
    socket: anytype,
    max_bytes: usize,
    head_request: bool,
) !UpstreamResponse {
    return readHttp1ResponseFrom(alloc, transport.stream(socket), max_bytes, head_request);
}

/// Buffered HTTP/2 forwarding retains its bounded, connection-close exchange.
/// Streaming HTTP/2 connections are handled separately by http2_connection.
fn readProtocolResponse(alloc: std.mem.Allocator, wire: anytype, max_bytes: usize, options: Options) !UpstreamResponse {
    if (options.protocol == .http1) return readHttp1ResponseFrom(alloc, wire, max_bytes, options.head);
    const response = try alloc.alloc(u8, max_bytes);
    errdefer alloc.free(response);
    var total: usize = 0;
    while (total < response.len) {
        const count = try readUpstream(wire, response[total..]);
        if (count == 0) break;
        total += count;
    }
    if (total == response.len) {
        var extra: [1]u8 = undefined;
        if (try readUpstream(wire, &extra) != 0) return error.ResponseTooLarge;
    }
    if (total == 0) return error.ReceiveFailed;
    return shrinkResponse(alloc, response, total, false);
}

/// TLS and plaintext use the same bounded framing rules. Keep interim bytes
/// for forwarding, but only the final response controls body framing and reuse.
fn readHttp1ResponseFrom(alloc: std.mem.Allocator, wire: anytype, max_bytes: usize, head_request: bool) !UpstreamResponse {
    var response = try alloc.alloc(u8, max_bytes);
    errdefer alloc.free(response);
    var total: usize = 0;
    var final_start: usize = 0;
    var interim: usize = 0;
    var status: u16 = 0;
    const headers_end = while (true) {
        if (std.mem.indexOfPos(u8, response[0..total], final_start, "\r\n\r\n")) |idx| {
            const end = idx + 4;
            status = try parseResponseStatusLine(response[final_start..end]);
            if (status >= 100 and status < 200 and status != 101) {
                if (interim == max_informational_responses) return error.InvalidResponse;
                interim += 1;
                final_start = end;
                continue;
            }
            break end;
        }
        if (total == response.len) return error.ResponseTooLarge;
        const n = try readUpstream(wire, response[total..]);
        if (n == 0) return if (total == 0) error.ReceiveFailed else error.InvalidResponse;
        total += n;
    };
    const headers = response[final_start..headers_end];
    const wants_close = http1ResponseWantsClose(headers);
    const framing = responseBodyFraming(headers, status, head_request);

    switch (framing) {
        .upgrade => return error.UnsupportedUpgrade,
        .empty => {
            // any bytes past the headers are unexpected for a bodiless response.
            const reusable = !wants_close and total == headers_end;
            return try shrinkResponse(alloc, response, headers_end, reusable);
        },
        .fixed => |body_len| {
            const target = std.math.add(usize, headers_end, body_len) catch return error.ResponseTooLarge;
            if (target > response.len) return error.ResponseTooLarge;
            while (total < target) {
                const bytes_read = try readUpstream(wire, response[total..]);
                if (bytes_read == 0) {
                    return error.InvalidResponse;
                }
                total += bytes_read;
            }
            const reusable = !wants_close and total == target;
            return try shrinkResponse(alloc, response, target, reusable);
        },
        .chunked => {
            while (true) {
                if (try chunkedBodyEnd(response[headers_end..total])) |body_len| {
                    const target = headers_end + body_len;
                    const reusable = !wants_close and total == target;
                    return try shrinkResponse(alloc, response, target, reusable);
                }
                if (total == response.len) return error.ResponseTooLarge;
                const bytes_read = try readUpstream(wire, response[total..]);
                if (bytes_read == 0) {
                    return error.InvalidResponse;
                }
                total += bytes_read;
            }
        },
        .eof => {
            while (total < response.len) {
                const bytes_read = try readUpstream(wire, response[total..]);
                if (bytes_read == 0) break;
                total += bytes_read;
            }
            if (total == response.len) {
                var extra_buf: [1]u8 = undefined;
                const extra = try readUpstream(wire, &extra_buf);
                if (extra > 0) return error.ResponseTooLarge;
            }
            return try shrinkResponse(alloc, response, total, false);
        },
    }
}

fn readUpstream(reader: anytype, buffer: []u8) !usize {
    return reader.read(buffer) catch |err| {
        const failure: anyerror = err;
        return switch (failure) {
            error.PeerClosed => 0,
            error.TimedOut => error.TimedOut,
            else => error.ReceiveFailed,
        };
    };
}

/// shrink the over-allocated read buffer down to the bytes actually used and
/// package it with its reusability verdict.
fn shrinkResponse(alloc: std.mem.Allocator, response: []u8, len: usize, reusable: bool) !UpstreamResponse {
    var bytes = response;
    if (len < bytes.len) bytes = try alloc.realloc(bytes, len);
    return .{ .bytes = bytes, .reusable = reusable };
}

/// pick the body framing from the response headers. mirrors RFC 9112 message
/// body rules for the cases we care about; anything we cannot classify becomes
/// connection-close (EOF) delimited so we never misframe.
fn responseBodyFraming(headers: []const u8, status: u16, head_request: bool) BodyFraming {
    if (status == 101) return .upgrade;
    if (status >= 100 and status < 200) return .empty;
    if (head_request or status == 204 or status == 304) return .empty;

    if (http.findHeaderValue(headers, "Transfer-Encoding")) |te| {
        if (headerListContains(te, "chunked")) return .chunked;
    }
    if (http.findHeaderValue(headers, "Content-Length") != null) {
        const len = http.findContentLength(headers) catch return .eof;
        return .{ .fixed = len };
    }
    return .eof;
}

/// true when the upstream signalled the connection should close (explicit
/// `Connection: close`, or an HTTP/1.0 response which defaults to close).
fn http1ResponseWantsClose(headers: []const u8) bool {
    if (std.mem.startsWith(u8, headers, "HTTP/1.0")) return true;
    if (http.findHeaderValue(headers, "Connection")) |conn| {
        return headerListContains(conn, "close");
    }
    return false;
}

/// case-insensitive membership test over a comma-separated header value.
fn headerListContains(value: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t");
        if (std.ascii.eqlIgnoreCase(trimmed, token)) return true;
    }
    return false;
}

/// given the bytes received after the header block, return the offset at which
/// a complete chunked body ends, or null if more data is still needed. handles
/// chunk extensions and trailer fields. Invalid framing is distinct from an
/// incomplete body, so malformed sizes never wait for more network data.
fn chunkedBodyEnd(body: []const u8) error{InvalidResponse}!?usize {
    var pos: usize = 0;
    while (true) {
        const line_end = std.mem.indexOfPos(u8, body, pos, "\r\n") orelse return null;
        var size_field = body[pos..line_end];
        if (std.mem.indexOfScalar(u8, size_field, ';')) |semi| size_field = size_field[0..semi];
        size_field = std.mem.trim(u8, size_field, " \t");
        if (size_field.len == 0) return error.InvalidResponse;
        for (size_field) |digit| _ = std.fmt.charToDigit(digit, 16) catch return error.InvalidResponse;
        const size = std.fmt.parseInt(usize, size_field, 16) catch return error.InvalidResponse;

        const data_start = line_end + 2;
        if (size == 0) {
            // last chunk: skip any trailer lines up to the terminating blank line.
            var trailer_pos = data_start;
            while (true) {
                const trailer_end = std.mem.indexOfPos(u8, body, trailer_pos, "\r\n") orelse return null;
                if (trailer_end == trailer_pos) return trailer_pos + 2;
                trailer_pos = trailer_end + 2;
            }
        }

        const size_with_terminator = std.math.add(usize, size, 2) catch return error.InvalidResponse;
        const next = std.math.add(usize, data_start, size_with_terminator) catch return error.InvalidResponse;
        if (next > body.len) return null;
        if (!std.mem.eql(u8, body[next - 2 .. next], "\r\n")) return error.InvalidResponse;
        pos = next;
    }
}

test "headerListContains matches tokens case-insensitively" {
    try std.testing.expect(headerListContains("close", "close"));
    try std.testing.expect(headerListContains("keep-alive, Close", "close"));
    try std.testing.expect(headerListContains("chunked", "chunked"));
    try std.testing.expect(!headerListContains("keep-alive", "close"));
}

test "responseBodyFraming reads Content-Length, chunked, and close-delimited bodies" {
    const cl = responseBodyFraming("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", 200, false);
    try std.testing.expectEqual(@as(usize, 5), cl.fixed);

    const chunked = responseBodyFraming("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", 200, false);
    try std.testing.expect(chunked == .chunked);

    const none = responseBodyFraming("HTTP/1.1 200 OK\r\n\r\n", 200, false);
    try std.testing.expect(none == .eof);
}

test "responseBodyFraming treats HEAD, 204, 304, and 1xx specially" {
    try std.testing.expect(responseBodyFraming("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", 200, true) == .empty);
    try std.testing.expect(responseBodyFraming("HTTP/1.1 204 No Content\r\n\r\n", 204, false) == .empty);
    try std.testing.expect(responseBodyFraming("HTTP/1.1 304 Not Modified\r\n\r\n", 304, false) == .empty);
    try std.testing.expect(responseBodyFraming("HTTP/1.1 100 Continue\r\n\r\n", 100, false) == .empty);
}

test "http1ResponseWantsClose honors Connection header and HTTP/1.0" {
    try std.testing.expect(http1ResponseWantsClose("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"));
    try std.testing.expect(http1ResponseWantsClose("HTTP/1.0 200 OK\r\n\r\n"));
    try std.testing.expect(!http1ResponseWantsClose("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n"));
}

test "chunkedBodyEnd finds the end of a complete chunked body" {
    const body = "5\r\nhello\r\n0\r\n\r\n";
    try std.testing.expectEqual(@as(?usize, body.len), try chunkedBodyEnd(body));

    // incomplete: terminating chunk not yet received.
    try std.testing.expectEqual(@as(?usize, null), try chunkedBodyEnd("5\r\nhello\r\n"));

    // trailers before the final blank line.
    const with_trailers = "0\r\nX-Trace: abc\r\n\r\n";
    try std.testing.expectEqual(@as(?usize, with_trailers.len), try chunkedBodyEnd(with_trailers));
}

fn readResponseTestPair() ![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SocketFailed;
    return fds;
}

test "readResponse returns a Content-Length body without waiting for EOF" {
    const fds = try readResponseTestPair();
    defer linux_platform.posix.close(fds[0]);
    defer linux_platform.posix.close(fds[1]);

    // peer stays open after writing — a framed read must not block on it.
    try socket_helpers.writeAll(fds[1], "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");

    const result = try readResponse(std.testing.allocator, fds[0], 64 * 1024, false);
    defer std.testing.allocator.free(result.bytes);
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", result.bytes);
    try std.testing.expect(result.reusable);
}

test "readResponse marks Connection: close responses as not reusable" {
    const fds = try readResponseTestPair();
    defer linux_platform.posix.close(fds[0]);
    defer linux_platform.posix.close(fds[1]);

    try socket_helpers.writeAll(fds[1], "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");

    const result = try readResponse(std.testing.allocator, fds[0], 64 * 1024, false);
    defer std.testing.allocator.free(result.bytes);
    try std.testing.expect(!result.reusable);
}

test "readResponse reads a chunked body to completion" {
    const fds = try readResponseTestPair();
    defer linux_platform.posix.close(fds[0]);
    defer linux_platform.posix.close(fds[1]);

    try socket_helpers.writeAll(fds[1], "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n");

    const result = try readResponse(std.testing.allocator, fds[0], 64 * 1024, false);
    defer std.testing.allocator.free(result.bytes);
    try std.testing.expect(std.mem.endsWith(u8, result.bytes, "0\r\n\r\n"));
    try std.testing.expect(result.reusable);
}

// A session-shaped reader verifies TLS framing without requiring EOF.
const FakeSession = struct {
    chunks: []const []const u8,
    index: usize = 0,
    offset: usize = 0,

    fn read(self: *FakeSession, buf: []u8) !usize {
        if (self.index == self.chunks.len) return error.PeerClosed;
        const chunk = self.chunks[self.index][self.offset..];
        const n = @min(buf.len, chunk.len);
        @memcpy(buf[0..n], chunk[0..n]);
        self.offset += n;
        if (self.offset == self.chunks[self.index].len) {
            self.index += 1;
            self.offset = 0;
        }
        return n;
    }
};

test "response framing TLS reader stops at a complete response without EOF" {
    var sess = FakeSession{ .chunks = &.{ "HTTP/1.1 103 Early Hints\r\nLink: /style.css\r\n\r\nHTTP/1.1 200 OK\r\n", "Content-Length: 2\r\n\r\nok", "unread" } };
    const result = try readHttp1ResponseFrom(std.testing.allocator, &sess, 64 * 1024, false);
    defer std.testing.allocator.free(result.bytes);
    try std.testing.expectEqual(@as(usize, 2), sess.index);
    try std.testing.expectEqual(@as(u16, 200), try parseUpstreamStatusCode(result.bytes));
    try std.testing.expect(result.reusable);
}

test "response framing TLS reader rejects oversized and empty responses" {
    var sess = FakeSession{ .chunks = &.{ "AAAA", "BBBB", "CCCC" } };
    try std.testing.expectError(error.ResponseTooLarge, readHttp1ResponseFrom(std.testing.allocator, &sess, 6, false));
    var empty = FakeSession{ .chunks = &.{} };
    try std.testing.expectError(error.ReceiveFailed, readHttp1ResponseFrom(std.testing.allocator, &empty, 64, false));
}

test "response framing rejects overflowing chunk sizes before waiting for payload" {
    for ([_]usize{ std.math.maxInt(usize), std.math.maxInt(usize) - 1, std.math.maxInt(usize) - 2 }) |size| {
        var chunk_buf: [64]u8 = undefined;
        const chunk = try std.fmt.bufPrint(&chunk_buf, "{x}\r\n", .{size});
        try std.testing.expectError(error.InvalidResponse, chunkedBodyEnd(chunk));
        const fds = try readResponseTestPair();
        defer for (fds) |fd| linux_platform.posix.close(fd);
        try socket_helpers.writeAll(fds[1], "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        try socket_helpers.writeAll(fds[1], chunk);
        const wire = transport.Stream{ .fd = fds[0], .deadline = transport.Deadline.afterMilliseconds(1000) };
        // Peer stays open with no payload. Malformed framing must fail now.
        try std.testing.expectError(error.InvalidResponse, readResponse(std.testing.allocator, wire, 4096, false));
    }
    try std.testing.expectError(error.InvalidResponse, chunkedBodyEnd("1\r\nxZZ"));
    try std.testing.expectError(error.InvalidResponse, chunkedBodyEnd("+1\r\nx\r\n"));
    try std.testing.expectError(error.InvalidResponse, chunkedBodyEnd("ffffffffffffffffffffffffffffffff\r\n"));
    try std.testing.expectEqual(@as(?usize, null), try chunkedBodyEnd("5\r\nhel"));
}

test "response framing preserves informational blocks and completes on a persistent socket" {
    const raw = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: /style.css\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const fds = try readResponseTestPair();
    defer for (fds) |fd| linux_platform.posix.close(fd);
    try socket_helpers.writeAll(fds[1], raw);
    const wire = transport.Stream{ .fd = fds[0], .deadline = transport.Deadline.afterMilliseconds(1000) };
    const result = try readResponse(std.testing.allocator, wire, 4096, false);
    defer std.testing.allocator.free(result.bytes);
    try std.testing.expectEqualStrings(raw, result.bytes);
    try std.testing.expect(result.reusable);
    try std.testing.expectEqual(@as(u16, 200), try parseUpstreamStatusCode(result.bytes));

    var fragments = FakeSession{ .chunks = &.{ "HTTP/1.1 10", "0 Continue\r\n\r", "\nHTTP/1.1 103 Early Hints\r\nLink: /style.css\r\n\r\nHTTP/1.1 503 Unavailable\r\nContent-Length: 2\r\n\r\nx", "x", "unread" } };
    const final = try readHttp1ResponseFrom(std.testing.allocator, &fragments, 4096, false);
    defer std.testing.allocator.free(final.bytes);
    try std.testing.expectEqual(@as(u16, 503), try parseUpstreamStatusCode(final.bytes));
    try std.testing.expectEqual(@as(usize, 4), fragments.index);
    try std.testing.expect(final.reusable);
}

test "response framing bounds interim floods and separates unsupported upgrades" {
    const interim = "HTTP/1.1 103 Early Hints\r\nLink: /style.css\r\n\r\n";
    var flood: [max_informational_responses + 2][]const u8 = @splat(interim);
    flood[flood.len - 1] = "unread";
    var reader = FakeSession{ .chunks = &flood };
    try std.testing.expectError(error.InvalidResponse, readHttp1ResponseFrom(std.testing.allocator, &reader, 4096, false));
    try std.testing.expectEqual(@as(usize, max_informational_responses + 1), reader.index);
    var upgrade = FakeSession{ .chunks = &.{ "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", "unread" } };
    try std.testing.expectError(error.UnsupportedUpgrade, readHttp1ResponseFrom(std.testing.allocator, &upgrade, 4096, false));
    try std.testing.expectEqual(@as(usize, 1), upgrade.index);
    var truncated = FakeSession{ .chunks = &.{"HTTP/1.1 103 Early Hints\r\n\r\n"} };
    try std.testing.expectError(error.InvalidResponse, readHttp1ResponseFrom(std.testing.allocator, &truncated, 4096, false));
}

test "response framing keeps binary HTTP2 separate on TLS readers" {
    const binary = "\x00\x00\x00\x04\x00\x00\x00\x00\x00";
    var session = FakeSession{ .chunks = &.{ binary[0..3], binary[3..] } };
    const response = try readProtocolResponse(std.testing.allocator, &session, 64, .{ .connect_timeout_ms = 1000, .request_timeout_ms = 1000, .protocol = .http2 });
    defer std.testing.allocator.free(response.bytes);
    try std.testing.expectEqualStrings(binary, response.bytes);
    try std.testing.expect(!response.reusable);
    var malformed_http1 = FakeSession{ .chunks = &.{binary} };
    try std.testing.expectError(error.InvalidResponse, readProtocolResponse(std.testing.allocator, &malformed_http1, 64, .{ .connect_timeout_ms = 1000, .request_timeout_ms = 1000 }));
}

test "proxy transport policy does not replay a failed pooled write" {
    upstream_pool.resetForTest();
    defer upstream_pool.resetForTest();
    const fds = try readResponseTestPair();
    defer linux_platform.posix.close(fds[1]);
    // A socket can look alive to a read probe while its write side has failed.
    // The exchange must report that failure instead of reconnecting and
    // replaying a request whose method it does not own.
    _ = std.os.linux.shutdown(fds[0], 1);
    upstream_pool.release("api-1", "invalid-address", 1, fds[0]);
    const upstream = upstream_mod.Upstream{ .service = "api", .endpoint_id = "api-1", .address = "invalid-address", .port = 1 };
    const client = Client{ .allocator = std.testing.allocator };
    try std.testing.expectError(error.SendFailed, client.forwardPlain("POST /charge HTTP/1.1\r\nContent-Length: 0\r\n\r\n", .{ .connect_timeout_ms = 100, .request_timeout_ms = 100 }, &upstream));
    try std.testing.expectEqual(@as(usize, 1), upstream_pool.snapshot().reuse_total);
    try std.testing.expectEqual(@as(usize, 0), upstream_pool.snapshot().created_total);
}
