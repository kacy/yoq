const std = @import("std");
const platform = @import("linux_platform");
const posix = std.posix;
const http = @import("../../api/http.zig");
const response = @import("http1_stream.zig");
const exchange = @import("upstream_exchange.zig");
const transport = @import("../../tls/client_transport.zig");

const buffer_size = 16 * 1024;
const max_chunk_line = 4096;
const max_trailer_bytes = 16 * 1024;

// validate framing before forwarding each bounded batch. bytes after the body
// belong to a later request and are never sent on this upstream connection.
pub const Body = struct {
    state: enum { fixed, size_line, data, data_cr, data_lf, trailers, done },
    remaining: usize = 0,
    decoded: usize = 0,
    limit: usize = http.max_body_bytes,
    line: [max_chunk_line]u8 = undefined,
    line_used: usize = 0,
    trailer_bytes: usize = 0,

    pub fn init(request: http.Request) Body {
        return .{
            .state = if (request.chunked) .size_line else if (request.content_length == 0) .done else .fixed,
            .remaining = request.content_length,
        };
    }

    pub fn consume(self: *Body, bytes: []const u8) !usize {
        var used: usize = 0;
        while (used < bytes.len and self.state != .done) {
            switch (self.state) {
                .fixed, .data => {
                    const count = @min(self.remaining, bytes.len - used);
                    self.remaining -= count;
                    used += count;
                    if (self.remaining == 0) self.state = if (self.state == .fixed) .done else .data_cr;
                },
                .data_cr, .data_lf => {
                    const expected: u8 = if (self.state == .data_cr) '\r' else '\n';
                    if (bytes[used] != expected) return error.MalformedRequestBody;
                    used += 1;
                    self.state = if (self.state == .data_cr) .data_lf else .size_line;
                },
                .size_line, .trailers => {
                    if (self.line_used == self.line.len) return error.MalformedRequestBody;
                    const byte = bytes[used];
                    self.line[self.line_used] = byte;
                    self.line_used += 1;
                    used += 1;
                    if (self.state == .trailers) {
                        self.trailer_bytes += 1;
                        if (self.trailer_bytes > max_trailer_bytes) return error.MalformedRequestBody;
                    }
                    if (byte == '\n') {
                        if (self.line_used < 2 or self.line[self.line_used - 2] != '\r') return error.MalformedRequestBody;
                        const line = self.line[0 .. self.line_used - 2];
                        if (self.state == .size_line) try self.chunkSize(line) else try self.trailer(line);
                        self.line_used = 0;
                    }
                },
                .done => return used,
            }
        }
        return used;
    }

    fn chunkSize(self: *Body, line: []const u8) !void {
        const end = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        if (end == 0) return error.MalformedRequestBody;
        for (line[0..end]) |byte| if (!std.ascii.isHex(byte)) return error.MalformedRequestBody;
        for (line[end..]) |byte| if (byte < 0x20 or byte == 0x7f) return error.MalformedRequestBody;
        const size = std.fmt.parseInt(usize, line[0..end], 16) catch return error.MalformedRequestBody;
        if (size > self.limit - self.decoded) return error.BodyTooLarge;
        self.decoded += size;
        self.remaining = size;
        self.state = if (size == 0) .trailers else .data;
    }

    fn trailer(self: *Body, line: []const u8) !void {
        if (line.len == 0) {
            self.state = .done;
            return;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedRequestBody;
        if (colon == 0) return error.MalformedRequestBody;
        for (line[0..colon]) |byte| if (!http.isHeaderNameByte(byte)) return error.MalformedRequestBody;
        for (line[colon + 1 ..]) |byte| if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return error.MalformedRequestBody;
        for ([_][]const u8{ "content-length", "transfer-encoding", "host", "connection", "trailer", "authorization", "proxy-authorization", "expect", "upgrade" }) |name|
            if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return error.MalformedRequestBody;
    }
};

pub fn hasBody(request: http.Request) bool {
    return request.chunked or request.content_length != 0;
}

pub fn expectsContinue(request: http.Request) !bool {
    const value = http.findHeaderValue(request.headers_raw, "Expect") orelse return false;
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, value, " \t"), "100-continue")) return error.MalformedRequestBody;
    return hasBody(request);
}

// one owner polls both directions. an upstream response can finish before the
// upload, and each direction stops reading while its bounded output is full.
pub fn sendAndReadHead(
    connection: *exchange.StreamingConnection,
    downstream: *response.Downstream,
    headers: []const u8,
    prefetched: []const u8,
    request: http.Request,
) !response.Head {
    var body = Body.init(request);
    const expect_continue = try expectsContinue(request);
    var head: response.Head = .{};
    var buffer: [buffer_size]u8 = undefined;
    var pending = headers;
    var input = prefetched;
    var headers_sent = false;
    var deadline = transport.Deadline.afterMilliseconds(connection.timeout_ms);
    const prior_deadline = connection.operation_deadline;
    defer connection.operation_deadline = prior_deadline;

    while (true) {
        connection.operation_deadline = deadline;
        if (try head.readAvailable(connection, request.method == .HEAD)) return head;
        var progress = false;
        if (connection.pendingWrite()) {
            if (try connection.flushAvailable()) progress = true;
        }
        if (pending.len > 0) {
            const count = try connection.writeAvailable(pending);
            pending = pending[count..];
            progress = count != 0 or progress;
        }
        if (pending.len == 0 and !connection.pendingWrite()) {
            if (!headers_sent) {
                headers_sent = true;
                if (expect_continue) {
                    // the proxy handles this expectation, so the upstream head
                    // omits Expect and the final-response state remains unset.
                    (transport.Stream{ .fd = downstream.fd, .deadline = deadline }).writeAll("HTTP/1.1 100 Continue\r\n\r\n") catch return error.ClientClosed;
                }
            }
            if (body.state != .done and input.len == 0) {
                const count: ?usize = platform.posix.recv(downstream.fd, &buffer, posix.MSG.DONTWAIT) catch |err| switch (err) {
                    error.WouldBlock => null,
                    else => return error.ClientClosed,
                };
                if (count) |received| {
                    if (received == 0) return error.IncompleteRequestBody;
                    input = buffer[0..received];
                }
            }
            if (body.state != .done and input.len > 0) {
                const consumed = try body.consume(input);
                pending = input[0..consumed];
                input = input[consumed..];
                progress = consumed != 0 or progress;
            }
        }
        if (progress) {
            deadline = transport.Deadline.afterMilliseconds(connection.timeout_ms);
            continue;
        }
        var fds = [_]posix.pollfd{
            .{ .fd = connection.fd(), .events = posix.POLL.IN | @as(i16, if (pending.len > 0 or connection.pendingWrite()) posix.POLL.OUT else 0), .revents = 0 },
            .{ .fd = downstream.fd, .events = if (headers_sent and body.state != .done and pending.len == 0 and !connection.pendingWrite()) posix.POLL.IN else 0, .revents = 0 },
        };
        const milliseconds = try deadline.remaining();
        const timeout: posix.timespec = .{ .sec = @divTrunc(milliseconds, 1000), .nsec = @rem(milliseconds, 1000) * std.time.ns_per_ms };
        const ready = posix.ppoll(&fds, &timeout, null) catch |err| switch (err) {
            error.SignalInterrupt => continue,
            else => return error.ReceiveFailed,
        };
        if (ready == 0) return error.TimedOut;
        if (fds[1].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) return error.ClientClosed;
    }
}

test "http1 upload validates fragmented chunk framing and leaves the next request unread" {
    const encoded = "3;name=value\r\nabc\r\n2\r\nde\r\n0\r\nX-Result: done\r\n\r\n";
    for (1..encoded.len + 1) |fragment_size| {
        var body: Body = .{ .state = .size_line };
        var consumed: usize = 0;
        const bytes = encoded ++ "GET /next HTTP/1.1\r\n\r\n";
        while (body.state != .done) consumed += try body.consume(bytes[consumed..][0..@min(fragment_size, bytes.len - consumed)]);
        try std.testing.expectEqual(encoded.len, consumed);
        try std.testing.expectEqual(@as(usize, 5), body.decoded);
    }
}

test "http1 upload rejects ambiguous framing malformed chunks and oversized decoded bodies" {
    for ([_][]const u8{ "-1\r\n", "+1\r\n", "g\r\n", "1\nx", "1\r\nx!", "0\r\nContent-Length: 1\r\n\r\n", "0\r\n folded: value\r\n\r\n" }) |bytes| {
        var body: Body = .{ .state = .size_line };
        try std.testing.expectError(error.MalformedRequestBody, body.consume(bytes));
    }
    var limited: Body = .{ .state = .size_line, .limit = 4 };
    try std.testing.expectError(error.BodyTooLarge, limited.consume("3\r\nabc\r\n2\r\n"));
    var line: Body = .{ .state = .size_line };
    try std.testing.expectError(error.MalformedRequestBody, line.consume(&([_]u8{'f'} ** (max_chunk_line + 1))));
}
