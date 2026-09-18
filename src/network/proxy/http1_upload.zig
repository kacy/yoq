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

const UploadFixture = struct {
    const upload_size = 2 * 1024 * 1024;
    const Sha256 = std.crypto.hash.sha2.Sha256;
    observed_body: std.atomic.Value(bool) = .init(false),
    chunked: bool,
    expect_continue: bool,
    producer_error: ?anyerror = null,
    upstream_error: ?anyerror = null,
    sent_digest: [32]u8 = undefined,
    received_digest: [32]u8 = undefined,

    fn pair() ![2]posix.fd_t {
        var sockets: [2]posix.fd_t = undefined;
        if (std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &sockets) != 0) return error.SkipZigTest;
        return sockets;
    }

    fn wire(fd: posix.fd_t) transport.Stream {
        return .{ .fd = fd, .deadline = transport.Deadline.afterMilliseconds(3000) };
    }

    fn produce(self: *UploadFixture, fd: posix.fd_t) void {
        self.produceBody(fd) catch |err| {
            self.producer_error = err;
            _ = std.os.linux.shutdown(fd, 2);
        };
    }

    fn produceBody(self: *UploadFixture, fd: posix.fd_t) !void {
        const socket = wire(fd);
        if (self.expect_continue) {
            var interim: [25]u8 = undefined;
            var used: usize = 0;
            while (used < interim.len) {
                const count = try socket.read(interim[used..]);
                if (count == 0) return error.UnexpectedEof;
                used += count;
            }
            try std.testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", &interim);
        }
        var hash: Sha256 = .init(.{});
        const block = [_]u8{'x'} ** buffer_size;
        for (0..upload_size / block.len) |index| {
            if (self.chunked) try writeHashed(socket, &hash, "4000\r\n");
            try writeHashed(socket, &hash, &block);
            if (self.chunked) try writeHashed(socket, &hash, "\r\n");
            if (index == 0) {
                // a buffering proxy would deadlock here: the remaining body is
                // sent only after the backend has received the first chunk.
                while (!self.observed_body.load(.acquire)) {
                    _ = try socket.deadline.?.remaining();
                    try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
                }
            }
        }
        if (self.chunked) try writeHashed(socket, &hash, "0\r\nX-Checksum: fixture\r\n\r\n");
        self.sent_digest = hash.finalResult();
    }

    fn writeHashed(socket: transport.Stream, hash: *Sha256, bytes: []const u8) !void {
        try socket.writeAll(bytes);
        hash.update(bytes);
    }

    fn serve(self: *UploadFixture, fd: posix.fd_t) void {
        self.receiveBody(fd) catch |err| {
            self.upstream_error = err;
            _ = std.os.linux.shutdown(fd, 2);
        };
    }

    fn receiveBody(self: *UploadFixture, fd: posix.fd_t) !void {
        const socket = wire(fd);
        var buffer: [buffer_size]u8 = undefined;
        var used: usize = 0;
        while (std.mem.indexOf(u8, buffer[0..used], "\r\n\r\n") == null) {
            const count = try socket.read(buffer[used..]);
            if (count == 0) return error.UnexpectedEof;
            used += count;
        }
        const head_end = std.mem.indexOf(u8, buffer[0..used], "\r\n\r\n").? + 4;
        const request = (try http.parseRequestHeadWithOptions(buffer[0..head_end], .{ .allow_chunked = true })).?;
        var body = Body.init(request);
        var input = buffer[head_end..used];
        var hash: Sha256 = .init(.{});
        var received_total: usize = 0;
        while (body.state != .done) {
            if (input.len == 0) {
                const count = try socket.read(&buffer);
                if (count == 0) return error.UnexpectedEof;
                input = buffer[0..count];
            }
            const count = try body.consume(input);
            hash.update(input[0..count]);
            input = input[count..];
            received_total += count;
            if (received_total >= buffer_size) self.observed_body.store(true, .release);
        }
        self.received_digest = hash.finalResult();
        try socket.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    }
};

test "http1 upload forwards large length and chunked bodies before the client finishes" {
    for ([_]bool{ false, true }) |chunked| {
        const client = try UploadFixture.pair();
        defer for (client) |fd| platform.posix.close(fd);
        const upstream = try UploadFixture.pair();
        defer for (upstream) |fd| platform.posix.close(fd);
        var fixture: UploadFixture = .{ .chunked = chunked, .expect_continue = true };
        const producer = try std.Thread.spawn(.{}, UploadFixture.produce, .{ &fixture, client[1] });
        var producer_joined = false;
        defer if (!producer_joined) producer.join();
        const server = try std.Thread.spawn(.{}, UploadFixture.serve, .{ &fixture, upstream[1] });
        var server_joined = false;
        defer if (!server_joined) server.join();
        var connection: exchange.StreamingConnection = .{ .connection = .{ .bare = upstream[0] }, .timeout_ms = 3000 };
        var started = false;
        var downstream: response.Downstream = .{ .fd = client[0], .timeout_ms = 3000, .started = &started };
        const headers = if (chunked)
            "POST /upload HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\n\r\n"
        else
            "POST /upload HTTP/1.1\r\nHost: app.test\r\nContent-Length: 2097152\r\n\r\n";
        var parsed = (try http.parseRequestHeadWithOptions(headers, .{ .allow_chunked = true })).?;
        // the proxy strips Expect from the forwarded head after handling it.
        parsed.headers_raw = "Expect: 100-continue";
        const head = try sendAndReadHead(&connection, &downstream, headers, "", parsed);
        try std.testing.expectEqual(@as(u16, 200), head.status);
        try std.testing.expect(!started);
        // the backend sends its final response only after consuming all bytes;
        // joins synchronize the digests and any fixture errors before inspection.
        server.join();
        server_joined = true;
        producer.join();
        producer_joined = true;
        if (fixture.producer_error) |err| return err;
        if (fixture.upstream_error) |err| return err;
        try std.testing.expectEqualSlices(u8, &fixture.sent_digest, &fixture.received_digest);
    }
}

test "http1 upload accepts early rejection without waiting for a stalled client body" {
    const client = try UploadFixture.pair();
    defer for (client) |fd| platform.posix.close(fd);
    const upstream = try UploadFixture.pair();
    defer for (upstream) |fd| platform.posix.close(fd);
    var connection: exchange.StreamingConnection = .{ .connection = .{ .bare = upstream[0] }, .timeout_ms = 100 };
    var started = false;
    var downstream: response.Downstream = .{ .fd = client[0], .timeout_ms = 100, .started = &started };
    const headers = "POST /upload HTTP/1.1\r\nHost: app.test\r\nContent-Length: 2097152\r\n\r\n";
    const parsed = (try http.parseRequestHead(headers)).?;
    try UploadFixture.wire(upstream[1]).writeAll("HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n");
    const head = try sendAndReadHead(&connection, &downstream, headers, "", parsed);
    try std.testing.expectEqual(@as(u16, 413), head.status);
    try std.testing.expect(!started);
}

test "http1 upload cancellation and stalled bodies return within the operation deadline" {
    const client = try UploadFixture.pair();
    defer for (client) |fd| platform.posix.close(fd);
    const upstream = try UploadFixture.pair();
    defer for (upstream) |fd| platform.posix.close(fd);
    var connection: exchange.StreamingConnection = .{ .connection = .{ .bare = upstream[0] }, .timeout_ms = 20 };
    var started = false;
    var downstream: response.Downstream = .{ .fd = client[0], .timeout_ms = 20, .started = &started };
    const headers = "POST /upload HTTP/1.1\r\nHost: app.test\r\nContent-Length: 8\r\n\r\n";
    const parsed = (try http.parseRequestHead(headers)).?;
    try std.testing.expectError(error.TimedOut, sendAndReadHead(&connection, &downstream, headers, "", parsed));
    _ = std.os.linux.shutdown(client[1], 1);
    try std.testing.expectError(error.IncompleteRequestBody, sendAndReadHead(&connection, &downstream, headers, "", parsed));
}
