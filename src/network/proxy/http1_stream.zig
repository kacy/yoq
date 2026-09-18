const std = @import("std");
const platform = @import("linux_platform");
const posix = std.posix;
const exchange = @import("upstream_exchange.zig");
const transport = @import("../../tls/client_transport.zig");
const http = @import("../../api/http.zig");

pub const max_header_bytes = 32 * 1024;
const buffer_size = 16 * 1024;

pub const Head = struct {
    bytes: [max_header_bytes]u8 = undefined,
    used: usize = 0,
    end: usize = 0,
    status: u16 = 0,
    framing: exchange.BodyFraming = .empty,

    informational: u8 = 0,

    pub fn read(connection: *exchange.StreamingConnection, client_fd: posix.fd_t, head_request: bool) !Head {
        const previous_deadline = connection.operation_deadline;
        connection.operation_deadline = transport.Deadline.afterMilliseconds(connection.timeout_ms);
        defer connection.operation_deadline = previous_deadline;
        var result: Head = .{};
        while (!try result.readAvailable(connection, head_request)) try waitReadable(connection, client_fd);
        return result;
    }

    // preserve a partial response head while an upload continues in the other
    // direction. informational responses are bounded and never become final.
    pub fn readAvailable(self: *Head, connection: *exchange.StreamingConnection, head_request: bool) !bool {
        while (true) {
            if (std.mem.indexOf(u8, self.bytes[0..self.used], "\r\n\r\n")) |index| {
                self.end = index + 4;
                self.status = try exchange.parseResponseStatusLine(self.bytes[0..self.end]);
                if (self.status >= 100 and self.status < 200 and self.status != 101) {
                    self.informational += 1;
                    if (self.informational > 16) return error.InvalidResponse;
                    std.mem.copyForwards(u8, &self.bytes, self.bytes[self.end..self.used]);
                    self.used -= self.end;
                    continue;
                }
                self.framing = try exchange.responseBodyFraming(self.bytes[0..self.end], self.status, head_request);
                return true;
            }
            if (self.used == self.bytes.len) return error.ResponseTooLarge;
            const count = (try connection.readAvailable(self.bytes[self.used..])) orelse return false;
            if (count == 0) return error.InvalidResponse;
            self.used += count;
        }
    }
};

pub const Downstream = struct {
    fd: posix.fd_t,
    timeout_ms: u32,
    started: *bool,

    pub fn writeAll(self: *Downstream, bytes: []const u8) !void {
        if (bytes.len == 0) return;
        self.started.* = true;
        (transport.Stream{ .fd = self.fd, .deadline = transport.Deadline.afterMilliseconds(self.timeout_ms) }).writeAll(bytes) catch return error.ClientClosed;
    }
};

pub const Reader = struct {
    connection: *exchange.StreamingConnection,
    client_fd: posix.fd_t,
    prefetched: []const u8,

    pub fn read(self: *Reader, bytes: []u8) !usize {
        if (self.prefetched.len > 0) {
            const count = @min(bytes.len, self.prefetched.len);
            @memcpy(bytes[0..count], self.prefetched[0..count]);
            self.prefetched = self.prefetched[count..];
            return count;
        }
        try waitReadable(self.connection, self.client_fd);
        return self.connection.read(bytes);
    }
};

fn waitReadable(connection: *exchange.StreamingConnection, client_fd: posix.fd_t) !void {
    if (connection.buffered()) return;
    const deadline = connection.operation_deadline orelse transport.Deadline.afterMilliseconds(connection.timeout_ms);
    while (true) {
        var fds = [_]posix.pollfd{
            .{ .fd = connection.fd(), .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = client_fd, .events = 0, .revents = 0 },
        };
        const milliseconds = try deadline.remaining();
        const timeout: posix.timespec = .{ .sec = @divTrunc(milliseconds, 1000), .nsec = @rem(milliseconds, 1000) * std.time.ns_per_ms };
        const count = posix.ppoll(&fds, &timeout, null) catch |err| switch (err) {
            error.SignalInterrupt => continue,
            else => return error.ReceiveFailed,
        };
        if (count == 0) return error.TimedOut;
        if (fds[1].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) return error.ClientClosed;
        if (fds[0].revents != 0) return;
    }
}

// ordinary responses close after one request; upgrades retain their handshake.
pub fn writeHead(writer: anytype, head: *const Head, http10: bool) !void {
    if (http10 and head.framing == .chunked) {
        // removing chunk framing cannot also remove another transfer coding.
        // reject before the first downstream byte rather than corrupt the body.
        var headers = std.mem.splitSequence(u8, head.bytes[0..head.end], "\r\n");
        while (headers.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            if (!std.ascii.eqlIgnoreCase(line[0..colon], "Transfer-Encoding")) continue;
            if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[colon + 1 ..], " \t"), "chunked")) return error.InvalidResponse;
        }
    }
    var lines = std.mem.splitSequence(u8, head.bytes[0..head.end], "\r\n");
    const status_line = lines.next() orelse return error.InvalidResponse;
    if (http10 and std.mem.startsWith(u8, status_line, "HTTP/1.1")) {
        try writer.writeAll("HTTP/1.0");
        try writer.writeAll(status_line[8..]);
    } else try writer.writeAll(status_line);
    try writer.writeAll("\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidResponse;
        const name = line[0..colon];
        if (head.framing != .upgrade and std.ascii.eqlIgnoreCase(name, "Connection")) continue;
        if (http10 and head.framing == .chunked and std.ascii.eqlIgnoreCase(name, "Transfer-Encoding")) continue;
        try writer.writeAll(line);
        try writer.writeAll("\r\n");
    }
    if (head.framing != .upgrade) try writer.writeAll("Connection: close\r\n");
    try writer.writeAll("\r\n");
}

pub fn copyBody(reader: anytype, writer: anytype, framing: exchange.BodyFraming, preserve_chunks: bool) !void {
    switch (framing) {
        .empty => {},
        .upgrade => return error.UnsupportedUpgrade,
        .fixed => |length| try copyExact(reader, writer, length),
        .eof => {
            var buffer: [buffer_size]u8 = undefined;
            while (true) {
                const count = try reader.read(&buffer);
                if (count == 0) return;
                try writer.writeAll(buffer[0..count]);
            }
        },
        .chunked => {
            var line_buffer: [1024]u8 = undefined;
            while (true) {
                const line = try readLine(reader, &line_buffer);
                const semicolon = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
                for (line) |byte| if (byte < 0x20 or byte == 0x7f) return error.InvalidResponse;
                const digits = line[0..semicolon];
                if (digits.len == 0) return error.InvalidResponse;
                for (digits) |digit| _ = std.fmt.charToDigit(digit, 16) catch return error.InvalidResponse;
                const size = std.fmt.parseInt(usize, digits, 16) catch return error.InvalidResponse;
                if (preserve_chunks) {
                    try writer.writeAll(line);
                    try writer.writeAll("\r\n");
                }
                if (size == 0) {
                    var trailer_bytes: usize = 0;
                    while (true) {
                        const trailer = try readLine(reader, &line_buffer);
                        trailer_bytes += trailer.len + 2;
                        if (trailer_bytes > max_header_bytes) return error.ResponseTooLarge;
                        if (trailer.len > 0 and std.mem.indexOfScalar(u8, trailer, ':') == null) return error.InvalidResponse;
                        if (preserve_chunks) {
                            try writer.writeAll(trailer);
                            try writer.writeAll("\r\n");
                        }
                        if (trailer.len == 0) return;
                    }
                }
                try copyExact(reader, writer, size);
                const terminator = try readLine(reader, &line_buffer);
                if (terminator.len != 0) return error.InvalidResponse;
                if (preserve_chunks) try writer.writeAll("\r\n");
            }
        },
    }
}

fn copyExact(reader: anytype, writer: anytype, length: usize) !void {
    var remaining = length;
    var buffer: [buffer_size]u8 = undefined;
    while (remaining > 0) {
        const count = try reader.read(buffer[0..@min(remaining, buffer.len)]);
        if (count == 0) return error.InvalidResponse;
        try writer.writeAll(buffer[0..count]);
        remaining -= count;
    }
}

fn readLine(reader: anytype, buffer: []u8) ![]const u8 {
    var used: usize = 0;
    while (used < buffer.len) {
        if (try reader.read(buffer[used..][0..1]) == 0) return error.InvalidResponse;
        used += 1;
        if (used >= 2 and std.mem.eql(u8, buffer[used - 2 .. used], "\r\n")) return buffer[0 .. used - 2];
    }
    return error.ResponseTooLarge;
}

pub fn isWebSocket(headers: []const u8) bool {
    const upgrade = http.findHeaderValue(headers, "Upgrade") orelse return false;
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade, " \t"), "websocket")) return false;
    const connection = http.findHeaderValue(headers, "Connection") orelse return false;
    var tokens = std.mem.splitScalar(u8, connection, ',');
    while (tokens.next()) |token| if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), "upgrade")) return true;
    return false;
}

// one worker owns both directions, including tls state. each chunk is written
// before another is read, which bounds memory when either peer is slow.
pub fn tunnel(connection: *exchange.StreamingConnection, downstream: *Downstream, prefetched: []const u8) !void {
    try downstream.writeAll(prefetched);
    var buffer: [buffer_size]u8 = undefined;
    while (true) {
        var fds = [_]posix.pollfd{
            .{ .fd = connection.fd(), .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = downstream.fd, .events = posix.POLL.IN, .revents = 0 },
        };
        const pending = connection.buffered();
        const ready = try posix.poll(&fds, if (pending) 0 else @intCast(@min(connection.timeout_ms, std.math.maxInt(i32))));
        if (ready == 0 and !pending) return error.TimedOut;
        if (fds[1].revents != 0) {
            const count = (transport.Stream{ .fd = downstream.fd, .deadline = transport.Deadline.afterMilliseconds(connection.timeout_ms) }).read(&buffer) catch return error.ClientClosed;
            if (count == 0) return;
            try connection.writeAll(buffer[0..count]);
        }
        if (pending or fds[0].revents != 0) {
            const count = try connection.read(&buffer);
            if (count == 0) return;
            try downstream.writeAll(buffer[0..count]);
        }
    }
}

const TestReader = struct {
    bytes: []const u8,
    consumed: usize = 0,
    pub fn read(self: *@This(), buffer: []u8) !usize {
        const count = @min(buffer.len, self.bytes.len);
        @memcpy(buffer[0..count], self.bytes[0..count]);
        self.bytes = self.bytes[count..];
        self.consumed += count;
        return count;
    }
};

test "http1 streaming preserves chunk framing and decodes it for http1.0" {
    const encoded = "3;name=value\r\nabc\r\n2\r\nde\r\n0\r\nX-Result: done\r\n\r\n";
    for ([_]bool{ true, false }) |preserve| {
        var reader = TestReader{ .bytes = encoded ++ "next response" };
        var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer output.deinit();
        try copyBody(&reader, &output.writer, .chunked, preserve);
        try std.testing.expectEqualStrings(if (preserve) encoded else "abcde", output.written());
        try std.testing.expectEqualStrings("next response", reader.bytes);
    }
}

test "http1 streaming bounds body buffers and stops reading after a failed client write" {
    const Source = struct {
        remaining: usize = 2 * 1024 * 1024,
        consumed: usize = 0,
        pub fn read(self: *@This(), bytes: []u8) !usize {
            try std.testing.expect(bytes.len <= buffer_size);
            const count = @min(bytes.len, self.remaining);
            @memset(bytes[0..count], 'x');
            self.remaining -= count;
            self.consumed += count;
            return count;
        }
    };
    const Sink = struct {
        count: usize = 0,
        fail_after: usize = std.math.maxInt(usize),
        pub fn writeAll(self: *@This(), bytes: []const u8) !void {
            if (self.count >= self.fail_after) return error.ClientClosed;
            self.count += bytes.len;
        }
    };
    var source: Source = .{};
    var sink: Sink = .{};
    try copyBody(&source, &sink, .{ .fixed = source.remaining }, true);
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024), sink.count);
    source = .{};
    sink = .{ .fail_after = buffer_size };
    try std.testing.expectError(error.ClientClosed, copyBody(&source, &sink, .eof, true));
    try std.testing.expectEqual(@as(usize, buffer_size * 2), source.consumed);
}

test "http1 streaming rejects incomplete and malformed bodies" {
    for ([_][]const u8{ "z\r\n", "1\r\na!\r\n0\r\n\r\n", "0\r\nmissing-colon\r\n\r\n", "3\r\nab" }) |bytes| {
        var reader = TestReader{ .bytes = bytes };
        var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
        defer output.deinit();
        try std.testing.expectError(error.InvalidResponse, copyBody(&reader, &output.writer, .chunked, true));
    }
    var reader = TestReader{ .bytes = "short" };
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try std.testing.expectError(error.InvalidResponse, copyBody(&reader, &output.writer, .{ .fixed = 6 }, true));
}

fn testPair() ![2]posix.fd_t {
    var sockets: [2]posix.fd_t = undefined;
    if (std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &sockets) != 0) return error.SkipZigTest;
    return sockets;
}

fn expectSocketBytes(socket: posix.fd_t, expected: []const u8) !void {
    var bytes: [128]u8 = undefined;
    var used: usize = 0;
    const wire = transport.Stream{ .fd = socket, .deadline = transport.Deadline.afterMilliseconds(1000) };
    while (used < expected.len) {
        const count = try wire.read(bytes[used..expected.len]);
        if (count == 0) return error.UnexpectedEof;
        used += count;
    }
    try std.testing.expectEqualStrings(expected, bytes[0..used]);
}

test "http1 websocket tunnel relays both directions and stops when the client closes" {
    const upstream = try testPair();
    defer for (upstream) |fd| platform.posix.close(fd);
    const client = try testPair();
    defer for (client) |fd| platform.posix.close(fd);
    const Fixture = struct {
        connection: exchange.StreamingConnection,
        fd: posix.fd_t,
        failed: bool = false,
        fn run(self: *@This()) void {
            var started = false;
            var writer = Downstream{ .fd = self.fd, .timeout_ms = 1000, .started = &started };
            tunnel(&self.connection, &writer, "early frame") catch {
                self.failed = true;
            };
        }
    };
    var fixture = Fixture{ .connection = .{ .connection = .{ .bare = upstream[0] }, .timeout_ms = 1000 }, .fd = client[0] };
    const worker = try std.Thread.spawn(.{}, Fixture.run, .{&fixture});
    var joined = false;
    defer if (!joined) {
        _ = std.os.linux.shutdown(client[1], 2);
        worker.join();
    };
    try expectSocketBytes(client[1], "early frame");
    try (transport.Stream{ .fd = client[1], .deadline = transport.Deadline.afterMilliseconds(1000) }).writeAll("client frame");
    try expectSocketBytes(upstream[1], "client frame");
    try (transport.Stream{ .fd = upstream[1], .deadline = transport.Deadline.afterMilliseconds(1000) }).writeAll("server frame");
    try expectSocketBytes(client[1], "server frame");
    _ = std.os.linux.shutdown(client[1], 2);
    worker.join();
    joined = true;
    try std.testing.expect(!fixture.failed);
}

test "http1 event stream reaches the client before the terminating chunk" {
    const upstream = try testPair();
    defer for (upstream) |fd| platform.posix.close(fd);
    const client = try testPair();
    defer for (client) |fd| platform.posix.close(fd);
    const Fixture = struct {
        connection: exchange.StreamingConnection,
        fd: posix.fd_t,
        failed: bool = false,
        fn run(self: *@This()) void {
            self.forward() catch {
                self.failed = true;
            };
        }
        fn forward(self: *@This()) !void {
            var started = false;
            var writer = Downstream{ .fd = self.fd, .timeout_ms = 1000, .started = &started };
            const head = try Head.read(&self.connection, self.fd, false);
            try writeHead(&writer, &head, false);
            var reader = Reader{ .connection = &self.connection, .client_fd = self.fd, .prefetched = head.bytes[head.end..head.used] };
            try copyBody(&reader, &writer, head.framing, true);
        }
    };
    var fixture = Fixture{ .connection = .{ .connection = .{ .bare = upstream[0] }, .timeout_ms = 1000 }, .fd = client[0] };
    const worker = try std.Thread.spawn(.{}, Fixture.run, .{&fixture});
    var joined = false;
    defer if (!joined) {
        _ = std.os.linux.shutdown(client[1], 2);
        worker.join();
    };
    const wire = transport.Stream{ .fd = upstream[1], .deadline = transport.Deadline.afterMilliseconds(1000) };
    try wire.writeAll("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n");
    try expectSocketBytes(client[1], "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nfirst\r\n");
    try wire.writeAll("6\r\nsecond\r\n0\r\n\r\n");
    try expectSocketBytes(client[1], "6\r\nsecond\r\n0\r\n\r\n");
    worker.join();
    joined = true;
    try std.testing.expect(!fixture.failed);
}

test "http1.0 streaming refuses stacked transfer codings before writing response bytes" {
    const bytes = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
    var head: Head = .{ .end = bytes.len, .used = bytes.len, .status = 200, .framing = .chunked };
    @memcpy(head.bytes[0..bytes.len], bytes);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try std.testing.expectError(error.InvalidResponse, writeHead(&output.writer, &head, true));
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}
