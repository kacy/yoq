// http_client — simple blocking HTTP/1.1 client
//
// one TCP connection per request. used by agents to communicate with
// the cluster server API. no keep-alive, no pipelining — management
// plane traffic is low volume so simplicity wins.
//
// extracted from the pattern in cmdClusterStatus (main.zig) to avoid
// duplicating socket setup code across agent operations.

const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const Allocator = std.mem.Allocator;

pub const RequestOptions = struct {
    deadline_ms: ?i64 = null,
    canceled: ?*const std.atomic.Value(bool) = null,

    pub fn check(self: RequestOptions) HttpClientError!void {
        if (self.canceled) |flag| if (flag.load(.acquire)) return error.Canceled;
        if (self.deadline_ms) |deadline| if (nowMilliseconds() >= deadline) return error.RequestTimeout;
    }
};

fn nowMilliseconds() i64 {
    return std.Io.Clock.awake.now(std.Options.debug_io).toMilliseconds();
}

pub const HttpClientError = error{
    Canceled,
    RequestTimeout,
    OutOfMemory,
    /// TCP connection to the server could not be established
    ConnectFailed,
    /// failed to write the HTTP request to the socket
    SendFailed,
    /// request headers or body exceed the client limit
    RequestTooLarge,
    /// failed to read any response bytes from the server
    ReceiveFailed,
    /// response body exceeds the 64KB read buffer
    ResponseTooLarge,
    /// response does not start with a valid HTTP status line
    InvalidResponse,
};

pub const Response = struct {
    status_code: u16,
    body: []const u8,
    /// full response buffer (caller frees this)
    raw: []const u8,

    pub fn deinit(self: *Response, alloc: Allocator) void {
        alloc.free(self.raw);
    }
};

/// send an HTTP GET request and return the response.
/// if auth_token is provided, includes an Authorization: Bearer header.
pub fn get(alloc: Allocator, addr: [4]u8, port: u16, path: []const u8) HttpClientError!Response {
    return getWithAuth(alloc, addr, port, path, null);
}

/// send an HTTP GET request with optional bearer token auth.
pub fn getWithAuth(alloc: Allocator, addr: [4]u8, port: u16, path: []const u8, auth_token: ?[]const u8) HttpClientError!Response {
    return getWithOptions(alloc, addr, port, path, auth_token, .{});
}

pub fn getWithOptions(alloc: Allocator, addr: [4]u8, port: u16, path: []const u8, auth_token: ?[]const u8, options: RequestOptions) HttpClientError!Response {
    var req_buf: [1024]u8 = undefined;
    const request = if (auth_token) |token|
        std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {s}\r\n\r\n", .{ path, token }) catch
            return HttpClientError.RequestTooLarge
    else
        std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", .{path}) catch
            return HttpClientError.RequestTooLarge;

    return doRequest(alloc, addr, port, request, options);
}

/// send an HTTP POST request with a body and return the response.
pub fn post(alloc: Allocator, addr: [4]u8, port: u16, path: []const u8, body: []const u8) HttpClientError!Response {
    return postWithAuth(alloc, addr, port, path, body, null);
}

/// send an HTTP POST request with optional bearer token auth.
pub fn postWithAuth(alloc: Allocator, addr: [4]u8, port: u16, path: []const u8, body: []const u8, auth_token: ?[]const u8) HttpClientError!Response {
    return postWithOptions(alloc, addr, port, path, body, auth_token, .{});
}

pub fn postWithOptions(alloc: Allocator, addr: [4]u8, port: u16, path: []const u8, body: []const u8, auth_token: ?[]const u8, options: RequestOptions) HttpClientError!Response {
    try options.check();
    const request = try buildPostRequest(alloc, path, body, auth_token);
    defer alloc.free(request);
    return doRequest(alloc, addr, port, request, options);
}

// ordinary api endpoints accept bodies up to one mebibyte.
const max_post_body_bytes: usize = 1024 * 1024;

fn buildPostRequest(alloc: Allocator, path: []const u8, body: []const u8, auth_token: ?[]const u8) HttpClientError![]u8 {
    if (body.len > max_post_body_bytes) return HttpClientError.RequestTooLarge;
    var header_buf: [2048]u8 = undefined;
    const headers = if (auth_token) |token|
        std.fmt.bufPrint(
            &header_buf,
            "POST {s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {d}\r\nContent-Type: application/json\r\nAuthorization: Bearer {s}\r\n\r\n",
            .{ path, body.len, token },
        ) catch return HttpClientError.RequestTooLarge
    else
        std.fmt.bufPrint(
            &header_buf,
            "POST {s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {d}\r\nContent-Type: application/json\r\n\r\n",
            .{ path, body.len },
        ) catch return HttpClientError.RequestTooLarge;

    // both lengths are bounded before allocation; the body keeps its exact bytes.
    const request = alloc.alloc(u8, headers.len + body.len) catch return HttpClientError.OutOfMemory;
    @memcpy(request[0..headers.len], headers);
    @memcpy(request[headers.len..], body);
    return request;
}

fn doRequest(alloc: Allocator, addr: [4]u8, port: u16, request: []const u8, options: RequestOptions) HttpClientError!Response {
    const started = nowMilliseconds();
    const budget: RequestOptions = .{
        .deadline_ms = @min(options.deadline_ms orelse std.math.maxInt(i64), started + 10_000),
        .canceled = options.canceled,
    };
    try budget.check();
    const fd = linux_platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, 0) catch return error.ConnectFailed;
    defer linux_platform.posix.close(fd);
    const address = linux_platform.net.Address.initIp4(addr, port);
    linux_platform.posix.connect(fd, &address.any, address.getOsSockLen()) catch |err| switch (err) {
        error.ConnectionPending, error.WouldBlock => {
            var connect_budget = budget;
            connect_budget.deadline_ms = @min(budget.deadline_ms.?, started + 5_000);
            try waitReady(fd, posix.POLL.OUT, connect_budget);
            linux_platform.posix.getsockoptError(fd) catch return error.ConnectFailed;
        },
        else => return error.ConnectFailed,
    };
    var sent: usize = 0;
    while (sent < request.len) {
        try budget.check();
        const count = linux_platform.posix.send(fd, request[sent..], posix.MSG.NOSIGNAL) catch |err| switch (err) {
            error.WouldBlock => {
                try waitReady(fd, posix.POLL.OUT, budget);
                continue;
            },
            else => return error.SendFailed,
        };
        if (count == 0) return error.SendFailed;
        sent += count;
    }
    const max_size = 64 * 1024;
    var buffer = alloc.alloc(u8, max_size) catch return error.OutOfMemory;
    errdefer alloc.free(buffer);
    var used: usize = 0;
    while (used < buffer.len) {
        const count = try readBytes(fd, buffer[used..], budget);
        if (count == 0) break;
        used += count;
    }
    if (used == buffer.len) {
        var extra: [1]u8 = undefined;
        if (try readBytes(fd, &extra, budget) != 0) return error.ResponseTooLarge;
    }
    if (used == 0) return error.ReceiveFailed;
    if (alloc.resize(buffer, used)) buffer = buffer[0..used];
    return parseResponse(buffer[0..used], buffer) catch return error.InvalidResponse;
}

fn readBytes(fd: posix.fd_t, buffer: []u8, options: RequestOptions) HttpClientError!usize {
    while (true) {
        try options.check();
        return linux_platform.posix.recv(fd, buffer, 0) catch |err| switch (err) {
            error.WouldBlock => {
                try waitReady(fd, posix.POLL.IN, options);
                continue;
            },
            else => error.ReceiveFailed,
        };
    }
}

fn waitReady(fd: posix.fd_t, events: i16, options: RequestOptions) HttpClientError!void {
    while (true) {
        try options.check();
        const remaining = options.deadline_ms.? - nowMilliseconds();
        if (remaining <= 0) return error.RequestTimeout;
        // short waits observe shutdown even when the remote server stays silent.
        const milliseconds = @min(remaining, 100);
        const timeout: posix.timespec = .{ .sec = 0, .nsec = milliseconds * std.time.ns_per_ms };
        var fds = [_]posix.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
        const ready = posix.ppoll(&fds, &timeout, null) catch |err| switch (err) {
            error.SignalInterrupt => continue,
            else => return error.ReceiveFailed,
        };
        if (ready == 0) continue;
        if (fds[0].revents & posix.POLL.NVAL != 0) return error.ReceiveFailed;
        if (fds[0].revents & (events | posix.POLL.HUP | posix.POLL.ERR) != 0) return;
    }
}

fn writeAll(fd: linux_platform.posix.socket_t, data: []const u8) !void {
    var total: usize = 0;
    while (total < data.len) {
        const written = linux_platform.posix.write(fd, data[total..]) catch return error.WriteFailed;
        if (written == 0) return error.WriteFailed;
        total += written;
    }
}

fn parseStatusCode(response: []const u8) !u16 {
    // "HTTP/1.1 200 OK\r\n" — status code starts at offset 9
    if (response.len < 12) return error.InvalidResponse;
    if (!std.mem.startsWith(u8, response, "HTTP/")) return error.InvalidResponse;

    // find the space after HTTP/1.1
    const first_space = std.mem.indexOf(u8, response, " ") orelse return error.InvalidResponse;
    const status_start = first_space + 1;
    if (status_start + 3 > response.len) return error.InvalidResponse;

    return std.fmt.parseInt(u16, response[status_start .. status_start + 3], 10) catch
        return error.InvalidResponse;
}

fn parseResponse(response: []const u8, raw: []const u8) !Response {
    const status_code = try parseStatusCode(response);
    const body = if (std.mem.indexOf(u8, response, "\r\n\r\n")) |pos|
        raw[pos + 4 .. response.len]
    else
        raw[response.len..response.len];

    return .{
        .status_code = status_code,
        .body = body,
        .raw = raw,
    };
}

// -- tests --

test "parseStatusCode extracts 200" {
    const code = try parseStatusCode("HTTP/1.1 200 OK\r\n");
    try std.testing.expectEqual(@as(u16, 200), code);
}

test "parseStatusCode extracts 404" {
    const code = try parseStatusCode("HTTP/1.1 404 Not Found\r\n");
    try std.testing.expectEqual(@as(u16, 404), code);
}

test "parseStatusCode rejects garbage" {
    try std.testing.expectError(error.InvalidResponse, parseStatusCode("garbage"));
}

test "parseStatusCode rejects empty" {
    try std.testing.expectError(error.InvalidResponse, parseStatusCode(""));
}

test "parseStatusCode extracts 100" {
    const code = try parseStatusCode("HTTP/1.1 100 Continue\r\n");
    try std.testing.expectEqual(@as(u16, 100), code);
}

test "parseStatusCode extracts 500" {
    const code = try parseStatusCode("HTTP/1.1 500 Internal Server Error\r\n");
    try std.testing.expectEqual(@as(u16, 500), code);
}

test "parseResponse extracts body after headers" {
    var raw = "HTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\ntest".*;
    const resp = try parseResponse(raw[0..], raw[0..]);
    try std.testing.expectEqual(@as(u16, 201), resp.status_code);
    try std.testing.expectEqualStrings("test", resp.body);
}

test "parseResponse allows empty body when separator is missing" {
    var raw = "HTTP/1.1 204 No Content\r\n".*;
    const resp = try parseResponse(raw[0..], raw[0..]);
    try std.testing.expectEqual(@as(u16, 204), resp.status_code);
    try std.testing.expectEqual(@as(usize, 0), resp.body.len);
}

test "parseResponse rejects invalid status line" {
    var raw = "not http".*;
    try std.testing.expectError(error.InvalidResponse, parseResponse(raw[0..], raw[0..]));
}

test "http client frees failed responses once and handles the next request" {
    const socket = linux_platform.posix;
    const listener = try socket.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer socket.close(listener);
    var address = linux_platform.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try socket.bind(listener, &address.any, address.getOsSockLen());
    try socket.listen(listener, 8);
    const timeout = posix.timeval{ .sec = 3, .usec = 0 };
    try socket.setsockopt(listener, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    var address_len = address.getOsSockLen();
    try socket.getsockname(listener, &address.any, &address_len);

    const oversized = [_]u8{'x'} ** (64 * 1024 + 1);
    const failures = [_][]const u8{ "", "not an HTTP response", &oversized };
    const healthy = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    const Peer = struct {
        fn serve(fd: posix.fd_t, bad_responses: []const []const u8, good_response: []const u8) void {
            for (bad_responses) |bad| {
                for ([_][]const u8{ bad, good_response }) |response| {
                    const client = linux_platform.posix.accept(fd, null, null, posix.SOCK.CLOEXEC) catch return;
                    defer linux_platform.posix.close(client);
                    var request: [2048]u8 = undefined;
                    _ = linux_platform.posix.read(client, &request) catch return;
                    writeAll(client, response) catch return;
                }
            }
        }
    };
    const thread = try std.Thread.spawn(.{}, Peer.serve, .{ listener, &failures, healthy });
    defer thread.join();
    for ([_]HttpClientError{ error.ReceiveFailed, error.InvalidResponse, error.ResponseTooLarge }) |expected| {
        try std.testing.expectError(expected, get(std.testing.allocator, .{ 127, 0, 0, 1 }, std.mem.bigToNative(u16, address.in.port), "/"));
        var response = try get(std.testing.allocator, .{ 127, 0, 0, 1 }, std.mem.bigToNative(u16, address.in.port), "/");
        defer response.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status_code);
        try std.testing.expectEqualStrings("ok", response.body);
    }
}

test "http client posts a multiline manifest larger than the header buffer over tcp" {
    const socket = linux_platform.posix;
    const listener = try socket.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer socket.close(listener);
    var address = linux_platform.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try socket.bind(listener, &address.any, address.getOsSockLen());
    try socket.listen(listener, 1);
    const timeout = posix.timeval{ .sec = 3, .usec = 0 };
    try socket.setsockopt(listener, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    var address_len = address.getOsSockLen();
    try socket.getsockname(listener, &address.any, &address_len);

    const body = "{\n  \"app_name\": \"demo\",\n  \"notes\": \"" ++ ("manifest payload " ** 512) ++ "\"\n}\n";
    const Peer = struct {
        received: [16 * 1024]u8 = undefined,
        len: usize = 0,

        fn serve(self: *@This(), fd: posix.fd_t, body_len: usize) void {
            const client = linux_platform.posix.accept(fd, null, null, posix.SOCK.CLOEXEC) catch return;
            defer linux_platform.posix.close(client);
            const read_timeout = posix.timeval{ .sec = 3, .usec = 0 };
            posix.setsockopt(client, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&read_timeout)) catch return;
            while (self.len < self.received.len) {
                const count = posix.read(client, self.received[self.len..]) catch return;
                if (count == 0) return;
                self.len += count;
                if (std.mem.indexOf(u8, self.received[0..self.len], "\r\n\r\n")) |end| {
                    if (self.len >= end + 4 + body_len) break;
                }
            }
            writeAll(client, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok") catch return;
        }
    };
    var peer: Peer = .{};
    const thread = try std.Thread.spawn(.{}, Peer.serve, .{ &peer, listener, body.len });
    var response = postWithAuth(std.testing.allocator, .{ 127, 0, 0, 1 }, std.mem.bigToNative(u16, address.in.port), "/apps/apply", body, "operator-token") catch |err| {
        thread.join();
        return err;
    };
    defer response.deinit(std.testing.allocator);
    thread.join();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("ok", response.body);
    const request = peer.received[0..peer.len];
    const end = std.mem.indexOf(u8, request, "\r\n\r\n") orelse return error.MissingRequestHeaders;
    try std.testing.expect(std.mem.startsWith(u8, request, "POST /apps/apply HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, request[0..end], "Authorization: Bearer operator-token") != null);
    var length_buf: [64]u8 = undefined;
    const expected_length = try std.fmt.bufPrint(&length_buf, "Content-Length: {d}\r\n", .{body.len});
    try std.testing.expect(std.mem.indexOf(u8, request[0 .. end + 2], expected_length) != null);
    try std.testing.expectEqualStrings(body, request[end + 4 ..]);
}

test "http client rejects oversized posts before connecting" {
    const body = try std.testing.allocator.alloc(u8, max_post_body_bytes + 1);
    defer std.testing.allocator.free(body);
    @memset(body, 'x');
    try std.testing.expectError(error.RequestTooLarge, post(std.testing.allocator, .{ 127, 0, 0, 1 }, 0, "/apps/apply", body));
    const largest = try buildPostRequest(std.testing.allocator, "/apps/apply", body[0..max_post_body_bytes], null);
    defer std.testing.allocator.free(largest);
    const body_start = (std.mem.indexOf(u8, largest, "\r\n\r\n") orelse return error.MissingRequestHeaders) + 4;
    try std.testing.expectEqualSlices(u8, body[0..max_post_body_bytes], largest[body_start..]);
    const oversized_path = [_]u8{'x'} ** 2048;
    try std.testing.expectError(error.RequestTooLarge, post(std.testing.allocator, .{ 127, 0, 0, 1 }, 0, &oversized_path, ""));
}

test "agent enrollment cancels silent responses and shares an absolute request deadline" {
    const socket = linux_platform.posix;
    const listener = try socket.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer socket.close(listener);
    var address = linux_platform.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try socket.bind(listener, &address.any, address.getOsSockLen());
    try socket.listen(listener, 2);
    const timeout = posix.timeval{ .sec = 3, .usec = 0 };
    try socket.setsockopt(listener, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    var len = address.getOsSockLen();
    try socket.getsockname(listener, &address.any, &len);
    const Peer = struct {
        canceled: ?*std.atomic.Value(bool),
        closed: bool = false,
        received: bool = false,
        fn serve(self: *@This(), fd: posix.fd_t) void {
            const client = linux_platform.posix.accept(fd, null, null, 0) catch return;
            defer linux_platform.posix.close(client);
            const read_timeout = posix.timeval{ .sec = 3, .usec = 0 };
            linux_platform.posix.setsockopt(client, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&read_timeout)) catch return;
            var buffer: [2048]u8 = undefined;
            if ((linux_platform.posix.read(client, &buffer) catch return) == 0) return;
            self.received = true;
            if (self.canceled) |flag| flag.store(true, .release);
            // keep the response silent until the client cancels or times out.
            while (true) {
                if ((linux_platform.posix.read(client, &buffer) catch return) == 0) {
                    self.closed = true;
                    return;
                }
            }
        }
    };
    for ([_]bool{ true, false }) |cancel| {
        var canceled: std.atomic.Value(bool) = .init(false);
        var peer: Peer = .{ .canceled = if (cancel) &canceled else null };
        const thread = try std.Thread.spawn(.{}, Peer.serve, .{ &peer, listener });
        const started = nowMilliseconds();
        const response = getWithOptions(std.testing.allocator, .{ 127, 0, 0, 1 }, std.mem.bigToNative(u16, address.in.port), "/agents", "dummy", .{
            .deadline_ms = started + if (cancel) @as(i64, 2000) else 100,
            .canceled = &canceled,
        });
        thread.join();
        try std.testing.expectError(if (cancel) error.Canceled else error.RequestTimeout, response);
        try std.testing.expect(peer.received and peer.closed);
        try std.testing.expect(nowMilliseconds() - started < 1500);
    }
}
