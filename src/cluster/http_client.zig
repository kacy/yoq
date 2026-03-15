// http_client — simple blocking HTTP/1.1 client
//
// one TCP connection per request. used by agents to communicate with
// the cluster server API. no keep-alive, no pipelining — management
// plane traffic is low volume so simplicity wins.
//
// extracted from the pattern in cmdClusterStatus (main.zig) to avoid
// duplicating socket setup code across agent operations.

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;

pub const HttpClientError = error{
    /// TCP connection to the server could not be established
    ConnectFailed,
    /// failed to write the HTTP request to the socket
    SendFailed,
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
    var req_buf: [1024]u8 = undefined;
    const request = if (auth_token) |token|
        std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {s}\r\n\r\n", .{ path, token }) catch
            return HttpClientError.SendFailed
    else
        std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", .{path}) catch
            return HttpClientError.SendFailed;

    return doRequest(alloc, addr, port, request);
}

/// send an HTTP POST request with a body and return the response.
pub fn post(alloc: Allocator, addr: [4]u8, port: u16, path: []const u8, body: []const u8) HttpClientError!Response {
    return postWithAuth(alloc, addr, port, path, body, null);
}

/// send an HTTP POST request with optional bearer token auth.
pub fn postWithAuth(alloc: Allocator, addr: [4]u8, port: u16, path: []const u8, body: []const u8, auth_token: ?[]const u8) HttpClientError!Response {
    var req_buf: [2048]u8 = undefined;
    const request = if (auth_token) |token|
        std.fmt.bufPrint(
            &req_buf,
            "POST {s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {d}\r\nContent-Type: application/json\r\nAuthorization: Bearer {s}\r\n\r\n{s}",
            .{ path, body.len, token, body },
        ) catch return HttpClientError.SendFailed
    else
        std.fmt.bufPrint(
            &req_buf,
            "POST {s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {d}\r\nContent-Type: application/json\r\n\r\n{s}",
            .{ path, body.len, body },
        ) catch return HttpClientError.SendFailed;

    return doRequest(alloc, addr, port, request);
}

fn doRequest(alloc: Allocator, addr: [4]u8, port: u16, request: []const u8) HttpClientError!Response {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch
        return HttpClientError.ConnectFailed;
    defer posix.close(fd);

    // set timeouts — send timeout must be set before connect() because
    // Linux uses SO_SNDTIMEO as the connect timeout
    const timeout = posix.timeval{ .sec = 5, .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

    // connect
    const sock_addr = std.net.Address.initIp4(addr, port);
    posix.connect(fd, &sock_addr.any, sock_addr.getOsSockLen()) catch
        return HttpClientError.ConnectFailed;

    // send
    _ = posix.write(fd, request) catch
        return HttpClientError.SendFailed;

    // read response
    const max_size: usize = 64 * 1024;
    var buf = alloc.alloc(u8, max_size) catch return HttpClientError.ReceiveFailed;
    errdefer alloc.free(buf);

    var total: usize = 0;
    while (total < buf.len) {
        const bytes_read = posix.read(fd, buf[total..]) catch break;
        if (bytes_read == 0) break;
        total += bytes_read;
    }

    if (total == 0) {
        alloc.free(buf);
        return HttpClientError.ReceiveFailed;
    }

    // shrink to actual size
    if (alloc.resize(buf, total)) {
        buf = buf[0..total];
    }

    // parse status code from first line: "HTTP/1.1 200 OK\r\n"
    const status_code = parseStatusCode(buf[0..total]) catch {
        alloc.free(buf);
        return HttpClientError.InvalidResponse;
    };

    // find body (after \r\n\r\n)
    const body = if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n")) |pos|
        buf[pos + 4 .. total]
    else
        buf[total..total]; // empty body

    return .{
        .status_code = status_code,
        .body = body,
        .raw = buf,
    };
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
