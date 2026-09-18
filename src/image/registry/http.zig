const std = @import("std");
const common = @import("common.zig");

const posix = std.posix;

/// initialize the client clock and trust bundle before applying socket timeouts.
pub fn requestWithTimeout(
    client: *std.http.Client,
    method: std.http.Method,
    uri: std.Uri,
    options: std.http.Client.RequestOptions,
) !std.http.Client.Request {
    var request_options = options;
    // zig's redirect handler does not clear authorization overrides. registry
    // credentials therefore never follow an automatic redirect, even on the
    // same host: a changed port or scheme is a different origin.
    if (request_options.headers.authorization == .override and
        request_options.headers.authorization.override.len > 0)
        request_options.redirect_behavior = .not_allowed;
    // registry callers consume raw body readers and verify blob digests.
    // do not advertise transport encodings that these readers do not decode.
    if (request_options.headers.accept_encoding == .default)
        request_options.headers.accept_encoding = .{ .override = "identity" };
    const request = try client.request(method, uri, request_options);
    setSocketTimeouts(request.connection.?);
    return request;
}

/// copy the location into caller storage so it outlives the response head.
/// registry-relative locations use the registry's https endpoint.
pub fn parseLocationHeader(host: []const u8, head: std.http.Client.Response.Head, buf: []u8) ?[]const u8 {
    var it = head.iterateHeaders();
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "location")) continue;

        const value = header.value;
        if (value.len == 0) continue;

        if (std.mem.startsWith(u8, value, "http://") or
            std.mem.startsWith(u8, value, "https://"))
        {
            return std.fmt.bufPrint(buf, "{s}", .{value}) catch null;
        }

        return std.fmt.bufPrint(buf, "https://{s}{s}", .{ host, value }) catch null;
    }
    return null;
}

fn setSocketTimeouts(conn: *std.http.Client.Connection) void {
    const stream = conn.stream_reader.stream;
    const tv = posix.timeval{ .sec = common.registry_timeout_sec, .usec = 0 };
    const opt_bytes = std.mem.asBytes(&tv);
    posix.setsockopt(stream.socket.handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, opt_bytes) catch {};
    posix.setsockopt(stream.socket.handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, opt_bytes) catch {};
}

/// stop at the cap, including chunked responses and those without a length.
/// read at most one extra byte to detect an oversized body.
pub fn readBody(alloc: std.mem.Allocator, reader: *std.Io.Reader, limit: usize) error{ NetworkError, ResponseTooLarge }![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(alloc);
    var chunk: [8192]u8 = undefined;
    while (true) {
        const remaining = limit - body.items.len;
        const count = reader.readSliceShort(chunk[0..@min(chunk.len, remaining + 1)]) catch return error.NetworkError;
        if (count == 0) break;
        if (count > remaining) return error.ResponseTooLarge;
        body.appendSlice(alloc, chunk[0..count]) catch return error.NetworkError;
    }
    return body.toOwnedSlice(alloc) catch return error.NetworkError;
}

test "registry transfer bounded reader accepts the limit and stops at one extra byte" {
    const alloc = std.testing.allocator;
    var exact = std.Io.Reader.fixed("abcd");
    const body = try readBody(alloc, &exact, 4);
    defer alloc.free(body);
    try std.testing.expectEqualStrings("abcd", body);
    var oversized = std.Io.Reader.fixed("abcdefghi");
    try std.testing.expectError(error.ResponseTooLarge, readBody(alloc, &oversized, 4));
    try std.testing.expectEqual(@as(usize, 5), oversized.seek);
}

test "parseLocationHeader copies absolute locations" {
    const response_bytes = "HTTP/1.1 202 Accepted\r\n" ++
        "Location: https://registry.example.io/v2/myrepo/blobs/uploads/uuid-123\r\n" ++
        "Content-Length: 0\r\n\r\n";

    var location_buf: [8192]u8 = undefined;
    const head = try std.http.Client.Response.Head.parse(response_bytes);
    const location = parseLocationHeader("registry.example.io", head, &location_buf) orelse return error.ExpectedLocation;
    try std.testing.expectEqualStrings(
        "https://registry.example.io/v2/myrepo/blobs/uploads/uuid-123",
        location,
    );
}

test "parseLocationHeader — relative URL gets host prepended" {
    const response_bytes = "HTTP/1.1 202 Accepted\r\n" ++
        "Location: /v2/myrepo/blobs/uploads/uuid-456\r\n" ++
        "Content-Length: 0\r\n\r\n";

    var location_buf: [8192]u8 = undefined;
    const head = try std.http.Client.Response.Head.parse(response_bytes);
    const location = parseLocationHeader("registry.example.io", head, &location_buf) orelse return error.ExpectedLocation;
    try std.testing.expectEqualStrings(
        "https://registry.example.io/v2/myrepo/blobs/uploads/uuid-456",
        location,
    );
}

test "parseLocationHeader — missing header returns null" {
    const response_bytes = "HTTP/1.1 202 Accepted\r\n" ++
        "Content-Length: 0\r\n\r\n";

    var location_buf: [8192]u8 = undefined;
    const head = try std.http.Client.Response.Head.parse(response_bytes);
    try std.testing.expect(parseLocationHeader("registry.example.io", head, &location_buf) == null);
}

test "parseLocationHeader keeps locations after response storage is reused" {
    var response_bytes = ("HTTP/1.1 202 Accepted\r\n" ++
        "Location: https://registry.example.io/upload?id=123\r\n" ++
        "Content-Length: 0\r\n\r\n").*;
    const head = try std.http.Client.Response.Head.parse(&response_bytes);
    var location_buf: [128]u8 = undefined;
    const location = parseLocationHeader("registry.example.io", head, &location_buf) orelse return error.ExpectedLocation;
    @memset(&response_bytes, 'x');
    try std.testing.expectEqualStrings("https://registry.example.io/upload?id=123", location);
}

test "parseLocationHeader keeps separate results in caller buffers" {
    const head = try std.http.Client.Response.Head.parse("HTTP/1.1 202 Accepted\r\nLocation: /upload\r\n\r\n");
    var first_buf: [128]u8 = undefined;
    var second_buf: [128]u8 = undefined;
    const first = parseLocationHeader("first.example.io", head, &first_buf) orelse return error.ExpectedLocation;
    const second = parseLocationHeader("second.example.io", head, &second_buf) orelse return error.ExpectedLocation;
    try std.testing.expectEqualStrings("https://first.example.io/upload", first);
    try std.testing.expectEqualStrings("https://second.example.io/upload", second);
}

test "parseLocationHeader rejects locations that do not fit caller storage" {
    for ([_][]const u8{
        "HTTP/1.1 202 Accepted\r\nLocation: https://registry.example.io/upload\r\n\r\n",
        "HTTP/1.1 202 Accepted\r\nLocation: /upload\r\n\r\n",
    }) |response_bytes| {
        const head = try std.http.Client.Response.Head.parse(response_bytes);
        var buf: [4]u8 = undefined;
        try std.testing.expect(parseLocationHeader("registry.example.io", head, &buf) == null);
    }
}

test "registry authenticated request methods refuse redirects before contacting another origin" {
    const Server = @import("test_support.zig").Server;
    const alloc = std.testing.allocator;
    for ([_]std.http.Method{ .GET, .HEAD, .POST, .PUT }) |method| {
        for ([_][]const u8{ "Basic ZHVtbXk6cGFzcw==", "Bearer dummy-token" }) |authorization| {
            var target = try Server.init(&.{.{}});
            defer target.deinit();
            try target.start();
            var target_host: [64]u8 = undefined;
            var location_buffer: [160]u8 = undefined;
            const location = try std.fmt.bufPrint(&location_buffer, "Location: http://{s}/foreign\r\n", .{try target.host(&target_host)});
            var source = try Server.init(&.{.{ .status = "302 Found", .headers = location }});
            defer source.deinit();
            try source.start();
            var source_host: [64]u8 = undefined;
            var url_buffer: [160]u8 = undefined;
            const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buffer, "http://{s}/registry", .{try source.host(&source_host)}));
            var client: std.http.Client = .{ .io = std.testing.io, .allocator = alloc };
            defer client.deinit();
            var request = try requestWithTimeout(&client, method, uri, .{
                .redirect_behavior = @enumFromInt(3),
                .keep_alive = false,
                .headers = .{ .authorization = .{ .override = authorization } },
            });
            defer request.deinit();
            if (method == .POST or method == .PUT) try request.sendBodyComplete(&.{}) else try request.sendBodiless();
            var redirects: [1024]u8 = undefined;
            try std.testing.expectError(error.TooManyHttpRedirects, request.receiveHead(&redirects));
            source.worker.?.join();
            source.worker = null;
            const received = source.last_request[0..source.last_request_length];
            try std.testing.expectEqualStrings(authorization, @import("../../api/http.zig").findHeaderValue(received, "Authorization").?);
            _ = std.os.linux.shutdown(target.fd, 2);
            target.worker.?.join();
            target.worker = null;
            try std.testing.expectEqual(@as(usize, 0), target.requests);
        }
    }
}
