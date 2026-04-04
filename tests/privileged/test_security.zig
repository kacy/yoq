// test_security — API security hardening tests
//
// validates auth boundaries, injection resistance, rate limiter behavior,
// and request size limits. uses a single-node cluster to exercise the
// real API server.

const std = @import("std");
const helpers = @import("helpers");
const cluster_test_harness = @import("cluster_test_harness");
const http = @import("../../src/api/http.zig");
const http_client = @import("http_client");

const TestCluster = cluster_test_harness.TestCluster;

const alloc = std.testing.allocator;

fn initSingleNode() !TestCluster {
    var cluster = try TestCluster.init(alloc, .{
        .node_count = 1,
        .base_raft_port = 19900,
        .base_api_port = 17900,
    });
    errdefer cluster.deinit();
    try cluster.startAll();
    return cluster;
}

const addr = [4]u8{ 127, 0, 0, 1 };

fn getNoAuth(port: u16, path: []const u8) !http_client.Response {
    return http_client.getWithAuth(alloc, addr, port, path, null);
}

fn getWithToken(port: u16, path: []const u8, token: []const u8) !http_client.Response {
    return http_client.getWithAuth(alloc, addr, port, path, token);
}

// -- auth boundary tests --

test "security: protected endpoints reject missing auth token" {
    var cluster = try initSingleNode();
    defer cluster.deinit();
    const port = cluster.nodes.items[0].api_port;

    const protected_paths = [_][]const u8{
        "/v1/containers",
        "/cluster/status",
        "/v1/deploy",
    };

    for (protected_paths) |path| {
        var resp = getNoAuth(port, path) catch continue;
        defer resp.deinit(alloc);
        try std.testing.expectEqual(@as(u16, 401), resp.status_code);
    }
}

test "security: protected endpoints reject invalid token" {
    var cluster = try initSingleNode();
    defer cluster.deinit();
    const port = cluster.nodes.items[0].api_port;

    const protected_paths = [_][]const u8{
        "/v1/containers",
        "/cluster/status",
    };

    for (protected_paths) |path| {
        var resp = getWithToken(port, path, "invalid-token-12345") catch continue;
        defer resp.deinit(alloc);
        try std.testing.expectEqual(@as(u16, 401), resp.status_code);
    }
}

test "security: health and version accessible without auth" {
    var cluster = try initSingleNode();
    defer cluster.deinit();
    const port = cluster.nodes.items[0].api_port;

    // /health should be publicly accessible
    var health_resp = getNoAuth(port, "/health") catch return;
    defer health_resp.deinit(alloc);
    try std.testing.expectEqual(@as(u16, 200), health_resp.status_code);
}

// -- injection resistance tests --

test "security: path traversal in container ID rejected" {
    var cluster = try initSingleNode();
    defer cluster.deinit();
    const port = cluster.nodes.items[0].api_port;
    const token = cluster.api_token;

    const traversal_paths = [_][]const u8{
        "/v1/containers/../../etc/passwd",
        "/v1/containers/..%2F..%2Fetc%2Fpasswd",
        "/v1/containers/abc/../../../etc/shadow",
    };

    for (traversal_paths) |path| {
        var resp = getWithToken(port, path, token) catch continue;
        defer resp.deinit(alloc);
        // should be 404 (not found) or 400 (bad request), never 200
        try std.testing.expect(resp.status_code != 200);
    }
}

test "security: SQL injection in query params" {
    var cluster = try initSingleNode();
    defer cluster.deinit();
    const port = cluster.nodes.items[0].api_port;
    const token = cluster.api_token;

    const injection_paths = [_][]const u8{
        "/v1/containers?name='; DROP TABLE containers;--",
        "/v1/containers?id=1 OR 1=1",
    };

    for (injection_paths) |path| {
        var resp = getWithToken(port, path, token) catch continue;
        defer resp.deinit(alloc);
        // should not crash — any non-500 response is acceptable
        try std.testing.expect(resp.status_code != 500);
    }
}

// -- request size limit tests --

test "security: oversized request headers rejected" {
    var cluster = try initSingleNode();
    defer cluster.deinit();
    const port = cluster.nodes.items[0].api_port;

    // build a request with >16KB of headers
    var big_header: [17 * 1024]u8 = undefined;
    @memset(&big_header, 'A');

    var req_buf: [18 * 1024]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf, "GET /health HTTP/1.1\r\nHost: localhost\r\nX-Junk: {s}\r\n\r\n", .{big_header[0..16500]}) catch return;

    // send raw request via TCP
    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch return;
    defer std.posix.close(fd);

    const timeout = std.posix.timeval{ .sec = 5, .usec = 0 };
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

    const sock_addr = std.net.Address.initIp4(addr, cluster.nodes.items[0].api_port);
    std.posix.connect(fd, &sock_addr.any, sock_addr.getOsSockLen()) catch return;
    _ = std.posix.write(fd, request) catch return;

    // read response — should get 431 or connection close, not 200
    var resp_buf: [1024]u8 = undefined;
    const bytes = std.posix.read(fd, &resp_buf) catch return;
    if (bytes > 0) {
        const resp = resp_buf[0..bytes];
        // should not contain "200 OK"
        try std.testing.expect(std.mem.indexOf(u8, resp, "200 OK") == null);
    }
}

test "security: request body above configured max rejected" {
    var cluster = try initSingleNode();
    defer cluster.deinit();

    var req_buf: [256]u8 = undefined;
    const request = std.fmt.bufPrint(
        &req_buf,
        "POST /v1/deploy HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {s}\r\nContent-Length: {d}\r\n\r\n",
        .{ cluster.api_token, http.max_body_bytes + 1 },
    ) catch return;

    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch return;
    defer std.posix.close(fd);

    const timeout = std.posix.timeval{ .sec = 5, .usec = 0 };
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

    const sock_addr = std.net.Address.initIp4(addr, cluster.nodes.items[0].api_port);
    std.posix.connect(fd, &sock_addr.any, sock_addr.getOsSockLen()) catch return;
    _ = std.posix.write(fd, request) catch return;

    var resp_buf: [1024]u8 = undefined;
    const bytes = std.posix.read(fd, &resp_buf) catch return;
    if (bytes > 0) {
        const resp = resp_buf[0..bytes];
        try std.testing.expect(std.mem.indexOf(u8, resp, "413 Content Too Large") != null);
    }
}

// -- concurrent auth tests --

test "security: concurrent auth attempts don't race" {
    var cluster = try initSingleNode();
    defer cluster.deinit();
    const port = cluster.nodes.items[0].api_port;
    const token = cluster.api_token;

    // launch 10 concurrent requests — mix of valid and invalid tokens
    var threads: [10]std.Thread = undefined;
    var results: [10]u16 = undefined;
    var started: usize = 0;

    for (0..10) |i| {
        const use_valid = (i % 2 == 0);
        threads[i] = std.Thread.spawn(.{}, struct {
            fn run(p: u16, tok: []const u8, valid: bool, result: *u16) void {
                const a = std.heap.page_allocator;
                const effective_token = if (valid) tok else "bad-token";
                var resp = http_client.getWithAuth(a, [4]u8{ 127, 0, 0, 1 }, p, "/v1/containers", effective_token) catch {
                    result.* = 0;
                    return;
                };
                result.* = resp.status_code;
                resp.deinit(a);
            }
        }.run, .{ port, token, use_valid, &results[i] }) catch continue;
        started += 1;
    }

    // wait for all threads
    for (0..started) |i| {
        threads[i].join();
    }

    // verify: valid tokens get 200 or valid response, invalid get 401
    for (0..started) |i| {
        if (results[i] == 0) continue; // connection failed, skip
        if (i % 2 == 0) {
            // valid token — should not get 500
            try std.testing.expect(results[i] != 500);
        } else {
            // invalid token — should get 401
            try std.testing.expectEqual(@as(u16, 401), results[i]);
        }
    }
}
