const std = @import("std");
const platform = @import("platform");
const posix = std.posix;
const http = @import("api/http.zig");
const routes = @import("api/routes.zig");
const connection_runtime = @import("api/server/connection_runtime.zig");
const s3 = @import("storage/s3.zig");
const support = @import("test_contract_support.zig");

fn runHandleConnectionRaw(alloc: std.mem.Allocator, raw_request: []const u8) ![]u8 {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try platform.Dir.from(tmp.dir).createFile("raw-http.txt", .{ .read = true });
    defer file.close();

    try file.writeAll(raw_request);
    try file.seekTo(0);

    const dup_fd = try posix.dup(file.handle);
    connection_runtime.handleConnection(alloc, dup_fd);

    try file.seekTo(0);
    const contents = try file.readToEndAlloc(alloc, raw_request.len + 16 * 1024);
    errdefer alloc.free(contents);

    if (contents.len < raw_request.len) return error.ResponseMissing;
    const response = try alloc.dupe(u8, contents[raw_request.len..]);
    alloc.free(contents);
    return response;
}

fn responseBody(response: []const u8) ![]const u8 {
    const header_end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return error.BadResponse;
    return response[header_end + 4 ..];
}

test "contract: unauthorized operator route returns exact json body" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    const saved_api = routes.api_token;
    const saved_join = routes.join_token;
    defer {
        routes.api_token = saved_api;
        routes.join_token = saved_join;
    }

    routes.api_token = "secret-token";
    routes.join_token = null;

    const req = (try http.parseRequest("GET /agents HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = routes.dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
    try std.testing.expectEqualStrings("{\"error\":\"unauthorized\"}", resp.body);
    try std.testing.expect(resp.content_type == null);
}

test "contract: bearer header name is case insensitive but prefix is case sensitive" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    const saved_api = routes.api_token;
    const saved_join = routes.join_token;
    const saved_cluster = routes.cluster;
    defer {
        routes.api_token = saved_api;
        routes.join_token = saved_join;
        routes.cluster = saved_cluster;
    }

    routes.api_token = "secret-token";
    routes.join_token = null;
    routes.cluster = null;

    const accepted = (try http.parseRequest(
        "GET /agents HTTP/1.1\r\nHost: localhost\r\nauthorization: Bearer secret-token\r\n\r\n",
    )).?;
    const accepted_resp = routes.dispatch(accepted, std.testing.allocator);
    defer if (accepted_resp.allocated) std.testing.allocator.free(accepted_resp.body);
    try std.testing.expectEqual(http.StatusCode.ok, accepted_resp.status);
    try std.testing.expectEqualStrings("[]", accepted_resp.body);

    const rejected = (try http.parseRequest(
        "GET /agents HTTP/1.1\r\nHost: localhost\r\nAuthorization: bearer secret-token\r\n\r\n",
    )).?;
    const rejected_resp = routes.dispatch(rejected, std.testing.allocator);
    defer if (rejected_resp.allocated) std.testing.allocator.free(rejected_resp.body);
    try std.testing.expectEqual(http.StatusCode.unauthorized, rejected_resp.status);
    try std.testing.expectEqualStrings("{\"error\":\"unauthorized\"}", rejected_resp.body);
}

test "contract: empty bearer token is rejected" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    const saved_api = routes.api_token;
    const saved_join = routes.join_token;
    defer {
        routes.api_token = saved_api;
        routes.join_token = saved_join;
    }

    routes.api_token = "secret-token";
    routes.join_token = null;

    const req = (try http.parseRequest(
        "GET /agents HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer \r\n\r\n",
    )).?;
    const resp = routes.dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
    try std.testing.expectEqualStrings("{\"error\":\"unauthorized\"}", resp.body);
}

test "contract: join token only authorizes join routes" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    const saved_api = routes.api_token;
    const saved_join = routes.join_token;
    const saved_cluster = routes.cluster;
    defer {
        routes.api_token = saved_api;
        routes.join_token = saved_join;
        routes.cluster = saved_cluster;
    }

    routes.api_token = "api-token";
    routes.join_token = "join-token";
    routes.cluster = null;

    const join_req = (try http.parseRequest(
        "POST /agents/register HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer join-token\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const join_resp = routes.dispatch(join_req, std.testing.allocator);
    defer if (join_resp.allocated) std.testing.allocator.free(join_resp.body);
    try std.testing.expectEqual(http.StatusCode.bad_request, join_resp.status);

    const operator_req = (try http.parseRequest(
        "GET /agents HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer join-token\r\n\r\n",
    )).?;
    const operator_resp = routes.dispatch(operator_req, std.testing.allocator);
    defer if (operator_resp.allocated) std.testing.allocator.free(operator_resp.body);
    try std.testing.expectEqual(http.StatusCode.unauthorized, operator_resp.status);
    try std.testing.expectEqualStrings("{\"error\":\"unauthorized\"}", operator_resp.body);
}

test "contract: public routes stay accessible when auth is configured" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    const saved_api = routes.api_token;
    const saved_join = routes.join_token;
    defer {
        routes.api_token = saved_api;
        routes.join_token = saved_join;
    }

    routes.api_token = "secret-token";
    routes.join_token = "join-token";

    const health_req = (try http.parseRequest("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const health_resp = routes.dispatch(health_req, std.testing.allocator);
    defer if (health_resp.allocated) std.testing.allocator.free(health_resp.body);
    try std.testing.expectEqual(http.StatusCode.ok, health_resp.status);
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", health_resp.body);

    const version_req = (try http.parseRequest("GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const version_resp = routes.dispatch(version_req, std.testing.allocator);
    defer if (version_resp.allocated) std.testing.allocator.free(version_resp.body);
    try std.testing.expectEqual(http.StatusCode.ok, version_resp.status);
    try std.testing.expectEqualStrings("{\"version\":\"0.1.8\"}", version_resp.body);
}

test "contract: malformed content-length returns 400 json response" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    const response = try runHandleConnectionRaw(
        std.testing.allocator,
        "POST /agents/register HTTP/1.1\r\nHost: localhost\r\nContent-Length: nope\r\n\r\n",
    );
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 400 Bad Request\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Content-Type: application/json\r\n") != null);
    try std.testing.expectEqualStrings("{\"error\":\"malformed request\"}", try responseBody(response));
}

test "contract: duplicate content-length returns 400 json response" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    const response = try runHandleConnectionRaw(
        std.testing.allocator,
        "POST /agents/register HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
    );
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 400 Bad Request\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Content-Type: application/json\r\n") != null);
    try std.testing.expectEqualStrings("{\"error\":\"malformed request\"}", try responseBody(response));
}

test "contract: oversized headers return 431" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    var big_header: [17 * 1024]u8 = undefined;
    @memset(&big_header, 'A');

    var req_buf: [18 * 1024]u8 = undefined;
    const raw = try std.fmt.bufPrint(
        &req_buf,
        "GET /health HTTP/1.1\r\nHost: localhost\r\nX-Junk: {s}\r\n\r\n",
        .{big_header[0..16500]},
    );

    const response = try runHandleConnectionRaw(std.testing.allocator, raw);
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 431 Request Header Fields Too Large\r\n"));
    try std.testing.expectEqualStrings("{\"error\":\"headers too large\"}", try responseBody(response));
}

test "contract: content-length above max returns 413" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    var req_buf: [256]u8 = undefined;
    const raw = try std.fmt.bufPrint(
        &req_buf,
        "POST /v1/deploy HTTP/1.1\r\nHost: localhost\r\nContent-Length: {d}\r\n\r\n",
        .{http.max_body_bytes + 1},
    );

    const response = try runHandleConnectionRaw(std.testing.allocator, raw);
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 413 Content Too Large\r\n"));
    try std.testing.expectEqualStrings("{\"error\":\"request body too large\"}", try responseBody(response));
}

test "contract: incomplete body returns 400 timeout-style error" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    const response = try runHandleConnectionRaw(
        std.testing.allocator,
        "POST /v1/deploy HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nno",
    );
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 400 Bad Request\r\n"));
    try std.testing.expectEqualStrings("{\"error\":\"request too large or timed out\"}", try responseBody(response));
}

test "contract: unauthorized raw response uses json content type" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    const saved_api = routes.api_token;
    const saved_join = routes.join_token;
    defer {
        routes.api_token = saved_api;
        routes.join_token = saved_join;
    }

    routes.api_token = "secret-token";
    routes.join_token = null;

    const response = try runHandleConnectionRaw(
        std.testing.allocator,
        "GET /agents HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 401 Unauthorized\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Content-Type: application/json\r\n") != null);
    try std.testing.expectEqualStrings("{\"error\":\"unauthorized\"}", try responseBody(response));
}

test "contract: s3 missing key raw response uses xml content type" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    try support.cleanupS3TestState();
    defer support.cleanupS3TestState() catch {};

    try s3.createBucket("http-contract-bucket");

    const response = try runHandleConnectionRaw(
        std.testing.allocator,
        "GET /s3/http-contract-bucket/missing.txt HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 404 Not Found\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Content-Type: application/xml\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, try responseBody(response), "<Code>NoSuchKey</Code>") != null);
}

test "contract: HEAD omits body bytes but preserves content length" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    try support.cleanupS3TestState();
    defer support.cleanupS3TestState() catch {};

    try s3.createBucket("head-contract-bucket");
    _ = try s3.putObject("head-contract-bucket", "object.txt", "head-body");

    const head_req = (try http.parseRequest(
        "HEAD /s3/head-contract-bucket/object.txt HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const route_resp = routes.dispatch(head_req, std.testing.allocator);
    defer if (route_resp.allocated) std.testing.allocator.free(route_resp.body);

    const response = try runHandleConnectionRaw(
        std.testing.allocator,
        "HEAD /s3/head-contract-bucket/object.txt HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    defer std.testing.allocator.free(response);

    var len_buf: [64]u8 = undefined;
    const content_length_header = try std.fmt.bufPrint(&len_buf, "Content-Length: {d}\r\n", .{route_resp.body.len});
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, content_length_header) != null);
    try std.testing.expectEqual(@as(usize, 0), (try responseBody(response)).len);
}
