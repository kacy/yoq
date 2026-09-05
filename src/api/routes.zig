// routes — API dispatch/auth shell with concern-specific route modules

const std = @import("std");
const http = @import("http.zig");
const store = @import("../state/store.zig");
const cluster_node = @import("../cluster/node.zig");
const json_helpers = @import("../lib/json_helpers.zig");
const service_registry_runtime = @import("../network/service_registry_runtime.zig");
const common = @import("routes/common.zig");
const containers_images = @import("routes/containers_images.zig");
const cluster_agents = @import("routes/cluster_agents.zig");
const services = @import("routes/services.zig");
const status_metrics = @import("routes/status_metrics.zig");
const security = @import("routes/security.zig");
const s3_gateway = @import("routes/s3_gateway.zig");
const audit = @import("../state/audit.zig");
const auth = @import("auth.zig");

pub var cluster: ?*cluster_node.Node = null;
pub var join_token: ?[]const u8 = null;
pub var api_token: ?[]const u8 = null;

pub const Response = common.Response;

pub fn dispatch(request: http.Request, alloc: std.mem.Allocator) Response {
    defer audit.resetActor();
    if (authorizeRequest(request, alloc)) |denied| return denied;

    if (request.method == .GET) {
        if (std.mem.eql(u8, request.path_only, "/health")) {
            return .{ .status = .ok, .body = "{\"status\":\"ok\"}", .allocated = false };
        }
        if (std.mem.eql(u8, request.path_only, "/version")) {
            return .{ .status = .ok, .body = "{\"version\":\"0.1.8\"}", .allocated = false };
        }
    }

    if (s3_gateway.route(request, alloc)) |resp| return resp;
    if (containers_images.route(request, alloc)) |resp| return resp;

    const ctx: common.RouteContext = .{
        .cluster = cluster,
        .join_token = join_token,
        .api_token = api_token,
    };

    if (cluster_agents.route(request, alloc, ctx)) |resp| return resp;
    if (services.route(request, alloc)) |resp| return resp;
    if (status_metrics.route(request, alloc)) |resp| return resp;
    if (security.route(request, alloc)) |resp| return resp;

    return common.notFound();
}

/// Shared by header admission and dispatch so body intake cannot bypass scope checks.
/// Callers reset the thread-local audit actor after checking or dispatching.
pub fn authorizeRequest(request: http.Request, alloc: std.mem.Allocator) ?Response {
    const is_public = std.mem.eql(u8, request.path_only, "/health") or
        std.mem.eql(u8, request.path_only, "/version");
    const is_join_route = request.method == .POST and std.mem.eql(u8, request.path_only, "/agents/register");
    if (workerRouteAgent(&request)) |agent_id| {
        const node = cluster orelse return common.unauthorized();
        const bearer = common.extractBearerToken(&request) orelse return common.unauthorized();
        if (!(@import("../cluster/agent_credentials.zig").authenticates(node.stateMachineDb(), bearer, if (agent_id.len == 0) null else agent_id) catch false))
            return common.unauthorized();
        audit.setActorName("agent");
        return null;
    }
    const has_any_auth = api_token != null or join_token != null;

    var auth_result = auth.AuthResult{};
    defer auth_result.deinit(alloc);

    if (has_any_auth and !is_public) {
        if (is_join_route) {
            // cluster join routes are gated by the join token only.
            const has_join_auth = if (join_token) |jt| common.hasValidBearerToken(&request, jt) else false;
            if (!has_join_auth) return common.unauthorized();
            audit.setActorName("join-token");
        } else {
            // operator routes: a legacy admin token or a named, scoped token.
            auth_result = auth.authorize(alloc, &request, api_token);
            if (!auth_result.ok) return common.unauthorized();
            if (auth.requiredScope(request.method, request.path_only)) |scope| {
                if (!auth_result.allows(scope)) return common.forbidden();
            }
            audit.setActorName(auth_result.actor_name);
        }
    } else {
        audit.setActor(.unauthenticated);
    }

    return null;
}

fn workerRouteAgent(request: *const http.Request) ?[]const u8 {
    if (request.method == .GET and std.mem.eql(u8, request.path_only, "/wireguard/peers")) return "";
    if (!std.mem.startsWith(u8, request.path_only, "/agents/")) return null;
    const rest = request.path_only["/agents/".len..];
    if (common.matchSubpath(rest, "/heartbeat")) |id| {
        if (request.method == .POST) return id;
    }
    if (common.matchSubpath(rest, "/assignments")) |id| {
        if (request.method == .GET) return id;
    }
    if (common.matchAssignmentStatusPath(rest)) |ids| {
        if (request.method == .POST) return ids.agent_id;
    }
    return null;
}

// -- tests --

test "dispatch health" {
    const req = (try http.parseRequest("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", resp.body);
    try std.testing.expect(!resp.allocated);
}

test "dispatch version" {
    const req = (try http.parseRequest("GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expectEqualStrings("{\"version\":\"0.1.8\"}", resp.body);
}

test "dispatch not found" {
    const req = (try http.parseRequest("GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.not_found, resp.status);
}

test "dispatch method not allowed on health" {
    const req = (try http.parseRequest("POST /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.not_found, resp.status);
}

test "dispatch POST to container stop" {
    const req = (try http.parseRequest(
        "POST /containers/abc123/stop HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch GET on container stop returns method not allowed" {
    const req = (try http.parseRequest(
        "GET /containers/abc123/stop HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
}

test "dispatch DELETE container" {
    store.initTestDb() catch return error.SkipZigTest;
    defer store.deinitTestDb();

    const record = store.ContainerRecord{
        .id = "abc123def456",
        .hostname = "test-container",
        .rootfs = "/tmp/rootfs",
        .status = "stopped",
        .command = "sleep 100",
        .created_at = 1234567890,
        .pid = null,
        .exit_code = null,
    };
    try store.save(record);

    const req = (try http.parseRequest(
        "DELETE /containers/abc123def456 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
}

test "dispatch DELETE image" {
    store.initTestDb() catch return error.SkipZigTest;
    defer store.deinitTestDb();

    const req = (try http.parseRequest(
        "DELETE /images/sha256:abc HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch GET agents without cluster returns empty" {
    cluster = null;
    const req = (try http.parseRequest("GET /agents HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expectEqualStrings("[]", resp.body);
}

test "dispatch POST register without cluster returns error" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/register HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch agent heartbeat routing" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/abc123/heartbeat HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
}

test "dispatch assignment status update routing" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/abc123/assignments/def456/status HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\n{\"status\":\"running\"}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
}

test "dispatch agent drain routing" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/abc123/drain HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch deploy without cluster returns error" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /deploy HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch services routing" {
    store.initTestDb() catch return error.SkipZigTest;
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    service_registry_runtime.syncServiceFromStore("api");

    const req = (try http.parseRequest("GET /v1/services/api HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"service_name\":\"api\"") != null);
}

test "dispatch rejects non-hex container id" {
    const req = (try http.parseRequest(
        "GET /containers/INVALID! HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch rejects non-hex agent id" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/NOT-HEX!/heartbeat HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
}

test "dispatch GET /v1/secrets routes correctly" {
    const req = (try http.parseRequest("GET /v1/secrets HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expect(resp.status == .ok or resp.status == .internal_server_error);
}

test "dispatch POST /v1/secrets with missing body returns bad request" {
    const req = (try http.parseRequest(
        "POST /v1/secrets HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch GET /v1/secrets/mykey routes correctly" {
    const req = (try http.parseRequest(
        "GET /v1/secrets/mykey HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
}

test "dispatch DELETE /v1/secrets/mykey routes correctly" {
    const req = (try http.parseRequest(
        "DELETE /v1/secrets/mykey HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch PUT /v1/secrets returns method not allowed" {
    const req = (try http.parseRequest(
        "PUT /v1/secrets HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
}

test "dispatch returns 401 for missing auth on protected endpoint when api_token is set" {
    const saved = api_token;
    defer api_token = saved;
    api_token = "test-secret-token";

    const req = (try http.parseRequest(
        "GET /containers HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
}

test "dispatch returns 401 for wrong token on protected endpoint" {
    const saved = api_token;
    defer api_token = saved;
    api_token = "correct-token";

    const req = (try http.parseRequest(
        "GET /containers HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong-token\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
}

test "dispatch allows unauthenticated /health when api_token is set" {
    const saved = api_token;
    defer api_token = saved;
    api_token = "test-secret-token";

    const req = (try http.parseRequest(
        "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
}

test "dispatch allows unauthenticated /version when api_token is set" {
    const saved = api_token;
    defer api_token = saved;
    api_token = "test-secret-token";

    const req = (try http.parseRequest(
        "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
}

test "dispatch rejects enrollment token on agent heartbeat route" {
    const saved_api = api_token;
    const saved_join = join_token;
    defer {
        api_token = saved_api;
        join_token = saved_join;
    }
    api_token = "api-secret";
    join_token = "join-secret";

    const req = (try http.parseRequest(
        "POST /agents/abc123def456/heartbeat HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer join-secret\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
}

test "dispatch rejects join token on operator-only agent list route" {
    const saved_api = api_token;
    const saved_join = join_token;
    defer {
        api_token = saved_api;
        join_token = saved_join;
    }
    api_token = "api-secret";
    join_token = "join-secret";

    const req = (try http.parseRequest(
        "GET /agents HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer join-secret\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
}

test "dispatch rejects protected operator route when only join token is configured" {
    const saved_api = api_token;
    const saved_join = join_token;
    defer {
        api_token = saved_api;
        join_token = saved_join;
    }
    api_token = null;
    join_token = "join-secret";

    const req = (try http.parseRequest(
        "GET /agents HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
}

test "dispatch allows join route when only join token is configured" {
    const saved_api = api_token;
    const saved_join = join_token;
    const saved_cluster = cluster;
    defer {
        api_token = saved_api;
        join_token = saved_join;
        cluster = saved_cluster;
    }
    api_token = null;
    join_token = "join-secret";
    cluster = null;

    const req = (try http.parseRequest(
        "POST /agents/register HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer join-secret\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch allows unauthenticated public route when only join token is configured" {
    const saved_api = api_token;
    const saved_join = join_token;
    defer {
        api_token = saved_api;
        join_token = saved_join;
    }
    api_token = null;
    join_token = "join-secret";

    const req = (try http.parseRequest(
        "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
}

fn workerCredentialRequest(method: http.Method, path: []const u8, secret: []const u8, body: []const u8) !Response {
    const alloc = std.testing.allocator;
    const headers = try std.fmt.allocPrint(alloc, "Authorization: Bearer {s}\r\n", .{secret});
    defer alloc.free(headers);
    const request: http.Request = .{
        .method = method,
        .path = path,
        .path_only = path,
        .query = "",
        .headers_raw = headers,
        .body = body,
        .content_length = body.len,
    };
    // Header admission must reach the same decision as full dispatch.
    if (authorizeRequest(request, alloc)) |denied| {
        const result = dispatch(request, alloc);
        try std.testing.expectEqual(denied.status, result.status);
        return result;
    }
    return dispatch(request, alloc);
}

test "worker credential enrollment binds reads updates and revocation to one agent" {
    const alloc = std.testing.allocator;
    var harness = try @import("routes/cluster_agents/route_test_support.zig").Harness.init(alloc);
    defer harness.deinit();
    const saved_cluster = cluster;
    const saved_join = join_token;
    const saved_api = api_token;
    defer {
        cluster = saved_cluster;
        join_token = saved_join;
        api_token = saved_api;
    }
    cluster = harness.node;
    join_token = "enroll-only";
    api_token = "operator-only";
    const enrollment = "{\"token\":\"enroll-only\",\"address\":\"127.0.0.1\",\"cpu_cores\":2,\"memory_mb\":1024}";
    const first = try workerCredentialRequest(.POST, "/agents/register", "enroll-only", enrollment);
    defer if (first.allocated) alloc.free(first.body);
    try std.testing.expectEqual(http.StatusCode.ok, first.status);
    harness.applyCommitted();
    const second = try workerCredentialRequest(.POST, "/agents/register", "enroll-only", enrollment);
    defer if (second.allocated) alloc.free(second.body);
    try std.testing.expectEqual(http.StatusCode.ok, second.status);
    harness.applyCommitted();
    const first_id = json_helpers.extractJsonString(first.body, "id").?;
    const second_id = json_helpers.extractJsonString(second.body, "id").?;
    const first_secret = json_helpers.extractJsonString(first.body, "credential").?;
    const second_secret = json_helpers.extractJsonString(second.body, "credential").?;
    try std.testing.expect(!std.mem.eql(u8, first_secret, second_secret));
    const registration_entry = (try harness.node.log.getEntry(alloc, 1)).?;
    defer alloc.free(registration_entry.data);
    try std.testing.expect(std.mem.indexOf(u8, registration_entry.data, first_secret) == null);
    const db = harness.node.stateMachineDb();
    try db.exec("INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES ('abcd12', ?, 'private-image', 'pending', 1);", .{}, .{second_id});
    const first_path = try std.fmt.allocPrint(alloc, "/agents/{s}/assignments", .{first_id});
    defer alloc.free(first_path);
    const second_path = try std.fmt.allocPrint(alloc, "/agents/{s}/assignments", .{second_id});
    defer alloc.free(second_path);
    for ([_]struct { path: []const u8, secret: []const u8, expected: http.StatusCode }{
        .{ .path = first_path, .secret = first_secret, .expected = .ok },
        .{ .path = second_path, .secret = first_secret, .expected = .unauthorized },
        .{ .path = second_path, .secret = "enroll-only", .expected = .unauthorized },
        .{ .path = second_path, .secret = second_secret, .expected = .ok },
    }) |case| {
        const response = try workerCredentialRequest(.GET, case.path, case.secret, "");
        defer if (response.allocated) alloc.free(response.body);
        try std.testing.expectEqual(case.expected, response.status);
    }
    const wrong_owner_path = try std.fmt.allocPrint(alloc, "/agents/{s}/assignments/abcd12/status", .{first_id});
    defer alloc.free(wrong_owner_path);
    const denied = try workerCredentialRequest(.POST, wrong_owner_path, first_secret, "{\"status\":\"running\"}");
    defer if (denied.allocated) alloc.free(denied.body);
    try std.testing.expectEqual(http.StatusCode.forbidden, denied.status);
    const own_path = try std.fmt.allocPrint(alloc, "/agents/{s}/assignments/abcd12/status", .{second_id});
    defer alloc.free(own_path);
    const updated = try workerCredentialRequest(.POST, own_path, second_secret, "{\"status\":\"running\"}");
    defer if (updated.allocated) alloc.free(updated.body);
    try std.testing.expectEqual(http.StatusCode.ok, updated.status);
    harness.applyCommitted();
    const row = (try db.one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignments WHERE id = 'abcd12' AND status = 'running';", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 1), row.count);
    const revoke_path = try std.fmt.allocPrint(alloc, "/agents/{s}/credential", .{second_id});
    defer alloc.free(revoke_path);
    const revoked = try workerCredentialRequest(.DELETE, revoke_path, "operator-only", "");
    defer if (revoked.allocated) alloc.free(revoked.body);
    try std.testing.expectEqual(http.StatusCode.ok, revoked.status);
    harness.applyCommitted();
    const after = try workerCredentialRequest(.GET, second_path, second_secret, "");
    defer if (after.allocated) alloc.free(after.body);
    try std.testing.expectEqual(http.StatusCode.unauthorized, after.status);
    const unaffected = try workerCredentialRequest(.GET, first_path, first_secret, "");
    defer if (unaffected.allocated) alloc.free(unaffected.body);
    try std.testing.expectEqual(http.StatusCode.ok, unaffected.status);
}
