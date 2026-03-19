const std = @import("std");
const http = @import("../http.zig");
const common = @import("common.zig");
const secrets_routes = @import("security/secrets_routes.zig");
const cert_routes = @import("security/cert_routes.zig");
const policy_routes = @import("security/policy_routes.zig");

const Response = common.Response;
const Status = http.StatusCode;

pub fn route(request: http.Request, alloc: std.mem.Allocator) ?Response {
    const path = request.path_only;

    if (std.mem.eql(u8, path, "/v1/secrets")) {
        if (request.method == .GET) return secrets_routes.handleListSecrets(alloc);
        if (request.method == .POST) return secrets_routes.handleSetSecret(alloc, request);
        return common.methodNotAllowed();
    }
    if (path.len > "/v1/secrets/".len and std.mem.startsWith(u8, path, "/v1/secrets/")) {
        const name = path["/v1/secrets/".len..];
        if (std.mem.indexOf(u8, name, "/") == null and name.len > 0) {
            if (request.method == .GET) return common.methodNotAllowed();
            if (request.method == .DELETE) return secrets_routes.handleDeleteSecret(alloc, name);
            return common.methodNotAllowed();
        }
    }

    if (std.mem.eql(u8, path, "/v1/policies")) {
        if (request.method == .GET) return policy_routes.handleListPolicies(alloc);
        if (request.method == .POST) return policy_routes.handleAddPolicy(alloc, request);
        return common.methodNotAllowed();
    }
    if (path.len > "/v1/policies/".len and std.mem.startsWith(u8, path, "/v1/policies/")) {
        const rest = path["/v1/policies/".len..];
        if (std.mem.indexOf(u8, rest, "/")) |slash| {
            const source = rest[0..slash];
            const target = rest[slash + 1 ..];
            if (source.len > 0 and target.len > 0 and std.mem.indexOf(u8, target, "/") == null) {
                if (request.method == .DELETE) return policy_routes.handleDeletePolicy(alloc, source, target);
                return common.methodNotAllowed();
            }
        }
    }

    if (std.mem.eql(u8, path, "/v1/certificates")) {
        if (request.method == .GET) return cert_routes.handleListCertificates(alloc);
        return common.methodNotAllowed();
    }
    if (path.len > "/v1/certificates/".len and std.mem.startsWith(u8, path, "/v1/certificates/")) {
        const domain = path["/v1/certificates/".len..];
        if (std.mem.indexOf(u8, domain, "/") == null and domain.len > 0) {
            if (request.method == .DELETE) return cert_routes.handleDeleteCertificate(alloc, domain);
            return common.methodNotAllowed();
        }
    }

    return null;
}

// -- tests --

const testing = std.testing;

test "route returns null for unknown security path" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/unknown",
        .path_only = "/v1/unknown",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    try testing.expect(route(req, testing.allocator) == null);
}

test "route handles /v1/secrets GET" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/secrets",
        .path_only = "/v1/secrets",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    const resp = route(req, testing.allocator).?;
    if (resp.allocated) testing.allocator.free(resp.body);
    try testing.expectEqual(Status.ok, resp.status);
}

test "route handles /v1/secrets POST" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/secrets",
        .path_only = "/v1/secrets",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"name\":\"db\",\"value\":\"secret\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expect(resp.status == .ok or resp.status == .internal_server_error);
}

test "route rejects /v1/secrets PUT" {
    const req = http.Request{
        .method = .PUT,
        .path = "/v1/secrets",
        .path_only = "/v1/secrets",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.method_not_allowed, resp.status);
}

test "route handles /v1/secrets/{name} DELETE" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/secrets/api_key",
        .path_only = "/v1/secrets/api_key",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expect(resp.status == .ok or resp.status == .not_found or resp.status == .internal_server_error);
}

test "route rejects /v1/secrets/{name} GET" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/secrets/api_key",
        .path_only = "/v1/secrets/api_key",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.method_not_allowed, resp.status);
}

test "route rejects empty secret name" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/secrets/",
        .path_only = "/v1/secrets/",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    try testing.expect(route(req, testing.allocator) == null);
}

test "route handles /v1/policies GET" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/policies",
        .path_only = "/v1/policies",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    const resp = route(req, testing.allocator).?;
    if (resp.allocated) testing.allocator.free(resp.body);
    try testing.expectEqual(Status.ok, resp.status);
}

test "route handles /v1/policies POST" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .path_only = "/v1/policies",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"source\":\"web\",\"target\":\"db\",\"action\":\"deny\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expect(resp.status == .ok or resp.status == .internal_server_error);
}

test "route handles /v1/policies/{source}/{target} DELETE" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/policies/web/db",
        .path_only = "/v1/policies/web/db",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expect(resp.status == .ok or resp.status == .internal_server_error);
}

test "route rejects malformed policy delete path" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/policies/web",
        .path_only = "/v1/policies/web",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    try testing.expect(route(req, testing.allocator) == null);
}

test "route rejects policy path with too many segments" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/policies/web/db/extra",
        .path_only = "/v1/policies/web/db/extra",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    try testing.expect(route(req, testing.allocator) == null);
}

test "route handles /v1/certificates GET" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/certificates",
        .path_only = "/v1/certificates",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    const resp = route(req, testing.allocator).?;
    if (resp.allocated) testing.allocator.free(resp.body);
    try testing.expectEqual(Status.ok, resp.status);
}

test "route rejects /v1/certificates POST" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/certificates",
        .path_only = "/v1/certificates",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.method_not_allowed, resp.status);
}

test "route handles /v1/certificates/{domain} DELETE" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/certificates/example.com",
        .path_only = "/v1/certificates/example.com",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expect(resp.status == .ok or resp.status == .not_found or resp.status == .internal_server_error);
}

test "route rejects empty certificate domain" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/certificates/",
        .path_only = "/v1/certificates/",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    try testing.expect(route(req, testing.allocator) == null);
}

test "policy action validation - allow is valid" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .path_only = "/v1/policies",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"source\":\"web\",\"target\":\"db\",\"action\":\"allow\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expect(resp.status == .ok or resp.status == .internal_server_error);
}

test "policy action validation - deny is valid" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .path_only = "/v1/policies",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"source\":\"web\",\"target\":\"db\",\"action\":\"deny\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expect(resp.status == .ok or resp.status == .internal_server_error);
}

test "policy action validation - invalid action rejected" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .path_only = "/v1/policies",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"source\":\"web\",\"target\":\"db\",\"action\":\"block\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.bad_request, resp.status);
}

test "set secret rejects empty body" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/secrets",
        .path_only = "/v1/secrets",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.bad_request, resp.status);
}

test "add policy rejects empty body" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .path_only = "/v1/policies",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.bad_request, resp.status);
}

test "set secret requires name field" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/secrets",
        .path_only = "/v1/secrets",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"value\":\"secret\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.bad_request, resp.status);
}

test "set secret requires value field" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/secrets",
        .path_only = "/v1/secrets",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"name\":\"db\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.bad_request, resp.status);
}

test "add policy requires source field" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .path_only = "/v1/policies",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"target\":\"db\",\"action\":\"deny\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.bad_request, resp.status);
}

test "add policy requires target field" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .path_only = "/v1/policies",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"source\":\"web\",\"action\":\"deny\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.bad_request, resp.status);
}

test "add policy requires action field" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .path_only = "/v1/policies",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"source\":\"web\",\"target\":\"db\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.bad_request, resp.status);
}

test "set secret rejects empty name" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/secrets",
        .path_only = "/v1/secrets",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"name\":\"\",\"value\":\"secret\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.bad_request, resp.status);
}

test "add policy rejects empty source" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .path_only = "/v1/policies",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"source\":\"\",\"target\":\"db\",\"action\":\"deny\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.bad_request, resp.status);
}

test "add policy rejects empty target" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .path_only = "/v1/policies",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"source\":\"web\",\"target\":\"\",\"action\":\"deny\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.bad_request, resp.status);
}

test "policy action is case sensitive" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .path_only = "/v1/policies",
        .query = "",
        .headers_raw = "",
        .content_length = 0,
        .body = "{\"source\":\"web\",\"target\":\"db\",\"action\":\"ALLOW\"}",
    };
    const resp = route(req, testing.allocator).?;
    try testing.expectEqual(Status.bad_request, resp.status);
}
