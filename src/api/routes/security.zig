const std = @import("std");
const http = @import("../http.zig");
const store = @import("../../state/store.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const sqlite = @import("sqlite");
const secrets = @import("../../state/secrets.zig");
const net_policy = @import("../../network/policy.zig");
const cert_store = @import("../../tls/cert_store.zig");
const common = @import("common.zig");

const Response = common.Response;
const extractJsonString = json_helpers.extractJsonString;

pub fn route(request: http.Request, alloc: std.mem.Allocator) ?Response {
    const path = request.path_only;

    if (std.mem.eql(u8, path, "/v1/secrets")) {
        if (request.method == .GET) return handleListSecrets(alloc);
        if (request.method == .POST) return handleSetSecret(alloc, request);
        return common.methodNotAllowed();
    }
    if (path.len > "/v1/secrets/".len and std.mem.startsWith(u8, path, "/v1/secrets/")) {
        const name = path["/v1/secrets/".len..];
        if (std.mem.indexOf(u8, name, "/") == null and name.len > 0) {
            if (request.method == .GET) return common.methodNotAllowed();
            if (request.method == .DELETE) return handleDeleteSecret(alloc, name);
            return common.methodNotAllowed();
        }
    }

    if (std.mem.eql(u8, path, "/v1/policies")) {
        if (request.method == .GET) return handleListPolicies(alloc);
        if (request.method == .POST) return handleAddPolicy(alloc, request);
        return common.methodNotAllowed();
    }
    if (path.len > "/v1/policies/".len and std.mem.startsWith(u8, path, "/v1/policies/")) {
        const rest = path["/v1/policies/".len..];
        if (std.mem.indexOf(u8, rest, "/")) |slash| {
            const source = rest[0..slash];
            const target = rest[slash + 1 ..];
            if (source.len > 0 and target.len > 0 and std.mem.indexOf(u8, target, "/") == null) {
                if (request.method == .DELETE) return handleDeletePolicy(alloc, source, target);
                return common.methodNotAllowed();
            }
        }
    }

    if (std.mem.eql(u8, path, "/v1/certificates")) {
        if (request.method == .GET) return handleListCertificates(alloc);
        return common.methodNotAllowed();
    }
    if (path.len > "/v1/certificates/".len and std.mem.startsWith(u8, path, "/v1/certificates/")) {
        const domain = path["/v1/certificates/".len..];
        if (std.mem.indexOf(u8, domain, "/") == null and domain.len > 0) {
            if (request.method == .DELETE) return handleDeleteCertificate(alloc, domain);
            return common.methodNotAllowed();
        }
    }

    return null;
}

fn openSecretsStore(alloc: std.mem.Allocator) ?secrets.SecretsStore {
    const db_ptr = alloc.create(sqlite.Db) catch return null;
    db_ptr.* = store.openDb() catch {
        alloc.destroy(db_ptr);
        return null;
    };
    return secrets.SecretsStore.init(db_ptr, alloc) catch {
        db_ptr.deinit();
        alloc.destroy(db_ptr);
        return null;
    };
}

fn closeSecretsStore(alloc: std.mem.Allocator, sec: *secrets.SecretsStore) void {
    sec.db.deinit();
    alloc.destroy(sec.db);
}

fn handleListSecrets(alloc: std.mem.Allocator) Response {
    var sec = openSecretsStore(alloc) orelse return common.internalError();
    defer closeSecretsStore(alloc, &sec);

    var names = sec.list() catch return common.internalError();
    defer {
        for (names.items) |n| alloc.free(n);
        names.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();
    for (names.items, 0..) |name, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writer.writeByte('"') catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, name) catch return common.internalError();
        writer.writeByte('"') catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleSetSecret(alloc: std.mem.Allocator, request: http.Request) Response {
    if (request.body.len == 0) return common.badRequest("missing request body");

    const name = extractJsonString(request.body, "name") orelse return common.badRequest("missing name field");
    const value = extractJsonString(request.body, "value") orelse return common.badRequest("missing value field");

    if (name.len == 0) return common.badRequest("name cannot be empty");

    var sec = openSecretsStore(alloc) orelse return common.internalError();
    defer closeSecretsStore(alloc, &sec);

    sec.set(name, value) catch return common.internalError();

    return .{ .status = .ok, .body = "{\"status\":\"ok\"}", .allocated = false };
}

fn handleDeleteSecret(alloc: std.mem.Allocator, name: []const u8) Response {
    var sec = openSecretsStore(alloc) orelse return common.internalError();
    defer closeSecretsStore(alloc, &sec);

    sec.remove(name) catch |err| {
        if (err == secrets.SecretsError.NotFound) return common.notFound();
        return common.internalError();
    };

    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}

fn openCertStore(alloc: std.mem.Allocator) ?cert_store.CertStore {
    const db_ptr = alloc.create(sqlite.Db) catch return null;
    db_ptr.* = store.openDb() catch {
        alloc.destroy(db_ptr);
        return null;
    };
    return cert_store.CertStore.init(db_ptr, alloc) catch {
        db_ptr.deinit();
        alloc.destroy(db_ptr);
        return null;
    };
}

fn closeCertStore(alloc: std.mem.Allocator, cs: *cert_store.CertStore) void {
    cs.db.deinit();
    alloc.destroy(cs.db);
}

fn handleListCertificates(alloc: std.mem.Allocator) Response {
    var cs = openCertStore(alloc) orelse return common.internalError();
    defer closeCertStore(alloc, &cs);

    var certs = cs.list() catch return common.internalError();
    defer {
        for (certs.items) |c| c.deinit(alloc);
        certs.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();
    for (certs.items, 0..) |cert, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writer.writeAll("{\"domain\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, cert.domain) catch return common.internalError();
        writer.writeAll("\",\"not_after\":") catch return common.internalError();
        std.fmt.format(writer, "{d}", .{cert.not_after}) catch return common.internalError();
        writer.writeAll(",\"source\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, cert.source) catch return common.internalError();
        writer.writeAll("\"}") catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleDeleteCertificate(alloc: std.mem.Allocator, domain: []const u8) Response {
    var cs = openCertStore(alloc) orelse return common.internalError();
    defer closeCertStore(alloc, &cs);

    cs.remove(domain) catch |err| {
        if (err == cert_store.CertError.NotFound) return common.notFound();
        return common.internalError();
    };

    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}

fn handleListPolicies(alloc: std.mem.Allocator) Response {
    var policies = store.listNetworkPolicies(alloc) catch return common.internalError();
    defer {
        for (policies.items) |p| p.deinit(alloc);
        policies.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();
    for (policies.items, 0..) |pol, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writer.writeAll("{\"source\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, pol.source_service) catch return common.internalError();
        writer.writeAll("\",\"target\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, pol.target_service) catch return common.internalError();
        writer.writeAll("\",\"action\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, pol.action) catch return common.internalError();
        writer.writeAll("\"}") catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleAddPolicy(alloc: std.mem.Allocator, request: http.Request) Response {
    if (request.body.len == 0) return common.badRequest("missing request body");

    const source = extractJsonString(request.body, "source") orelse return common.badRequest("missing source field");
    const target = extractJsonString(request.body, "target") orelse return common.badRequest("missing target field");
    const action = extractJsonString(request.body, "action") orelse return common.badRequest("missing action field");

    if (source.len == 0) return common.badRequest("source cannot be empty");
    if (target.len == 0) return common.badRequest("target cannot be empty");

    if (!std.mem.eql(u8, action, "deny") and !std.mem.eql(u8, action, "allow")) {
        return common.badRequest("action must be 'deny' or 'allow'");
    }

    store.addNetworkPolicy(source, target, action) catch return common.internalError();
    net_policy.syncPolicies(alloc);

    return .{ .status = .ok, .body = "{\"status\":\"ok\"}", .allocated = false };
}

fn handleDeletePolicy(alloc: std.mem.Allocator, source: []const u8, target: []const u8) Response {
    store.removeNetworkPolicy(source, target) catch return common.internalError();
    net_policy.syncPolicies(alloc);

    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}

// -- tests --

const testing = std.testing;

// Test route function returns null for unmatched paths
test "route returns null for unknown security path" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/unknown",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response == null);
}

// Test /v1/secrets routing
test "route handles /v1/secrets GET" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/secrets",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        // Will return [] or error depending on store state
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route handles /v1/secrets POST" {
    const body = "{\"name\":\"test_secret\",\"value\":\"secret_value\"}";
    const req = http.Request{
        .method = .POST,
        .path = "/v1/secrets",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route rejects /v1/secrets PUT" {
    const req = http.Request{
        .method = .PUT,
        .path = "/v1/secrets",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.MethodNotAllowed, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

// Test /v1/secrets/{name} DELETE
test "route handles /v1/secrets/{name} DELETE" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/secrets/test_secret",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route rejects /v1/secrets/{name} GET" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/secrets/test_secret",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.MethodNotAllowed, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

// Test /v1/secrets path validation
test "route rejects empty secret name" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/secrets/",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    // Empty name after /v1/secrets/ won't match pattern
    try testing.expect(response == null);
}

// Test /v1/policies routing
test "route handles /v1/policies GET" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/policies",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route handles /v1/policies POST" {
    const body = "{\"source\":\"web\",\"target\":\"db\",\"action\":\"allow\"}";
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

// Test /v1/policies/{source}/{target} DELETE
test "route handles /v1/policies/{source}/{target} DELETE" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/policies/web/db",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route rejects malformed policy delete path" {
    // Missing target
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/policies/web",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    // No slash found, won't match pattern
    try testing.expect(response == null);
}

test "route rejects policy path with too many segments" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/policies/web/db/extra",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    // target contains "/", won't match
    try testing.expect(response == null);
}

// Test /v1/certificates routing
test "route handles /v1/certificates GET" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/certificates",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route rejects /v1/certificates POST" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/certificates",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.MethodNotAllowed, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route handles /v1/certificates/{domain} DELETE" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/certificates/example.com",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route rejects empty certificate domain" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/certificates/",
        .body = null,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    // Empty domain won't match
    try testing.expect(response == null);
}

// Test action validation in policy
test "policy action validation - allow is valid" {
    const body = "{\"source\":\"a\",\"target\":\"b\",\"action\":\"allow\"}";
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        // Should be ok or error depending on store, but not bad request
        try testing.expect(resp.status != .BadRequest);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "policy action validation - deny is valid" {
    const body = "{\"source\":\"a\",\"target\":\"b\",\"action\":\"deny\"}";
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expect(resp.status != .BadRequest);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "policy action validation - invalid action rejected" {
    const body = "{\"source\":\"a\",\"target\":\"b\",\"action\":\"invalid\"}";
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.BadRequest, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

// Test empty body handling
test "set secret rejects empty body" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/secrets",
        .body = "",
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.BadRequest, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "add policy rejects empty body" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .body = "",
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.BadRequest, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

// Test missing JSON fields
test "set secret requires name field" {
    const body = "{\"value\":\"secret_value\"}"; // Missing name
    const req = http.Request{
        .method = .POST,
        .path = "/v1/secrets",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.BadRequest, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "set secret requires value field" {
    const body = "{\"name\":\"test_secret\"}"; // Missing value
    const req = http.Request{
        .method = .POST,
        .path = "/v1/secrets",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.BadRequest, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "add policy requires source field" {
    const body = "{\"target\":\"b\",\"action\":\"allow\"}"; // Missing source
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.BadRequest, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "add policy requires target field" {
    const body = "{\"source\":\"a\",\"action\":\"allow\"}"; // Missing target
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.BadRequest, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "add policy requires action field" {
    const body = "{\"source\":\"a\",\"target\":\"b\"}"; // Missing action
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.BadRequest, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

// Test empty field validation
test "set secret rejects empty name" {
    const body = "{\"name\":\"\",\"value\":\"secret\"}"; // Empty name
    const req = http.Request{
        .method = .POST,
        .path = "/v1/secrets",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.BadRequest, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "add policy rejects empty source" {
    const body = "{\"source\":\"\",\"target\":\"b\",\"action\":\"allow\"}";
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.BadRequest, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "add policy rejects empty target" {
    const body = "{\"source\":\"a\",\"target\":\"\",\"action\":\"allow\"}";
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.BadRequest, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

// Test case sensitivity in action
test "policy action is case sensitive" {
    const body = "{\"source\":\"a\",\"target\":\"b\",\"action\":\"ALLOW\"}"; // Uppercase
    const req = http.Request{
        .method = .POST,
        .path = "/v1/policies",
        .body = body,
        .headers = &.{},
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        // Should be rejected (only lowercase 'allow'/'deny' accepted)
        try testing.expectEqual(http.StatusCode.BadRequest, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}
