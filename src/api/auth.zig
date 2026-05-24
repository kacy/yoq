// auth — request authorization for the API: map a request to its required
// scope, and resolve a bearer token (legacy admin token or a named scoped
// token) into the scopes it carries.
//
// the scope vocabulary and matching live in lib/scopes.zig; this module is the
// HTTP-facing glue (path -> required scope, token -> granted scopes).

const std = @import("std");
const http = @import("http.zig");
const common = @import("routes/common.zig");
const store = @import("../state/store.zig");
const scopes = @import("../lib/scopes.zig");

fn nowSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

fn isWrite(method: http.Method) bool {
    return switch (method) {
        .GET, .HEAD => false,
        .POST, .PUT, .DELETE => true,
    };
}

/// the scope a request requires, or null for public/unauthenticated routes.
/// unknown routes fail closed by requiring full admin ("*").
pub fn requiredScope(method: http.Method, path: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, path, "/health") or std.mem.eql(u8, path, "/version")) return null;
    const w = isWrite(method);

    if (std.mem.startsWith(u8, path, "/v1/secrets")) return if (w) "secrets:write" else "secrets:read";
    if (std.mem.startsWith(u8, path, "/v1/policies")) return if (w) "policies:write" else "policies:read";
    if (std.mem.startsWith(u8, path, "/v1/certificates")) return if (w) "certificates:write" else "certificates:read";
    if (std.mem.startsWith(u8, path, "/v1/audit")) return "audit:read";
    if (std.mem.startsWith(u8, path, "/v1/status") or std.mem.startsWith(u8, path, "/v1/metrics")) return "status:read";
    if (std.mem.startsWith(u8, path, "/v1/services")) return if (w) "services:write" else "services:read";
    if (std.mem.eql(u8, path, "/apps/dry-run")) return "apps:read";
    if (std.mem.startsWith(u8, path, "/apps") or std.mem.eql(u8, path, "/deploy")) return if (w) "apps:write" else "apps:read";
    if (std.mem.startsWith(u8, path, "/cluster")) return if (w) "cluster:admin" else "cluster:read";
    if (std.mem.startsWith(u8, path, "/agents") or std.mem.startsWith(u8, path, "/wireguard")) return if (w) "agents:write" else "agents:read";
    if (std.mem.startsWith(u8, path, "/containers")) return if (w) "containers:write" else "containers:read";
    if (std.mem.startsWith(u8, path, "/images")) return if (w) "images:write" else "images:read";
    if (std.mem.startsWith(u8, path, "/s3")) return if (w) "s3:write" else "s3:read";

    return "*"; // unknown route: require admin
}

/// the outcome of authorizing a request.
pub const AuthResult = struct {
    ok: bool = false,
    scopes: []const u8 = "",
    actor_name: []const u8 = "unauthenticated",
    /// set when scopes/actor_name borrow from a token record we must free.
    record: ?store.TokenRecord = null,

    pub fn deinit(self: AuthResult, alloc: std.mem.Allocator) void {
        if (self.record) |r| r.deinit(alloc);
    }

    pub fn allows(self: AuthResult, scope: []const u8) bool {
        return scopes.allows(self.scopes, scope);
    }
};

/// resolve the request's bearer token. `legacy_admin` is the configured single
/// api_token (full admin) if any. precedence: legacy admin token, then a named
/// token looked up by sha256(secret). returns ok=false if neither matches.
pub fn authorize(alloc: std.mem.Allocator, request: *const http.Request, legacy_admin: ?[]const u8) AuthResult {
    if (legacy_admin) |t| {
        if (common.hasValidBearerToken(request, t)) {
            return .{ .ok = true, .scopes = "*", .actor_name = "api-token" };
        }
    }

    const bearer = common.extractBearerToken(request) orelse return .{};
    const hash = hashSecretHex(bearer);
    const rec = (store.findActiveTokenByHash(alloc, &hash, nowSeconds()) catch null) orelse return .{};
    return .{ .ok = true, .scopes = rec.scopes, .actor_name = rec.name, .record = rec };
}

/// sha256 of the presented secret, hex-encoded — matches how the store records
/// a token's hash at create time.
pub fn hashSecretHex(secret: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(secret, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

// -- tests --

test "requiredScope maps representative routes" {
    try std.testing.expect(requiredScope(.GET, "/health") == null);
    try std.testing.expectEqualStrings("secrets:read", requiredScope(.GET, "/v1/secrets").?);
    try std.testing.expectEqualStrings("secrets:write", requiredScope(.POST, "/v1/secrets").?);
    try std.testing.expectEqualStrings("secrets:write", requiredScope(.DELETE, "/v1/secrets/db").?);
    try std.testing.expectEqualStrings("apps:write", requiredScope(.POST, "/apps/apply").?);
    try std.testing.expectEqualStrings("apps:read", requiredScope(.POST, "/apps/dry-run").?);
    try std.testing.expectEqualStrings("apps:read", requiredScope(.GET, "/apps").?);
    try std.testing.expectEqualStrings("cluster:admin", requiredScope(.POST, "/cluster/propose").?);
    try std.testing.expectEqualStrings("cluster:read", requiredScope(.GET, "/cluster/status").?);
    try std.testing.expectEqualStrings("audit:read", requiredScope(.GET, "/v1/audit").?);
    try std.testing.expectEqualStrings("status:read", requiredScope(.GET, "/v1/status/bpf").?);
    // unknown route fails closed
    try std.testing.expectEqualStrings("*", requiredScope(.GET, "/v1/whatever").?);
}

test "authorize accepts the legacy admin token as full admin" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/secrets",
        .path_only = "/v1/secrets",
        .query = "",
        .headers_raw = "Authorization: Bearer adminsecret\r\n",
        .content_length = 0,
        .body = "",
    };
    const result = authorize(std.testing.allocator, &req, "adminsecret");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(result.ok);
    try std.testing.expect(result.allows("secrets:write"));
    try std.testing.expectEqualStrings("api-token", result.actor_name);
}

test "authorize rejects a missing or wrong token" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/secrets",
        .path_only = "/v1/secrets",
        .query = "",
        .headers_raw = "Authorization: Bearer wrong\r\n",
        .content_length = 0,
        .body = "",
    };
    const result = authorize(std.testing.allocator, &req, "adminsecret");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(!result.ok);
}
