// scopes — the permission vocabulary for API tokens.
//
// a scope is one of:
//   "*"                  full admin (everything)
//   "<resource>:read"    read (GET/HEAD) on a resource
//   "<resource>:write"   write (POST/PUT/DELETE) on a resource
//   "<resource>:*"       any operation on a resource
//   "cluster:admin"      cluster mutations (propose, step-down)
//
// write implies read for the same resource. a token carries a comma-separated
// list of scopes; a request requires one concrete scope (e.g. "secrets:write").

const std = @import("std");

pub const resources = [_][]const u8{
    "apps",   "secrets",    "policies", "certificates",
    "audit",  "status",     "services", "cluster",
    "agents", "containers", "images",   "s3",
};

fn isResource(name: []const u8) bool {
    for (resources) |r| {
        if (std.mem.eql(u8, r, name)) return true;
    }
    return false;
}

/// validate a scope string a user passed to `yoq token create`.
pub fn isValidScope(scope: []const u8) bool {
    if (std.mem.eql(u8, scope, "*")) return true;
    const colon = std.mem.indexOfScalar(u8, scope, ':') orelse return false;
    const res = scope[0..colon];
    const verb = scope[colon + 1 ..];
    if (!isResource(res)) return false;
    if (std.mem.eql(u8, verb, "read") or std.mem.eql(u8, verb, "write") or std.mem.eql(u8, verb, "*")) return true;
    if (std.mem.eql(u8, res, "cluster") and std.mem.eql(u8, verb, "admin")) return true;
    return false;
}

/// does a token's comma-separated scope list grant `required`?
/// `required` is a concrete scope like "secrets:write" or "cluster:admin".
pub fn allows(csv: []const u8, required: []const u8) bool {
    var it = std.mem.splitScalar(u8, csv, ',');
    while (it.next()) |raw| {
        if (grants(std.mem.trim(u8, raw, " \t"), required)) return true;
    }
    return false;
}

fn grants(scope: []const u8, required: []const u8) bool {
    if (std.mem.eql(u8, scope, "*")) return true;
    if (std.mem.eql(u8, scope, required)) return true;

    const req_colon = std.mem.indexOfScalar(u8, required, ':') orelse return false;
    const scope_colon = std.mem.indexOfScalar(u8, scope, ':') orelse return false;
    const req_res = required[0..req_colon];
    const req_verb = required[req_colon + 1 ..];
    const scope_res = scope[0..scope_colon];
    const scope_verb = scope[scope_colon + 1 ..];

    if (!std.mem.eql(u8, scope_res, req_res)) return false;
    if (std.mem.eql(u8, scope_verb, "*")) return true;
    // write implies read for the same resource.
    if (std.mem.eql(u8, req_verb, "read") and std.mem.eql(u8, scope_verb, "write")) return true;
    return false;
}

test "isValidScope accepts known forms and rejects unknown" {
    try std.testing.expect(isValidScope("*"));
    try std.testing.expect(isValidScope("apps:read"));
    try std.testing.expect(isValidScope("secrets:write"));
    try std.testing.expect(isValidScope("secrets:*"));
    try std.testing.expect(isValidScope("cluster:admin"));
    try std.testing.expect(!isValidScope("apps"));
    try std.testing.expect(!isValidScope("bogus:read"));
    try std.testing.expect(!isValidScope("apps:delete"));
    try std.testing.expect(!isValidScope("status:admin")); // admin is cluster-only
}

test "allows honors wildcards and write-implies-read" {
    try std.testing.expect(allows("*", "secrets:write"));
    try std.testing.expect(allows("secrets:*", "secrets:read"));
    try std.testing.expect(allows("secrets:write", "secrets:read")); // write implies read
    try std.testing.expect(allows("apps:read,secrets:write", "apps:read"));
    try std.testing.expect(!allows("secrets:read", "secrets:write")); // read does not imply write
    try std.testing.expect(!allows("apps:write", "secrets:read"));
    try std.testing.expect(!allows("apps:read", "cluster:admin"));
}
