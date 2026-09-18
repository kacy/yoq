const std = @import("std");

pub const Credentials = struct {
    encoded_auth: []u8,
    token_origin: ?[]u8 = null,

    pub fn deinit(self: Credentials, alloc: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.encoded_auth);
        alloc.free(self.encoded_auth);
        if (self.token_origin) |origin| alloc.free(origin);
    }
};

// read standard docker auth entries without executing credential helpers.
// a separate token service must be explicitly trusted by its registry entry.
pub fn load(alloc: std.mem.Allocator, host: []const u8) error{ AuthFailed, OutOfMemory }!?Credentials {
    var path_buffer: [4096]u8 = undefined;
    const docker_config = if (std.c.getenv("DOCKER_CONFIG")) |value| std.mem.span(value) else "";
    const path = if (docker_config.len > 0)
        std.fmt.bufPrint(&path_buffer, "{s}/config.json", .{docker_config}) catch return error.AuthFailed
    else if (std.c.getenv("HOME")) |home|
        std.fmt.bufPrint(&path_buffer, "{s}/.docker/config.json", .{std.mem.span(home)}) catch return error.AuthFailed
    else
        return null;
    const bytes = std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, path, alloc, .limited(1024 * 1024)) catch |err| return switch (err) {
        error.FileNotFound => null,
        error.OutOfMemory => error.OutOfMemory,
        else => error.AuthFailed,
    };
    defer {
        std.crypto.secureZero(u8, bytes);
        alloc.free(bytes);
    }
    return parse(alloc, bytes, host);
}

fn parse(alloc: std.mem.Allocator, bytes: []const u8, host: []const u8) error{ AuthFailed, OutOfMemory }!?Credentials {
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, bytes, .{}) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.AuthFailed,
    };
    defer parsed.deinit();
    if (parsed.value != .object) return error.AuthFailed;
    const auths = parsed.value.object.get("auths") orelse return null;
    if (auths != .object) return error.AuthFailed;
    var entries = auths.object.iterator();
    while (entries.next()) |entry| {
        if (!matchesHost(entry.key_ptr.*, host)) continue;
        if (entry.value_ptr.* != .object) return error.AuthFailed;
        const auth = entry.value_ptr.object.get("auth") orelse return null;
        if (auth != .string or auth.string.len == 0 or auth.string.len > 4096) return error.AuthFailed;
        var decoded: [4096]u8 = undefined;
        defer std.crypto.secureZero(u8, &decoded);
        const length = std.base64.standard.Decoder.calcSizeForSlice(auth.string) catch return error.AuthFailed;
        std.base64.standard.Decoder.decode(decoded[0..length], auth.string) catch return error.AuthFailed;
        if (std.mem.indexOfScalar(u8, decoded[0..length], ':') == null) return error.AuthFailed;
        const encoded = try alloc.dupe(u8, auth.string);
        errdefer {
            std.crypto.secureZero(u8, encoded);
            alloc.free(encoded);
        }
        const origin = entry.value_ptr.object.get("yoq_token_origin");
        if (origin) |value| if (value != .string) return error.AuthFailed;
        return .{ .encoded_auth = encoded, .token_origin = if (origin) |value| try alloc.dupe(u8, value.string) else null };
    }
    return null;
}

fn matchesHost(key: []const u8, host: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(key, host)) return true;
    if (std.ascii.eqlIgnoreCase(host, "registry-1.docker.io") and
        (std.ascii.eqlIgnoreCase(key, "https://index.docker.io/v1/") or std.ascii.eqlIgnoreCase(key, "docker.io"))) return true;
    if (!std.mem.startsWith(u8, key, "https://")) return false;
    return std.ascii.eqlIgnoreCase(std.mem.trimEnd(u8, key[8..], "/"), host);
}

pub fn permitsTokenUrl(host: []const u8, credentials: Credentials, uri: std.Uri) bool {
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https") or uri.user != null or uri.password != null) return false;
    var origin_buffer: [1024]u8 = undefined;
    const registry_origin = std.fmt.bufPrint(&origin_buffer, "https://{s}", .{host}) catch return false;
    if (sameOrigin(registry_origin, uri)) return true;
    if (std.ascii.eqlIgnoreCase(host, "registry-1.docker.io") and sameOrigin("https://auth.docker.io", uri)) return true;
    return if (credentials.token_origin) |origin| sameOrigin(origin, uri) else false;
}

fn sameOrigin(origin: []const u8, uri: std.Uri) bool {
    const expected = std.Uri.parse(origin) catch return false;
    if (!std.ascii.eqlIgnoreCase(expected.scheme, "https") or expected.user != null or expected.password != null or expected.query != null or expected.fragment != null or !expected.path.isEmpty()) return false;
    var expected_buffer: [255]u8 = undefined;
    var actual_buffer: [255]u8 = undefined;
    const expected_host = expected.getHost(&expected_buffer) catch return false;
    const actual_host = uri.getHost(&actual_buffer) catch return false;
    return std.ascii.eqlIgnoreCase(expected_host.bytes, actual_host.bytes) and (expected.port orelse 443) == (uri.port orelse 443);
}

test "registry credentials match exact hosts and keep token services scoped" {
    const alloc = std.testing.allocator;
    const config = "{\"auths\":{\"registry.example:5000\":{\"auth\":\"dXNlcjpwYXNz\",\"yoq_token_origin\":\"https://auth.example\"}}}";
    const credentials = (try parse(alloc, config, "registry.example:5000")) orelse return error.MissingCredentials;
    defer credentials.deinit(alloc);
    try std.testing.expectEqualStrings("dXNlcjpwYXNz", credentials.encoded_auth);
    try std.testing.expectEqual(null, try parse(alloc, config, "registry.example"));
    try std.testing.expectEqual(null, try parse(alloc, config, "registry.example:5000.evil"));
    try std.testing.expect(permitsTokenUrl("registry.example:5000", credentials, try std.Uri.parse("https://registry.example:5000/token")));
    try std.testing.expect(permitsTokenUrl("registry.example:5000", credentials, try std.Uri.parse("https://auth.example/token")));
    for ([_][]const u8{ "http://auth.example/token", "https://auth.example:444/token", "https://auth.example.evil/token", "https://user@auth.example/token" }) |url|
        try std.testing.expect(!permitsTokenUrl("registry.example:5000", credentials, try std.Uri.parse(url)));
}

test "registry credentials reject invalid encodings and recognize the docker login key" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.AuthFailed, parse(alloc, "{\"auths\":{\"example\":{\"auth\":\"%%%\"}}}", "example"));
    const credentials = (try parse(alloc, "{\"auths\":{\"https://index.docker.io/v1/\":{\"auth\":\"dXNlcjpwYXNz\"}}}", "registry-1.docker.io")) orelse return error.MissingCredentials;
    defer credentials.deinit(alloc);
    try std.testing.expect(permitsTokenUrl("registry-1.docker.io", credentials, try std.Uri.parse("https://auth.docker.io/token")));
    try std.testing.expect(!permitsTokenUrl("registry-1.docker.io", credentials, try std.Uri.parse("https://auth.docker.io.evil/token")));
}

test "registry credentials release partial allocations" {
    const Fixture = struct {
        fn load(alloc: std.mem.Allocator) !void {
            const credentials = (try parse(alloc, "{\"auths\":{\"registry.example\":{\"auth\":\"dXNlcjpwYXNz\",\"yoq_token_origin\":\"https://auth.example\"}}}", "registry.example")) orelse return error.MissingCredentials;
            defer credentials.deinit(alloc);
            try std.testing.expectEqualStrings("dXNlcjpwYXNz", credentials.encoded_auth);
            try std.testing.expectEqualStrings("https://auth.example", credentials.token_origin.?);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Fixture.load, .{});
}
