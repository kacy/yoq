const std = @import("std");

pub const Match = struct {
    host: ?[]const u8 = null,
    path_prefix: []const u8 = "/",
};

pub const MethodMatch = struct {
    method: []const u8,

    pub fn deinit(self: MethodMatch, alloc: std.mem.Allocator) void {
        alloc.free(self.method);
    }
};

pub const HeaderMatch = struct {
    name: []const u8,
    value: []const u8,

    pub fn deinit(self: HeaderMatch, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.value);
    }
};

pub const RequestHeader = struct {
    name: []const u8,
    value: []const u8,
};

pub const BackendTarget = struct {
    service_name: []const u8,
    weight: u8,

    pub fn deinit(self: BackendTarget, alloc: std.mem.Allocator) void {
        alloc.free(self.service_name);
    }
};

pub const Route = struct {
    name: []const u8,
    service: []const u8,
    vip_address: []const u8,
    match: Match,
    rewrite_prefix: ?[]const u8 = null,
    method_matches: []const MethodMatch = &.{},
    header_matches: []const HeaderMatch = &.{},
    backend_services: []const BackendTarget = &.{},
    mirror_service: ?[]const u8 = null,
    eligible_endpoints: u32 = 0,
    healthy_endpoints: u32 = 0,
    degraded: bool = false,
    retries: u8 = 0,
    connect_timeout_ms: u32 = 1000,
    request_timeout_ms: u32 = 5000,
    http2_idle_timeout_ms: u32 = 30000,
    preserve_host: bool = true,
    retry_on_5xx: bool = true,
    circuit_breaker_threshold: u8 = 3,
    circuit_breaker_timeout_ms: u32 = 30_000,
};

pub fn matchRoute(routes: []const Route, method: []const u8, host: []const u8, path: []const u8, request_headers: []const RequestHeader) ?Route {
    var best: ?Route = null;
    var best_prefix_len: usize = 0;
    var best_header_match_count: usize = 0;
    var best_method_specificity: usize = std.math.maxInt(usize);

    for (routes) |route| {
        if (route.match.host) |expected_host| {
            if (!std.ascii.eqlIgnoreCase(expected_host, host)) continue;
        }
        if (!std.mem.startsWith(u8, path, route.match.path_prefix)) continue;
        if (!routeMethodsMatch(route.method_matches, method)) continue;
        if (!routeHeadersMatch(route.header_matches, request_headers)) continue;
        const method_specificity = methodSpecificity(route.method_matches);

        if (best == null or
            route.match.path_prefix.len > best_prefix_len or
            (route.match.path_prefix.len == best_prefix_len and route.header_matches.len > best_header_match_count) or
            (route.match.path_prefix.len == best_prefix_len and
                route.header_matches.len == best_header_match_count and
                method_specificity < best_method_specificity))
        {
            best = route;
            best_prefix_len = route.match.path_prefix.len;
            best_header_match_count = route.header_matches.len;
            best_method_specificity = method_specificity;
        }
    }

    return best;
}

pub fn collectHttp1Headers(alloc: std.mem.Allocator, headers_raw: []const u8) ![]const RequestHeader {
    var headers: std.ArrayList(RequestHeader) = .empty;
    errdefer headers.deinit(alloc);

    var pos: usize = 0;
    while (pos < headers_raw.len) {
        const line_end = std.mem.indexOfPos(u8, headers_raw, pos, "\r\n") orelse headers_raw.len;
        const line = headers_raw[pos..line_end];
        if (std.mem.indexOfScalar(u8, line, ':')) |sep| {
            const name = std.mem.trim(u8, line[0..sep], " \t");
            const value = std.mem.trim(u8, line[sep + 1 ..], " \t");
            try headers.append(alloc, .{
                .name = name,
                .value = value,
            });
        }
        pos = if (line_end + 2 <= headers_raw.len) line_end + 2 else headers_raw.len;
    }

    return headers.toOwnedSlice(alloc);
}

fn routeMethodsMatch(route_matches: []const MethodMatch, request_method: []const u8) bool {
    if (route_matches.len == 0) return true;
    for (route_matches) |expected| {
        if (std.mem.eql(u8, expected.method, request_method)) return true;
    }
    return false;
}

fn methodSpecificity(route_matches: []const MethodMatch) usize {
    return if (route_matches.len == 0) std.math.maxInt(usize) else route_matches.len;
}

fn routeHeadersMatch(route_matches: []const HeaderMatch, request_headers: []const RequestHeader) bool {
    for (route_matches) |expected| {
        var found = false;
        for (request_headers) |header| {
            if (!std.ascii.eqlIgnoreCase(expected.name, header.name)) continue;
            if (!std.mem.eql(u8, expected.value, header.value)) continue;
            found = true;
            break;
        }
        if (!found) return false;
    }
    return true;
}

test "matchRoute matches host and path prefix" {
    const routes = [_]Route{
        .{
            .name = "web-root",
            .service = "web",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "example.com", .path_prefix = "/" },
        },
        .{
            .name = "api-v1",
            .service = "api",
            .vip_address = "10.43.0.3",
            .match = .{ .host = "api.example.com", .path_prefix = "/v1" },
        },
    };

    const route = matchRoute(&routes, "GET", "api.example.com", "/v1/users", &.{}) orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("api-v1", route.name);
}

test "matchRoute prefers longest path prefix" {
    const routes = [_]Route{
        .{
            .name = "api-root",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.example.com", .path_prefix = "/" },
        },
        .{
            .name = "api-v1",
            .service = "api-v1",
            .vip_address = "10.43.0.3",
            .match = .{ .host = "api.example.com", .path_prefix = "/v1" },
        },
    };

    const route = matchRoute(&routes, "GET", "api.example.com", "/v1/health", &.{}) orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("api-v1", route.service);
}

test "matchRoute accepts wildcard host when omitted" {
    const routes = [_]Route{
        .{
            .name = "catch-all",
            .service = "web",
            .vip_address = "10.43.0.2",
            .match = .{ .host = null, .path_prefix = "/" },
        },
    };

    const route = matchRoute(&routes, "GET", "unknown.example.com", "/", &.{}) orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("catch-all", route.name);
}

test "matchRoute prefers more specific header match on the same path" {
    const routes = [_]Route{
        .{
            .name = "api-default",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.example.com", .path_prefix = "/v1" },
        },
        .{
            .name = "api-canary",
            .service = "api-canary",
            .vip_address = "10.43.0.3",
            .match = .{ .host = "api.example.com", .path_prefix = "/v1" },
            .header_matches = &.{
                .{ .name = "x-env", .value = "canary" },
            },
        },
    };
    const request_headers = [_]RequestHeader{
        .{ .name = "X-Env", .value = "canary" },
    };

    const route = matchRoute(&routes, "GET", "api.example.com", "/v1/users", &request_headers) orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("api-canary", route.name);
}

test "matchRoute rejects route when required header is missing" {
    const routes = [_]Route{
        .{
            .name = "api-canary",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.example.com", .path_prefix = "/v1" },
            .header_matches = &.{
                .{ .name = "x-env", .value = "canary" },
            },
        },
    };

    try std.testing.expect(matchRoute(&routes, "GET", "api.example.com", "/v1/users", &.{}) == null);
}

test "matchRoute prefers method-specific route on the same path" {
    const routes = [_]Route{
        .{
            .name = "api-default",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.example.com", .path_prefix = "/v1" },
        },
        .{
            .name = "api-post",
            .service = "api-write",
            .vip_address = "10.43.0.3",
            .match = .{ .host = "api.example.com", .path_prefix = "/v1" },
            .method_matches = &.{
                .{ .method = "POST" },
            },
        },
    };

    const route = matchRoute(&routes, "POST", "api.example.com", "/v1/users", &.{}) orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("api-post", route.name);
}

test "matchRoute rejects route when method is not allowed" {
    const routes = [_]Route{
        .{
            .name = "api-post",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.example.com", .path_prefix = "/v1" },
            .method_matches = &.{
                .{ .method = "POST" },
            },
        },
    };

    try std.testing.expect(matchRoute(&routes, "GET", "api.example.com", "/v1/users", &.{}) == null);
}
