const std = @import("std");

pub const Match = struct {
    host: ?[]const u8 = null,
    path_prefix: []const u8 = "/",
};

pub const Route = struct {
    name: []const u8,
    service: []const u8,
    vip_address: []const u8,
    match: Match,
    retries: u8 = 0,
    connect_timeout_ms: u32 = 1000,
    request_timeout_ms: u32 = 5000,
    preserve_host: bool = true,
};

pub fn matchRoute(routes: []const Route, host: []const u8, path: []const u8) ?Route {
    var best: ?Route = null;
    var best_prefix_len: usize = 0;

    for (routes) |route| {
        if (route.match.host) |expected_host| {
            if (!std.ascii.eqlIgnoreCase(expected_host, host)) continue;
        }
        if (!std.mem.startsWith(u8, path, route.match.path_prefix)) continue;

        if (best == null or route.match.path_prefix.len > best_prefix_len) {
            best = route;
            best_prefix_len = route.match.path_prefix.len;
        }
    }

    return best;
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

    const route = matchRoute(&routes, "api.example.com", "/v1/users") orelse return error.TestExpectedNonNull;
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

    const route = matchRoute(&routes, "api.example.com", "/v1/health") orelse return error.TestExpectedNonNull;
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

    const route = matchRoute(&routes, "unknown.example.com", "/") orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("catch-all", route.name);
}
