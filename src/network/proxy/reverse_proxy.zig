const std = @import("std");
const router = @import("router.zig");

pub const ReverseProxy = struct {
    allocator: std.mem.Allocator,
    routes: []const router.Route,
    running: bool = false,

    pub fn init(allocator: std.mem.Allocator, routes: []const router.Route) ReverseProxy {
        return .{
            .allocator = allocator,
            .routes = routes,
        };
    }

    pub fn deinit(self: *ReverseProxy) void {
        _ = self;
    }

    pub fn start(self: *ReverseProxy) void {
        self.running = true;
    }

    pub fn stop(self: *ReverseProxy) void {
        self.running = false;
    }

    pub fn isRunning(self: *const ReverseProxy) bool {
        return self.running;
    }
};

test "reverse proxy starts and stops" {
    const alloc = std.testing.allocator;
    const routes = [_]router.Route{
        .{
            .name = "api",
            .service = "api",
            .match = .{ .host = "api.example.com", .path_prefix = "/" },
        },
    };

    var proxy = ReverseProxy.init(alloc, &routes);
    defer proxy.deinit();

    try std.testing.expect(!proxy.isRunning());
    proxy.start();
    try std.testing.expect(proxy.isRunning());
    proxy.stop();
    try std.testing.expect(!proxy.isRunning());
}

test "reverse proxy retains configured routes" {
    const alloc = std.testing.allocator;
    const routes = [_]router.Route{
        .{
            .name = "api-v1",
            .service = "api",
            .match = .{ .host = "api.example.com", .path_prefix = "/v1" },
        },
    };

    var proxy = ReverseProxy.init(alloc, &routes);
    defer proxy.deinit();

    try std.testing.expectEqual(@as(usize, 1), proxy.routes.len);
    try std.testing.expectEqualStrings("api-v1", proxy.routes[0].name);
}
