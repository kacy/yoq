const std = @import("std");
const http = @import("../../api/http.zig");
const proxy_runtime = @import("runtime.zig");
const router = @import("router.zig");
const upstream_mod = @import("upstream.zig");

pub const ProxyResponse = struct {
    status: http.StatusCode,
    body: []const u8,
};

pub const ForwardPlan = struct {
    method: http.Method,
    path: []const u8,
    host: []const u8,
    outbound_host: []const u8,
    route: proxy_runtime.RouteSnapshot,
    upstream: upstream_mod.Upstream,

    pub fn deinit(self: ForwardPlan, alloc: std.mem.Allocator) void {
        alloc.free(self.path);
        alloc.free(self.host);
        alloc.free(self.outbound_host);
        self.route.deinit(alloc);
        self.upstream.deinit(alloc);
    }
};

pub const HandleResult = union(enum) {
    forward: ForwardPlan,
    response: ProxyResponse,

    pub fn deinit(self: HandleResult, alloc: std.mem.Allocator) void {
        switch (self) {
            .forward => |plan| plan.deinit(alloc),
            .response => {},
        }
    }
};

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

    pub fn handleRequest(self: *const ReverseProxy, raw_request: []const u8) !HandleResult {
        const request = http.parseRequest(raw_request) catch {
            return .{ .response = .{
                .status = .bad_request,
                .body = "{\"error\":\"invalid request\"}",
            } };
        } orelse return .{ .response = .{
            .status = .bad_request,
            .body = "{\"error\":\"incomplete request\"}",
        } };

        const host_header = http.findHeaderValue(request.headers_raw, "Host") orelse return .{ .response = .{
            .status = .bad_request,
            .body = "{\"error\":\"missing host header\"}",
        } };
        const host = normalizeHost(host_header);

        const matched_route = router.matchRoute(self.routes, host, request.path_only) orelse return .{ .response = .{
            .status = .not_found,
            .body = "{\"error\":\"route not found\"}",
        } };
        const route = try cloneRouteSnapshot(self.allocator, matched_route);
        errdefer route.deinit(self.allocator);

        const upstream = proxy_runtime.resolveUpstream(self.allocator, route.service) catch |err| switch (err) {
            error.NoHealthyUpstream => return .{ .response = .{
                .status = .service_unavailable,
                .body = "{\"error\":\"no eligible upstream\"}",
            } },
            else => return err,
        };
        errdefer upstream.deinit(self.allocator);

        return .{ .forward = .{
            .method = request.method,
            .path = try self.allocator.dupe(u8, request.path),
            .host = try self.allocator.dupe(u8, host),
            .outbound_host = if (route.preserve_host)
                try self.allocator.dupe(u8, host)
            else
                try self.allocator.dupe(u8, route.service),
            .route = route,
            .upstream = upstream,
        } };
    }

    pub fn buildForwardRequest(self: *const ReverseProxy, raw_request: []const u8, plan: *const ForwardPlan) ![]u8 {
        const parsed = (http.parseRequest(raw_request) catch return error.BadRequest) orelse return error.BadRequest;

        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        const writer = buf.writer(self.allocator);

        try writer.print("{s} {s} HTTP/1.1\r\n", .{
            methodString(parsed.method),
            parsed.path,
        });
        try writer.print("Host: {s}\r\n", .{plan.outbound_host});

        var pos: usize = 0;
        while (pos < parsed.headers_raw.len) {
            const line_end = std.mem.indexOfPos(u8, parsed.headers_raw, pos, "\r\n") orelse parsed.headers_raw.len;
            const line = parsed.headers_raw[pos..line_end];
            pos = if (line_end + 2 <= parsed.headers_raw.len) line_end + 2 else parsed.headers_raw.len;

            if (line.len == 0) continue;
            if (startsWithHeaderName(line, "Host")) continue;
            if (startsWithHeaderName(line, "Connection")) continue;
            if (startsWithHeaderName(line, "Content-Length")) continue;

            try writer.writeAll(line);
            try writer.writeAll("\r\n");
        }

        try writer.print("Content-Length: {d}\r\n", .{parsed.body.len});
        try writer.writeAll("Connection: close\r\n\r\n");
        try writer.writeAll(parsed.body);

        return buf.toOwnedSlice(self.allocator);
    }
};

fn normalizeHost(host_header: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, host_header, ':')) |port_sep| {
        return host_header[0..port_sep];
    }
    return host_header;
}

fn methodString(method: http.Method) []const u8 {
    return switch (method) {
        .GET => "GET",
        .HEAD => "HEAD",
        .POST => "POST",
        .PUT => "PUT",
        .DELETE => "DELETE",
    };
}

fn startsWithHeaderName(line: []const u8, name: []const u8) bool {
    if (line.len <= name.len or line[name.len] != ':') return false;
    for (line[0..name.len], name) |a, b| {
        if (std.ascii.toLower(a) != std.ascii.toLower(b)) return false;
    }
    return true;
}

fn cloneRouteSnapshot(alloc: std.mem.Allocator, route: router.Route) !proxy_runtime.RouteSnapshot {
    return .{
        .name = try alloc.dupe(u8, route.name),
        .service = try alloc.dupe(u8, route.service),
        .vip_address = try alloc.dupe(u8, route.vip_address),
        .host = try alloc.dupe(u8, route.match.host orelse ""),
        .path_prefix = try alloc.dupe(u8, route.match.path_prefix),
        .eligible_endpoints = route.eligible_endpoints,
        .healthy_endpoints = route.healthy_endpoints,
        .degraded = route.degraded,
        .retries = route.retries,
        .connect_timeout_ms = route.connect_timeout_ms,
        .request_timeout_ms = route.request_timeout_ms,
        .preserve_host = route.preserve_host,
    };
}

test "reverse proxy starts and stops" {
    const alloc = std.testing.allocator;
    const routes = [_]router.Route{
        .{
            .name = "api",
            .service = "api",
            .vip_address = "10.43.0.2",
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
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.example.com", .path_prefix = "/v1" },
        },
    };

    var proxy = ReverseProxy.init(alloc, &routes);
    defer proxy.deinit();

    try std.testing.expectEqual(@as(usize, 1), proxy.routes.len);
    try std.testing.expectEqualStrings("api-v1", proxy.routes[0].name);
}

test "handleRequest returns forward plan for a routable request" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .http_proxy_preserve_host = false,
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-1",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "10.42.0.9",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    proxy_runtime.bootstrapIfEnabled();

    const routes = [_]router.Route{
        .{
            .name = "api:/v1",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/v1" },
            .eligible_endpoints = 1,
        },
    };

    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const result = try proxy.handleRequest(
        "GET /v1/users HTTP/1.1\r\nHost: api.internal\r\n\r\n",
    );
    defer result.deinit(std.testing.allocator);

    switch (result) {
        .forward => |plan| {
            try std.testing.expectEqual(http.Method.GET, plan.method);
            try std.testing.expectEqualStrings("/v1/users", plan.path);
            try std.testing.expectEqualStrings("api", plan.route.service);
            try std.testing.expectEqualStrings("10.42.0.9", plan.upstream.address);
            try std.testing.expectEqualStrings("api", plan.outbound_host);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "handleRequest returns bad request when Host is missing" {
    const routes = [_]router.Route{
        .{
            .name = "api:/",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/" },
        },
    };

    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const result = try proxy.handleRequest(
        "GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
    );
    defer result.deinit(std.testing.allocator);

    switch (result) {
        .response => |resp| try std.testing.expectEqual(http.StatusCode.bad_request, resp.status),
        .forward => return error.TestUnexpectedResult,
    }
}

test "handleRequest returns not found when no route matches" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .created_at = 1000,
        .updated_at = 1000,
    });
    proxy_runtime.bootstrapIfEnabled();

    const routes = [_]router.Route{};
    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const result = try proxy.handleRequest(
        "GET /missing HTTP/1.1\r\nHost: unknown.internal\r\n\r\n",
    );
    defer result.deinit(std.testing.allocator);

    switch (result) {
        .response => |resp| try std.testing.expectEqual(http.StatusCode.not_found, resp.status),
        .forward => return error.TestUnexpectedResult,
    }
}

test "handleRequest returns service unavailable when route has no eligible upstream" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-1",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "10.42.0.9",
        .port = 8080,
        .weight = 1,
        .admin_state = "draining",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    proxy_runtime.bootstrapIfEnabled();

    const routes = [_]router.Route{
        .{
            .name = "api:/v1",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/v1" },
        },
    };
    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const result = try proxy.handleRequest(
        "GET /v1/users HTTP/1.1\r\nHost: api.internal\r\n\r\n",
    );
    defer result.deinit(std.testing.allocator);

    switch (result) {
        .response => |resp| try std.testing.expectEqual(http.StatusCode.service_unavailable, resp.status),
        .forward => return error.TestUnexpectedResult,
    }
}

test "buildForwardRequest rewrites Host when preserve_host is false" {
    const routes = [_]router.Route{
        .{
            .name = "api:/v1",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/v1" },
            .preserve_host = false,
        },
    };

    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    var plan = ForwardPlan{
        .method = .GET,
        .path = try std.testing.allocator.dupe(u8, "/v1/users"),
        .host = try std.testing.allocator.dupe(u8, "api.internal"),
        .outbound_host = try std.testing.allocator.dupe(u8, "api"),
        .route = .{
            .name = try std.testing.allocator.dupe(u8, "api:/v1"),
            .service = try std.testing.allocator.dupe(u8, "api"),
            .vip_address = try std.testing.allocator.dupe(u8, "10.43.0.2"),
            .host = try std.testing.allocator.dupe(u8, "api.internal"),
            .path_prefix = try std.testing.allocator.dupe(u8, "/v1"),
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
            .degraded = false,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
            .preserve_host = false,
        },
        .upstream = .{
            .service = try std.testing.allocator.dupe(u8, "api"),
            .endpoint_id = try std.testing.allocator.dupe(u8, "api-1"),
            .address = try std.testing.allocator.dupe(u8, "10.42.0.9"),
            .port = 8080,
            .eligible = true,
        },
    };
    defer plan.deinit(std.testing.allocator);

    const forwarded = try proxy.buildForwardRequest(
        "GET /v1/users HTTP/1.1\r\nHost: api.internal\r\nConnection: keep-alive\r\nX-Test: 1\r\n\r\n",
        &plan,
    );
    defer std.testing.allocator.free(forwarded);

    try std.testing.expect(std.mem.indexOf(u8, forwarded, "GET /v1/users HTTP/1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Host: api\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "X-Test: 1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Connection: close\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Connection: keep-alive\r\n") == null);
}

test "buildForwardRequest preserves body and content length" {
    const routes = [_]router.Route{
        .{
            .name = "api:/",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/" },
            .preserve_host = true,
        },
    };

    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    var plan = ForwardPlan{
        .method = .POST,
        .path = try std.testing.allocator.dupe(u8, "/submit"),
        .host = try std.testing.allocator.dupe(u8, "api.internal"),
        .outbound_host = try std.testing.allocator.dupe(u8, "api.internal"),
        .route = .{
            .name = try std.testing.allocator.dupe(u8, "api:/"),
            .service = try std.testing.allocator.dupe(u8, "api"),
            .vip_address = try std.testing.allocator.dupe(u8, "10.43.0.2"),
            .host = try std.testing.allocator.dupe(u8, "api.internal"),
            .path_prefix = try std.testing.allocator.dupe(u8, "/"),
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
            .degraded = false,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
            .preserve_host = true,
        },
        .upstream = .{
            .service = try std.testing.allocator.dupe(u8, "api"),
            .endpoint_id = try std.testing.allocator.dupe(u8, "api-1"),
            .address = try std.testing.allocator.dupe(u8, "10.42.0.9"),
            .port = 8080,
            .eligible = true,
        },
    };
    defer plan.deinit(std.testing.allocator);

    const forwarded = try proxy.buildForwardRequest(
        "POST /submit HTTP/1.1\r\nHost: api.internal\r\nContent-Length: 999\r\n\r\nhello",
        &plan,
    );
    defer std.testing.allocator.free(forwarded);

    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Host: api.internal\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Content-Length: 5\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, forwarded, "hello"));
}
