const std = @import("std");
const posix = std.posix;
const http = @import("../../api/http.zig");
const ip = @import("../ip.zig");
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
    max_response_bytes: usize = 64 * 1024,

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

    pub fn forwardRequest(self: *const ReverseProxy, raw_request: []const u8) ![]u8 {
        const handled = try self.handleRequest(raw_request);
        switch (handled) {
            .response => |resp| return formatProxyResponse(self.allocator, resp),
            .forward => |plan| {
                defer plan.deinit(self.allocator);
                return self.forwardPlan(raw_request, &plan);
            },
        }
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

    fn forwardPlan(self: *const ReverseProxy, raw_request: []const u8, plan: *const ForwardPlan) ![]u8 {
        var retries_remaining = plan.route.retries;
        while (true) {
            const response = self.forwardSingleAttempt(raw_request, plan) catch |err| {
                if (shouldRetryForward(plan.method, retries_remaining, err)) {
                    retries_remaining -= 1;
                    continue;
                }
                return formatProxyResponse(self.allocator, proxyFailureResponse(err));
            };
            return response;
        }
    }

    fn forwardSingleAttempt(self: *const ReverseProxy, raw_request: []const u8, plan: *const ForwardPlan) ![]u8 {
        const request = try self.buildForwardRequest(raw_request, plan);
        defer self.allocator.free(request);

        const fd = try connectToUpstream(plan);
        defer posix.close(fd);

        writeAll(fd, request) catch return error.SendFailed;
        return readResponse(self.allocator, fd, self.max_response_bytes);
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

fn formatProxyResponse(alloc: std.mem.Allocator, response: ProxyResponse) ![]u8 {
    return std.fmt.allocPrint(
        alloc,
        "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{
            @intFromEnum(response.status),
            response.status.phrase(),
            response.body.len,
            response.body,
        },
    );
}

fn proxyFailureResponse(err: anyerror) ProxyResponse {
    return switch (err) {
        error.InvalidUpstreamAddress => .{
            .status = .bad_gateway,
            .body = "{\"error\":\"invalid upstream address\"}",
        },
        error.ResponseTooLarge => .{
            .status = .bad_gateway,
            .body = "{\"error\":\"upstream response too large\"}",
        },
        error.ConnectFailed => .{
            .status = .bad_gateway,
            .body = "{\"error\":\"upstream connect failed\"}",
        },
        error.SendFailed => .{
            .status = .bad_gateway,
            .body = "{\"error\":\"upstream send failed\"}",
        },
        error.ReceiveFailed => .{
            .status = .bad_gateway,
            .body = "{\"error\":\"upstream receive failed\"}",
        },
        else => .{
            .status = .bad_gateway,
            .body = "{\"error\":\"upstream request failed\"}",
        },
    };
}

fn shouldRetryForward(method: http.Method, retries_remaining: u8, err: anyerror) bool {
    if (retries_remaining == 0) return false;
    if (!isSafeRetryMethod(method)) return false;

    return switch (err) {
        error.ConnectFailed, error.SendFailed, error.ReceiveFailed => true,
        else => false,
    };
}

fn isSafeRetryMethod(method: http.Method) bool {
    return switch (method) {
        .GET, .HEAD => true,
        .POST, .PUT, .DELETE => false,
    };
}

fn connectToUpstream(plan: *const ForwardPlan) !posix.socket_t {
    const upstream_ip = ip.parseIp(plan.upstream.address) orelse return error.InvalidUpstreamAddress;

    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch
        return error.ConnectFailed;
    errdefer posix.close(fd);

    setSocketTimeoutMs(fd, plan.route.connect_timeout_ms);
    const addr = std.net.Address.initIp4(upstream_ip, plan.upstream.port);
    posix.connect(fd, &addr.any, addr.getOsSockLen()) catch return error.ConnectFailed;
    setSocketTimeoutMs(fd, plan.route.request_timeout_ms);
    return fd;
}

fn setSocketTimeoutMs(fd: posix.socket_t, timeout_ms: u32) void {
    const tv = posix.timeval{
        .sec = @divTrunc(timeout_ms, 1000),
        .usec = @as(i64, @intCast(@rem(timeout_ms, 1000))) * 1000,
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};
}

fn writeAll(fd: posix.socket_t, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const bytes_written = posix.write(fd, data[written..]) catch return error.WriteFailed;
        if (bytes_written == 0) return error.WriteFailed;
        written += bytes_written;
    }
}

fn readResponse(alloc: std.mem.Allocator, fd: posix.socket_t, max_bytes: usize) ![]u8 {
    var response = try alloc.alloc(u8, max_bytes);
    errdefer alloc.free(response);

    var total: usize = 0;
    while (total < response.len) {
        const bytes_read = posix.read(fd, response[total..]) catch return error.ReceiveFailed;
        if (bytes_read == 0) break;
        total += bytes_read;
    }

    if (total == response.len) {
        var extra_buf: [1]u8 = undefined;
        const extra = posix.read(fd, &extra_buf) catch 0;
        if (extra > 0) return error.ResponseTooLarge;
    }
    if (total == 0) return error.ReceiveFailed;

    if (alloc.resize(response, total)) {
        response = response[0..total];
    }
    return response[0..total];
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

const TestUpstreamAction = union(enum) {
    close,
    respond: []const u8,
};

const TestUpstreamServer = struct {
    listen_fd: posix.socket_t,
    port: u16,
    actions: []const TestUpstreamAction,
    thread: ?std.Thread = null,
    request_bufs: [4][2048]u8 = undefined,
    request_lens: [4]usize = [_]usize{0} ** 4,
    accepted: usize = 0,

    fn init(actions: []const TestUpstreamAction) !TestUpstreamServer {
        const listen_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
        errdefer posix.close(listen_fd);

        const reuseaddr: i32 = 1;
        posix.setsockopt(listen_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuseaddr)) catch {};

        const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
        try posix.bind(listen_fd, &addr.any, addr.getOsSockLen());
        try posix.listen(listen_fd, 1);

        var bound_addr: posix.sockaddr.in = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        try posix.getsockname(listen_fd, @ptrCast(&bound_addr), &bound_len);

        return .{
            .listen_fd = listen_fd,
            .port = std.mem.bigToNative(u16, bound_addr.port),
            .actions = actions,
        };
    }

    fn deinit(self: *TestUpstreamServer) void {
        if (self.thread) |thread| thread.join();
        posix.close(self.listen_fd);
    }

    fn start(self: *TestUpstreamServer) !void {
        self.thread = try std.Thread.spawn(.{}, acceptOne, .{self});
    }

    fn request(self: *const TestUpstreamServer, index: usize) []const u8 {
        return self.request_bufs[index][0..self.request_lens[index]];
    }

    fn acceptOne(self: *TestUpstreamServer) void {
        for (self.actions, 0..) |action, index| {
            const client_fd = posix.accept(self.listen_fd, null, null, posix.SOCK.CLOEXEC) catch return;
            defer posix.close(client_fd);

            setSocketTimeoutMs(client_fd, 1000);
            self.request_lens[index] = posix.read(client_fd, &self.request_bufs[index]) catch 0;
            self.accepted = index + 1;

            switch (action) {
                .close => {},
                .respond => |response| _ = writeAll(client_fd, response) catch {},
            }
        }
    }
};

test "forwardRequest proxies upstream response bytes" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    const actions = [_]TestUpstreamAction{
        .{ .respond = "HTTP/1.1 201 Created\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncreated" },
    };
    var upstream = try TestUpstreamServer.init(&actions);
    defer upstream.deinit();
    try upstream.start();

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
        .ip_address = "127.0.0.1",
        .port = upstream.port,
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
            .healthy_endpoints = 1,
            .preserve_host = false,
        },
    };

    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const response = try proxy.forwardRequest(
        "GET /v1/users HTTP/1.1\r\nHost: api.internal\r\nX-Test: 1\r\n\r\n",
    );
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 201 Created\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "\r\n\r\ncreated") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(0), "GET /v1/users HTTP/1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(0), "Host: api\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(0), "X-Test: 1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(0), "Connection: close\r\n") != null);
}

test "forwardRequest formats local error responses" {
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

    const response = try proxy.forwardRequest(
        "GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
    );
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 400 Bad Request\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "{\"error\":\"missing host header\"}") != null);
}

test "forwardRequest retries safe methods after upstream receive failure" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    const actions = [_]TestUpstreamAction{
        .close,
        .{ .respond = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok" },
    };
    var upstream = try TestUpstreamServer.init(&actions);
    defer upstream.deinit();
    try upstream.start();

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
        .http_proxy_path_prefix = "/",
        .http_proxy_retries = 1,
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-1",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "127.0.0.1",
        .port = upstream.port,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    proxy_runtime.bootstrapIfEnabled();

    const routes = [_]router.Route{
        .{
            .name = "api:/",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/" },
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
            .retries = 1,
        },
    };

    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const response = try proxy.forwardRequest(
        "GET /users HTTP/1.1\r\nHost: api.internal\r\n\r\n",
    );
    defer std.testing.allocator.free(response);

    try std.testing.expectEqual(@as(usize, 2), upstream.accepted);
    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 200 OK\r\n") != null);
}

test "shouldRetryForward only retries safe methods and retryable errors" {
    try std.testing.expect(shouldRetryForward(.GET, 1, error.ReceiveFailed));
    try std.testing.expect(!shouldRetryForward(.POST, 1, error.ReceiveFailed));
    try std.testing.expect(!shouldRetryForward(.GET, 0, error.ReceiveFailed));
    try std.testing.expect(!shouldRetryForward(.GET, 1, error.ResponseTooLarge));
}
