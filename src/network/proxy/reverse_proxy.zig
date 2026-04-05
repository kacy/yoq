const std = @import("std");
const posix = std.posix;
const http = @import("../../api/http.zig");
const log = @import("../../lib/log.zig");
const proxy_helpers = @import("proxy_helpers.zig");
const socket_helpers = @import("socket_helpers.zig");
const ip = @import("../ip.zig");
const http2 = @import("http2.zig");
const http2_connection_router = @import("http2_connection_router.zig");
const http2_passthrough = @import("http2_passthrough.zig");
const http2_request = @import("http2_request.zig");
const http2_response = @import("http2_response.zig");
const proxy_policy = @import("policy.zig");
const request_plan = @import("request_plan.zig");
const proxy_runtime = @import("runtime.zig");
const router = @import("router.zig");
const upstream_mod = @import("upstream.zig");

const proxy_loop_header = "X-Yoq-Proxy";
const x_forwarded_for_header = "X-Forwarded-For";
const x_forwarded_host_header = "X-Forwarded-Host";
const x_forwarded_proto_header = "X-Forwarded-Proto";
const traceparent_header = "traceparent";
const tracestate_header = "tracestate";

const Protocol = enum {
    http1,
    http2,
};

pub const ProxyResponse = struct {
    protocol: Protocol = .http1,
    http2_stream_id: ?u32 = null,
    status: http.StatusCode,
    body: []const u8,
};

pub const ForwardPlan = struct {
    protocol: Protocol = .http1,
    http2_stream_id: ?u32 = null,
    http2_request_end_stream: bool = false,
    method: http.Method,
    path: []const u8,
    outbound_path: []const u8,
    host: []const u8,
    outbound_host: []const u8,
    backend_service: []const u8,
    selection_key: u64,
    route: proxy_runtime.RouteSnapshot,
    upstream: upstream_mod.Upstream,

    pub fn deinit(self: ForwardPlan, alloc: std.mem.Allocator) void {
        alloc.free(self.path);
        alloc.free(self.outbound_path);
        alloc.free(self.host);
        alloc.free(self.outbound_host);
        alloc.free(self.backend_service);
        self.route.deinit(alloc);
        self.upstream.deinit(alloc);
    }
};

const MirrorTask = struct {
    allocator: std.mem.Allocator,
    active_mirror_requests: *std.atomic.Value(usize),
    raw_request: []u8,
    protocol: Protocol,
    method: http.Method,
    path: []u8,
    outbound_path: []u8,
    host: []u8,
    outbound_host: []u8,
    route_name: []u8,
    route_service: []u8,
    mirror_service: []u8,
    connect_timeout_ms: u32,
    request_timeout_ms: u32,
    max_response_bytes: usize,
    client_ip: ?[4]u8,

    fn deinit(self: MirrorTask) void {
        self.allocator.free(self.raw_request);
        self.allocator.free(self.path);
        self.allocator.free(self.outbound_path);
        self.allocator.free(self.host);
        self.allocator.free(self.outbound_host);
        self.allocator.free(self.route_name);
        self.allocator.free(self.route_service);
        self.allocator.free(self.mirror_service);
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
    active_mirror_requests: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    pub fn init(allocator: std.mem.Allocator, routes: []const router.Route) ReverseProxy {
        return .{
            .allocator = allocator,
            .routes = routes,
        };
    }

    pub fn deinit(self: *ReverseProxy) void {
        while (self.active_mirror_requests.load(.acquire) != 0) {
            std.Thread.sleep(std.time.ns_per_ms);
        }
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
        if (!http2.startsWithClientPreface(raw_request)) {
            if (try http1LoopResponse(self, raw_request)) |response| {
                return .{ .response = response };
            }
        }

        const planned = request_plan.planRequest(self.allocator, self.routes, raw_request) catch |err| {
            return .{ .response = responseForPlanError(self, raw_request, err) };
        };
        defer planned.deinit(self.allocator);

        if (planned.protocol == .http2 and planned.method_enum == null) {
            return .{ .response = .{
                .protocol = .http2,
                .http2_stream_id = planned.http2_stream_id,
                .status = .bad_request,
                .body = "{\"error\":\"unsupported http2 method\"}",
            } };
        }

        return resolvePlannedRequest(self, &planned);
    }

    pub fn forwardRequest(self: *const ReverseProxy, raw_request: []const u8) ![]u8 {
        return self.forwardRequestWithClient(raw_request, null);
    }

    fn forwardRequestWithClient(self: *const ReverseProxy, raw_request: []const u8, client_ip: ?[4]u8) ![]u8 {
        proxy_runtime.recordRequestStart();
        const handled = try self.handleRequest(raw_request);
        switch (handled) {
            .response => |resp| {
                proxy_runtime.recordResponse(resp.status);
                return formatResponseForProtocol(self.allocator, resp);
            },
            .forward => |plan| {
                defer plan.deinit(self.allocator);
                proxy_runtime.recordRouteRequestStart(plan.route.name, plan.route.service, plan.backend_service);
                self.startMirrorRequest(raw_request, &plan, client_ip);
                const response = try self.forwardPlanWithClient(raw_request, &plan, client_ip);
                if (parseForwardedStatusCode(self.allocator, plan.protocol, response)) |status_code| {
                    proxy_runtime.recordResponseCode(status_code);
                } else |_| if (plan.protocol == .http1) {
                    proxy_runtime.recordResponse(.bad_gateway);
                }
                return response;
            },
        }
    }

    pub fn handleConnection(self: *const ReverseProxy, client_fd: posix.fd_t) void {
        defer posix.close(client_fd);
        socket_helpers.setSocketTimeoutMs(client_fd, 5000);
        var trace_id: [16]u8 = undefined;
        log.generateTraceId(&trace_id);
        log.setTraceId(&trace_id);
        defer log.clearTraceId();

        var request_buf: [64 * 1024]u8 = undefined;
        const request = readRequestBytes(client_fd, &request_buf) catch |err| {
            const response = switch (err) {
                error.MalformedRequest => formatProxyResponse(self.allocator, .{
                    .status = .bad_request,
                    .body = "{\"error\":\"malformed request\"}",
                }),
                error.UriTooLong => formatProxyResponse(self.allocator, .{
                    .status = .bad_request,
                    .body = "{\"error\":\"request uri too long\"}",
                }),
                error.HeadersTooLarge => formatProxyResponse(self.allocator, .{
                    .status = .request_header_fields_too_large,
                    .body = "{\"error\":\"headers too large\"}",
                }),
                error.BodyTooLarge => formatProxyResponse(self.allocator, .{
                    .status = .content_too_large,
                    .body = "{\"error\":\"request body too large\"}",
                }),
                error.ReadIncomplete => formatProxyResponse(self.allocator, .{
                    .status = .bad_request,
                    .body = "{\"error\":\"request incomplete\"}",
                }),
            } catch return;
            defer self.allocator.free(response);
            _ = socket_helpers.writeAll(client_fd, response) catch |e| {
                log.warn("l7 proxy client write failed: {}", .{e});
            };
            return;
        };

        const handled = self.handleRequest(request) catch {
            proxy_runtime.recordResponse(.internal_server_error);
            const internal = formatProxyResponse(self.allocator, .{
                .status = .internal_server_error,
                .body = "{\"error\":\"proxy request failed\"}",
            }) catch return;
            defer self.allocator.free(internal);
            _ = socket_helpers.writeAll(client_fd, internal) catch |e| {
                log.warn("l7 proxy client write failed: {}", .{e});
            };
            return;
        };
        switch (handled) {
            .response => |resp| {
                proxy_runtime.recordResponse(resp.status);
                const response = formatResponseForProtocol(self.allocator, resp) catch return;
                defer self.allocator.free(response);
                _ = socket_helpers.writeAll(client_fd, response) catch |e| {
                    log.warn("l7 proxy client write failed: {}", .{e});
                };
            },
            .forward => |plan| {
                defer plan.deinit(self.allocator);
                if (plan.protocol == .http2) {
                    http2_connection_router.proxyConnection(
                        self.allocator,
                        self.routes,
                        client_fd,
                        request,
                        peerIpFromSocket(client_fd),
                    ) catch {
                        proxy_runtime.recordResponse(.internal_server_error);
                        const internal = http2_response.formatSimpleResponse(
                            self.allocator,
                            plan.http2_stream_id orelse 1,
                            @intFromEnum(http.StatusCode.internal_server_error),
                            "application/json",
                            "{\"error\":\"proxy request failed\"}",
                        ) catch return;
                        defer self.allocator.free(internal);
                        _ = socket_helpers.writeAll(client_fd, internal) catch |e| {
                            log.warn("l7 proxy client write failed: {}", .{e});
                        };
                    };
                    return;
                }

                proxy_runtime.recordRouteRequestStart(plan.route.name, plan.route.service, plan.backend_service);
                self.startMirrorRequest(request, &plan, peerIpFromSocket(client_fd));
                const response = self.forwardPlanWithClient(request, &plan, peerIpFromSocket(client_fd)) catch {
                    proxy_runtime.recordResponse(.internal_server_error);
                    const internal = formatProxyResponse(self.allocator, .{
                        .status = .internal_server_error,
                        .body = "{\"error\":\"proxy request failed\"}",
                    }) catch return;
                    defer self.allocator.free(internal);
                    _ = socket_helpers.writeAll(client_fd, internal) catch |e| {
                        log.warn("l7 proxy client write failed: {}", .{e});
                    };
                    return;
                };
                defer self.allocator.free(response);
                _ = socket_helpers.writeAll(client_fd, response) catch |e| {
                    log.warn("l7 proxy client write failed: {}", .{e});
                };
            },
        }
    }

    pub fn buildForwardRequest(self: *const ReverseProxy, raw_request: []const u8, plan: *const ForwardPlan) ![]u8 {
        return self.buildForwardRequestWithClient(raw_request, plan, null);
    }

    fn buildForwardRequestWithClient(
        self: *const ReverseProxy,
        raw_request: []const u8,
        plan: *const ForwardPlan,
        client_ip: ?[4]u8,
    ) ![]u8 {
        return buildForwardRequestBytes(self.allocator, raw_request, .{
            .protocol = plan.protocol,
            .method = plan.method,
            .path = plan.path,
            .outbound_path = plan.outbound_path,
            .host = plan.host,
            .outbound_host = plan.outbound_host,
        }, client_ip);
    }

    fn startMirrorRequest(self: *const ReverseProxy, raw_request: []const u8, plan: *const ForwardPlan, client_ip: ?[4]u8) void {
        const mirror_service = plan.route.mirror_service orelse return;
        _ = @constCast(&self.active_mirror_requests).fetchAdd(1, .monotonic);
        var task = cloneMirrorTask(
            self.allocator,
            @constCast(&self.active_mirror_requests),
            self.max_response_bytes,
            raw_request,
            plan,
            mirror_service,
            client_ip,
        ) catch {
            _ = @constCast(&self.active_mirror_requests).fetchSub(1, .monotonic);
            return;
        };
        const thread = std.Thread.spawn(.{}, runMirrorTask, .{task}) catch {
            _ = @constCast(&self.active_mirror_requests).fetchSub(1, .monotonic);
            task.deinit();
            return;
        };
        thread.detach();
    }

    const ForwardRequestSpec = struct {
        protocol: Protocol,
        method: http.Method,
        path: []const u8,
        outbound_path: []const u8,
        host: []const u8,
        outbound_host: []const u8,
    };

    fn buildForwardRequestBytes(
        alloc: std.mem.Allocator,
        raw_request: []const u8,
        spec: ForwardRequestSpec,
        client_ip: ?[4]u8,
    ) ![]u8 {
        return switch (spec.protocol) {
            .http1 => buildHttp1ForwardRequestBytes(alloc, raw_request, spec, client_ip),
            .http2 => http2_request.rewriteClientConnectionPreface(
                alloc,
                raw_request,
                if (std.mem.eql(u8, spec.outbound_host, spec.host)) null else spec.outbound_host,
                if (std.mem.eql(u8, spec.outbound_path, spec.path)) null else spec.outbound_path,
                trustedForwardedProtoFromRawRequest(raw_request, client_ip),
            ),
        };
    }

    fn buildHttp1ForwardRequestBytes(
        alloc: std.mem.Allocator,
        raw_request: []const u8,
        spec: ForwardRequestSpec,
        client_ip: ?[4]u8,
    ) ![]u8 {
        const parsed = (http.parseRequest(raw_request) catch return error.BadRequest) orelse return error.BadRequest;
        const inbound_host = http.findHeaderValue(parsed.headers_raw, "Host") orelse spec.host;
        const prior_forwarded_for = http.findHeaderValue(parsed.headers_raw, x_forwarded_for_header);
        const inbound_traceparent = http.findHeaderValue(parsed.headers_raw, traceparent_header);
        const inbound_tracestate = http.findHeaderValue(parsed.headers_raw, tracestate_header);
        const forwarded_proto = trustedForwardedProto(parsed.headers_raw, client_ip) orelse "http";

        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(alloc);
        const writer = buf.writer(alloc);

        try writer.print("{s} {s} HTTP/1.1\r\n", .{
            proxy_helpers.methodString(parsed.method),
            spec.outbound_path,
        });
        try writer.print("Host: {s}\r\n", .{spec.outbound_host});

        var pos: usize = 0;
        while (pos < parsed.headers_raw.len) {
            const line_end = std.mem.indexOfPos(u8, parsed.headers_raw, pos, "\r\n") orelse parsed.headers_raw.len;
            const line = parsed.headers_raw[pos..line_end];
            pos = if (line_end + 2 <= parsed.headers_raw.len) line_end + 2 else parsed.headers_raw.len;

            if (line.len == 0) continue;
            if (isForwardSkippedHeader(line)) continue;

            try writer.writeAll(line);
            try writer.writeAll("\r\n");
        }

        if (client_ip) |address| {
            if (prior_forwarded_for) |existing| {
                try writer.print("{s}: {s}, ", .{ x_forwarded_for_header, existing });
            } else {
                try writer.print("{s}: ", .{x_forwarded_for_header});
            }
            try writeIp4(&writer, address);
            try writer.writeAll("\r\n");
        }
        try writer.print("{s}: {s}\r\n", .{ x_forwarded_host_header, inbound_host });
        try writer.print("{s}: {s}\r\n", .{ x_forwarded_proto_header, forwarded_proto });
        try writeTraceHeaders(writer, inbound_traceparent, inbound_tracestate);
        try writer.print("Content-Length: {d}\r\n", .{parsed.body.len});
        try writer.writeAll(proxy_loop_header ++ ": 1\r\n");
        try writer.writeAll("Connection: close\r\n\r\n");
        try writer.writeAll(parsed.body);

        return buf.toOwnedSlice(alloc);
    }

    fn forwardPlan(self: *const ReverseProxy, raw_request: []const u8, plan: *const ForwardPlan) ![]u8 {
        return self.forwardPlanWithClient(raw_request, plan, null);
    }

    fn forwardPlanWithClient(
        self: *const ReverseProxy,
        raw_request: []const u8,
        plan: *const ForwardPlan,
        client_ip: ?[4]u8,
    ) ![]u8 {
        const policy = proxy_policy.RequestPolicy{
            .retries = plan.route.retries,
            .preserve_host = plan.route.preserve_host,
            .retry_on_5xx = plan.route.retry_on_5xx,
        };
        const cb_policy = proxy_policy.CircuitBreakerPolicy{
            .failure_threshold = plan.route.circuit_breaker_threshold,
            .open_timeout_ms = plan.route.circuit_breaker_timeout_ms,
        };
        var attempt: u8 = 0;
        var retries_used: u8 = 0;
        while (true) : (attempt += 1) {
            var upstream = resolveAttemptUpstream(self.allocator, plan, attempt, cb_policy) catch |err| switch (err) {
                error.NoHealthyUpstream => {
                    log.warn("l7 proxy no eligible upstream after retries method={s} host={s} path={s} service={s} retries={d}", .{
                        proxy_helpers.methodString(plan.method), plan.host, plan.path, plan.route.service, retries_used,
                    });
                    return formatProxyResponse(self.allocator, .{
                        .status = .service_unavailable,
                        .body = "{\"error\":\"no eligible upstream\"}",
                    });
                },
                else => return err,
            };
            defer upstream.deinit(self.allocator);

            const response = self.forwardSingleAttempt(raw_request, plan, &upstream, client_ip) catch |err| {
                recordUpstreamError(upstream.endpoint_id, cb_policy, mapUpstreamFailure(err), plan.route.name, plan.route.service, upstream.service);
                if (proxy_policy.shouldRetry(policy, proxy_helpers.methodString(plan.method), attempt, null, true)) {
                    proxy_runtime.recordRetry();
                    proxy_runtime.recordRouteRetry(plan.route.name, plan.route.service, upstream.service);
                    retries_used += 1;
                    continue;
                }
                proxy_runtime.recordRouteFailure(plan.route.name, mapRouteFailureKind(err));
                log.warn("l7 proxy upstream failure method={s} host={s} path={s} service={s} upstream={s}:{d} retries={d} error={}", .{
                    proxy_helpers.methodString(plan.method), plan.host,     plan.path,    plan.route.service,
                    upstream.address,                        upstream.port, retries_used, err,
                });
                return formatProxyResponse(self.allocator, proxyFailureResponse(err));
            };

            if (plan.protocol == .http2) {
                proxy_runtime.recordEndpointSuccess(upstream.endpoint_id);
                proxy_runtime.recordRouteRecovered(plan.route.name);
                return response;
            }

            if (self.evaluateHttp1Response(response, plan, &upstream, policy, cb_policy, attempt, retries_used)) |final_response| {
                return final_response;
            }
            retries_used += 1;
        }
    }

    /// Evaluate an HTTP/1 upstream response: parse status, record circuit state,
    /// decide retry. Returns the final response bytes to send, or null to retry.
    fn evaluateHttp1Response(
        self: *const ReverseProxy,
        response: []u8,
        plan: *const ForwardPlan,
        upstream: *const upstream_mod.Upstream,
        policy: proxy_policy.RequestPolicy,
        cb_policy: proxy_policy.CircuitBreakerPolicy,
        attempt: u8,
        retries_used: u8,
    ) ?[]u8 {
        const status_code = parseUpstreamStatusCode(response) catch {
            recordUpstreamError(upstream.endpoint_id, cb_policy, .other, plan.route.name, plan.route.service, upstream.service);
            log.warn("l7 proxy invalid upstream response method={s} host={s} path={s} service={s} upstream={s}:{d} retries={d}", .{
                proxy_helpers.methodString(plan.method), plan.host,     plan.path,    plan.route.service,
                upstream.address,                        upstream.port, retries_used,
            });
            self.allocator.free(response);
            proxy_runtime.recordRouteFailure(plan.route.name, .invalid_response);
            return formatProxyResponse(self.allocator, .{
                .status = .bad_gateway,
                .body = "{\"error\":\"invalid upstream response\"}",
            }) catch return null;
        };

        if (status_code >= 500 and status_code <= 599) {
            proxy_runtime.recordEndpointFailure(upstream.endpoint_id, cb_policy);
        } else {
            proxy_runtime.recordEndpointSuccess(upstream.endpoint_id);
        }
        if (proxy_policy.shouldRetry(policy, proxy_helpers.methodString(plan.method), attempt, status_code, false)) {
            proxy_runtime.recordRetry();
            proxy_runtime.recordRouteRetry(plan.route.name, plan.route.service, upstream.service);
            self.allocator.free(response);
            return null;
        }
        log.info("l7 proxy proxied method={s} host={s} path={s} service={s} upstream={s}:{d} status={d} retries={d}", .{
            proxy_helpers.methodString(plan.method), plan.host,     plan.path,   plan.route.service,
            upstream.address,                        upstream.port, status_code, retries_used,
        });
        proxy_runtime.recordRouteResponseCode(plan.route.name, plan.route.service, upstream.service, status_code);
        proxy_runtime.recordRouteRecovered(plan.route.name);
        return response;
    }

    fn forwardSingleAttempt(
        self: *const ReverseProxy,
        raw_request: []const u8,
        plan: *const ForwardPlan,
        upstream: *const upstream_mod.Upstream,
        client_ip: ?[4]u8,
    ) ![]u8 {
        const fd = try socket_helpers.connectToUpstream(plan.route.connect_timeout_ms, plan.route.request_timeout_ms, upstream);
        defer posix.close(fd);
        const request = try self.buildForwardRequestWithClient(raw_request, plan, client_ip);
        defer self.allocator.free(request);

        socket_helpers.writeAll(fd, request) catch return error.SendFailed;
        return readResponse(self.allocator, fd, self.max_response_bytes);
    }
};

fn cloneMirrorTask(
    alloc: std.mem.Allocator,
    active_mirror_requests: *std.atomic.Value(usize),
    max_response_bytes: usize,
    raw_request: []const u8,
    plan: *const ForwardPlan,
    mirror_service: []const u8,
    client_ip: ?[4]u8,
) !MirrorTask {
    return .{
        .allocator = alloc,
        .active_mirror_requests = active_mirror_requests,
        .raw_request = try alloc.dupe(u8, raw_request),
        .protocol = plan.protocol,
        .method = plan.method,
        .path = try alloc.dupe(u8, plan.path),
        .outbound_path = try alloc.dupe(u8, plan.outbound_path),
        .host = try alloc.dupe(u8, plan.host),
        .outbound_host = if (plan.route.preserve_host)
            try alloc.dupe(u8, plan.host)
        else
            try alloc.dupe(u8, mirror_service),
        .route_name = try alloc.dupe(u8, plan.route.name),
        .route_service = try alloc.dupe(u8, plan.route.service),
        .mirror_service = try alloc.dupe(u8, mirror_service),
        .connect_timeout_ms = plan.route.connect_timeout_ms,
        .request_timeout_ms = plan.route.request_timeout_ms,
        .max_response_bytes = max_response_bytes,
        .client_ip = client_ip,
    };
}

fn runMirrorTask(task: MirrorTask) void {
    defer _ = task.active_mirror_requests.fetchSub(1, .release);
    defer task.deinit();

    proxy_runtime.recordMirrorRouteRequestStart(task.route_name, task.route_service, task.mirror_service);
    var upstream = proxy_runtime.resolveUpstream(task.allocator, task.mirror_service) catch {
        proxy_runtime.recordMirrorRouteUpstreamFailure(task.route_name, task.route_service, task.mirror_service);
        return;
    };
    defer upstream.deinit(task.allocator);

    const fd = socket_helpers.connectToUpstream(task.connect_timeout_ms, task.request_timeout_ms, &upstream) catch {
        proxy_runtime.recordMirrorRouteUpstreamFailure(task.route_name, task.route_service, task.mirror_service);
        return;
    };
    defer posix.close(fd);

    const request = ReverseProxy.buildForwardRequestBytes(task.allocator, task.raw_request, .{
        .protocol = task.protocol,
        .method = task.method,
        .path = task.path,
        .outbound_path = task.outbound_path,
        .host = task.host,
        .outbound_host = task.outbound_host,
    }, task.client_ip) catch {
        proxy_runtime.recordMirrorRouteUpstreamFailure(task.route_name, task.route_service, task.mirror_service);
        return;
    };
    defer task.allocator.free(request);

    socket_helpers.writeAll(fd, request) catch {
        proxy_runtime.recordMirrorRouteUpstreamFailure(task.route_name, task.route_service, task.mirror_service);
        return;
    };

    const response = readResponse(task.allocator, fd, task.max_response_bytes) catch {
        proxy_runtime.recordMirrorRouteUpstreamFailure(task.route_name, task.route_service, task.mirror_service);
        return;
    };
    defer task.allocator.free(response);

    const status_code = parseForwardedStatusCode(task.allocator, task.protocol, response) catch {
        proxy_runtime.recordMirrorRouteUpstreamFailure(task.route_name, task.route_service, task.mirror_service);
        return;
    };
    proxy_runtime.recordMirrorRouteResponseCode(task.route_name, task.route_service, task.mirror_service, status_code);
}

fn peerIpFromSocket(fd: posix.socket_t) ?[4]u8 {
    var peer_addr: posix.sockaddr.in = undefined;
    var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    posix.getpeername(fd, @ptrCast(&peer_addr), &peer_len) catch return null;
    const address = std.mem.toBytes(peer_addr.addr);
    return .{ address[0], address[1], address[2], address[3] };
}

fn trustedForwardedProto(headers_raw: []const u8, client_ip: ?[4]u8) ?[]const u8 {
    if (client_ip == null or !std.mem.eql(u8, &client_ip.?, &proxy_helpers.trusted_forwarded_proto_ip)) return null;
    return http.findHeaderValue(headers_raw, x_forwarded_proto_header);
}

fn trustedForwardedProtoFromRawRequest(raw_request: []const u8, client_ip: ?[4]u8) ?[]const u8 {
    if (client_ip == null or !std.mem.eql(u8, &client_ip.?, &proxy_helpers.trusted_forwarded_proto_ip)) return null;
    if (!http2.startsWithClientPreface(raw_request)) return null;

    var parsed = http2_request.parseClientConnectionPreface(std.heap.page_allocator, raw_request) catch return null;
    defer parsed.deinit(std.heap.page_allocator);
    for (parsed.headers) |header| {
        if (std.mem.eql(u8, header.name, "x-forwarded-proto")) return "https";
    }
    return null;
}

fn writeIp4(writer: anytype, address: [4]u8) !void {
    try writer.print("{d}.{d}.{d}.{d}", .{ address[0], address[1], address[2], address[3] });
}

const forward_skip_headers = [_][]const u8{
    "Host",
    "Connection",
    "Content-Length",
    proxy_loop_header,
    x_forwarded_for_header,
    x_forwarded_host_header,
    x_forwarded_proto_header,
    traceparent_header,
    tracestate_header,
};

fn isForwardSkippedHeader(line: []const u8) bool {
    for (forward_skip_headers) |name| {
        if (startsWithHeaderName(line, name)) return true;
    }
    return false;
}

fn startsWithHeaderName(line: []const u8, name: []const u8) bool {
    if (line.len <= name.len or line[name.len] != ':') return false;
    for (line[0..name.len], name) |a, b| {
        if (std.ascii.toLower(a) != std.ascii.toLower(b)) return false;
    }
    return true;
}

fn writeTraceHeaders(writer: anytype, inbound_traceparent: ?[]const u8, inbound_tracestate: ?[]const u8) !void {
    if (inbound_traceparent) |value| {
        if (isValidTraceparent(value)) {
            try writer.print("{s}: {s}\r\n", .{ traceparent_header, value });
            if (inbound_tracestate) |state| {
                try writer.print("{s}: {s}\r\n", .{ tracestate_header, state });
            }
            return;
        }
    }
    try writeGeneratedTraceHeaders(writer);
}

fn writeGeneratedTraceHeaders(writer: anytype) !void {
    var trace_hi: [16]u8 = undefined;
    var trace_lo: [16]u8 = undefined;
    var parent_id: [16]u8 = undefined;
    log.generateTraceId(&trace_hi);
    log.generateTraceId(&trace_lo);
    log.generateTraceId(&parent_id);
    try writer.print(
        "{s}: 00-{s}{s}-{s}-01\r\n",
        .{ traceparent_header, trace_hi, trace_lo, parent_id },
    );
}

fn isValidTraceparent(value: []const u8) bool {
    if (value.len != 55) return false;
    if (value[2] != '-' or value[35] != '-' or value[52] != '-') return false;
    return isLowerHex(value[0..2]) and
        isLowerHex(value[3..35]) and
        isLowerHex(value[36..52]) and
        isLowerHex(value[53..55]);
}

fn isLowerHex(value: []const u8) bool {
    for (value) |char| {
        if (!std.ascii.isDigit(char) and (char < 'a' or char > 'f')) return false;
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

fn formatResponseForProtocol(alloc: std.mem.Allocator, response: ProxyResponse) ![]u8 {
    return switch (response.protocol) {
        .http1 => formatProxyResponse(alloc, response),
        .http2 => if (response.http2_stream_id) |stream_id|
            http2_response.formatSimpleResponse(alloc, stream_id, @intFromEnum(response.status), "application/json", response.body)
        else
            alloc.dupe(u8, ""),
    };
}

fn responseForPlanError(self: *const ReverseProxy, raw_request: []const u8, err: anyerror) ProxyResponse {
    _ = self;
    const protocol: Protocol = if (http2.startsWithClientPreface(raw_request)) .http2 else .http1;
    const http2_stream_id = if (protocol == .http2) peekHttp2StreamId(raw_request) else null;

    return switch (err) {
        error.InvalidHttp1Request => .{
            .protocol = protocol,
            .http2_stream_id = http2_stream_id,
            .status = .bad_request,
            .body = if (protocol == .http2) "{\"error\":\"invalid http2 request\"}" else "{\"error\":\"invalid request\"}",
        },
        error.IncompleteHttp1Request => .{
            .protocol = .http1,
            .status = .bad_request,
            .body = "{\"error\":\"incomplete request\"}",
        },
        error.MissingHostHeader => .{
            .protocol = .http1,
            .status = .bad_request,
            .body = "{\"error\":\"missing host header\"}",
        },
        error.RouteNotFound => .{
            .protocol = protocol,
            .http2_stream_id = http2_stream_id,
            .status = .not_found,
            .body = "{\"error\":\"route not found\"}",
        },
        else => .{
            .protocol = protocol,
            .http2_stream_id = http2_stream_id,
            .status = .bad_request,
            .body = if (protocol == .http2) "{\"error\":\"invalid http2 request\"}" else "{\"error\":\"invalid request\"}",
        },
    };
}

fn resolvePlannedRequest(self: *const ReverseProxy, planned: *const request_plan.RequestPlan) !HandleResult {
    const route = try cloneRouteSnapshot(self.allocator, planned.route);
    errdefer route.deinit(self.allocator);
    const selection_key = routeSelectionKey(planned.method, planned.host, planned.path);
    const backend_service = proxy_runtime.selectBackendService(planned.route, selection_key, 0);
    const upstream = proxy_runtime.resolveUpstream(self.allocator, backend_service) catch |err| switch (err) {
        error.NoHealthyUpstream => {
            proxy_runtime.recordRouteFailure(planned.route.name, .no_eligible_upstream);
            log.warn("l7 proxy no eligible upstream method={s} host={s} path={s} service={s}", .{
                planned.method,
                planned.host,
                planned.path,
                backend_service,
            });
            route.deinit(self.allocator);
            return .{ .response = .{
                .protocol = switch (planned.protocol) {
                    .http1 => .http1,
                    .http2 => .http2,
                },
                .http2_stream_id = planned.http2_stream_id,
                .status = .service_unavailable,
                .body = "{\"error\":\"no eligible upstream\"}",
            } };
        },
        else => return err,
    };
    errdefer upstream.deinit(self.allocator);

    return .{ .forward = .{
        .protocol = switch (planned.protocol) {
            .http1 => .http1,
            .http2 => .http2,
        },
        .http2_stream_id = planned.http2_stream_id,
        .http2_request_end_stream = planned.end_stream,
        .method = planned.method_enum.?,
        .path = try self.allocator.dupe(u8, planned.path),
        .outbound_path = try proxy_helpers.buildOutboundPath(self.allocator, planned.path, planned.route.match.path_prefix, planned.route.rewrite_prefix),
        .host = try self.allocator.dupe(u8, planned.host),
        .outbound_host = if (route.preserve_host)
            try self.allocator.dupe(u8, planned.host)
        else
            try self.allocator.dupe(u8, backend_service),
        .backend_service = try self.allocator.dupe(u8, backend_service),
        .selection_key = selection_key,
        .route = route,
        .upstream = upstream,
    } };
}

fn http1LoopResponse(self: *const ReverseProxy, raw_request: []const u8) !?ProxyResponse {
    const request = (http.parseRequest(raw_request) catch return null) orelse return null;
    if (http.findHeaderValue(request.headers_raw, proxy_loop_header) == null) return null;

    const host_header = http.findHeaderValue(request.headers_raw, "Host") orelse "";
    const host = proxy_helpers.normalizeHost(host_header);
    proxy_runtime.recordLoopRejection();
    log.warn("l7 proxy loop rejected method={s} host={s} path={s}", .{
        proxy_helpers.methodString(request.method),
        host,
        request.path_only,
    });
    _ = self;
    return .{
        .status = .bad_gateway,
        .body = "{\"error\":\"proxy loop detected\"}",
    };
}

fn peekHttp2StreamId(raw_request: []const u8) ?u32 {
    if (!http2.startsWithClientPreface(raw_request)) return null;

    var pos: usize = http2.client_preface.len;
    while (pos + http2.frame_header_len <= raw_request.len) {
        const header = http2.parseFrameHeader(raw_request[pos .. pos + http2.frame_header_len]) orelse return null;
        pos += http2.frame_header_len;
        if (pos + header.length > raw_request.len) return null;
        if (header.frame_type == .headers and header.stream_id != 0) return header.stream_id;
        pos += header.length;
    }

    return null;
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
        error.ConnectTimedOut => .{
            .status = .bad_gateway,
            .body = "{\"error\":\"upstream connect timed out\"}",
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

fn recordUpstreamError(
    endpoint_id: []const u8,
    cb_policy: proxy_policy.CircuitBreakerPolicy,
    failure_kind: proxy_runtime.UpstreamFailureKind,
    route_name: []const u8,
    route_service: []const u8,
    backend_service: []const u8,
) void {
    proxy_runtime.recordEndpointFailure(endpoint_id, cb_policy);
    proxy_runtime.recordUpstreamFailure(failure_kind);
    proxy_runtime.recordRouteUpstreamFailure(route_name, route_service, backend_service);
}

fn mapUpstreamFailure(err: anyerror) proxy_runtime.UpstreamFailureKind {
    return switch (err) {
        error.ConnectFailed, error.ConnectTimedOut => .connect,
        error.SendFailed => .send,
        error.ReceiveFailed => .receive,
        else => .other,
    };
}

fn mapRouteFailureKind(err: anyerror) proxy_runtime.RouteFailureKind {
    return switch (err) {
        error.ConnectFailed, error.ConnectTimedOut => .connect,
        error.SendFailed => .send,
        error.ReceiveFailed => .receive,
        else => .invalid_response,
    };
}

fn resolveAttemptUpstream(alloc: std.mem.Allocator, plan: *const ForwardPlan, attempt: u8, cb_policy: proxy_policy.CircuitBreakerPolicy) !upstream_mod.Upstream {
    if (attempt == 0) {
        return .{
            .service = try alloc.dupe(u8, plan.backend_service),
            .endpoint_id = try alloc.dupe(u8, plan.upstream.endpoint_id),
            .address = try alloc.dupe(u8, plan.upstream.address),
            .port = plan.upstream.port,
            .eligible = plan.upstream.eligible,
        };
    }

    const backend_service = proxy_runtime.selectSnapshotBackendService(plan.route, plan.selection_key, attempt);
    return proxy_runtime.resolveUpstreamWithPolicy(alloc, backend_service, cb_policy);
}

fn routeSelectionKey(method: []const u8, host: []const u8, path: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(method);
    hasher.update(host);
    hasher.update(path);
    return hasher.final();
}

fn parseUpstreamStatusCode(response: []const u8) !u16 {
    if (response.len < 12) return error.InvalidResponse;
    if (!std.mem.startsWith(u8, response, "HTTP/")) return error.InvalidResponse;

    const first_space = std.mem.indexOfScalar(u8, response, ' ') orelse return error.InvalidResponse;
    const status_start = first_space + 1;
    if (status_start + 3 > response.len) return error.InvalidResponse;
    return std.fmt.parseInt(u16, response[status_start .. status_start + 3], 10) catch error.InvalidResponse;
}

fn parseForwardedStatusCode(alloc: std.mem.Allocator, protocol: Protocol, response: []const u8) !u16 {
    return switch (protocol) {
        .http1 => parseUpstreamStatusCode(response),
        .http2 => http2_passthrough.parseStatusCode(alloc, response),
    };
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

    if (total < response.len) {
        response = try alloc.realloc(response, total);
    }
    return response;
}

const ReadRequestError = error{
    MalformedRequest,
    UriTooLong,
    HeadersTooLarge,
    BodyTooLarge,
    ReadIncomplete,
};

fn readRequestBytes(fd: posix.socket_t, buf: []u8) ReadRequestError![]const u8 {
    var total: usize = 0;
    while (total < buf.len) {
        const bytes_read = posix.read(fd, buf[total..]) catch break;
        if (bytes_read == 0) break;
        total += bytes_read;

        const preface_probe_len = @min(total, http2.client_preface.len);
        if (http2.hasClientPrefacePrefix(buf[0..preface_probe_len])) {
            if (!http2.startsWithClientPreface(buf[0..total])) continue;

            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            _ = http2_request.parseClientConnectionPreface(arena.allocator(), buf[0..total]) catch |err| switch (err) {
                error.BufferTooShort, error.MissingHeaders => continue,
                else => return error.MalformedRequest,
            };
            return buf[0..total];
        }

        if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") == null and total > http.max_header_bytes) {
            return error.HeadersTooLarge;
        }

        const parsed = http.parseRequest(buf[0..total]) catch |err| return switch (err) {
            error.UriTooLong => error.UriTooLong,
            error.HeadersTooLarge => error.HeadersTooLarge,
            error.BodyTooLarge => error.BodyTooLarge,
            else => error.MalformedRequest,
        };
        if (parsed) |request| {
            return buf[0..requestEndOffset(buf[0..total], request)];
        }
    }

    return error.ReadIncomplete;
}

fn requestEndOffset(buf: []const u8, request: http.Request) usize {
    const base = @intFromPtr(buf.ptr);
    const body_start = @intFromPtr(request.body.ptr) - base;
    return body_start + request.body.len;
}

fn cloneRouteSnapshot(alloc: std.mem.Allocator, route: router.Route) !proxy_runtime.RouteSnapshot {
    return .{
        .name = try alloc.dupe(u8, route.name),
        .service = try alloc.dupe(u8, route.service),
        .vip_address = try alloc.dupe(u8, route.vip_address),
        .host = try alloc.dupe(u8, route.match.host orelse ""),
        .path_prefix = try alloc.dupe(u8, route.match.path_prefix),
        .rewrite_prefix = if (route.rewrite_prefix) |rewrite_prefix| try alloc.dupe(u8, rewrite_prefix) else null,
        .mirror_service = if (route.mirror_service) |mirror_service| try alloc.dupe(u8, mirror_service) else null,
        .eligible_endpoints = route.eligible_endpoints,
        .healthy_endpoints = route.healthy_endpoints,
        .degraded = route.degraded,
        .degraded_reason = if (route.degraded) .service_state else .none,
        .last_failure_kind = null,
        .last_failure_at = null,
        .retries = route.retries,
        .connect_timeout_ms = route.connect_timeout_ms,
        .request_timeout_ms = route.request_timeout_ms,
        .http2_idle_timeout_ms = route.http2_idle_timeout_ms,
        .preserve_host = route.preserve_host,
        .steering_desired_ports = 0,
        .steering_applied_ports = 0,
        .steering_ready = false,
        .steering_blocked = true,
        .steering_drifted = false,
        .steering_blocked_reason = .rollout_disabled,
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
            try std.testing.expectEqualStrings("api.internal", plan.outbound_host);
        },
        .response => return error.TestUnexpectedResult,
    }
}

test "handleRequest selects configured weighted backend service" {
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
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.createService(.{
        .service_name = "api-canary",
        .vip_address = "10.43.0.3",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api-canary",
        .endpoint_id = "api-canary-1",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "10.42.0.10",
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
            .backend_services = &.{
                .{ .service_name = "api-canary", .weight = 100 },
            },
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
            try std.testing.expectEqualStrings("api-canary", plan.backend_service);
            try std.testing.expectEqualStrings("api-canary", plan.upstream.service);
            try std.testing.expectEqualStrings("10.42.0.10", plan.upstream.address);
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

test "handleRequest returns forward plan for HTTP/2 route" {
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
        .service_name = "grpc",
        .vip_address = "10.43.0.9",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "grpc.internal",
        .http_proxy_path_prefix = "/pkg.Service",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "grpc",
        .endpoint_id = "grpc-1",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "10.42.0.9",
        .port = 50051,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    proxy_runtime.bootstrapIfEnabled();

    const routes = [_]router.Route{
        .{
            .name = "grpc:/pkg.Service",
            .service = "grpc",
            .vip_address = "10.43.0.9",
            .match = .{ .host = "grpc.internal", .path_prefix = "/pkg.Service" },
        },
    };
    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const request = try buildTestHttp2Request(std.testing.allocator, 1, "POST", "grpc.internal", "/pkg.Service/Call");
    defer std.testing.allocator.free(request);

    const result = try proxy.handleRequest(request);
    defer result.deinit(std.testing.allocator);

    switch (result) {
        .forward => |plan| {
            try std.testing.expectEqual(Protocol.http2, plan.protocol);
            try std.testing.expectEqual(@as(?u32, 1), plan.http2_stream_id);
            try std.testing.expectEqual(http.Method.POST, plan.method);
            try std.testing.expectEqualStrings("/pkg.Service/Call", plan.path);
            try std.testing.expectEqualStrings("grpc.internal", plan.host);
            try std.testing.expectEqualStrings("10.42.0.9", plan.upstream.address);
        },
        .response => return error.TestUnexpectedResult,
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
        .outbound_path = try std.testing.allocator.dupe(u8, "/v1/users"),
        .host = try std.testing.allocator.dupe(u8, "api.internal"),
        .outbound_host = try std.testing.allocator.dupe(u8, "api"),
        .backend_service = try std.testing.allocator.dupe(u8, "api"),
        .selection_key = 0,
        .route = .{
            .name = try std.testing.allocator.dupe(u8, "api:/v1"),
            .service = try std.testing.allocator.dupe(u8, "api"),
            .vip_address = try std.testing.allocator.dupe(u8, "10.43.0.2"),
            .host = try std.testing.allocator.dupe(u8, "api.internal"),
            .path_prefix = try std.testing.allocator.dupe(u8, "/v1"),
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
            .degraded = false,
            .degraded_reason = .none,
            .last_failure_kind = null,
            .last_failure_at = null,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
            .http2_idle_timeout_ms = 30000,
            .preserve_host = false,
            .steering_desired_ports = 0,
            .steering_applied_ports = 0,
            .steering_ready = false,
            .steering_blocked = true,
            .steering_drifted = false,
            .steering_blocked_reason = .rollout_disabled,
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
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "X-Yoq-Proxy: 1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Connection: close\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Connection: keep-alive\r\n") == null);
}

test "buildForwardRequest rewrites request path with preserved query" {
    const routes = [_]router.Route{
        .{
            .name = "api:/api",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/api" },
            .rewrite_prefix = "/",
        },
    };

    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    var plan = ForwardPlan{
        .method = .GET,
        .path = try std.testing.allocator.dupe(u8, "/api/users?id=7"),
        .outbound_path = try std.testing.allocator.dupe(u8, "/users?id=7"),
        .host = try std.testing.allocator.dupe(u8, "api.internal"),
        .outbound_host = try std.testing.allocator.dupe(u8, "api.internal"),
        .backend_service = try std.testing.allocator.dupe(u8, "api"),
        .selection_key = 0,
        .route = .{
            .name = try std.testing.allocator.dupe(u8, "api:/api"),
            .service = try std.testing.allocator.dupe(u8, "api"),
            .vip_address = try std.testing.allocator.dupe(u8, "10.43.0.2"),
            .host = try std.testing.allocator.dupe(u8, "api.internal"),
            .path_prefix = try std.testing.allocator.dupe(u8, "/api"),
            .rewrite_prefix = try std.testing.allocator.dupe(u8, "/"),
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
            .degraded = false,
            .degraded_reason = .none,
            .last_failure_kind = null,
            .last_failure_at = null,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
            .http2_idle_timeout_ms = 30000,
            .preserve_host = true,
            .steering_desired_ports = 0,
            .steering_applied_ports = 0,
            .steering_ready = false,
            .steering_blocked = true,
            .steering_drifted = false,
            .steering_blocked_reason = .rollout_disabled,
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
        "GET /api/users?id=7 HTTP/1.1\r\nHost: api.internal\r\n\r\n",
        &plan,
    );
    defer std.testing.allocator.free(forwarded);

    try std.testing.expect(std.mem.indexOf(u8, forwarded, "GET /users?id=7 HTTP/1.1\r\n") != null);
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
        .outbound_path = try std.testing.allocator.dupe(u8, "/submit"),
        .host = try std.testing.allocator.dupe(u8, "api.internal"),
        .outbound_host = try std.testing.allocator.dupe(u8, "api.internal"),
        .backend_service = try std.testing.allocator.dupe(u8, "api"),
        .selection_key = 0,
        .route = .{
            .name = try std.testing.allocator.dupe(u8, "api:/"),
            .service = try std.testing.allocator.dupe(u8, "api"),
            .vip_address = try std.testing.allocator.dupe(u8, "10.43.0.2"),
            .host = try std.testing.allocator.dupe(u8, "api.internal"),
            .path_prefix = try std.testing.allocator.dupe(u8, "/"),
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
            .degraded = false,
            .degraded_reason = .none,
            .last_failure_kind = null,
            .last_failure_at = null,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
            .http2_idle_timeout_ms = 30000,
            .preserve_host = true,
            .steering_desired_ports = 0,
            .steering_applied_ports = 0,
            .steering_ready = false,
            .steering_blocked = true,
            .steering_drifted = false,
            .steering_blocked_reason = .rollout_disabled,
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
        "POST /submit HTTP/1.1\r\nHost: api.internal\r\nContent-Length: 5\r\n\r\nhello",
        &plan,
    );
    defer std.testing.allocator.free(forwarded);

    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Host: api.internal\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Content-Length: 5\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, forwarded, "hello"));
}

test "buildForwardRequest rewrites forwarded headers from client context" {
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
        .method = .GET,
        .path = try std.testing.allocator.dupe(u8, "/"),
        .outbound_path = try std.testing.allocator.dupe(u8, "/"),
        .host = try std.testing.allocator.dupe(u8, "api.internal"),
        .outbound_host = try std.testing.allocator.dupe(u8, "api.internal"),
        .backend_service = try std.testing.allocator.dupe(u8, "api"),
        .selection_key = 0,
        .route = .{
            .name = try std.testing.allocator.dupe(u8, "api:/"),
            .service = try std.testing.allocator.dupe(u8, "api"),
            .vip_address = try std.testing.allocator.dupe(u8, "10.43.0.2"),
            .host = try std.testing.allocator.dupe(u8, "api.internal"),
            .path_prefix = try std.testing.allocator.dupe(u8, "/"),
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
            .degraded = false,
            .degraded_reason = .none,
            .last_failure_kind = null,
            .last_failure_at = null,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
            .http2_idle_timeout_ms = 30000,
            .preserve_host = true,
            .steering_desired_ports = 0,
            .steering_applied_ports = 0,
            .steering_ready = false,
            .steering_blocked = true,
            .steering_drifted = false,
            .steering_blocked_reason = .rollout_disabled,
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

    const forwarded = try proxy.buildForwardRequestWithClient(
        "GET / HTTP/1.1\r\nHost: api.internal:8080\r\nX-Forwarded-For: 10.0.0.1\r\nX-Forwarded-Host: forged\r\nX-Forwarded-Proto: https\r\n\r\n",
        &plan,
        .{ 10, 42, 0, 77 },
    );
    defer std.testing.allocator.free(forwarded);

    try std.testing.expect(std.mem.indexOf(u8, forwarded, "X-Forwarded-For: 10.0.0.1, 10.42.0.77\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "X-Forwarded-Host: api.internal:8080\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "X-Forwarded-Proto: http\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "X-Forwarded-Host: forged\r\n") == null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "X-Forwarded-Proto: https\r\n") == null);
}

test "buildForwardRequest preserves traceparent and tracestate" {
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
        .method = .GET,
        .path = try std.testing.allocator.dupe(u8, "/"),
        .outbound_path = try std.testing.allocator.dupe(u8, "/"),
        .host = try std.testing.allocator.dupe(u8, "api.internal"),
        .outbound_host = try std.testing.allocator.dupe(u8, "api.internal"),
        .backend_service = try std.testing.allocator.dupe(u8, "api"),
        .selection_key = 0,
        .route = .{
            .name = try std.testing.allocator.dupe(u8, "api:/"),
            .service = try std.testing.allocator.dupe(u8, "api"),
            .vip_address = try std.testing.allocator.dupe(u8, "10.43.0.2"),
            .host = try std.testing.allocator.dupe(u8, "api.internal"),
            .path_prefix = try std.testing.allocator.dupe(u8, "/"),
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
            .degraded = false,
            .degraded_reason = .none,
            .last_failure_kind = null,
            .last_failure_at = null,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
            .http2_idle_timeout_ms = 30000,
            .preserve_host = true,
            .steering_desired_ports = 0,
            .steering_applied_ports = 0,
            .steering_ready = false,
            .steering_blocked = true,
            .steering_drifted = false,
            .steering_blocked_reason = .rollout_disabled,
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
        "GET / HTTP/1.1\r\nHost: api.internal\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\ntracestate: vendor=value\r\n\r\n",
        &plan,
    );
    defer std.testing.allocator.free(forwarded);

    try std.testing.expect(std.mem.indexOf(u8, forwarded, "traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "tracestate: vendor=value\r\n") != null);
}

test "buildForwardRequest generates traceparent when absent" {
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
        .method = .GET,
        .path = try std.testing.allocator.dupe(u8, "/"),
        .outbound_path = try std.testing.allocator.dupe(u8, "/"),
        .host = try std.testing.allocator.dupe(u8, "api.internal"),
        .outbound_host = try std.testing.allocator.dupe(u8, "api.internal"),
        .backend_service = try std.testing.allocator.dupe(u8, "api"),
        .selection_key = 0,
        .route = .{
            .name = try std.testing.allocator.dupe(u8, "api:/"),
            .service = try std.testing.allocator.dupe(u8, "api"),
            .vip_address = try std.testing.allocator.dupe(u8, "10.43.0.2"),
            .host = try std.testing.allocator.dupe(u8, "api.internal"),
            .path_prefix = try std.testing.allocator.dupe(u8, "/"),
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
            .degraded = false,
            .degraded_reason = .none,
            .last_failure_kind = null,
            .last_failure_at = null,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
            .http2_idle_timeout_ms = 30000,
            .preserve_host = true,
            .steering_desired_ports = 0,
            .steering_applied_ports = 0,
            .steering_ready = false,
            .steering_blocked = true,
            .steering_drifted = false,
            .steering_blocked_reason = .rollout_disabled,
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
        "GET / HTTP/1.1\r\nHost: api.internal\r\n\r\n",
        &plan,
    );
    defer std.testing.allocator.free(forwarded);

    const traceparent = http.findHeaderValue(forwarded, "traceparent").?;
    try std.testing.expect(isValidTraceparent(traceparent));
    try std.testing.expect(http.findHeaderValue(forwarded, "tracestate") == null);
}

const TestUpstreamAction = union(enum) {
    close,
    respond: []const u8,
    stream_respond: struct {
        first: []const u8,
        delay_ms: u32,
        second: []const u8,
    },
    delayed_respond: struct {
        delay_ms: u32,
        response: []const u8,
    },
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
        const listener = try initTestListenerSocket();

        return .{
            .listen_fd = listener.fd,
            .port = listener.port,
            .actions = actions,
        };
    }

    fn deinit(self: *TestUpstreamServer) void {
        self.wait();
        posix.close(self.listen_fd);
    }

    fn start(self: *TestUpstreamServer) !void {
        socket_helpers.setSocketTimeoutMs(self.listen_fd, 5000);
        self.thread = try std.Thread.spawn(.{}, acceptOne, .{self});
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }

    fn wait(self: *TestUpstreamServer) void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }

    fn request(self: *TestUpstreamServer, index: usize) []const u8 {
        self.wait();
        return self.request_bufs[index][0..self.request_lens[index]];
    }

    fn acceptOne(self: *TestUpstreamServer) void {
        for (self.actions, 0..) |action, index| {
            const client_fd = posix.accept(self.listen_fd, null, null, posix.SOCK.CLOEXEC) catch return;
            socket_helpers.setSocketTimeoutMs(client_fd, 1000);
            self.request_lens[index] = captureRequestBytes(client_fd, &self.request_bufs[index]);
            self.accepted = index + 1;

            switch (action) {
                .close => {},
                .respond => |response| _ = socket_helpers.writeAll(client_fd, response) catch {},
                .stream_respond => |resp| {
                    _ = socket_helpers.writeAll(client_fd, resp.first) catch {};
                    std.Thread.sleep(@as(u64, resp.delay_ms) * std.time.ns_per_ms);
                    _ = socket_helpers.writeAll(client_fd, resp.second) catch {};
                },
                .delayed_respond => |resp| {
                    std.Thread.sleep(@as(u64, resp.delay_ms) * std.time.ns_per_ms);
                    _ = socket_helpers.writeAll(client_fd, resp.response) catch {};
                },
            }
            posix.close(client_fd);
        }
    }
};

const TestListener = struct {
    fd: posix.socket_t,
    port: u16,

    fn init() !TestListener {
        const listener = try initTestListenerSocket();

        return .{
            .fd = listener.fd,
            .port = listener.port,
        };
    }

    fn deinit(self: *TestListener) void {
        posix.close(self.fd);
    }
};

const BoundTestListener = struct {
    fd: posix.socket_t,
    port: u16,
};

fn initTestListenerSocket() !BoundTestListener {
    const reuseaddr: i32 = 1;
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);

    var attempt: usize = 0;
    while (attempt < 50) : (attempt += 1) {
        const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch {
            if (attempt + 1 == 50) return error.SkipZigTest;
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };
        errdefer posix.close(fd);

        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuseaddr)) catch {};

        posix.bind(fd, &addr.any, addr.getOsSockLen()) catch {
            if (attempt + 1 == 50) return error.SkipZigTest;
            posix.close(fd);
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };
        posix.listen(fd, 1) catch {
            if (attempt + 1 == 50) return error.SkipZigTest;
            posix.close(fd);
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };

        var bound_addr: posix.sockaddr.in = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        posix.getsockname(fd, @ptrCast(&bound_addr), &bound_len) catch {
            if (attempt + 1 == 50) return error.SkipZigTest;
            posix.close(fd);
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };

        return .{
            .fd = fd,
            .port = std.mem.bigToNative(u16, bound_addr.port),
        };
    }

    unreachable;
}

fn captureRequestBytes(fd: posix.socket_t, buf: []u8) usize {
    var total: usize = 0;
    while (total < buf.len) {
        const bytes_read = posix.read(fd, buf[total..]) catch break;
        if (bytes_read == 0) break;
        total += bytes_read;

        const preface_probe_len = @min(total, http2.client_preface.len);
        if (http2.hasClientPrefacePrefix(buf[0..preface_probe_len])) {
            if (!http2.startsWithClientPreface(buf[0..total])) continue;

            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            const parsed = http2_request.parseClientConnectionPreface(arena.allocator(), buf[0..total]) catch continue;
            if (http2_passthrough.streamEndSeen(buf[0..total], parsed.request.stream_id)) {
                return total;
            }
            continue;
        }
        const parsed = http.parseRequest(buf[0..total]) catch return total;
        if (parsed) |request| {
            return requestEndOffset(buf[0..total], request);
        }
    }
    return total;
}

fn readSocketBytes(fd: posix.socket_t, buf: []u8) usize {
    var total: usize = 0;
    while (total < buf.len) {
        const bytes_read = posix.read(fd, buf[total..]) catch break;
        if (bytes_read == 0) break;
        total += bytes_read;
    }
    return total;
}

fn buildTestHttp2Request(
    alloc: std.mem.Allocator,
    stream_id: u32,
    method: []const u8,
    authority: []const u8,
    path: []const u8,
) ![]u8 {
    return buildTestHttp2RequestWithEndStream(alloc, stream_id, method, authority, path, true);
}

fn buildTestHttp2RequestWithEndStream(
    alloc: std.mem.Allocator,
    stream_id: u32,
    method: []const u8,
    authority: []const u8,
    path: []const u8,
    end_stream: bool,
) ![]u8 {
    const headers = try buildTestHttp2HeadersFrame(alloc, stream_id, method, authority, path, end_stream);
    defer alloc.free(headers);

    const settings = try buildHttp2Frame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(alloc);
    try request.appendSlice(alloc, http2.client_preface);
    try request.appendSlice(alloc, settings);
    try request.appendSlice(alloc, headers);
    return request.toOwnedSlice(alloc);
}

fn buildTestHttp2HeadersOnlyRequest(
    alloc: std.mem.Allocator,
    stream_id: u32,
    method: []const u8,
    authority: []const u8,
    path: []const u8,
    end_stream: bool,
) ![]u8 {
    return buildTestHttp2HeadersFrame(alloc, stream_id, method, authority, path, end_stream);
}

fn buildTestHttp2HeadersFrame(
    alloc: std.mem.Allocator,
    stream_id: u32,
    method: []const u8,
    authority: []const u8,
    path: []const u8,
    end_stream: bool,
) ![]u8 {
    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);

    if (std.mem.eql(u8, method, "GET")) {
        try header_block.append(alloc, 0x82);
    } else if (std.mem.eql(u8, method, "POST")) {
        try header_block.append(alloc, 0x83);
    } else {
        return error.UnsupportedMethod;
    }
    try header_block.append(alloc, 0x86);
    try appendLiteralWithIndexedName(&header_block, alloc, 0x01, authority);
    try appendLiteralWithIndexedName(&header_block, alloc, 0x04, path);

    const headers = try buildHttp2Frame(alloc, .{
        .length = @intCast(header_block.items.len),
        .frame_type = .headers,
        .flags = 0x4 | if (end_stream) @as(u8, 0x1) else 0,
        .stream_id = stream_id,
    }, header_block.items);
    return headers;
}

fn buildTestHttp2DataFrame(
    alloc: std.mem.Allocator,
    stream_id: u32,
    payload: []const u8,
    end_stream: bool,
) ![]u8 {
    return buildHttp2Frame(alloc, .{
        .length = @intCast(payload.len),
        .frame_type = .data,
        .flags = if (end_stream) 0x1 else 0,
        .stream_id = stream_id,
    }, payload);
}

fn appendLiteralWithIndexedName(
    buf: *std.ArrayList(u8),
    alloc: std.mem.Allocator,
    name_index: u8,
    value: []const u8,
) !void {
    if (value.len > 127) return error.HeaderTooLong;
    try buf.append(alloc, name_index);
    try buf.append(alloc, @intCast(value.len));
    try buf.appendSlice(alloc, value);
}

fn buildHttp2Frame(alloc: std.mem.Allocator, header: http2.FrameHeader, payload: []const u8) ![]u8 {
    const buf = try alloc.alloc(u8, http2.frame_header_len + payload.len);
    errdefer alloc.free(buf);
    try http2.writeFrameHeader(buf[0..http2.frame_header_len], header);
    @memcpy(buf[http2.frame_header_len..], payload);
    return buf;
}

fn buildHttp2SettingsAckFrame(alloc: std.mem.Allocator) ![]u8 {
    return buildHttp2Frame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0x1,
        .stream_id = 0,
    }, "");
}
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

test "forwardRequest mirrors shadow traffic without affecting the primary response" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    const primary_actions = [_]TestUpstreamAction{
        .{ .respond = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok" },
    };
    var primary_upstream = try TestUpstreamServer.init(&primary_actions);
    defer primary_upstream.deinit();
    try primary_upstream.start();

    const mirror_actions = [_]TestUpstreamAction{
        .{ .respond = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" },
    };
    var mirror_upstream = try TestUpstreamServer.init(&mirror_actions);
    defer mirror_upstream.deinit();
    try mirror_upstream.start();

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
        .http_proxy_mirror_service = "api-shadow",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.createService(.{
        .service_name = "api-shadow",
        .vip_address = "10.43.0.3",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-1",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "127.0.0.1",
        .port = primary_upstream.port,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api-shadow",
        .endpoint_id = "shadow-1",
        .container_id = "ctr-2",
        .node_id = null,
        .ip_address = "127.0.0.1",
        .port = mirror_upstream.port,
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
            .mirror_service = "api-shadow",
        },
    };

    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const response = try proxy.forwardRequest(
        "GET /v1/users HTTP/1.1\r\nHost: api.internal\r\nX-Test: mirror\r\n\r\n",
    );
    defer std.testing.allocator.free(response);

    primary_upstream.wait();
    mirror_upstream.wait();

    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 200 OK\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, primary_upstream.request(0), "GET /v1/users HTTP/1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, mirror_upstream.request(0), "GET /v1/users HTTP/1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, mirror_upstream.request(0), "Host: api-shadow\r\n") != null);

    var route_traffic = try proxy_runtime.snapshotRouteTraffic(std.testing.allocator);
    defer {
        for (route_traffic.items) |entry| entry.deinit(std.testing.allocator);
        route_traffic.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 2), route_traffic.items.len);
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

test "forwardRequest rejects looped proxy requests" {
    const routes = [_]router.Route{};

    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const response = try proxy.forwardRequest(
        "GET / HTTP/1.1\r\nHost: api.internal\r\nX-Yoq-Proxy: 1\r\n\r\n",
    );
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 502 Bad Gateway\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "{\"error\":\"proxy loop detected\"}") != null);
}

test "forwardRequest returns framed HTTP/2 not found response" {
    const routes = [_]router.Route{};

    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const request = try buildTestHttp2Request(std.testing.allocator, 3, "POST", "grpc.internal", "/pkg.Service/Call");
    defer std.testing.allocator.free(request);

    const response = try proxy.forwardRequest(request);
    defer std.testing.allocator.free(response);

    const settings = http2.parseFrameHeader(response[0..http2.frame_header_len]).?;
    try std.testing.expect(http2.isInitialServerSettingsFrame(settings));

    const headers_start = http2.frame_header_len;
    const headers = http2.parseFrameHeader(response[headers_start .. headers_start + http2.frame_header_len]).?;
    try std.testing.expectEqual(http2.FrameType.headers, headers.frame_type);
    try std.testing.expectEqual(@as(u32, 3), headers.stream_id);

    const payload_start = headers_start + http2.frame_header_len;
    const payload_end = payload_start + headers.length;
    var decoded = try @import("hpack.zig").decodeHeaderBlock(std.testing.allocator, response[payload_start..payload_end]);
    defer {
        for (decoded.items) |header| header.deinit(std.testing.allocator);
        decoded.deinit(std.testing.allocator);
    }
    try std.testing.expectEqualStrings(":status", decoded.items[0].name);
    try std.testing.expectEqualStrings("404", decoded.items[0].value);
}

test "forwardRequest proxies HTTP/2 upstream response bytes" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    const upstream_response = try http2_response.formatSimpleResponse(
        std.testing.allocator,
        1,
        200,
        "application/grpc",
        "ok",
    );
    defer std.testing.allocator.free(upstream_response);
    try std.testing.expectEqual(@as(u16, 200), try http2_passthrough.parseStatusCode(std.testing.allocator, upstream_response));

    const actions = [_]TestUpstreamAction{
        .{ .respond = upstream_response },
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
        .service_name = "grpc",
        .vip_address = "10.43.0.9",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "grpc.internal",
        .http_proxy_path_prefix = "/pkg.Service",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "grpc",
        .endpoint_id = "grpc-1",
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
            .name = "grpc:/pkg.Service",
            .service = "grpc",
            .vip_address = "10.43.0.9",
            .match = .{ .host = "grpc.internal", .path_prefix = "/pkg.Service" },
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
        },
    };
    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const request = try buildTestHttp2Request(std.testing.allocator, 1, "POST", "grpc.internal", "/pkg.Service/Call");
    defer std.testing.allocator.free(request);

    const response = try proxy.forwardRequest(request);
    defer std.testing.allocator.free(response);

    upstream.wait();
    try std.testing.expectEqualSlices(u8, upstream_response, response);
    try std.testing.expect(std.mem.eql(u8, http2.client_preface, upstream.request(0)[0..http2.client_preface.len]));
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

    upstream.wait();
    try std.testing.expectEqual(@as(usize, 2), upstream.accepted);
    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 200 OK\r\n") != null);
}

test "forwardRequest retries safe methods on upstream 5xx" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");
    const actions = [_]TestUpstreamAction{
        .{ .respond = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope" },
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

    upstream.wait();
    try std.testing.expectEqual(@as(usize, 2), upstream.accepted);
    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 200 OK\r\n") != null);
}

test "forwardRequest returns bad gateway after upstream request timeout" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    const actions = [_]TestUpstreamAction{
        .{ .delayed_respond = .{
            .delay_ms = 50,
            .response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        } },
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
        .http_proxy_request_timeout_ms = 10,
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
            .request_timeout_ms = 10,
        },
    };

    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const response = try proxy.forwardRequest(
        "GET /users HTTP/1.1\r\nHost: api.internal\r\n\r\n",
    );
    defer std.testing.allocator.free(response);

    upstream.wait();
    try std.testing.expectEqual(@as(usize, 1), upstream.accepted);
    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 502 Bad Gateway\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "{\"error\":\"upstream receive failed\"}") != null);
}

test "forwardRequest retries onto a different endpoint after circuit opens" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    const failing_actions = [_]TestUpstreamAction{.close};
    var failing_upstream = try TestUpstreamServer.init(&failing_actions);
    defer failing_upstream.deinit();
    try failing_upstream.start();

    const healthy_actions = [_]TestUpstreamAction{
        .{ .respond = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok" },
    };
    var healthy_upstream = try TestUpstreamServer.init(&healthy_actions);
    defer healthy_upstream.deinit();
    try healthy_upstream.start();

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
        .port = failing_upstream.port,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1001,
        .last_seen_at = 1001,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-2",
        .container_id = "ctr-2",
        .node_id = null,
        .ip_address = "127.0.0.1",
        .port = healthy_upstream.port,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    proxy_runtime.recordEndpointFailure("api-1", .{});
    proxy_runtime.recordEndpointFailure("api-1", .{});
    proxy_runtime.bootstrapIfEnabled();

    const routes = [_]router.Route{
        .{
            .name = "api:/",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/" },
            .eligible_endpoints = 2,
            .healthy_endpoints = 2,
            .retries = 1,
        },
    };

    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    const response = try proxy.forwardRequest(
        "GET /users HTTP/1.1\r\nHost: api.internal\r\n\r\n",
    );
    defer std.testing.allocator.free(response);

    failing_upstream.wait();
    healthy_upstream.wait();
    try std.testing.expectEqual(@as(usize, 1), failing_upstream.accepted);
    try std.testing.expectEqual(@as(usize, 1), healthy_upstream.accepted);
    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 200 OK\r\n") != null);
}

test "resolveAttemptUpstream retries onto a different weighted backend service" {
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
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.createService(.{
        .service_name = "api-canary",
        .vip_address = "10.43.0.3",
        .lb_policy = "consistent_hash",
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
    try store.upsertServiceEndpoint(.{
        .service_name = "api-canary",
        .endpoint_id = "api-canary-1",
        .container_id = "ctr-2",
        .node_id = null,
        .ip_address = "10.42.0.10",
        .port = 8081,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    proxy_runtime.bootstrapIfEnabled();

    var path_buf: [32]u8 = undefined;
    var request_path: []const u8 = undefined;
    var candidate: usize = 0;
    while (true) : (candidate += 1) {
        request_path = try std.fmt.bufPrint(&path_buf, "/users/{d}", .{candidate});
        const bucket = routeSelectionKey("GET", "api.internal", request_path) % 100;
        if (bucket >= 31 and bucket < 50) break;
    }

    var plan = ForwardPlan{
        .method = .GET,
        .path = try std.testing.allocator.dupe(u8, request_path),
        .outbound_path = try std.testing.allocator.dupe(u8, request_path),
        .host = try std.testing.allocator.dupe(u8, "api.internal"),
        .outbound_host = try std.testing.allocator.dupe(u8, "api.internal"),
        .backend_service = try std.testing.allocator.dupe(u8, "api"),
        .selection_key = routeSelectionKey("GET", "api.internal", request_path),
        .route = .{
            .name = try std.testing.allocator.dupe(u8, "api:/"),
            .service = try std.testing.allocator.dupe(u8, "api"),
            .vip_address = try std.testing.allocator.dupe(u8, "10.43.0.2"),
            .host = try std.testing.allocator.dupe(u8, "api.internal"),
            .path_prefix = try std.testing.allocator.dupe(u8, "/"),
            .backend_services = try std.testing.allocator.dupe(router.BackendTarget, &.{
                .{ .service_name = try std.testing.allocator.dupe(u8, "api"), .weight = 50 },
                .{ .service_name = try std.testing.allocator.dupe(u8, "api-canary"), .weight = 50 },
            }),
            .eligible_endpoints = 2,
            .healthy_endpoints = 2,
            .degraded = false,
            .degraded_reason = .none,
            .last_failure_kind = null,
            .last_failure_at = null,
            .retries = 1,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
            .http2_idle_timeout_ms = 30000,
            .preserve_host = true,
            .steering_desired_ports = 0,
            .steering_applied_ports = 0,
            .steering_ready = false,
            .steering_blocked = true,
            .steering_drifted = false,
            .steering_blocked_reason = .rollout_disabled,
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

    var retry_upstream = try resolveAttemptUpstream(std.testing.allocator, &plan, 1, .{});
    defer retry_upstream.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("api-canary", retry_upstream.service);
    try std.testing.expectEqualStrings("10.42.0.10", retry_upstream.address);
    try std.testing.expectEqual(@as(u16, 8081), retry_upstream.port);
}

test "handleConnection proxies a client socket request" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    const actions = [_]TestUpstreamAction{
        .{ .respond = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello" },
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
        },
    };
    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    var listener = try TestListener.init();
    defer listener.deinit();

    const ConnectionHarness = struct {
        fn serve(proxy_ptr: *const ReverseProxy, listen_fd: posix.fd_t) void {
            const client_fd = posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC) catch return;
            proxy_ptr.handleConnection(client_fd);
        }
    };

    const server_thread = try std.Thread.spawn(.{}, ConnectionHarness.serve, .{ &proxy, listener.fd });
    defer server_thread.join();

    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(client_fd);
    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, listener.port);
    try posix.connect(client_fd, &server_addr.any, server_addr.getOsSockLen());

    try socket_helpers.writeAll(client_fd, "GET / HTTP/1.1\r\nHost: api.internal\r\n\r\n");
    var response_buf: [1024]u8 = undefined;
    const bytes_read = try posix.read(client_fd, &response_buf);
    try std.testing.expect(bytes_read > 0);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "HTTP/1.1 200 OK\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "\r\n\r\nhello") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(0), "X-Forwarded-For: 127.0.0.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(0), "X-Forwarded-Host: api.internal\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(0), "X-Forwarded-Proto: http\r\n") != null);
}

test "handleConnection returns framed HTTP/2 local response" {
    const routes = [_]router.Route{};
    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    var listener = try TestListener.init();
    defer listener.deinit();

    const ConnectionHarness = struct {
        fn serve(proxy_ptr: *const ReverseProxy, listen_fd: posix.fd_t) void {
            const client_fd = posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC) catch return;
            proxy_ptr.handleConnection(client_fd);
        }
    };

    const server_thread = try std.Thread.spawn(.{}, ConnectionHarness.serve, .{ &proxy, listener.fd });
    defer server_thread.join();

    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(client_fd);
    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, listener.port);
    try posix.connect(client_fd, &server_addr.any, server_addr.getOsSockLen());

    const request = try buildTestHttp2Request(std.testing.allocator, 5, "POST", "grpc.internal", "/pkg.Service/Call");
    defer std.testing.allocator.free(request);
    try socket_helpers.writeAll(client_fd, request);

    var response_buf: [1024]u8 = undefined;
    socket_helpers.setSocketTimeoutMs(client_fd, 1000);
    const bytes_read = readSocketBytes(client_fd, &response_buf);
    try std.testing.expect(bytes_read > http2.frame_header_len * 2);

    const response = response_buf[0..bytes_read];
    const settings = http2.parseFrameHeader(response[0..http2.frame_header_len]).?;
    try std.testing.expect(http2.isInitialServerSettingsFrame(settings));

    const headers_start = http2.frame_header_len;
    const headers = http2.parseFrameHeader(response[headers_start .. headers_start + http2.frame_header_len]).?;
    try std.testing.expectEqual(http2.FrameType.headers, headers.frame_type);
    try std.testing.expectEqual(@as(u32, 5), headers.stream_id);

    const payload_start = headers_start + http2.frame_header_len;
    const payload_end = payload_start + headers.length;
    var decoded = try @import("hpack.zig").decodeHeaderBlock(std.testing.allocator, response[payload_start..payload_end]);
    defer {
        for (decoded.items) |header| header.deinit(std.testing.allocator);
        decoded.deinit(std.testing.allocator);
    }
    try std.testing.expectEqualStrings(":status", decoded.items[0].name);
    try std.testing.expectEqualStrings("404", decoded.items[0].value);
}

test "handleConnection proxies HTTP/2 upstream response bytes" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    const upstream_response = try http2_response.formatSimpleResponse(
        std.testing.allocator,
        7,
        200,
        "application/grpc",
        "ok",
    );
    defer std.testing.allocator.free(upstream_response);

    const actions = [_]TestUpstreamAction{
        .{ .respond = upstream_response },
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
        .service_name = "grpc",
        .vip_address = "10.43.0.9",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "grpc.internal",
        .http_proxy_path_prefix = "/pkg.Service",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "grpc",
        .endpoint_id = "grpc-1",
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
            .name = "grpc:/pkg.Service",
            .service = "grpc",
            .vip_address = "10.43.0.9",
            .match = .{ .host = "grpc.internal", .path_prefix = "/pkg.Service" },
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
        },
    };
    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    var listener = try TestListener.init();
    defer listener.deinit();

    const ConnectionHarness = struct {
        fn serve(proxy_ptr: *const ReverseProxy, listen_fd: posix.fd_t) void {
            const client_fd = posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC) catch return;
            proxy_ptr.handleConnection(client_fd);
        }
    };

    const server_thread = try std.Thread.spawn(.{}, ConnectionHarness.serve, .{ &proxy, listener.fd });
    defer server_thread.join();

    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(client_fd);
    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, listener.port);
    try posix.connect(client_fd, &server_addr.any, server_addr.getOsSockLen());

    const request = try buildTestHttp2Request(std.testing.allocator, 7, "POST", "grpc.internal", "/pkg.Service/Call");
    defer std.testing.allocator.free(request);
    try socket_helpers.writeAll(client_fd, request);

    const settings_ack = try buildHttp2SettingsAckFrame(std.testing.allocator);
    defer std.testing.allocator.free(settings_ack);
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(std.testing.allocator);
    try expected.appendSlice(std.testing.allocator, settings_ack);
    try expected.appendSlice(std.testing.allocator, upstream_response);

    var response_buf: [1024]u8 = undefined;
    socket_helpers.setSocketTimeoutMs(client_fd, 1000);
    const bytes_read = readSocketBytes(client_fd, &response_buf);
    try std.testing.expectEqualSlices(u8, expected.items, response_buf[0..bytes_read]);

    upstream.wait();
    try std.testing.expect(std.mem.eql(u8, http2.client_preface, upstream.request(0)[0..http2.client_preface.len]));
}

test "handleConnection streams HTTP/2 upstream frames before stream end" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    const upstream_response = try http2_response.formatSimpleResponse(
        std.testing.allocator,
        9,
        200,
        "application/grpc",
        "ok",
    );
    defer std.testing.allocator.free(upstream_response);

    const settings = http2.parseFrameHeader(upstream_response[0..http2.frame_header_len]).?;
    const headers_start = http2.frame_header_len + settings.length;
    const headers = http2.parseFrameHeader(upstream_response[headers_start .. headers_start + http2.frame_header_len]).?;
    const split_at = headers_start + http2.frame_header_len + headers.length;
    const first_chunk = try std.testing.allocator.dupe(u8, upstream_response[0..split_at]);
    defer std.testing.allocator.free(first_chunk);
    const second_chunk = try std.testing.allocator.dupe(u8, upstream_response[split_at..]);
    defer std.testing.allocator.free(second_chunk);

    const actions = [_]TestUpstreamAction{
        .{ .stream_respond = .{
            .first = first_chunk,
            .delay_ms = 150,
            .second = second_chunk,
        } },
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
        .service_name = "grpc",
        .vip_address = "10.43.0.9",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "grpc.internal",
        .http_proxy_path_prefix = "/pkg.Service",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "grpc",
        .endpoint_id = "grpc-1",
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
            .name = "grpc:/pkg.Service",
            .service = "grpc",
            .vip_address = "10.43.0.9",
            .match = .{ .host = "grpc.internal", .path_prefix = "/pkg.Service" },
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
        },
    };
    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    var listener = try TestListener.init();
    defer listener.deinit();

    const ConnectionHarness = struct {
        fn serve(proxy_ptr: *const ReverseProxy, listen_fd: posix.fd_t) void {
            const client_fd = posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC) catch return;
            proxy_ptr.handleConnection(client_fd);
        }
    };

    const server_thread = try std.Thread.spawn(.{}, ConnectionHarness.serve, .{ &proxy, listener.fd });
    defer server_thread.join();

    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(client_fd);
    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, listener.port);
    try posix.connect(client_fd, &server_addr.any, server_addr.getOsSockLen());

    const request = try buildTestHttp2Request(std.testing.allocator, 9, "POST", "grpc.internal", "/pkg.Service/Call");
    defer std.testing.allocator.free(request);
    try socket_helpers.writeAll(client_fd, request);

    socket_helpers.setSocketTimeoutMs(client_fd, 75);
    const settings_ack = try buildHttp2SettingsAckFrame(std.testing.allocator);
    defer std.testing.allocator.free(settings_ack);
    var ack_read_buf: [1024]u8 = undefined;
    const ack_read_len = try posix.read(client_fd, &ack_read_buf);
    try std.testing.expectEqualSlices(u8, settings_ack, ack_read_buf[0..ack_read_len]);

    var first_read_buf: [1024]u8 = undefined;
    const first_read_len = readSocketBytes(client_fd, &first_read_buf);
    try std.testing.expectEqualSlices(u8, first_chunk, first_read_buf[0..first_read_len]);

    socket_helpers.setSocketTimeoutMs(client_fd, 1000);
    var second_read_buf: [1024]u8 = undefined;
    const second_read_len = readSocketBytes(client_fd, &second_read_buf);
    try std.testing.expectEqualSlices(u8, second_chunk, second_read_buf[0..second_read_len]);
}

test "handleConnection relays HTTP/2 client data frames upstream" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    const upstream_response = try http2_response.formatSimpleResponse(
        std.testing.allocator,
        11,
        200,
        "application/grpc",
        "ok",
    );
    defer std.testing.allocator.free(upstream_response);

    const actions = [_]TestUpstreamAction{
        .{ .respond = upstream_response },
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
        .service_name = "grpc",
        .vip_address = "10.43.0.9",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "grpc.internal",
        .http_proxy_path_prefix = "/pkg.Service",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "grpc",
        .endpoint_id = "grpc-1",
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
            .name = "grpc:/pkg.Service",
            .service = "grpc",
            .vip_address = "10.43.0.9",
            .match = .{ .host = "grpc.internal", .path_prefix = "/pkg.Service" },
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
        },
    };
    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    var listener = try TestListener.init();
    defer listener.deinit();

    const ConnectionHarness = struct {
        fn serve(proxy_ptr: *const ReverseProxy, listen_fd: posix.fd_t) void {
            const client_fd = posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC) catch return;
            proxy_ptr.handleConnection(client_fd);
        }
    };

    const server_thread = try std.Thread.spawn(.{}, ConnectionHarness.serve, .{ &proxy, listener.fd });
    defer server_thread.join();

    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(client_fd);
    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, listener.port);
    try posix.connect(client_fd, &server_addr.any, server_addr.getOsSockLen());

    const request = try buildTestHttp2RequestWithEndStream(std.testing.allocator, 11, "POST", "grpc.internal", "/pkg.Service/Call", false);
    defer std.testing.allocator.free(request);
    const data = try buildTestHttp2DataFrame(std.testing.allocator, 11, "hello", true);
    defer std.testing.allocator.free(data);

    try socket_helpers.writeAll(client_fd, request);
    std.Thread.sleep(25 * std.time.ns_per_ms);
    try socket_helpers.writeAll(client_fd, data);

    const settings_ack = try buildHttp2SettingsAckFrame(std.testing.allocator);
    defer std.testing.allocator.free(settings_ack);
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(std.testing.allocator);
    try expected.appendSlice(std.testing.allocator, settings_ack);
    try expected.appendSlice(std.testing.allocator, upstream_response);

    var response_buf: [1024]u8 = undefined;
    socket_helpers.setSocketTimeoutMs(client_fd, 1000);
    const bytes_read = readSocketBytes(client_fd, &response_buf);
    try std.testing.expectEqualSlices(u8, expected.items, response_buf[0..bytes_read]);

    upstream.wait();
    try std.testing.expect(std.mem.eql(u8, http2.client_preface, upstream.request(0)[0..http2.client_preface.len]));
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(0), "hello") != null);
    try std.testing.expect(http2_passthrough.streamEndSeen(upstream.request(0), 1));
}

test "handleConnection routes later HTTP/2 streams independently on one client connection" {
    const store = @import("../../state/store.zig");
    const service_rollout = @import("../service_rollout.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    const upstream_one_response = try http2_response.formatSimpleResponse(
        std.testing.allocator,
        1,
        200,
        "application/grpc",
        "one",
    );
    defer std.testing.allocator.free(upstream_one_response);
    const upstream_two_response = try http2_response.formatSimpleStreamResponse(
        std.testing.allocator,
        1,
        200,
        "application/grpc",
        "two",
    );
    defer std.testing.allocator.free(upstream_two_response);

    const first_response = try http2_response.formatSimpleStreamResponse(
        std.testing.allocator,
        13,
        200,
        "application/grpc",
        "one",
    );
    defer std.testing.allocator.free(first_response);
    const second_response = try http2_response.formatSimpleStreamResponse(
        std.testing.allocator,
        15,
        200,
        "application/grpc",
        "two",
    );
    defer std.testing.allocator.free(second_response);
    const settings_ack = try buildHttp2SettingsAckFrame(std.testing.allocator);
    defer std.testing.allocator.free(settings_ack);
    const downstream_settings = try buildHttp2Frame(std.testing.allocator, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer std.testing.allocator.free(downstream_settings);

    const upstream_one_actions = [_]TestUpstreamAction{
        .{ .respond = upstream_one_response },
    };
    var upstream_one = try TestUpstreamServer.init(&upstream_one_actions);
    defer upstream_one.deinit();
    try upstream_one.start();

    const upstream_two_actions = [_]TestUpstreamAction{
        .{ .respond = upstream_two_response },
    };
    var upstream_two = try TestUpstreamServer.init(&upstream_two_actions);
    defer upstream_two.deinit();
    try upstream_two.start();

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
        .service_name = "grpc-one",
        .vip_address = "10.43.0.9",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "grpc-one.internal",
        .http_proxy_path_prefix = "/pkg.First",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.createService(.{
        .service_name = "grpc-two",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "grpc-two.internal",
        .http_proxy_path_prefix = "/pkg.Second",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "grpc-one",
        .endpoint_id = "grpc-one-1",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "127.0.0.1",
        .port = upstream_one.port,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "grpc-two",
        .endpoint_id = "grpc-two-1",
        .container_id = "ctr-2",
        .node_id = null,
        .ip_address = "127.0.0.1",
        .port = upstream_two.port,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    proxy_runtime.bootstrapIfEnabled();

    const routes = [_]router.Route{
        .{
            .name = "grpc-one:/pkg.First",
            .service = "grpc-one",
            .vip_address = "10.43.0.9",
            .match = .{ .host = "grpc-one.internal", .path_prefix = "/pkg.First" },
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
        },
        .{
            .name = "grpc-two:/pkg.Second",
            .service = "grpc-two",
            .vip_address = "10.43.0.10",
            .match = .{ .host = "grpc-two.internal", .path_prefix = "/pkg.Second" },
            .eligible_endpoints = 1,
            .healthy_endpoints = 1,
        },
    };
    var proxy = ReverseProxy.init(std.testing.allocator, &routes);
    defer proxy.deinit();

    var listener = try TestListener.init();
    defer listener.deinit();

    const ConnectionHarness = struct {
        fn serve(proxy_ptr: *const ReverseProxy, listen_fd: posix.fd_t) void {
            const client_fd = posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC) catch return;
            proxy_ptr.handleConnection(client_fd);
        }
    };

    const server_thread = try std.Thread.spawn(.{}, ConnectionHarness.serve, .{ &proxy, listener.fd });
    defer server_thread.join();

    const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer posix.close(client_fd);
    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, listener.port);
    try posix.connect(client_fd, &server_addr.any, server_addr.getOsSockLen());

    const first_request = try buildTestHttp2Request(std.testing.allocator, 13, "POST", "grpc-one.internal", "/pkg.First/Call");
    defer std.testing.allocator.free(first_request);
    const second_request = try buildTestHttp2HeadersOnlyRequest(std.testing.allocator, 15, "POST", "grpc-two.internal", "/pkg.Second/Call", true);
    defer std.testing.allocator.free(second_request);

    try socket_helpers.writeAll(client_fd, first_request);
    try socket_helpers.writeAll(client_fd, second_request);

    var response_buf: [2048]u8 = undefined;
    socket_helpers.setSocketTimeoutMs(client_fd, 1000);
    const bytes_read = readSocketBytes(client_fd, &response_buf);
    try std.testing.expectEqualSlices(u8, settings_ack, response_buf[0..settings_ack.len]);
    try std.testing.expectEqualSlices(u8, downstream_settings, response_buf[settings_ack.len .. settings_ack.len + downstream_settings.len]);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], first_response) != null);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], second_response) != null);

    upstream_one.wait();
    upstream_two.wait();
    try std.testing.expectEqual(@as(usize, 1), upstream_one.accepted);
    try std.testing.expectEqual(@as(usize, 1), upstream_two.accepted);
    try std.testing.expect(std.mem.eql(u8, http2.client_preface, upstream_one.request(0)[0..http2.client_preface.len]));
    try std.testing.expect(std.mem.eql(u8, http2.client_preface, upstream_two.request(0)[0..http2.client_preface.len]));
}

test "handleConnection rejects looped request after listener restart" {
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

    const ConnectionHarness = struct {
        fn serveOnce(proxy_ptr: *const ReverseProxy, listen_fd: posix.fd_t) void {
            const client_fd = posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC) catch return;
            proxy_ptr.handleConnection(client_fd);
        }
    };

    var listener = try TestListener.init();
    defer listener.deinit();
    var server_thread = try std.Thread.spawn(.{}, ConnectionHarness.serveOnce, .{ &proxy, listener.fd });

    var client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, listener.port);
    try posix.connect(client_fd, &server_addr.any, server_addr.getOsSockLen());
    try socket_helpers.writeAll(client_fd, "GET / HTTP/1.1\r\nHost: api.internal\r\nX-Yoq-Proxy: 1\r\n\r\n");

    var response_buf: [1024]u8 = undefined;
    var bytes_read = try posix.read(client_fd, &response_buf);
    try std.testing.expect(bytes_read > 0);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "HTTP/1.1 502 Bad Gateway\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "{\"error\":\"proxy loop detected\"}") != null);
    posix.close(client_fd);
    server_thread.join();

    listener.deinit();
    listener = try TestListener.init();
    server_thread = try std.Thread.spawn(.{}, ConnectionHarness.serveOnce, .{ &proxy, listener.fd });

    client_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    const restarted_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, listener.port);
    try posix.connect(client_fd, &restarted_addr.any, restarted_addr.getOsSockLen());
    try socket_helpers.writeAll(client_fd, "GET / HTTP/1.1\r\nHost: api.internal\r\nX-Yoq-Proxy: 1\r\n\r\n");

    bytes_read = try posix.read(client_fd, &response_buf);
    try std.testing.expect(bytes_read > 0);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "HTTP/1.1 502 Bad Gateway\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "{\"error\":\"proxy loop detected\"}") != null);
    posix.close(client_fd);
    server_thread.join();
}
