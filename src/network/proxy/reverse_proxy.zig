const std = @import("std");
const posix = std.posix;
const http = @import("../../api/http.zig");
const log = @import("../../lib/log.zig");
const ip = @import("../ip.zig");
const proxy_policy = @import("policy.zig");
const proxy_runtime = @import("runtime.zig");
const router = @import("router.zig");
const upstream_mod = @import("upstream.zig");

const proxy_loop_header = "X-Yoq-Proxy";
const x_forwarded_for_header = "X-Forwarded-For";
const x_forwarded_host_header = "X-Forwarded-Host";
const x_forwarded_proto_header = "X-Forwarded-Proto";
const traceparent_header = "traceparent";
const tracestate_header = "tracestate";

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
        if (http.findHeaderValue(request.headers_raw, proxy_loop_header) != null) {
            proxy_runtime.recordLoopRejection();
            log.warn("l7 proxy loop rejected method={s} host={s} path={s}", .{
                methodString(request.method),
                host,
                request.path_only,
            });
            return .{ .response = .{
                .status = .bad_gateway,
                .body = "{\"error\":\"proxy loop detected\"}",
            } };
        }

        const matched_route = router.matchRoute(self.routes, host, request.path_only) orelse {
            log.info("l7 proxy no route method={s} host={s} path={s}", .{
                methodString(request.method),
                host,
                request.path_only,
            });
            return .{ .response = .{
                .status = .not_found,
                .body = "{\"error\":\"route not found\"}",
            } };
        };
        const route = try cloneRouteSnapshot(self.allocator, matched_route);
        errdefer route.deinit(self.allocator);

        const upstream = proxy_runtime.resolveUpstream(self.allocator, route.service) catch |err| switch (err) {
            error.NoHealthyUpstream => {
                proxy_runtime.recordRouteFailure(matched_route.name, .no_eligible_upstream);
                log.warn("l7 proxy no eligible upstream method={s} host={s} path={s} service={s}", .{
                    methodString(request.method),
                    host,
                    request.path_only,
                    matched_route.service,
                });
                route.deinit(self.allocator);
                return .{ .response = .{
                    .status = .service_unavailable,
                    .body = "{\"error\":\"no eligible upstream\"}",
                } };
            },
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
        return self.forwardRequestWithClient(raw_request, null);
    }

    fn forwardRequestWithClient(self: *const ReverseProxy, raw_request: []const u8, client_ip: ?[4]u8) ![]u8 {
        proxy_runtime.recordRequestStart();
        const handled = try self.handleRequest(raw_request);
        switch (handled) {
            .response => |resp| {
                proxy_runtime.recordResponse(resp.status);
                return formatProxyResponse(self.allocator, resp);
            },
            .forward => |plan| {
                defer plan.deinit(self.allocator);
                const response = try self.forwardPlanWithClient(raw_request, &plan, client_ip);
                if (parseUpstreamStatusCode(response)) |status_code| {
                    proxy_runtime.recordResponseCode(status_code);
                } else |_| {
                    proxy_runtime.recordResponse(.bad_gateway);
                }
                return response;
            },
        }
    }

    pub fn handleConnection(self: *const ReverseProxy, client_fd: posix.fd_t) void {
        defer posix.close(client_fd);
        setSocketTimeoutMs(client_fd, 5000);
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
            _ = writeAll(client_fd, response) catch {};
            return;
        };

        const response = self.forwardRequestWithClient(request, peerIpFromSocket(client_fd)) catch {
            proxy_runtime.recordResponse(.internal_server_error);
            const internal = formatProxyResponse(self.allocator, .{
                .status = .internal_server_error,
                .body = "{\"error\":\"proxy request failed\"}",
            }) catch return;
            defer self.allocator.free(internal);
            _ = writeAll(client_fd, internal) catch {};
            return;
        };
        defer self.allocator.free(response);
        _ = writeAll(client_fd, response) catch {};
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
        const parsed = (http.parseRequest(raw_request) catch return error.BadRequest) orelse return error.BadRequest;
        const inbound_host = http.findHeaderValue(parsed.headers_raw, "Host") orelse plan.host;
        const prior_forwarded_for = http.findHeaderValue(parsed.headers_raw, x_forwarded_for_header);
        const inbound_traceparent = http.findHeaderValue(parsed.headers_raw, traceparent_header);
        const inbound_tracestate = http.findHeaderValue(parsed.headers_raw, tracestate_header);

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
            if (startsWithHeaderName(line, proxy_loop_header)) continue;
            if (startsWithHeaderName(line, x_forwarded_for_header)) continue;
            if (startsWithHeaderName(line, x_forwarded_host_header)) continue;
            if (startsWithHeaderName(line, x_forwarded_proto_header)) continue;
            if (startsWithHeaderName(line, traceparent_header)) continue;
            if (startsWithHeaderName(line, tracestate_header)) continue;

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
        try writer.print("{s}: http\r\n", .{x_forwarded_proto_header});
        if (inbound_traceparent) |value| {
            if (isValidTraceparent(value)) {
                try writer.print("{s}: {s}\r\n", .{ traceparent_header, value });
                if (inbound_tracestate) |state| {
                    try writer.print("{s}: {s}\r\n", .{ tracestate_header, state });
                }
            } else {
                try writeGeneratedTraceHeaders(writer);
            }
        } else {
            try writeGeneratedTraceHeaders(writer);
        }
        try writer.print("Content-Length: {d}\r\n", .{parsed.body.len});
        try writer.writeAll(proxy_loop_header ++ ": 1\r\n");
        try writer.writeAll("Connection: close\r\n\r\n");
        try writer.writeAll(parsed.body);

        return buf.toOwnedSlice(self.allocator);
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
        };
        var attempt: u8 = 0;
        var retries_used: u8 = 0;
        while (true) : (attempt += 1) {
            var upstream = resolveAttemptUpstream(self.allocator, plan, attempt) catch |err| switch (err) {
                error.NoHealthyUpstream => {
                    log.warn("l7 proxy no eligible upstream after retries method={s} host={s} path={s} service={s} retries={d}", .{
                        methodString(plan.method),
                        plan.host,
                        plan.path,
                        plan.route.service,
                        retries_used,
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
                proxy_runtime.recordEndpointFailure(upstream.endpoint_id);
                proxy_runtime.recordUpstreamFailure(mapUpstreamFailure(err));
                if (proxy_policy.shouldRetry(policy, methodString(plan.method), attempt, null, true)) {
                    proxy_runtime.recordRetry();
                    retries_used += 1;
                    continue;
                }
                proxy_runtime.recordRouteFailure(plan.route.name, mapRouteFailureKind(err));
                log.warn("l7 proxy upstream failure method={s} host={s} path={s} service={s} upstream={s}:{d} retries={d} error={}", .{
                    methodString(plan.method),
                    plan.host,
                    plan.path,
                    plan.route.service,
                    upstream.address,
                    upstream.port,
                    retries_used,
                    err,
                });
                return formatProxyResponse(self.allocator, proxyFailureResponse(err));
            };

            const status_code = parseUpstreamStatusCode(response) catch {
                proxy_runtime.recordUpstreamFailure(.other);
                proxy_runtime.recordEndpointFailure(upstream.endpoint_id);
                log.warn("l7 proxy invalid upstream response method={s} host={s} path={s} service={s} upstream={s}:{d} retries={d}", .{
                    methodString(plan.method),
                    plan.host,
                    plan.path,
                    plan.route.service,
                    upstream.address,
                    upstream.port,
                    retries_used,
                });
                self.allocator.free(response);
                proxy_runtime.recordRouteFailure(plan.route.name, .invalid_response);
                return formatProxyResponse(self.allocator, .{
                    .status = .bad_gateway,
                    .body = "{\"error\":\"invalid upstream response\"}",
                });
            };

            if (status_code >= 500 and status_code <= 599) {
                proxy_runtime.recordEndpointFailure(upstream.endpoint_id);
            } else {
                proxy_runtime.recordEndpointSuccess(upstream.endpoint_id);
            }
            if (proxy_policy.shouldRetry(policy, methodString(plan.method), attempt, status_code, false)) {
                proxy_runtime.recordRetry();
                retries_used += 1;
                self.allocator.free(response);
                continue;
            }
            log.info("l7 proxy proxied method={s} host={s} path={s} service={s} upstream={s}:{d} status={d} retries={d}", .{
                methodString(plan.method),
                plan.host,
                plan.path,
                plan.route.service,
                upstream.address,
                upstream.port,
                status_code,
                retries_used,
            });
            proxy_runtime.recordRouteRecovered(plan.route.name);
            return response;
        }
    }

    fn forwardSingleAttempt(
        self: *const ReverseProxy,
        raw_request: []const u8,
        plan: *const ForwardPlan,
        upstream: *const upstream_mod.Upstream,
        client_ip: ?[4]u8,
    ) ![]u8 {
        const request = try self.buildForwardRequestWithClient(raw_request, plan, client_ip);
        defer self.allocator.free(request);

        const fd = try connectToUpstream(plan.route, upstream);
        defer posix.close(fd);

        writeAll(fd, request) catch return error.SendFailed;
        return readResponse(self.allocator, fd, self.max_response_bytes);
    }
};

fn peerIpFromSocket(fd: posix.socket_t) ?[4]u8 {
    var peer_addr: posix.sockaddr.in = undefined;
    var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    posix.getpeername(fd, @ptrCast(&peer_addr), &peer_len) catch return null;
    const address = std.mem.toBytes(peer_addr.addr);
    return .{ address[0], address[1], address[2], address[3] };
}

fn writeIp4(writer: anytype, address: [4]u8) !void {
    try writer.print("{d}.{d}.{d}.{d}", .{ address[0], address[1], address[2], address[3] });
}

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

fn resolveAttemptUpstream(alloc: std.mem.Allocator, plan: *const ForwardPlan, attempt: u8) !upstream_mod.Upstream {
    if (attempt == 0) {
        return .{
            .service = try alloc.dupe(u8, plan.upstream.service),
            .endpoint_id = try alloc.dupe(u8, plan.upstream.endpoint_id),
            .address = try alloc.dupe(u8, plan.upstream.address),
            .port = plan.upstream.port,
            .eligible = plan.upstream.eligible,
        };
    }

    return proxy_runtime.resolveUpstream(alloc, plan.route.service);
}

fn parseUpstreamStatusCode(response: []const u8) !u16 {
    if (response.len < 12) return error.InvalidResponse;
    if (!std.mem.startsWith(u8, response, "HTTP/")) return error.InvalidResponse;

    const first_space = std.mem.indexOfScalar(u8, response, ' ') orelse return error.InvalidResponse;
    const status_start = first_space + 1;
    if (status_start + 3 > response.len) return error.InvalidResponse;
    return std.fmt.parseInt(u16, response[status_start .. status_start + 3], 10) catch error.InvalidResponse;
}

fn connectToUpstream(route: proxy_runtime.RouteSnapshot, upstream: *const upstream_mod.Upstream) !posix.socket_t {
    const upstream_ip = ip.parseIp(upstream.address) orelse return error.InvalidUpstreamAddress;

    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0) catch
        return error.ConnectFailed;
    errdefer posix.close(fd);

    const addr = std.net.Address.initIp4(upstream_ip, upstream.port);
    posix.connect(fd, &addr.any, addr.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock, error.ConnectionPending => try waitForConnect(fd, route.connect_timeout_ms),
        error.ConnectionTimedOut => return error.ConnectTimedOut,
        else => return error.ConnectFailed,
    };
    try setSocketBlocking(fd);
    setSocketTimeoutMs(fd, route.request_timeout_ms);
    return fd;
}

fn waitForConnect(fd: posix.socket_t, timeout_ms: u32) !void {
    var poll_fds = [_]posix.pollfd{
        .{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 },
    };
    const timeout = clampPollTimeout(timeout_ms);
    const ready = posix.poll(&poll_fds, timeout) catch return error.ConnectFailed;
    if (ready == 0) return error.ConnectTimedOut;
    if (poll_fds[0].revents & posix.POLL.OUT == 0 and poll_fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP) == 0) {
        return error.ConnectFailed;
    }

    posix.getsockoptError(fd) catch |err| switch (err) {
        error.ConnectionTimedOut => return error.ConnectTimedOut,
        else => return error.ConnectFailed,
    };
}

fn setSocketBlocking(fd: posix.socket_t) !void {
    const flags = posix.fcntl(fd, posix.F.GETFL, 0) catch return error.ConnectFailed;
    const nonblock: usize = @intCast(@as(u32, @bitCast(posix.O{ .NONBLOCK = true })));
    _ = posix.fcntl(fd, posix.F.SETFL, flags & ~nonblock) catch return error.ConnectFailed;
}

fn clampPollTimeout(timeout_ms: u32) i32 {
    return @intCast(@min(timeout_ms, @as(u32, @intCast(std.math.maxInt(i32)))));
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
        .eligible_endpoints = route.eligible_endpoints,
        .healthy_endpoints = route.healthy_endpoints,
        .degraded = route.degraded,
        .degraded_reason = if (route.degraded) .service_state else .none,
        .last_failure_kind = null,
        .last_failure_at = null,
        .retries = route.retries,
        .connect_timeout_ms = route.connect_timeout_ms,
        .request_timeout_ms = route.request_timeout_ms,
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
            .degraded_reason = .none,
            .last_failure_kind = null,
            .last_failure_at = null,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
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
            .degraded_reason = .none,
            .last_failure_kind = null,
            .last_failure_at = null,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
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
            .degraded_reason = .none,
            .last_failure_kind = null,
            .last_failure_at = null,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
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
            .degraded_reason = .none,
            .last_failure_kind = null,
            .last_failure_at = null,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
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
            .degraded_reason = .none,
            .last_failure_kind = null,
            .last_failure_at = null,
            .retries = 0,
            .connect_timeout_ms = 1000,
            .request_timeout_ms = 5000,
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
        self.thread = try std.Thread.spawn(.{}, acceptOne, .{self});
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
            setSocketTimeoutMs(client_fd, 1000);
            self.request_lens[index] = captureRequestBytes(client_fd, &self.request_bufs[index]);
            self.accepted = index + 1;

            switch (action) {
                .close => {},
                .respond => |response| _ = writeAll(client_fd, response) catch {},
                .delayed_respond => |resp| {
                    std.Thread.sleep(@as(u64, resp.delay_ms) * std.time.ns_per_ms);
                    _ = writeAll(client_fd, resp.response) catch {};
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
    while (attempt < 5) : (attempt += 1) {
        const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch |err| {
            if (attempt + 1 == 5) return err;
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };
        errdefer posix.close(fd);

        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuseaddr)) catch {};

        posix.bind(fd, &addr.any, addr.getOsSockLen()) catch |err| {
            if (attempt + 1 == 5) return err;
            posix.close(fd);
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };
        posix.listen(fd, 1) catch |err| {
            if (attempt + 1 == 5) return err;
            posix.close(fd);
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };

        var bound_addr: posix.sockaddr.in = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        posix.getsockname(fd, @ptrCast(&bound_addr), &bound_len) catch |err| {
            if (attempt + 1 == 5) return err;
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

        const parsed = http.parseRequest(buf[0..total]) catch return total;
        if (parsed) |request| {
            return requestEndOffset(buf[0..total], request);
        }
    }
    return total;
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
    proxy_runtime.recordEndpointFailure("api-1");
    proxy_runtime.recordEndpointFailure("api-1");
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

    try writeAll(client_fd, "GET / HTTP/1.1\r\nHost: api.internal\r\n\r\n");
    var response_buf: [1024]u8 = undefined;
    const bytes_read = try posix.read(client_fd, &response_buf);
    try std.testing.expect(bytes_read > 0);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "HTTP/1.1 200 OK\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "\r\n\r\nhello") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(0), "X-Forwarded-For: 127.0.0.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(0), "X-Forwarded-Host: api.internal\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(0), "X-Forwarded-Proto: http\r\n") != null);
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
    try writeAll(client_fd, "GET / HTTP/1.1\r\nHost: api.internal\r\nX-Yoq-Proxy: 1\r\n\r\n");

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
    try writeAll(client_fd, "GET / HTTP/1.1\r\nHost: api.internal\r\nX-Yoq-Proxy: 1\r\n\r\n");

    bytes_read = try posix.read(client_fd, &response_buf);
    try std.testing.expect(bytes_read > 0);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "HTTP/1.1 502 Bad Gateway\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "{\"error\":\"proxy loop detected\"}") != null);
    posix.close(client_fd);
    server_thread.join();
}
