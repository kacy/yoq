const std = @import("std");
const observations = @import("observations.zig");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const http = @import("../../api/http.zig");
const http2 = @import("http2.zig");
const h2c_upgrade = @import("h2c_upgrade.zig");
const proxy_helpers = @import("proxy_helpers.zig");
const socket_helpers = @import("socket_helpers.zig");
const transport = @import("../../tls/client_transport.zig");
const exchange = @import("upstream_exchange.zig");
const PeerKey = @import("../../tls/proxy_credentials.zig").Key;
const http2_request = @import("http2_request.zig");
const http2_response = @import("http2_response.zig");
const proxy_policy = @import("policy.zig");
const proxy_runtime = @import("runtime.zig");
const router = @import("router.zig");
const upstream_mod = @import("upstream.zig");
const ip = @import("../ip.zig");
const hpack = @import("hpack.zig");

// DoS bounds for a single HTTP/2 connection. without these a client can open
// unlimited concurrent streams or stall mid-frame while streaming bytes,
// growing the per-connection buffers until OOM.
const max_concurrent_streams: usize = 128;
const max_downstream_buf_bytes: usize = 1 << 20; // 1 MiB of un-parsed frames

pub fn proxyConnection(
    alloc: std.mem.Allocator,
    routes: []const router.Route,
    client_fd: linux_platform.posix.socket_t,
    initial_request: []const u8,
    client_ip: ?[4]u8,
    peer_key: ?PeerKey,
) !void {
    var connection = ConnectionRouter{
        .allocator = alloc,
        .routes = routes,
        .client_fd = client_fd,
        .client_ip = client_ip,
        .peer_key = peer_key,
    };
    defer connection.deinit();

    try connection.downstream_buf.appendSlice(alloc, initial_request);
    try connection.run();
}

pub fn proxyUpgradedConnection(
    alloc: std.mem.Allocator,
    routes: []const router.Route,
    client_fd: linux_platform.posix.socket_t,
    upgraded: h2c_upgrade.ParsedUpgrade,
    client_ip: ?[4]u8,
    peer_key: ?PeerKey,
) !void {
    var connection = ConnectionRouter{
        .allocator = alloc,
        .routes = routes,
        .client_fd = client_fd,
        .client_ip = client_ip,
        .peer_key = peer_key,
        .sent_settings = true,
    };
    defer connection.deinit();

    try connection.bootstrapUpgradedStream(upgraded);
    try connection.run();
}

const ConnectionRouter = struct {
    allocator: std.mem.Allocator,
    routes: []const router.Route,
    client_fd: linux_platform.posix.socket_t,
    client_ip: ?[4]u8,
    peer_key: ?PeerKey = null,
    downstream_buf: std.ArrayList(u8) = .empty,
    streams: std.ArrayList(StreamSession) = .empty,
    saw_client_preface: bool = false,
    sent_settings: bool = false,
    last_activity_ms: i64 = 0,

    fn deinit(self: *ConnectionRouter) void {
        if (self.peer_key) |*key| std.crypto.secureZero(u8, key);
        self.downstream_buf.deinit(self.allocator);
        for (self.streams.items) |*session| session.deinit(self.allocator);
        self.streams.deinit(self.allocator);
    }

    fn run(self: *ConnectionRouter) !void {
        self.last_activity_ms = nowMs();
        while (true) {
            try self.processDownstreamBuffer();

            const now = nowMs();
            if (try self.expireTimedOutStreams(now)) continue;

            var timeout_ms = self.connectionIdleRemainingMs(now);
            if (self.nextPendingDeadlineMs(now)) |pending_timeout| {
                timeout_ms = @min(timeout_ms, pending_timeout);
            }

            var poll_fds: std.ArrayList(posix.pollfd) = .empty;
            defer poll_fds.deinit(self.allocator);
            var session_targets: std.ArrayList(SessionPollTarget) = .empty;
            defer session_targets.deinit(self.allocator);

            try poll_fds.append(self.allocator, .{
                .fd = self.client_fd,
                .events = posix.POLL.IN,
                .revents = 0,
            });
            var buffered_input = false;
            for (self.streams.items, 0..) |session, idx| {
                buffered_input = buffered_input or session.connection.buffered();
                try poll_fds.append(self.allocator, .{
                    .fd = session.connection.fd(),
                    .events = posix.POLL.IN,
                    .revents = 0,
                });
                try session_targets.append(self.allocator, .{ .stream_idx = idx, .kind = .primary, .buffered = session.connection.buffered() });
                if (session.mirror) |mirror| {
                    buffered_input = buffered_input or mirror.connection.buffered();
                    try poll_fds.append(self.allocator, .{
                        .fd = mirror.connection.fd(),
                        .events = posix.POLL.IN,
                        .revents = 0,
                    });
                    try session_targets.append(self.allocator, .{ .stream_idx = idx, .kind = .mirror, .buffered = mirror.connection.buffered() });
                }
            }

            const ready = posix.poll(poll_fds.items, if (buffered_input) 0 else socket_helpers.clampPollTimeout(timeout_ms)) catch return error.ReceiveFailed;
            if (ready == 0 and !buffered_input) {
                if (try self.expireTimedOutStreams(nowMs())) continue;
                break;
            }

            if (poll_fds.items[0].revents & posix.POLL.IN != 0) {
                var buf: [16 * 1024]u8 = undefined;
                const bytes_read = posix.read(self.client_fd, &buf) catch return error.ReceiveFailed;
                if (bytes_read == 0) break;
                try self.downstream_buf.appendSlice(self.allocator, buf[0..bytes_read]);
                // bound un-parsed downstream bytes: a client that streams data
                // without ever completing a frame would otherwise grow this
                // without limit.
                if (self.downstream_buf.items.len > max_downstream_buf_bytes) return error.ReceiveFailed;
                self.last_activity_ms = nowMs();
            } else if (poll_fds.items[0].revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) {
                break;
            }

            var ready_sessions: std.ArrayList(usize) = .empty;
            defer ready_sessions.deinit(self.allocator);
            for (session_targets.items, 0..) |target, poll_idx| {
                const revents = poll_fds.items[poll_idx + 1].revents;
                if (target.buffered or revents & posix.POLL.IN != 0) {
                    try ready_sessions.append(self.allocator, poll_idx);
                } else if (revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) {
                    try ready_sessions.append(self.allocator, poll_idx);
                }
            }
            std.mem.sort(usize, ready_sessions.items, {}, comptime std.sort.desc(usize));
            for (ready_sessions.items) |target_idx| {
                if (target_idx >= session_targets.items.len) continue;
                const target = session_targets.items[target_idx];
                if (target.stream_idx >= self.streams.items.len) continue;
                switch (target.kind) {
                    .primary => try self.readUpstream(target.stream_idx),
                    .mirror => try self.readMirrorUpstream(target.stream_idx),
                }
            }
        }
    }

    fn bootstrapUpgradedStream(self: *ConnectionRouter, upgraded: h2c_upgrade.ParsedUpgrade) !void {
        const observation_started_ns = observations.nowNs();
        proxy_runtime.recordRequestStart();

        const route = router.matchRoute(
            self.routes,
            upgraded.method,
            proxy_helpers.normalizeHost(upgraded.authority),
            upgraded.path,
            upgraded.request_headers,
        ) orelse {
            proxy_runtime.recordResponse(.not_found);
            try self.sendLocalStreamResponse(1, .not_found, "{\"error\":\"route not found\"}");
            return;
        };

        const method_enum = proxy_helpers.parseMethodString(upgraded.method) orelse {
            proxy_runtime.recordResponse(.bad_request);
            try self.sendLocalStreamResponse(1, .bad_request, "{\"error\":\"unsupported http2 method\"}");
            return;
        };
        _ = method_enum;

        const normalized_host = proxy_helpers.normalizeHost(upgraded.authority);
        const selection_key = routeSelectionKey(upgraded.method, normalized_host, upgraded.path);
        const request_policy = proxy_policy.RequestPolicy{ .retries = route.retries, .retry_on_5xx = route.retry_on_5xx };
        const cb_policy = proxy_policy.CircuitBreakerPolicy{
            .failure_threshold = route.circuit_breaker_threshold,
            .open_timeout_ms = route.circuit_breaker_timeout_ms,
        };

        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            const backend_service = proxy_runtime.selectBackendService(route, selection_key, attempt);
            proxy_runtime.recordRouteRequestStart(route.name, route.service, backend_service);

            var upstream = proxy_runtime.resolveUpstreamWithPolicy(self.allocator, backend_service, cb_policy) catch |err| switch (err) {
                error.NoHealthyUpstream => {
                    proxy_runtime.recordRouteFailure(route.name, .no_eligible_upstream);
                    proxy_runtime.recordResponse(.service_unavailable);
                    try self.sendLocalStreamResponse(1, .service_unavailable, "{\"error\":\"no eligible upstream\"}");
                    return;
                },
                else => return err,
            };
            var transferred = false;
            defer if (!transferred) upstream.deinit(self.allocator);

            const outbound_path = try proxy_helpers.buildOutboundPath(
                self.allocator,
                upgraded.path,
                route.match.path_prefix,
                route.rewrite_prefix,
            );
            defer self.allocator.free(outbound_path);

            const outbound_authority = if (route.preserve_host) upgraded.authority else backend_service;
            const request_bytes = try h2c_upgrade.buildStream1HeadersFrame(
                self.allocator,
                outbound_authority,
                upgraded.method,
                outbound_path,
                upgraded.request_headers,
                "http",
            );
            defer self.allocator.free(request_bytes);

            const request_deadline_at_ms = nowMs() + @as(i64, @intCast(route.request_timeout_ms));
            var connection = connectAndSendUpstream(self.allocator, self.peer_key, route, &upstream, request_bytes, request_deadline_at_ms) catch |connect_err| {
                proxy_runtime.recordEndpointFailure(upstream.endpoint_id, cb_policy);
                const failure_kind: proxy_runtime.UpstreamFailureKind = if (connect_err == error.ConnectFailed or connect_err == error.ConnectTimedOut) .connect else .send;
                proxy_runtime.recordUpstreamFailure(failure_kind);
                proxy_runtime.recordRouteUpstreamFailure(route.name, route.service, backend_service);
                if (proxy_policy.shouldRetry(request_policy, upgraded.method, attempt, null, true)) {
                    proxy_runtime.recordRetry();
                    proxy_runtime.recordRouteRetry(route.name, route.service, backend_service);
                    continue;
                }
                const route_failure: proxy_runtime.RouteFailureKind = if (failure_kind == .connect) .connect else .send;
                proxy_runtime.recordRouteFailure(route.name, route_failure);
                observations.record(backend_service, observation_started_ns, true);
                proxy_runtime.recordResponse(.bad_gateway);
                const body = if (failure_kind == .connect) "{\"error\":\"upstream connect failed\"}" else "{\"error\":\"upstream send failed\"}";
                try self.sendLocalStreamResponse(1, .bad_gateway, body);
                return;
            };

            defer if (!transferred) connection.deinit();
            const owned_backend = try self.allocator.dupe(u8, backend_service);
            defer if (!transferred) self.allocator.free(owned_backend);
            try self.streams.append(self.allocator, .{
                .downstream_stream_id = 1,
                .route = route,
                .backend_service = owned_backend,
                .upstream = upstream,
                .connection = connection,
                .request_deadline_at_ms = request_deadline_at_ms,
                .observation_started_ns = observation_started_ns,
                .downstream_end_stream = true,
            });
            transferred = true;
            self.streams.items[self.streams.items.len - 1].mirror = self.startMirrorSessionForUpgrade(route, upgraded);
            return;
        }
    }

    fn processDownstreamBuffer(self: *ConnectionRouter) !void {
        while (true) {
            if (!self.saw_client_preface) {
                const probe_len = @min(self.downstream_buf.items.len, http2.client_preface.len);
                if (!http2.hasClientPrefacePrefix(self.downstream_buf.items[0..probe_len])) {
                    return error.MalformedRequest;
                }
                if (self.downstream_buf.items.len < http2.client_preface.len) return;
                self.downstream_buf.replaceRange(self.allocator, 0, http2.client_preface.len, "") catch return error.OutOfMemory;
                self.saw_client_preface = true;
            }

            if (self.downstream_buf.items.len < http2.frame_header_len) return;
            const frame = http2.parseFrameHeader(self.downstream_buf.items[0..http2.frame_header_len]).?;
            if (http2.frame_header_len + frame.length > self.downstream_buf.items.len) return;

            switch (frame.frame_type) {
                .settings => try self.handleClientSettings(frame),
                .ping => try self.handleClientPing(frame),
                .goaway => return,
                .headers => try self.handleClientHeaders(),
                .data => try self.forwardClientStreamFrame(.data),
                .rst_stream => try self.forwardClientStreamFrame(.rst_stream),
                .window_update, .priority, .continuation, .unknown, .push_promise => {
                    try self.discardFrame();
                },
            }
        }
    }

    fn handleClientSettings(self: *ConnectionRouter, frame: http2.FrameHeader) !void {
        if ((frame.flags & 0x1) == 0) {
            const ack = try http2.buildFrame(self.allocator, .{
                .length = 0,
                .frame_type = .settings,
                .flags = 0x1,
                .stream_id = 0,
            }, "");
            defer self.allocator.free(ack);
            try socket_helpers.writeAll(self.client_fd, ack);
        }
        try self.discardFrame();
    }

    fn handleClientPing(self: *ConnectionRouter, frame: http2.FrameHeader) !void {
        const payload = self.downstream_buf.items[http2.frame_header_len .. http2.frame_header_len + frame.length];
        if ((frame.flags & 0x1) == 0 and payload.len == 8) {
            const ack = try http2.buildFrame(self.allocator, .{
                .length = 8,
                .frame_type = .ping,
                .flags = 0x1,
                .stream_id = 0,
            }, payload);
            defer self.allocator.free(ack);
            try socket_helpers.writeAll(self.client_fd, ack);
        }
        try self.discardFrame();
    }

    fn handleClientHeaders(self: *ConnectionRouter) !void {
        const observation_started_ns = observations.nowNs();
        const parsed = http2_request.parseRequestHeaderSequence(self.allocator, self.downstream_buf.items, 0) catch |err| switch (err) {
            error.BufferTooShort => return,
            else => return err,
        };
        defer parsed.deinit(self.allocator);

        proxy_runtime.recordRequestStart();

        if (self.findStreamIndex(parsed.request.stream_id)) |stream_idx| {
            const rewritten = try http2_request.rewriteRequestHeaderSequence(self.allocator, self.downstream_buf.items, 0, .{
                .stream_id = 1,
            });
            defer rewritten.deinit(self.allocator);
            try writeSession(&self.streams.items[stream_idx], rewritten.bytes);
            try self.consumeDownstreamBytes(rewritten.consumed);
            self.last_activity_ms = nowMs();
            return;
        }

        // cap concurrent streams: refuse a new stream past the limit rather
        // than grow `streams` (and dial upstreams) without bound. handled
        // before any upstream dial so no fd is leaked.
        if (self.streams.items.len >= max_concurrent_streams) {
            try self.sendLocalStreamResponse(parsed.request.stream_id, .service_unavailable, "{\"error\":\"too many concurrent streams\"}");
            proxy_runtime.recordResponse(.service_unavailable);
            try self.consumeDownstreamBytes(parsed.consumed);
            return;
        }

        const route = self.matchRouteForParsedRequest(parsed) orelse {
            try self.sendLocalStreamResponse(parsed.request.stream_id, .not_found, "{\"error\":\"route not found\"}");
            proxy_runtime.recordResponse(.not_found);
            try self.consumeDownstreamBytes(parsed.consumed);
            return;
        };

        const method_enum = proxy_helpers.parseMethodString(parsed.request.method) orelse {
            try self.sendLocalStreamResponse(parsed.request.stream_id, .bad_request, "{\"error\":\"unsupported http2 method\"}");
            proxy_runtime.recordResponse(.bad_request);
            try self.consumeDownstreamBytes(parsed.consumed);
            return;
        };

        const normalized_host = proxy_helpers.normalizeHost(parsed.request.authority);
        const selection_key = routeSelectionKey(parsed.request.method, normalized_host, parsed.request.path);
        const forwarded_proto = trustedForwardedProto(parsed.headers, self.client_ip);

        const request_policy = proxy_policy.RequestPolicy{ .retries = route.retries, .retry_on_5xx = route.retry_on_5xx };
        const cb_policy = proxy_policy.CircuitBreakerPolicy{ .failure_threshold = route.circuit_breaker_threshold, .open_timeout_ms = route.circuit_breaker_timeout_ms };

        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            const backend_service = proxy_runtime.selectBackendService(route, selection_key, attempt);
            proxy_runtime.recordRouteRequestStart(route.name, route.service, backend_service);
            var upstream = proxy_runtime.resolveUpstreamWithPolicy(self.allocator, backend_service, cb_policy) catch |err| switch (err) {
                error.NoHealthyUpstream => {
                    proxy_runtime.recordRouteFailure(route.name, .no_eligible_upstream);
                    proxy_runtime.recordResponse(.service_unavailable);
                    try self.sendLocalStreamResponse(parsed.request.stream_id, .service_unavailable, "{\"error\":\"no eligible upstream\"}");
                    try self.consumeDownstreamBytes(parsed.consumed);
                    return;
                },
                else => return err,
            };
            var transferred = false;
            defer if (!transferred) upstream.deinit(self.allocator);

            const outbound_path = try proxy_helpers.buildOutboundPath(self.allocator, parsed.request.path, route.match.path_prefix, route.rewrite_prefix);
            defer self.allocator.free(outbound_path);
            const outbound_authority = if (route.preserve_host) normalized_host else backend_service;

            const rewritten = try http2_request.rewriteRequestHeaderSequence(self.allocator, self.downstream_buf.items, 0, .{
                .outbound_authority = if (std.mem.eql(u8, outbound_authority, normalized_host)) null else outbound_authority,
                .outbound_path = if (std.mem.eql(u8, outbound_path, parsed.request.path)) null else outbound_path,
                .forwarded_proto = forwarded_proto,
                .stream_id = 1,
            });
            defer rewritten.deinit(self.allocator);

            const request_deadline_at_ms = nowMs() + @as(i64, @intCast(route.request_timeout_ms));
            var connection = connectAndSendUpstream(self.allocator, self.peer_key, route, &upstream, rewritten.bytes, request_deadline_at_ms) catch |connect_err| {
                proxy_runtime.recordEndpointFailure(upstream.endpoint_id, cb_policy);
                const failure_kind: proxy_runtime.UpstreamFailureKind = if (connect_err == error.ConnectFailed or connect_err == error.ConnectTimedOut) .connect else .send;
                proxy_runtime.recordUpstreamFailure(failure_kind);
                proxy_runtime.recordRouteUpstreamFailure(route.name, route.service, backend_service);
                if (proxy_policy.shouldRetry(request_policy, parsed.request.method, attempt, null, true)) {
                    proxy_runtime.recordRetry();
                    proxy_runtime.recordRouteRetry(route.name, route.service, backend_service);
                    continue;
                }
                const route_failure: proxy_runtime.RouteFailureKind = if (failure_kind == .connect) .connect else .send;
                proxy_runtime.recordRouteFailure(route.name, route_failure);
                observations.record(backend_service, observation_started_ns, true);
                proxy_runtime.recordResponse(.bad_gateway);
                const body = if (failure_kind == .connect) "{\"error\":\"upstream connect failed\"}" else "{\"error\":\"upstream send failed\"}";
                try self.sendLocalStreamResponse(parsed.request.stream_id, .bad_gateway, body);
                try self.consumeDownstreamBytes(parsed.consumed);
                return;
            };

            defer if (!transferred) connection.deinit();
            const owned_backend = try self.allocator.dupe(u8, backend_service);
            defer if (!transferred) self.allocator.free(owned_backend);
            try self.streams.append(self.allocator, .{
                .downstream_stream_id = parsed.request.stream_id,
                .route = route,
                .backend_service = owned_backend,
                .upstream = upstream,
                .connection = connection,
                .request_deadline_at_ms = request_deadline_at_ms,
                .observation_started_ns = observation_started_ns,
            });
            transferred = true;
            self.streams.items[self.streams.items.len - 1].mirror = self.startMirrorSession(route, parsed);
            try self.consumeDownstreamBytes(parsed.consumed);
            self.last_activity_ms = nowMs();
            return;
        }

        _ = method_enum;
    }

    fn forwardClientStreamFrame(self: *ConnectionRouter, comptime expected_type: http2.FrameType) !void {
        const frame = http2.parseFrameHeader(self.downstream_buf.items[0..http2.frame_header_len]).?;
        if (frame.frame_type != expected_type) return error.InvalidFrameSequence;
        const stream_idx = self.findStreamIndex(frame.stream_id) orelse {
            try self.discardFrame();
            return;
        };
        const rewritten = try rewriteFrameSequenceStreamId(self.allocator, self.downstream_buf.items, 0, 1);
        defer rewritten.deinit(self.allocator);
        try writeSession(&self.streams.items[stream_idx], rewritten.bytes);
        if (self.streams.items[stream_idx].mirror) |*mirror| {
            self.forwardMirrorFrame(mirror, rewritten.bytes) catch {
                proxy_runtime.recordMirrorRouteUpstreamFailure(
                    self.streams.items[stream_idx].route.name,
                    self.streams.items[stream_idx].route.service,
                    mirror.backend_service,
                );
                self.closeMirrorSession(stream_idx);
            };
        }
        try self.consumeDownstreamBytes(rewritten.consumed);
        self.last_activity_ms = nowMs();

        if (expected_type == .rst_stream or (frame.frame_type == .data and (frame.flags & 0x1) != 0)) {
            self.streams.items[stream_idx].downstream_end_stream = true;
        }
    }

    fn readUpstream(self: *ConnectionRouter, session_idx: usize) !void {
        var buf: [16 * 1024]u8 = undefined;
        const session = &self.streams.items[session_idx];
        session.connection.operation_deadline = if (session.response_started) null else deadlineAt(session.request_deadline_at_ms);
        const bytes_read = (session.connection.readAvailable(&buf) catch {
            try self.failSession(session_idx, .receive, "{\"error\":\"upstream receive failed\"}");
            return;
        }) orelse return;
        if (bytes_read == 0) {
            if (!session.response_started) {
                try self.failSession(session_idx, .receive, "{\"error\":\"upstream closed before response\"}");
            } else {
                self.removeSession(session_idx);
            }
            return;
        }

        try session.upstream_buf.appendSlice(self.allocator, buf[0..bytes_read]);
        self.last_activity_ms = nowMs();

        while (session_idx < self.streams.items.len) {
            const active = &self.streams.items[session_idx];
            if (active.upstream_buf.items.len < http2.frame_header_len) return;
            const frame = http2.parseFrameHeader(active.upstream_buf.items[0..http2.frame_header_len]).?;
            if (http2.frame_header_len + frame.length > active.upstream_buf.items.len) return;

            switch (frame.frame_type) {
                .settings => try self.handleUpstreamSettings(session_idx, frame),
                .ping => try self.handleUpstreamPing(session_idx, frame),
                .headers => try self.handleUpstreamHeaders(session_idx),
                .data, .rst_stream => try self.forwardUpstreamStreamFrame(session_idx),
                .window_update, .priority, .continuation, .unknown, .push_promise, .goaway => try self.discardUpstreamFrame(session_idx),
            }
        }
    }

    fn readMirrorUpstream(self: *ConnectionRouter, session_idx: usize) !void {
        const session = &self.streams.items[session_idx];
        const mirror = if (session.mirror) |*value| value else return;
        var buf: [16 * 1024]u8 = undefined;
        mirror.connection.operation_deadline = if (mirror.response_started) null else deadlineAt(mirror.request_deadline_at_ms);
        const bytes_read = (mirror.connection.readAvailable(&buf) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(session.route.name, session.route.service, mirror.backend_service);
            self.closeMirrorSession(session_idx);
            return;
        }) orelse return;
        if (bytes_read == 0) {
            if (!mirror.response_started) {
                proxy_runtime.recordMirrorRouteUpstreamFailure(session.route.name, session.route.service, mirror.backend_service);
            }
            self.closeMirrorSession(session_idx);
            return;
        }

        mirror.upstream_buf.appendSlice(self.allocator, buf[0..bytes_read]) catch {
            self.failMirrorSession(session_idx);
            return;
        };
        self.last_activity_ms = nowMs();

        while (session_idx < self.streams.items.len and self.streams.items[session_idx].mirror != null) {
            const active = &(self.streams.items[session_idx].mirror.?);
            if (active.upstream_buf.items.len < http2.frame_header_len) return;
            const frame = http2.parseFrameHeader(active.upstream_buf.items[0..http2.frame_header_len]).?;
            if (http2.frame_header_len + frame.length > active.upstream_buf.items.len) return;

            switch (frame.frame_type) {
                .settings => self.handleMirrorSettings(session_idx, frame) catch {
                    self.failMirrorSession(session_idx);
                    return;
                },
                .ping => self.handleMirrorPing(session_idx, frame) catch {
                    self.failMirrorSession(session_idx);
                    return;
                },
                .headers => self.handleMirrorHeaders(session_idx) catch {
                    self.failMirrorSession(session_idx);
                    return;
                },
                .data, .rst_stream => self.discardMirrorStreamFrame(session_idx) catch {
                    self.failMirrorSession(session_idx);
                    return;
                },
                .window_update, .priority, .continuation, .unknown, .push_promise, .goaway => self.discardMirrorFrame(session_idx) catch {
                    self.failMirrorSession(session_idx);
                    return;
                },
            }
        }
    }

    fn handleUpstreamSettings(self: *ConnectionRouter, session_idx: usize, frame: http2.FrameHeader) !void {
        const payload = self.streams.items[session_idx].upstream_buf.items[http2.frame_header_len .. http2.frame_header_len + frame.length];
        if ((frame.flags & 0x1) == 0) {
            if (!self.sent_settings) {
                try self.sendDownstreamSettingsFrame(payload);
            }
            const ack = try http2.buildFrame(self.allocator, .{
                .length = 0,
                .frame_type = .settings,
                .flags = 0x1,
                .stream_id = 0,
            }, "");
            defer self.allocator.free(ack);
            try writeSession(&self.streams.items[session_idx], ack);
        }
        try self.discardUpstreamFrame(session_idx);
    }

    fn handleUpstreamPing(self: *ConnectionRouter, session_idx: usize, frame: http2.FrameHeader) !void {
        const payload = self.streams.items[session_idx].upstream_buf.items[http2.frame_header_len .. http2.frame_header_len + frame.length];
        if ((frame.flags & 0x1) == 0 and payload.len == 8) {
            const ack = try http2.buildFrame(self.allocator, .{
                .length = 8,
                .frame_type = .ping,
                .flags = 0x1,
                .stream_id = 0,
            }, payload);
            defer self.allocator.free(ack);
            try writeSession(&self.streams.items[session_idx], ack);
        }
        try self.discardUpstreamFrame(session_idx);
    }

    fn handleUpstreamHeaders(self: *ConnectionRouter, session_idx: usize) !void {
        const session = &self.streams.items[session_idx];
        if (!session.response_started) {
            const status = try parseResponseStatus(session.upstream_buf.items);
            session.response_started = true;
            session.response_status = status;
            if (status >= 500 and status <= 599) {
                proxy_runtime.recordEndpointFailure(session.upstream.endpoint_id, .{
                    .failure_threshold = session.route.circuit_breaker_threshold,
                    .open_timeout_ms = session.route.circuit_breaker_timeout_ms,
                });
            } else {
                proxy_runtime.recordEndpointSuccess(session.upstream.endpoint_id);
            }
            proxy_runtime.recordRouteResponseCode(session.route.name, session.route.service, session.backend_service, status);
        }
        try self.forwardUpstreamStreamFrame(session_idx);
    }

    fn forwardUpstreamStreamFrame(self: *ConnectionRouter, session_idx: usize) !void {
        const session = &self.streams.items[session_idx];
        const frame = http2.parseFrameHeader(session.upstream_buf.items[0..http2.frame_header_len]).?;
        if (!self.sent_settings and frame.frame_type != .settings) {
            try self.sendDownstreamSettingsFrame("");
        }
        const rewritten = try rewriteFrameSequenceStreamId(self.allocator, session.upstream_buf.items, 0, session.downstream_stream_id);
        defer rewritten.deinit(self.allocator);
        try socket_helpers.writeAll(self.client_fd, rewritten.bytes);
        try self.consumeUpstreamBytes(session_idx, rewritten.consumed);

        if (frame.frame_type == .rst_stream or (frame.flags & 0x1) != 0) {
            observations.record(session.backend_service, session.observation_started_ns, frame.frame_type == .rst_stream or (session.response_status orelse 500) >= 500);
            proxy_runtime.recordRouteRecovered(session.route.name);
            self.removeSession(session_idx);
        }
    }

    fn failSession(
        self: *ConnectionRouter,
        session_idx: usize,
        failure: proxy_runtime.UpstreamFailureKind,
        body: []const u8,
    ) !void {
        const session = &self.streams.items[session_idx];
        proxy_runtime.recordEndpointFailure(session.upstream.endpoint_id, .{
            .failure_threshold = session.route.circuit_breaker_threshold,
            .open_timeout_ms = session.route.circuit_breaker_timeout_ms,
        });
        proxy_runtime.recordUpstreamFailure(failure);
        proxy_runtime.recordRouteUpstreamFailure(session.route.name, session.route.service, session.backend_service);
        proxy_runtime.recordRouteFailure(session.route.name, switch (failure) {
            .connect => .connect,
            .send => .send,
            .receive => .receive,
            .other => .receive,
        });
        observations.record(session.backend_service, session.observation_started_ns, true);
        proxy_runtime.recordResponse(.bad_gateway);
        try self.sendLocalStreamResponse(session.downstream_stream_id, .bad_gateway, body);
        self.removeSession(session_idx);
    }

    fn expireTimedOutStreams(self: *ConnectionRouter, now: i64) !bool {
        var expired_any = false;
        var idx = self.streams.items.len;
        while (idx > 0) {
            idx -= 1;
            const session = &self.streams.items[idx];
            if (session.response_started) continue;
            if (now < session.request_deadline_at_ms) continue;
            try self.failSession(idx, .receive, "{\"error\":\"upstream request timed out\"}");
            expired_any = true;
        }
        idx = self.streams.items.len;
        while (idx > 0) {
            idx -= 1;
            const session = &self.streams.items[idx];
            const mirror = if (session.mirror) |*value| value else continue;
            if (mirror.response_started) continue;
            if (now < mirror.request_deadline_at_ms) continue;
            proxy_runtime.recordMirrorRouteUpstreamFailure(session.route.name, session.route.service, mirror.backend_service);
            self.closeMirrorSession(idx);
            expired_any = true;
        }
        return expired_any;
    }

    fn nextPendingDeadlineMs(self: *ConnectionRouter, now: i64) ?u32 {
        var next: ?u32 = null;
        for (self.streams.items) |session| {
            if (!session.response_started) {
                if (now >= session.request_deadline_at_ms) return 0;
                const remaining: u32 = @intCast(session.request_deadline_at_ms - now);
                next = if (next) |current| @min(current, remaining) else remaining;
            }
            if (session.mirror) |mirror| {
                if (!mirror.response_started) {
                    if (now >= mirror.request_deadline_at_ms) return 0;
                    const mirror_remaining: u32 = @intCast(mirror.request_deadline_at_ms - now);
                    next = if (next) |current| @min(current, mirror_remaining) else mirror_remaining;
                }
            }
        }
        return next;
    }

    fn connectionIdleRemainingMs(self: *ConnectionRouter, now: i64) u32 {
        const timeout_ms = self.currentConnectionIdleTimeoutMs();
        const elapsed = now - self.last_activity_ms;
        if (elapsed >= @as(i64, @intCast(timeout_ms))) return 0;
        return @intCast(@as(i64, @intCast(timeout_ms)) - elapsed);
    }

    fn currentConnectionIdleTimeoutMs(self: *const ConnectionRouter) u32 {
        var timeout_ms: u32 = 30000;
        for (self.streams.items) |session| {
            timeout_ms = @min(timeout_ms, session.route.http2_idle_timeout_ms);
        }
        return timeout_ms;
    }

    fn sendLocalStreamResponse(self: *ConnectionRouter, stream_id: u32, status: http.StatusCode, body: []const u8) !void {
        const response = if (self.sent_settings)
            try http2_response.formatSimpleStreamResponse(self.allocator, stream_id, @intFromEnum(status), "application/json", body)
        else
            try http2_response.formatSimpleResponse(self.allocator, stream_id, @intFromEnum(status), "application/json", body);
        defer self.allocator.free(response);
        self.sent_settings = true;
        try socket_helpers.writeAll(self.client_fd, response);
    }

    fn sendDownstreamSettingsFrame(self: *ConnectionRouter, payload: []const u8) !void {
        if (self.sent_settings) return;
        const frame = try http2.buildFrame(self.allocator, .{
            .length = @intCast(payload.len),
            .frame_type = .settings,
            .flags = 0,
            .stream_id = 0,
        }, payload);
        defer self.allocator.free(frame);
        self.sent_settings = true;
        try socket_helpers.writeAll(self.client_fd, frame);
    }

    fn discardFrame(self: *ConnectionRouter) !void {
        const frame = http2.parseFrameHeader(self.downstream_buf.items[0..http2.frame_header_len]).?;
        try self.consumeDownstreamBytes(http2.frame_header_len + frame.length);
    }

    fn discardUpstreamFrame(self: *ConnectionRouter, session_idx: usize) !void {
        const frame = http2.parseFrameHeader(self.streams.items[session_idx].upstream_buf.items[0..http2.frame_header_len]).?;
        try self.consumeUpstreamBytes(session_idx, http2.frame_header_len + frame.length);
    }

    fn consumeDownstreamBytes(self: *ConnectionRouter, consumed: usize) !void {
        try self.downstream_buf.replaceRange(self.allocator, 0, consumed, "");
    }

    fn consumeUpstreamBytes(self: *ConnectionRouter, session_idx: usize, consumed: usize) !void {
        try self.streams.items[session_idx].upstream_buf.replaceRange(self.allocator, 0, consumed, "");
    }

    fn removeSession(self: *ConnectionRouter, session_idx: usize) void {
        var session = self.streams.swapRemove(session_idx);
        session.deinit(self.allocator);
    }

    fn findStreamIndex(self: *const ConnectionRouter, stream_id: u32) ?usize {
        for (self.streams.items, 0..) |session, idx| {
            if (session.downstream_stream_id == stream_id) return idx;
        }
        return null;
    }

    fn matchRouteForParsedRequest(self: *ConnectionRouter, parsed: http2_request.ParseResult) ?router.Route {
        const host = proxy_helpers.normalizeHost(parsed.request.authority);
        var request_headers: std.ArrayList(router.RequestHeader) = .empty;
        defer request_headers.deinit(self.allocator);
        for (parsed.headers) |header| {
            request_headers.append(self.allocator, .{
                .name = header.name,
                .value = header.value,
            }) catch return null;
        }
        return router.matchRoute(self.routes, parsed.request.method, host, parsed.request.path, request_headers.items);
    }

    fn startMirrorSession(self: *ConnectionRouter, route: router.Route, parsed: http2_request.ParseResult) ?MirrorSession {
        const mirror_service = route.mirror_service orelse return null;
        proxy_runtime.recordMirrorRouteRequestStart(route.name, route.service, mirror_service);

        var upstream = proxy_runtime.resolveUpstream(self.allocator, mirror_service) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };
        var transferred = false;
        defer if (!transferred) upstream.deinit(self.allocator);

        const outbound_path = proxy_helpers.buildOutboundPath(self.allocator, parsed.request.path, route.match.path_prefix, route.rewrite_prefix) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };
        defer self.allocator.free(outbound_path);
        const normalized_host = proxy_helpers.normalizeHost(parsed.request.authority);
        const outbound_authority = if (route.preserve_host) normalized_host else mirror_service;
        const forwarded_proto = trustedForwardedProto(parsed.headers, self.client_ip);
        const rewritten = http2_request.rewriteRequestHeaderSequence(self.allocator, self.downstream_buf.items, 0, .{
            .outbound_authority = if (std.mem.eql(u8, outbound_authority, normalized_host)) null else outbound_authority,
            .outbound_path = if (std.mem.eql(u8, outbound_path, parsed.request.path)) null else outbound_path,
            .forwarded_proto = forwarded_proto,
            .stream_id = 1,
        }) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };
        defer rewritten.deinit(self.allocator);

        const request_deadline_at_ms = nowMs() + @as(i64, @intCast(route.request_timeout_ms));
        var connection = connectAndSendUpstream(self.allocator, self.peer_key, route, &upstream, rewritten.bytes, request_deadline_at_ms) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };
        defer if (!transferred) connection.deinit();
        const owned_backend = self.allocator.dupe(u8, mirror_service) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };
        transferred = true;
        return .{
            .backend_service = owned_backend,
            .upstream = upstream,
            .connection = connection,
            .request_deadline_at_ms = request_deadline_at_ms,
        };
    }

    fn startMirrorSessionForUpgrade(self: *ConnectionRouter, route: router.Route, upgraded: h2c_upgrade.ParsedUpgrade) ?MirrorSession {
        const mirror_service = route.mirror_service orelse return null;
        proxy_runtime.recordMirrorRouteRequestStart(route.name, route.service, mirror_service);

        var upstream = proxy_runtime.resolveUpstream(self.allocator, mirror_service) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };
        var transferred = false;
        defer if (!transferred) upstream.deinit(self.allocator);

        const outbound_path = proxy_helpers.buildOutboundPath(
            self.allocator,
            upgraded.path,
            route.match.path_prefix,
            route.rewrite_prefix,
        ) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };
        defer self.allocator.free(outbound_path);

        const outbound_authority = if (route.preserve_host) upgraded.authority else mirror_service;
        const request_bytes = h2c_upgrade.buildStream1HeadersFrame(
            self.allocator,
            outbound_authority,
            upgraded.method,
            outbound_path,
            upgraded.request_headers,
            "http",
        ) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };
        defer self.allocator.free(request_bytes);

        const request_deadline_at_ms = nowMs() + @as(i64, @intCast(route.request_timeout_ms));
        var connection = connectAndSendUpstream(self.allocator, self.peer_key, route, &upstream, request_bytes, request_deadline_at_ms) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };
        defer if (!transferred) connection.deinit();
        const owned_backend = self.allocator.dupe(u8, mirror_service) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };
        transferred = true;
        return .{
            .backend_service = owned_backend,
            .upstream = upstream,
            .connection = connection,
            .request_deadline_at_ms = request_deadline_at_ms,
        };
    }

    fn forwardMirrorFrame(self: *ConnectionRouter, mirror: *MirrorSession, frame_bytes: []const u8) !void {
        _ = self;
        writeSession(mirror, frame_bytes) catch {
            return error.WriteFailed;
        };
    }

    fn closeMirrorSession(self: *ConnectionRouter, session_idx: usize) void {
        if (self.streams.items[session_idx].mirror) |*mirror| {
            mirror.deinit(self.allocator);
            self.streams.items[session_idx].mirror = null;
        }
    }

    fn failMirrorSession(self: *ConnectionRouter, session_idx: usize) void {
        const session = &self.streams.items[session_idx];
        const mirror = session.mirror orelse return;
        proxy_runtime.recordMirrorRouteUpstreamFailure(session.route.name, session.route.service, mirror.backend_service);
        self.closeMirrorSession(session_idx);
    }

    fn handleMirrorSettings(self: *ConnectionRouter, session_idx: usize, frame: http2.FrameHeader) !void {
        const mirror = if (self.streams.items[session_idx].mirror) |*value| value else return;
        const payload = mirror.upstream_buf.items[http2.frame_header_len .. http2.frame_header_len + frame.length];
        if ((frame.flags & 0x1) == 0) {
            const ack = try http2.buildFrame(self.allocator, .{
                .length = 0,
                .frame_type = .settings,
                .flags = 0x1,
                .stream_id = 0,
            }, "");
            defer self.allocator.free(ack);
            try writeSession(mirror, ack);
        }
        _ = payload;
        try self.discardMirrorFrame(session_idx);
    }

    fn handleMirrorPing(self: *ConnectionRouter, session_idx: usize, frame: http2.FrameHeader) !void {
        const mirror = if (self.streams.items[session_idx].mirror) |*value| value else return;
        const payload = mirror.upstream_buf.items[http2.frame_header_len .. http2.frame_header_len + frame.length];
        if ((frame.flags & 0x1) == 0 and payload.len == 8) {
            const ack = try http2.buildFrame(self.allocator, .{
                .length = 8,
                .frame_type = .ping,
                .flags = 0x1,
                .stream_id = 0,
            }, payload);
            defer self.allocator.free(ack);
            try writeSession(mirror, ack);
        }
        try self.discardMirrorFrame(session_idx);
    }

    fn handleMirrorHeaders(self: *ConnectionRouter, session_idx: usize) !void {
        const session = &self.streams.items[session_idx];
        const mirror = if (session.mirror) |*value| value else return;
        if (!mirror.response_started) {
            const status = parseResponseStatus(mirror.upstream_buf.items) catch {
                proxy_runtime.recordMirrorRouteUpstreamFailure(session.route.name, session.route.service, mirror.backend_service);
                self.closeMirrorSession(session_idx);
                return;
            };
            mirror.response_started = true;
            proxy_runtime.recordMirrorRouteResponseCode(session.route.name, session.route.service, mirror.backend_service, status);
        }
        try self.discardMirrorStreamFrame(session_idx);
    }

    fn discardMirrorStreamFrame(self: *ConnectionRouter, session_idx: usize) !void {
        const mirror = if (self.streams.items[session_idx].mirror) |*value| value else return;
        const frame = http2.parseFrameHeader(mirror.upstream_buf.items[0..http2.frame_header_len]).?;
        try self.consumeMirrorBytes(session_idx, http2.frame_header_len + frame.length);
        if (frame.frame_type == .rst_stream or (frame.flags & 0x1) != 0) {
            self.closeMirrorSession(session_idx);
        }
    }

    fn discardMirrorFrame(self: *ConnectionRouter, session_idx: usize) !void {
        const mirror = if (self.streams.items[session_idx].mirror) |*value| value else return;
        const frame = http2.parseFrameHeader(mirror.upstream_buf.items[0..http2.frame_header_len]).?;
        try self.consumeMirrorBytes(session_idx, http2.frame_header_len + frame.length);
    }

    fn consumeMirrorBytes(self: *ConnectionRouter, session_idx: usize, consumed: usize) !void {
        const mirror = if (self.streams.items[session_idx].mirror) |*value| value else return;
        try mirror.upstream_buf.replaceRange(self.allocator, 0, consumed, "");
    }
};

const StreamSession = struct {
    downstream_stream_id: u32,
    route: router.Route,
    backend_service: []u8,
    upstream: upstream_mod.Upstream,
    connection: exchange.StreamingConnection,
    upstream_buf: std.ArrayList(u8) = .empty,
    mirror: ?MirrorSession = null,
    response_started: bool = false,
    response_status: ?u16 = null,
    downstream_end_stream: bool = false,
    request_deadline_at_ms: i64,
    observation_started_ns: u64 = 0,

    fn deinit(self: *StreamSession, alloc: std.mem.Allocator) void {
        self.connection.deinit();
        alloc.free(self.backend_service);
        self.upstream.deinit(alloc);
        self.upstream_buf.deinit(alloc);
        if (self.mirror) |*mirror| mirror.deinit(alloc);
    }
};

const MirrorSession = struct {
    backend_service: []u8,
    upstream: upstream_mod.Upstream,
    connection: exchange.StreamingConnection,
    upstream_buf: std.ArrayList(u8) = .empty,
    response_started: bool = false,
    request_deadline_at_ms: i64,

    fn deinit(self: *MirrorSession, alloc: std.mem.Allocator) void {
        self.connection.deinit();
        alloc.free(self.backend_service);
        self.upstream.deinit(alloc);
        self.upstream_buf.deinit(alloc);
    }
};

const SessionPollTarget = struct {
    stream_idx: usize,
    kind: Kind,
    buffered: bool = false,

    const Kind = enum {
        primary,
        mirror,
    };
};

fn trustedForwardedProto(headers: []const hpack.HeaderField, client_ip: ?[4]u8) ?[]const u8 {
    if (client_ip == null or !std.mem.eql(u8, &client_ip.?, &proxy_helpers.trusted_forwarded_proto_ip)) return null;
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, "x-forwarded-proto")) return header.value;
    }
    return null;
}

fn buildInitialUpstreamPreamble(alloc: std.mem.Allocator) ![]u8 {
    const settings = try http2.buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.appendSlice(alloc, http2.client_preface);
    try out.appendSlice(alloc, settings);
    return out.toOwnedSlice(alloc);
}

fn parseResponseStatus(buf: []const u8) !u16 {
    var pos: usize = 0;
    const first = http2.parseFrameHeader(buf[pos .. pos + http2.frame_header_len]) orelse return error.InvalidResponse;
    if (first.frame_type != .headers or first.stream_id == 0) return error.InvalidResponse;
    pos += http2.frame_header_len;
    if (pos + first.length > buf.len) return error.BufferTooShort;

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(std.heap.page_allocator);
    try header_block.appendSlice(std.heap.page_allocator, headerBlockFragment(buf[pos .. pos + first.length], first.flags) orelse return error.InvalidResponse);
    pos += first.length;

    while ((first.flags & 0x4) == 0) {
        if (pos + http2.frame_header_len > buf.len) return error.BufferTooShort;
        const continuation = http2.parseFrameHeader(buf[pos .. pos + http2.frame_header_len]) orelse return error.InvalidResponse;
        if (continuation.frame_type != .continuation or continuation.stream_id != first.stream_id) return error.InvalidResponse;
        pos += http2.frame_header_len;
        if (pos + continuation.length > buf.len) return error.BufferTooShort;
        try header_block.appendSlice(std.heap.page_allocator, buf[pos .. pos + continuation.length]);
        pos += continuation.length;
        if ((continuation.flags & 0x4) != 0) break;
    }

    var headers = try hpack.decodeHeaderBlock(std.heap.page_allocator, header_block.items);
    defer {
        for (headers.items) |header| header.deinit(std.heap.page_allocator);
        headers.deinit(std.heap.page_allocator);
    }
    for (headers.items) |header| {
        if (std.mem.eql(u8, header.name, ":status")) {
            return std.fmt.parseInt(u16, header.value, 10) catch error.InvalidResponse;
        }
    }
    return error.InvalidResponse;
}

fn rewriteFrameSequenceStreamId(
    alloc: std.mem.Allocator,
    buf: []const u8,
    start: usize,
    stream_id: u32,
) !http2_request.StreamRewriteResult {
    var pos = start;
    const first = http2.parseFrameHeader(buf[pos .. pos + http2.frame_header_len]).?;
    pos += http2.frame_header_len;
    if (pos + first.length > buf.len) return error.BufferTooShort;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try appendRewrittenFrame(&out, alloc, first, stream_id, buf[pos .. pos + first.length]);
    pos += first.length;

    if (first.frame_type == .headers) {
        while ((first.flags & 0x4) == 0) {
            if (pos + http2.frame_header_len > buf.len) return error.BufferTooShort;
            const continuation = http2.parseFrameHeader(buf[pos .. pos + http2.frame_header_len]).?;
            if (continuation.frame_type != .continuation or continuation.stream_id != first.stream_id) return error.InvalidFrameSequence;
            pos += http2.frame_header_len;
            if (pos + continuation.length > buf.len) return error.BufferTooShort;
            try appendRewrittenFrame(&out, alloc, continuation, stream_id, buf[pos .. pos + continuation.length]);
            pos += continuation.length;
            if ((continuation.flags & 0x4) != 0) break;
        }
    }

    return .{
        .bytes = try out.toOwnedSlice(alloc),
        .consumed = pos - start,
    };
}

fn appendRewrittenFrame(
    out: *std.ArrayList(u8),
    alloc: std.mem.Allocator,
    header: http2.FrameHeader,
    stream_id: u32,
    payload: []const u8,
) !void {
    var header_buf: [http2.frame_header_len]u8 = undefined;
    try http2.writeFrameHeader(&header_buf, .{
        .length = header.length,
        .frame_type = header.frame_type,
        .flags = header.flags,
        .stream_id = if (header.stream_id == 0) 0 else stream_id,
    });
    try out.appendSlice(alloc, &header_buf);
    try out.appendSlice(alloc, payload);
}

fn headerBlockFragment(payload: []const u8, flags: u8) ?[]const u8 {
    var pos: usize = 0;
    var padded_len: usize = 0;
    if ((flags & 0x8) != 0) {
        if (payload.len == 0) return null;
        padded_len = payload[0];
        pos += 1;
    }
    if ((flags & 0x20) != 0) pos += 5;
    if (pos > payload.len or padded_len > payload.len - pos) return null;
    return payload[pos .. payload.len - padded_len];
}

fn routeSelectionKey(method: []const u8, host: []const u8, path: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(method);
    hasher.update(host);
    hasher.update(path);
    return hasher.final();
}

fn writeSession(session: anytype, bytes: []const u8) !void {
    session.connection.operation_deadline = if (session.response_started) null else deadlineAt(session.request_deadline_at_ms);
    try session.connection.writeAll(bytes);
}

fn connectAndSendUpstream(alloc: std.mem.Allocator, peer_key: ?PeerKey, route: router.Route, upstream: *const upstream_mod.Upstream, request_bytes: []const u8, request_deadline_at_ms: i64) !exchange.StreamingConnection {
    var client = exchange.Client{ .allocator = alloc, .peer_key = peer_key };
    defer if (client.peer_key) |*key| std.crypto.secureZero(u8, key);
    var connection = try client.openStream(.{ .connect_timeout_ms = route.connect_timeout_ms, .request_timeout_ms = route.request_timeout_ms, .protocol = .http2, .deadline = deadlineAt(request_deadline_at_ms) }, upstream);
    errdefer connection.deinit();
    const preface_and_settings = try buildInitialUpstreamPreamble(alloc);
    defer alloc.free(preface_and_settings);
    try connection.writeAll(preface_and_settings);
    try connection.writeAll(request_bytes);
    return connection;
}

fn deadlineAt(milliseconds: i64) transport.Deadline {
    return .{ .expires_ns = @as(i96, milliseconds) * std.time.ns_per_ms };
}

fn nowMs() i64 {
    return std.Io.Clock.awake.now(std.Options.debug_io).toMilliseconds();
}

test "proxy transport policy refuses missing required peer credentials before dialing" {
    try @import("../../state/store.zig").initTestDb();
    defer @import("../../state/store.zig").deinitTestDb();
    const listener = try linux_platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
    defer linux_platform.posix.close(listener);
    var address = linux_platform.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try linux_platform.posix.bind(listener, &address.any, address.getOsSockLen());
    try linux_platform.posix.listen(listener, 1);
    var length = address.getOsSockLen();
    try linux_platform.posix.getsockname(listener, &address.any, &length);
    const upstream = upstream_mod.Upstream{ .service = "api", .endpoint_id = "api-1", .address = "127.0.0.1", .port = std.mem.bigToNative(u16, address.in.port), .peer_mode = .require };
    const route = router.Route{ .name = "api", .service = "api", .vip_address = "10.43.0.1", .match = .{ .host = "api", .path_prefix = "/" } };
    try std.testing.expectError(error.ClusterCaMissing, connectAndSendUpstream(std.testing.allocator, null, route, &upstream, "request must not be sent", nowMs() + 1000));
    try std.testing.expectError(error.WouldBlock, linux_platform.posix.accept(listener, null, null, posix.SOCK.CLOEXEC));
}

fn peerTestResponse(alloc: std.mem.Allocator) ![]u8 {
    const headers = try hpack.encodeHeaderBlockLiteral(alloc, &.{.{ .name = ":status", .value = "200" }});
    defer alloc.free(headers);
    const trailers = try hpack.encodeHeaderBlockLiteral(alloc, &.{.{ .name = "grpc-status", .value = "0" }});
    defer alloc.free(trailers);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(alloc);
    for ([_]struct { kind: http2.FrameType, flags: u8, payload: []const u8 }{
        .{ .kind = .headers, .flags = 4, .payload = headers },
        .{ .kind = .data, .flags = 0, .payload = "streamed body" },
        .{ .kind = .headers, .flags = 5, .payload = trailers },
    }) |part| {
        const frame = try http2.buildFrame(alloc, .{ .length = @intCast(part.payload.len), .frame_type = part.kind, .flags = part.flags, .stream_id = 1 }, part.payload);
        defer alloc.free(frame);
        try bytes.appendSlice(alloc, frame);
    }
    return bytes.toOwnedSlice(alloc);
}

fn ownedTestUpstream(alloc: std.mem.Allocator, upstream: upstream_mod.Upstream) !upstream_mod.Upstream {
    const service = try alloc.dupe(u8, upstream.service);
    errdefer alloc.free(service);
    const endpoint = try alloc.dupe(u8, upstream.endpoint_id);
    errdefer alloc.free(endpoint);
    const address = try alloc.dupe(u8, upstream.address);
    return .{ .service = service, .endpoint_id = endpoint, .address = address, .port = upstream.port, .peer_mode = upstream.peer_mode };
}

test "http2 peer tls verifies upstream identity and streams data and trailers" {
    const fixture = @import("http2_peer_fixture.zig");
    const store = @import("../../state/store.zig");
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();
    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    const ca = try fixture.x509.generateCa(std.testing.io, alloc, "h2-ca", now - 60, now + 86400);
    defer alloc.free(ca.cert_pem);
    const ca_sql = try store.buildClusterCaInsertSql(alloc, ca.cert_pem, "unused", "", "", now, now + 86400);
    defer alloc.free(ca_sql);
    try fixture.exec(ca_sql);
    const proxy = try fixture.x509.issueLeaf(std.testing.io, alloc, ca.key_pair, "h2-ca", "proxy", @import("../../tls/peer_identity.zig").proxy_identity, now - 60, now + 86400);
    defer alloc.free(proxy.cert_pem);
    try fixture.publish(proxy.cert_pem, &proxy.key_pair.secret_key.toBytes(), now);

    const response = try peerTestResponse(alloc);
    defer alloc.free(response);
    const request = try h2c_upgrade.buildStream1HeadersFrame(alloc, "api", "GET", "/stream", &.{}, "http");
    defer alloc.free(request);
    const preamble = try buildInitialUpstreamPreamble(alloc);
    defer alloc.free(preamble);
    const expected_request = try std.mem.concat(alloc, u8, &.{ preamble, request });
    defer alloc.free(expected_request);
    const Case = enum { primary, mirror, wrong_identity };
    for ([_]Case{ .primary, .mirror, .wrong_identity }) |case| {
        const matching_identity = case != .wrong_identity;
        const server_cert = try fixture.x509.issueLeaf(std.testing.io, alloc, ca.key_pair, "h2-ca", "api", if (matching_identity) "spiffe://yoq-cluster/service/api" else "spiffe://yoq-cluster/service/other", now - 60, now + 86400);
        defer alloc.free(server_cert.cert_pem);
        const server_key = try fixture.csr.derKeyToPem(alloc, &server_cert.key_pair.secret_key.toBytes());
        defer alloc.free(server_key);
        const listener = try fixture.listen();
        defer linux_platform.posix.close(listener.fd);
        var server = fixture.Server{ .fd = listener.fd, .ca = ca.cert_pem, .cert = server_cert.cert_pem, .private_key = server_key, .now = now, .request = expected_request, .response = response };
        const thread = try std.Thread.spawn(.{}, fixture.Server.run, .{&server});
        var joined = false;
        defer if (!joined) thread.join();
        const upstream = upstream_mod.Upstream{ .service = "api", .endpoint_id = "api-h2", .address = "127.0.0.1", .port = listener.port, .peer_mode = .require };
        const route = router.Route{ .name = "api", .service = "api", .vip_address = "10.43.0.1", .match = .{ .host = "api", .path_prefix = "/" }, .request_timeout_ms = 2000 };
        const opened = connectAndSendUpstream(alloc, fixture.key, route, &upstream, request, nowMs() + 2000);
        if (!matching_identity) {
            try std.testing.expectError(error.HandshakeFailed, opened);
            thread.join();
            joined = true;
            try std.testing.expect(!server.accepted and !server.saw_request);
            continue;
        }
        var connection = try opened;
        var transferred = false;
        defer if (!transferred) connection.deinit();
        var downstream: [2]i32 = undefined;
        if (std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &downstream) != 0) return error.SocketFailed;
        defer linux_platform.posix.close(downstream[0]);
        defer linux_platform.posix.close(downstream[1]);
        var routing = ConnectionRouter{ .allocator = alloc, .routes = &.{}, .client_fd = downstream[0], .client_ip = null, .sent_settings = true };
        defer routing.deinit();
        if (case == .mirror) {
            try routing.streams.append(alloc, .{
                .downstream_stream_id = 3,
                .route = route,
                .backend_service = try alloc.dupe(u8, "api"),
                .upstream = try ownedTestUpstream(alloc, upstream),
                .connection = .{ .connection = .{ .bare = try linux_platform.posix.dup(downstream[0]) }, .timeout_ms = 2000 },
                .request_deadline_at_ms = nowMs() + 2000,
                .response_started = true,
                .mirror = .{ .backend_service = try alloc.dupe(u8, "api"), .upstream = try ownedTestUpstream(alloc, upstream), .connection = connection, .request_deadline_at_ms = nowMs() + 1000 },
            });
            transferred = true;
            // a primary response must not hide its mirror's earlier deadline.
            try std.testing.expect(routing.nextPendingDeadlineMs(nowMs()).? <= 1000);
            while (routing.streams.items[0].mirror != null) {
                const active = &routing.streams.items[0].mirror.?;
                if (!active.connection.buffered()) try (transport.Stream{ .fd = active.connection.fd(), .deadline = transport.Deadline.afterMilliseconds(2000) }).wait(posix.POLL.IN);
                try routing.readMirrorUpstream(0);
            }
            try std.testing.expectEqual(@as(usize, 1), routing.streams.items.len);
            var unexpected: [1]u8 = undefined;
            try std.testing.expectError(error.WouldBlock, linux_platform.posix.recv(downstream[1], &unexpected, posix.MSG.DONTWAIT));
            thread.join();
            joined = true;
            try std.testing.expect(server.accepted and server.saw_request);
            try std.testing.expect(server.failure == null);
            continue;
        }
        try routing.streams.append(alloc, .{ .downstream_stream_id = 3, .route = route, .backend_service = try alloc.dupe(u8, "api"), .upstream = try ownedTestUpstream(alloc, upstream), .connection = connection, .request_deadline_at_ms = nowMs() + 2000 });
        transferred = true;
        while (routing.streams.items.len > 0) {
            const active = &routing.streams.items[0];
            if (!active.connection.buffered()) try (transport.Stream{ .fd = active.connection.fd(), .deadline = transport.Deadline.afterMilliseconds(2000) }).wait(posix.POLL.IN);
            try routing.readUpstream(0);
        }
        const output = try alloc.alloc(u8, response.len);
        defer alloc.free(output);
        var count: usize = 0;
        const socket = transport.Stream{ .fd = downstream[1], .deadline = transport.Deadline.afterMilliseconds(2000) };
        while (count < output.len) {
            const got = try socket.read(output[count..]);
            if (got == 0) return error.UnexpectedEof;
            count += got;
        }
        var offset: usize = 0;
        var frames: usize = 0;
        while (offset < output.len) {
            const header = http2.parseFrameHeader(output[offset..]).?;
            try std.testing.expectEqual(@as(u32, 3), header.stream_id);
            const expected = http2.parseFrameHeader(response[offset..]).?;
            try std.testing.expectEqual(expected.frame_type, header.frame_type);
            try std.testing.expectEqual(expected.flags, header.flags);
            try std.testing.expectEqualSlices(u8, response[offset + 9 ..][0..header.length], output[offset + 9 ..][0..header.length]);
            offset += 9 + header.length;
            frames += 1;
        }
        try std.testing.expectEqual(@as(usize, 3), frames);
        thread.join();
        joined = true;
        try std.testing.expect(server.accepted and server.saw_request);
        try std.testing.expect(server.failure == null);
    }
}

test "http2 partial tls record does not block another stream or its timeout" {
    const alloc = std.testing.allocator;
    const tls = @import("../../tls/client_session.zig");
    const framing = @import("../../tls/record_transport.zig");
    const handshake = @import("../../tls/handshake.zig");
    const keys = handshake.deriveTrafficKeys([_]u8{13} ** handshake.hash_len);
    var downstream: [2]i32 = undefined;
    var partial: [2]i32 = undefined;
    var ready: [2]i32 = undefined;
    if (std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &downstream) != 0) return error.SocketFailed;
    defer linux_platform.posix.close(downstream[0]);
    defer linux_platform.posix.close(downstream[1]);
    if (std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &partial) != 0) return error.SocketFailed;
    defer linux_platform.posix.close(partial[1]);
    if (std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &ready) != 0) return error.SocketFailed;
    defer linux_platform.posix.close(ready[1]);
    var routing = ConnectionRouter{ .allocator = alloc, .routes = &.{}, .client_fd = downstream[0], .client_ip = null, .sent_settings = true };
    defer routing.deinit();
    const deadline = nowMs() + 1000;
    const route = router.Route{ .name = "api", .service = "api", .vip_address = "10.43.0.1", .match = .{ .host = "api", .path_prefix = "/" } };
    const upstream = upstream_mod.Upstream{ .service = "api", .endpoint_id = "api-h2", .address = "127.0.0.1", .port = 1 };
    for ([_]i32{ partial[0], ready[0] }, 0..) |fd, index| {
        try routing.streams.append(alloc, .{
            .downstream_stream_id = @intCast(index * 2 + 1),
            .route = route,
            .backend_service = try alloc.dupe(u8, "api"),
            .upstream = try ownedTestUpstream(alloc, upstream),
            .connection = .{ .connection = .{ .session = tls.ClientSession{ .fd = fd, .alloc = alloc, .client_app = keys, .server_app = keys } }, .timeout_ms = 1000 },
            .request_deadline_at_ms = deadline,
        });
    }
    try (transport.Stream{ .fd = partial[1] }).writeAll(&.{ 23, 3 });
    const response = try peerTestResponse(alloc);
    defer alloc.free(response);
    var sequence: u64 = 0;
    try framing.write(.{ .fd = ready[1] }, keys, &sequence, .application_data, response);
    try routing.readUpstream(0);
    // the incomplete peer stays live; a blocking TLS read would instead wait
    // for its deadline and fail it before the ready peer gets a turn.
    try std.testing.expectEqual(@as(usize, 2), routing.streams.items.len);
    try std.testing.expectEqual(@as(usize, 2), routing.streams.items[0].connection.connection.session.rx_wire.items.len);
    try routing.readUpstream(1);
    try std.testing.expectEqual(@as(usize, 1), routing.streams.items.len);
    var header: [9]u8 = undefined;
    var offset: usize = 0;
    const socket = transport.Stream{ .fd = downstream[1], .deadline = transport.Deadline.afterMilliseconds(1000) };
    while (offset < header.len) offset += try socket.read(header[offset..]);
    try std.testing.expectEqual(@as(u32, 3), http2.parseFrameHeader(&header).?.stream_id);
    try std.testing.expect(try routing.expireTimedOutStreams(deadline));
    try std.testing.expectEqual(@as(usize, 0), routing.streams.items.len);
}
