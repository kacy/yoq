const std = @import("std");
const posix = std.posix;
const http = @import("../../api/http.zig");
const http2 = @import("http2.zig");
const proxy_helpers = @import("proxy_helpers.zig");
const socket_helpers = @import("socket_helpers.zig");
const http2_request = @import("http2_request.zig");
const http2_response = @import("http2_response.zig");
const proxy_policy = @import("policy.zig");
const proxy_runtime = @import("runtime.zig");
const router = @import("router.zig");
const upstream_mod = @import("upstream.zig");
const ip = @import("../ip.zig");
const hpack = @import("hpack.zig");

pub fn proxyConnection(
    alloc: std.mem.Allocator,
    routes: []const router.Route,
    client_fd: posix.socket_t,
    initial_request: []const u8,
    client_ip: ?[4]u8,
) !void {
    var connection = ConnectionRouter{
        .allocator = alloc,
        .routes = routes,
        .client_fd = client_fd,
        .client_ip = client_ip,
    };
    defer connection.deinit();

    try connection.downstream_buf.appendSlice(alloc, initial_request);
    try connection.run();
}

const ConnectionRouter = struct {
    allocator: std.mem.Allocator,
    routes: []const router.Route,
    client_fd: posix.socket_t,
    client_ip: ?[4]u8,
    downstream_buf: std.ArrayList(u8) = .empty,
    streams: std.ArrayList(StreamSession) = .empty,
    saw_client_preface: bool = false,
    sent_settings: bool = false,
    last_activity_ms: i64 = 0,

    fn deinit(self: *ConnectionRouter) void {
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
            for (self.streams.items, 0..) |session, idx| {
                try poll_fds.append(self.allocator, .{
                    .fd = session.upstream_fd,
                    .events = posix.POLL.IN,
                    .revents = 0,
                });
                try session_targets.append(self.allocator, .{ .stream_idx = idx, .kind = .primary });
                if (session.mirror) |mirror| {
                    try poll_fds.append(self.allocator, .{
                        .fd = mirror.upstream_fd,
                        .events = posix.POLL.IN,
                        .revents = 0,
                    });
                    try session_targets.append(self.allocator, .{ .stream_idx = idx, .kind = .mirror });
                }
            }

            const ready = posix.poll(poll_fds.items, socket_helpers.clampPollTimeout(timeout_ms)) catch return error.ReceiveFailed;
            if (ready == 0) {
                if (try self.expireTimedOutStreams(nowMs())) continue;
                break;
            }

            if (poll_fds.items[0].revents & posix.POLL.IN != 0) {
                var buf: [16 * 1024]u8 = undefined;
                const bytes_read = posix.read(self.client_fd, &buf) catch return error.ReceiveFailed;
                if (bytes_read == 0) break;
                try self.downstream_buf.appendSlice(self.allocator, buf[0..bytes_read]);
                self.last_activity_ms = nowMs();
            } else if (poll_fds.items[0].revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) {
                break;
            }

            var ready_sessions: std.ArrayList(usize) = .empty;
            defer ready_sessions.deinit(self.allocator);
            for (session_targets.items, 0..) |_, poll_idx| {
                const revents = poll_fds.items[poll_idx + 1].revents;
                if (revents & posix.POLL.IN != 0) {
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
            try socket_helpers.writeAll(self.streams.items[stream_idx].upstream_fd, rewritten.bytes);
            try self.consumeDownstreamBytes(rewritten.consumed);
            self.last_activity_ms = nowMs();
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
            errdefer upstream.deinit(self.allocator);

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

            const upstream_fd = connectAndSendUpstream(self.allocator, route, &upstream, rewritten.bytes) catch |connect_err| {
                proxy_runtime.recordEndpointFailure(upstream.endpoint_id, cb_policy);
                const failure_kind: proxy_runtime.UpstreamFailureKind = if (connect_err == error.ConnectFailed or connect_err == error.ConnectTimedOut) .connect else .send;
                proxy_runtime.recordUpstreamFailure(failure_kind);
                proxy_runtime.recordRouteUpstreamFailure(route.name, route.service, backend_service);
                upstream.deinit(self.allocator);
                if (proxy_policy.shouldRetry(request_policy, parsed.request.method, attempt, null, true)) {
                    proxy_runtime.recordRetry();
                    proxy_runtime.recordRouteRetry(route.name, route.service, backend_service);
                    continue;
                }
                const route_failure: proxy_runtime.RouteFailureKind = if (failure_kind == .connect) .connect else .send;
                proxy_runtime.recordRouteFailure(route.name, route_failure);
                proxy_runtime.recordResponse(.bad_gateway);
                const body = if (failure_kind == .connect) "{\"error\":\"upstream connect failed\"}" else "{\"error\":\"upstream send failed\"}";
                try self.sendLocalStreamResponse(parsed.request.stream_id, .bad_gateway, body);
                try self.consumeDownstreamBytes(parsed.consumed);
                return;
            };

            try self.streams.append(self.allocator, .{
                .downstream_stream_id = parsed.request.stream_id,
                .route = route,
                .backend_service = try self.allocator.dupe(u8, backend_service),
                .upstream = upstream,
                .upstream_fd = upstream_fd,
                .request_deadline_at_ms = nowMs() + @as(i64, @intCast(route.request_timeout_ms)),
                .mirror = self.startMirrorSession(route, parsed),
            });
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
        try socket_helpers.writeAll(self.streams.items[stream_idx].upstream_fd, rewritten.bytes);
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
        const bytes_read = posix.read(session.upstream_fd, &buf) catch |err| {
            try self.failSession(session_idx, .receive, "{\"error\":\"upstream receive failed\"}");
            return err;
        };
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
        const mirror = &(session.mirror orelse return);
        var buf: [16 * 1024]u8 = undefined;
        const bytes_read = posix.read(mirror.upstream_fd, &buf) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(session.route.name, session.route.service, mirror.backend_service);
            self.closeMirrorSession(session_idx);
            return;
        };
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
            try socket_helpers.writeAll(self.streams.items[session_idx].upstream_fd, ack);
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
            try socket_helpers.writeAll(self.streams.items[session_idx].upstream_fd, ack);
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
            const mirror = &(session.mirror orelse continue);
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
            if (session.response_started) continue;
            if (now >= session.request_deadline_at_ms) return 0;
            const remaining: u32 = @intCast(session.request_deadline_at_ms - now);
            next = if (next) |current| @min(current, remaining) else remaining;
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
        errdefer upstream.deinit(self.allocator);

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

        const upstream_fd = socket_helpers.connectToUpstream(route.connect_timeout_ms, route.request_timeout_ms, &upstream) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };
        errdefer posix.close(upstream_fd);

        const preface_and_settings = buildInitialUpstreamPreamble(self.allocator) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };
        defer self.allocator.free(preface_and_settings);
        sendUpstreamPreamble(upstream_fd, preface_and_settings, rewritten.bytes) catch {
            proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
            return null;
        };

        return .{
            .backend_service = self.allocator.dupe(u8, mirror_service) catch {
                proxy_runtime.recordMirrorRouteUpstreamFailure(route.name, route.service, mirror_service);
                return null;
            },
            .upstream = upstream,
            .upstream_fd = upstream_fd,
            .request_deadline_at_ms = nowMs() + @as(i64, @intCast(route.request_timeout_ms)),
        };
    }

    fn forwardMirrorFrame(self: *ConnectionRouter, mirror: *MirrorSession, frame_bytes: []const u8) !void {
        _ = self;
        socket_helpers.writeAll(mirror.upstream_fd, frame_bytes) catch {
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
        const mirror = &(self.streams.items[session_idx].mirror orelse return);
        const payload = mirror.upstream_buf.items[http2.frame_header_len .. http2.frame_header_len + frame.length];
        if ((frame.flags & 0x1) == 0) {
            const ack = try http2.buildFrame(self.allocator, .{
                .length = 0,
                .frame_type = .settings,
                .flags = 0x1,
                .stream_id = 0,
            }, "");
            defer self.allocator.free(ack);
            try socket_helpers.writeAll(mirror.upstream_fd, ack);
        }
        _ = payload;
        try self.discardMirrorFrame(session_idx);
    }

    fn handleMirrorPing(self: *ConnectionRouter, session_idx: usize, frame: http2.FrameHeader) !void {
        const mirror = &(self.streams.items[session_idx].mirror orelse return);
        const payload = mirror.upstream_buf.items[http2.frame_header_len .. http2.frame_header_len + frame.length];
        if ((frame.flags & 0x1) == 0 and payload.len == 8) {
            const ack = try http2.buildFrame(self.allocator, .{
                .length = 8,
                .frame_type = .ping,
                .flags = 0x1,
                .stream_id = 0,
            }, payload);
            defer self.allocator.free(ack);
            try socket_helpers.writeAll(mirror.upstream_fd, ack);
        }
        try self.discardMirrorFrame(session_idx);
    }

    fn handleMirrorHeaders(self: *ConnectionRouter, session_idx: usize) !void {
        const session = &self.streams.items[session_idx];
        const mirror = &(session.mirror orelse return);
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
        const mirror = &(self.streams.items[session_idx].mirror orelse return);
        const frame = http2.parseFrameHeader(mirror.upstream_buf.items[0..http2.frame_header_len]).?;
        try self.consumeMirrorBytes(session_idx, http2.frame_header_len + frame.length);
        if (frame.frame_type == .rst_stream or (frame.flags & 0x1) != 0) {
            self.closeMirrorSession(session_idx);
        }
    }

    fn discardMirrorFrame(self: *ConnectionRouter, session_idx: usize) !void {
        const mirror = &(self.streams.items[session_idx].mirror orelse return);
        const frame = http2.parseFrameHeader(mirror.upstream_buf.items[0..http2.frame_header_len]).?;
        try self.consumeMirrorBytes(session_idx, http2.frame_header_len + frame.length);
    }

    fn consumeMirrorBytes(self: *ConnectionRouter, session_idx: usize, consumed: usize) !void {
        const mirror = &(self.streams.items[session_idx].mirror orelse return);
        try mirror.upstream_buf.replaceRange(self.allocator, 0, consumed, "");
    }
};

const StreamSession = struct {
    downstream_stream_id: u32,
    route: router.Route,
    backend_service: []u8,
    upstream: upstream_mod.Upstream,
    upstream_fd: posix.socket_t,
    upstream_buf: std.ArrayList(u8) = .empty,
    mirror: ?MirrorSession = null,
    response_started: bool = false,
    response_status: ?u16 = null,
    downstream_end_stream: bool = false,
    request_deadline_at_ms: i64,

    fn deinit(self: *StreamSession, alloc: std.mem.Allocator) void {
        posix.close(self.upstream_fd);
        alloc.free(self.backend_service);
        self.upstream.deinit(alloc);
        self.upstream_buf.deinit(alloc);
        if (self.mirror) |*mirror| mirror.deinit(alloc);
    }
};

const MirrorSession = struct {
    backend_service: []u8,
    upstream: upstream_mod.Upstream,
    upstream_fd: posix.socket_t,
    upstream_buf: std.ArrayList(u8) = .empty,
    response_started: bool = false,
    request_deadline_at_ms: i64,

    fn deinit(self: *MirrorSession, alloc: std.mem.Allocator) void {
        posix.close(self.upstream_fd);
        alloc.free(self.backend_service);
        self.upstream.deinit(alloc);
        self.upstream_buf.deinit(alloc);
    }
};

const SessionPollTarget = struct {
    stream_idx: usize,
    kind: Kind,

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

fn connectAndSendUpstream(alloc: std.mem.Allocator, route: router.Route, upstream: *const upstream_mod.Upstream, request_bytes: []const u8) !posix.socket_t {
    const upstream_fd = try socket_helpers.connectToUpstream(route.connect_timeout_ms, route.request_timeout_ms, upstream);
    errdefer posix.close(upstream_fd);
    const preface_and_settings = try buildInitialUpstreamPreamble(alloc);
    defer alloc.free(preface_and_settings);
    try sendUpstreamPreamble(upstream_fd, preface_and_settings, request_bytes);
    return upstream_fd;
}

fn sendUpstreamPreamble(upstream_fd: posix.socket_t, preface_and_settings: []const u8, request_bytes: []const u8) !void {
    try socket_helpers.writeAll(upstream_fd, preface_and_settings);
    try socket_helpers.writeAll(upstream_fd, request_bytes);
}

fn nowMs() i64 {
    return std.time.milliTimestamp();
}
