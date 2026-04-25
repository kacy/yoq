const std = @import("std");
const http = @import("../../api/http.zig");
const log = @import("../../lib/log.zig");
const proxy_policy = @import("policy.zig");
const router = @import("router.zig");
const steering_runtime = @import("steering_runtime.zig");
const upstream_mod = @import("upstream.zig");
const service_registry_runtime = @import("../service_registry_runtime.zig");
const service_rollout = @import("../service_rollout.zig");

pub const max_routes_in_status = 16;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

fn nowRealMilliseconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toMilliseconds();
}

pub const RouteDegradedReason = enum {
    none,
    service_state,
    steering_not_ready,
    no_eligible_upstream,
    connect_failure,
    send_failure,
    receive_failure,
    invalid_response,

    pub fn label(self: RouteDegradedReason) []const u8 {
        return switch (self) {
            .none => "none",
            .service_state => "service_state",
            .steering_not_ready => "steering_not_ready",
            .no_eligible_upstream => "no_eligible_upstream",
            .connect_failure => "connect_failure",
            .send_failure => "send_failure",
            .receive_failure => "receive_failure",
            .invalid_response => "invalid_response",
        };
    }
};

pub const RouteFailureKind = enum {
    no_eligible_upstream,
    connect,
    send,
    receive,
    invalid_response,

    pub fn label(self: RouteFailureKind) []const u8 {
        return switch (self) {
            .no_eligible_upstream => "no_eligible_upstream",
            .connect => "connect",
            .send => "send",
            .receive => "receive",
            .invalid_response => "invalid_response",
        };
    }
};

pub const VipTrafficMode = enum {
    not_applicable,
    l7_proxy,
    l4_fallback,

    pub fn label(self: VipTrafficMode) []const u8 {
        return switch (self) {
            .not_applicable => "not_applicable",
            .l7_proxy => "l7_proxy",
            .l4_fallback => "l4_fallback",
        };
    }
};

pub const RouteSnapshot = struct {
    name: []const u8,
    service: []const u8,
    vip_address: []const u8,
    host: []const u8,
    path_prefix: []const u8,
    rewrite_prefix: ?[]const u8 = null,
    method_matches: []const router.MethodMatch = &.{},
    header_matches: []const router.HeaderMatch = &.{},
    backend_services: []const router.BackendTarget = &.{},
    mirror_service: ?[]const u8 = null,
    eligible_endpoints: u32,
    healthy_endpoints: u32,
    degraded: bool,
    degraded_reason: RouteDegradedReason,
    last_failure_kind: ?RouteFailureKind,
    last_failure_at: ?i64,
    retries: u8,
    connect_timeout_ms: u32,
    request_timeout_ms: u32,
    http2_idle_timeout_ms: u32,
    preserve_host: bool,
    retry_on_5xx: bool = true,
    circuit_breaker_threshold: u8 = 3,
    circuit_breaker_timeout_ms: u32 = 30_000,
    vip_traffic_mode: VipTrafficMode = .not_applicable,
    steering_desired_ports: u32,
    steering_applied_ports: u32,
    steering_ready: bool,
    steering_blocked: bool,
    steering_drifted: bool,
    steering_blocked_reason: steering_runtime.BlockedReason,

    pub fn deinit(self: RouteSnapshot, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.service);
        alloc.free(self.vip_address);
        alloc.free(self.host);
        alloc.free(self.path_prefix);
        if (self.rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
        for (self.method_matches) |method_match| method_match.deinit(alloc);
        if (self.method_matches.len > 0) alloc.free(self.method_matches);
        for (self.header_matches) |header_match| header_match.deinit(alloc);
        if (self.header_matches.len > 0) alloc.free(self.header_matches);
        for (self.backend_services) |backend| backend.deinit(alloc);
        if (self.backend_services.len > 0) alloc.free(self.backend_services);
        if (self.mirror_service) |mirror_service| alloc.free(mirror_service);
    }
};

pub const Snapshot = struct {
    enabled: bool,
    running: bool,
    configured_services: u32,
    routes: u32,
    requests_total: u64,
    responses_2xx_total: u64,
    responses_4xx_total: u64,
    responses_5xx_total: u64,
    retries_total: u64,
    loop_rejections_total: u64,
    upstream_connect_failures_total: u64,
    upstream_send_failures_total: u64,
    upstream_receive_failures_total: u64,
    upstream_other_failures_total: u64,
    circuit_trips_total: u64,
    circuit_open_endpoints: u32,
    circuit_half_open_endpoints: u32,
    last_sync_at: ?i64,
    last_error: ?[]const u8,

    pub fn deinit(self: Snapshot, alloc: std.mem.Allocator) void {
        if (self.last_error) |message| alloc.free(message);
    }
};

pub const RouteTrafficSnapshot = struct {
    traffic_role: RouteTrafficRole,
    route_name: []const u8,
    service_name: []const u8,
    backend_service: []const u8,
    requests_total: u64,
    responses_2xx_total: u64,
    responses_4xx_total: u64,
    responses_5xx_total: u64,
    retries_total: u64,
    upstream_failures_total: u64,

    pub fn deinit(self: RouteTrafficSnapshot, alloc: std.mem.Allocator) void {
        alloc.free(self.route_name);
        alloc.free(self.service_name);
        alloc.free(self.backend_service);
    }
};

pub const RouteTrafficRole = enum {
    primary,
    mirror,

    pub fn label(self: RouteTrafficRole) []const u8 {
        return switch (self) {
            .primary => "primary",
            .mirror => "mirror",
        };
    }
};

var mutex: std.Io.Mutex = .init;
var materialized_routes: std.ArrayList(router.Route) = .empty;
var running: bool = false;
var configured_services: u32 = 0;
var routes: u32 = 0;
var requests_total: u64 = 0;
var responses_2xx_total: u64 = 0;
var responses_4xx_total: u64 = 0;
var responses_5xx_total: u64 = 0;
var retries_total: u64 = 0;
var loop_rejections_total: u64 = 0;
var upstream_connect_failures_total: u64 = 0;
var upstream_send_failures_total: u64 = 0;
var upstream_receive_failures_total: u64 = 0;
var upstream_other_failures_total: u64 = 0;
var circuit_trips_total: u64 = 0;
var last_sync_at: ?i64 = null;
var last_error: ?[]u8 = null;
var endpoint_circuits: std.StringHashMapUnmanaged(EndpointCircuit) = .{};
var route_statuses: std.StringHashMapUnmanaged(RouteStatusState) = .{};
var route_traffic: std.StringHashMapUnmanaged(RouteTrafficState) = .{};

pub const UpstreamFailureKind = enum {
    connect,
    send,
    receive,
    other,
};

const default_circuit_policy: proxy_policy.CircuitBreakerPolicy = .{};

const EndpointCircuit = struct {
    state: proxy_policy.CircuitState = .closed,
    consecutive_failures: u8 = 0,
    opened_at_ms: ?i64 = null,
    half_open_in_flight: bool = false,
};

const RouteStatusState = struct {
    degraded_reason: RouteDegradedReason = .none,
    last_failure_kind: ?RouteFailureKind = null,
    last_failure_at: ?i64 = null,
};

const RouteTrafficState = struct {
    traffic_role: RouteTrafficRole,
    route_name: []const u8,
    service_name: []const u8,
    backend_service: []const u8,
    requests_total: u64 = 0,
    responses_2xx_total: u64 = 0,
    responses_4xx_total: u64 = 0,
    responses_5xx_total: u64 = 0,
    retries_total: u64 = 0,
    upstream_failures_total: u64 = 0,
};

pub fn resetForTest() void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    running = false;
    configured_services = 0;
    routes = 0;
    requests_total = 0;
    responses_2xx_total = 0;
    responses_4xx_total = 0;
    responses_5xx_total = 0;
    retries_total = 0;
    loop_rejections_total = 0;
    upstream_connect_failures_total = 0;
    upstream_send_failures_total = 0;
    upstream_receive_failures_total = 0;
    upstream_other_failures_total = 0;
    circuit_trips_total = 0;
    last_sync_at = null;
    deinitRoutesLocked();
    deinitCircuitsLocked();
    deinitRouteStatusesLocked();
    deinitRouteTrafficLocked();
    clearLastErrorLocked();
}

pub fn bootstrapIfEnabled() void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    syncLocked() catch |err| {
        setLastErrorLocked(err);
        log.warn("l7 proxy runtime: bootstrap failed: {}", .{err});
    };
}

pub fn snapshot(alloc: std.mem.Allocator) !Snapshot {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    var circuit_open_endpoints: u32 = 0;
    var circuit_half_open_endpoints: u32 = 0;
    var it = endpoint_circuits.iterator();
    while (it.next()) |entry| {
        switch (entry.value_ptr.state) {
            .open => circuit_open_endpoints += 1,
            .half_open => circuit_half_open_endpoints += 1,
            .closed => {},
        }
    }

    return .{
        .enabled = configured_services > 0,
        .running = running,
        .configured_services = configured_services,
        .routes = routes,
        .requests_total = requests_total,
        .responses_2xx_total = responses_2xx_total,
        .responses_4xx_total = responses_4xx_total,
        .responses_5xx_total = responses_5xx_total,
        .retries_total = retries_total,
        .loop_rejections_total = loop_rejections_total,
        .upstream_connect_failures_total = upstream_connect_failures_total,
        .upstream_send_failures_total = upstream_send_failures_total,
        .upstream_receive_failures_total = upstream_receive_failures_total,
        .upstream_other_failures_total = upstream_other_failures_total,
        .circuit_trips_total = circuit_trips_total,
        .circuit_open_endpoints = circuit_open_endpoints,
        .circuit_half_open_endpoints = circuit_half_open_endpoints,
        .last_sync_at = last_sync_at,
        .last_error = if (last_error) |message| try alloc.dupe(u8, message) else null,
    };
}

pub fn configuredServiceCount() u32 {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    return configured_services;
}

pub fn recordRequestStart() void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    requests_total += 1;
}

pub fn recordRouteRequestStart(route_name: []const u8, service_name: []const u8, backend_service: []const u8) void {
    recordRouteRequestStartWithRole(.primary, route_name, service_name, backend_service);
}

pub fn recordMirrorRouteRequestStart(route_name: []const u8, service_name: []const u8, backend_service: []const u8) void {
    recordRouteRequestStartWithRole(.mirror, route_name, service_name, backend_service);
}

fn recordRouteRequestStartWithRole(role: RouteTrafficRole, route_name: []const u8, service_name: []const u8, backend_service: []const u8) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    const state = ensureRouteTrafficLocked(role, route_name, service_name, backend_service) orelse return;
    state.requests_total += 1;
}

pub fn recordResponse(status: http.StatusCode) void {
    recordResponseCode(@intFromEnum(status));
}

pub fn recordResponseCode(status_code: u16) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    switch (status_code) {
        200...299 => responses_2xx_total += 1,
        400...499 => responses_4xx_total += 1,
        500...599 => responses_5xx_total += 1,
        else => {},
    }
}

pub fn recordRouteResponseCode(route_name: []const u8, service_name: []const u8, backend_service: []const u8, status_code: u16) void {
    recordRouteResponseCodeWithRole(.primary, route_name, service_name, backend_service, status_code);
}

pub fn recordMirrorRouteResponseCode(route_name: []const u8, service_name: []const u8, backend_service: []const u8, status_code: u16) void {
    recordRouteResponseCodeWithRole(.mirror, route_name, service_name, backend_service, status_code);
}

fn recordRouteResponseCodeWithRole(role: RouteTrafficRole, route_name: []const u8, service_name: []const u8, backend_service: []const u8, status_code: u16) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    const state = ensureRouteTrafficLocked(role, route_name, service_name, backend_service) orelse return;
    switch (status_code) {
        200...299 => state.responses_2xx_total += 1,
        400...499 => state.responses_4xx_total += 1,
        500...599 => state.responses_5xx_total += 1,
        else => {},
    }
}

pub fn recordRetry() void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    retries_total += 1;
}

pub fn recordRouteRetry(route_name: []const u8, service_name: []const u8, backend_service: []const u8) void {
    recordRouteRetryWithRole(.primary, route_name, service_name, backend_service);
}

pub fn recordMirrorRouteRetry(route_name: []const u8, service_name: []const u8, backend_service: []const u8) void {
    recordRouteRetryWithRole(.mirror, route_name, service_name, backend_service);
}

fn recordRouteRetryWithRole(role: RouteTrafficRole, route_name: []const u8, service_name: []const u8, backend_service: []const u8) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    const state = ensureRouteTrafficLocked(role, route_name, service_name, backend_service) orelse return;
    state.retries_total += 1;
}

pub fn recordLoopRejection() void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    loop_rejections_total += 1;
}

pub fn recordUpstreamFailure(kind: UpstreamFailureKind) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    switch (kind) {
        .connect => upstream_connect_failures_total += 1,
        .send => upstream_send_failures_total += 1,
        .receive => upstream_receive_failures_total += 1,
        .other => upstream_other_failures_total += 1,
    }
}

pub fn recordRouteUpstreamFailure(route_name: []const u8, service_name: []const u8, backend_service: []const u8) void {
    recordRouteUpstreamFailureWithRole(.primary, route_name, service_name, backend_service);
}

pub fn recordMirrorRouteUpstreamFailure(route_name: []const u8, service_name: []const u8, backend_service: []const u8) void {
    recordRouteUpstreamFailureWithRole(.mirror, route_name, service_name, backend_service);
}

fn recordRouteUpstreamFailureWithRole(role: RouteTrafficRole, route_name: []const u8, service_name: []const u8, backend_service: []const u8) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    const state = ensureRouteTrafficLocked(role, route_name, service_name, backend_service) orelse return;
    state.upstream_failures_total += 1;
}

pub fn recordEndpointSuccess(endpoint_id: []const u8) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    const circuit = endpoint_circuits.getPtr(endpoint_id) orelse return;
    circuit.* = .{};
}

pub fn recordEndpointFailure(endpoint_id: []const u8, cb_policy: proxy_policy.CircuitBreakerPolicy) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    const circuit = blk: {
        if (endpoint_circuits.getPtr(endpoint_id)) |existing| break :blk existing;

        const key_copy = std.heap.page_allocator.dupe(u8, endpoint_id) catch return;
        errdefer std.heap.page_allocator.free(key_copy);

        endpoint_circuits.put(std.heap.page_allocator, key_copy, .{}) catch return;
        break :blk endpoint_circuits.getPtr(key_copy).?;
    };

    switch (circuit.state) {
        .closed => {
            if (circuit.consecutive_failures < std.math.maxInt(u8)) {
                circuit.consecutive_failures += 1;
            }
            if (proxy_policy.shouldTripCircuit(cb_policy, circuit.consecutive_failures)) {
                circuit.state = .open;
                circuit.opened_at_ms = nowRealMilliseconds();
                circuit.half_open_in_flight = false;
                circuit_trips_total += 1;
            }
        },
        .half_open => {
            circuit.state = .open;
            circuit.opened_at_ms = nowRealMilliseconds();
            circuit.half_open_in_flight = false;
            circuit.consecutive_failures = cb_policy.failure_threshold;
            circuit_trips_total += 1;
        },
        .open => {
            circuit.opened_at_ms = nowRealMilliseconds();
            circuit.half_open_in_flight = false;
        },
    }
}

pub fn recordRouteFailure(route_name: []const u8, kind: RouteFailureKind) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    const state = ensureRouteStatusLocked(route_name) orelse return;
    state.degraded_reason = degradedReasonForFailure(kind);
    state.last_failure_kind = kind;
    state.last_failure_at = nowRealSeconds();
}

pub fn recordRouteRecovered(route_name: []const u8) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    const state = route_statuses.getPtr(route_name) orelse return;
    state.degraded_reason = .none;
}

pub fn snapshotRoutes(alloc: std.mem.Allocator) !std.ArrayList(RouteSnapshot) {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    var routes_snapshot: std.ArrayList(RouteSnapshot) = .empty;
    errdefer {
        for (routes_snapshot.items) |route| route.deinit(alloc);
        routes_snapshot.deinit(alloc);
    }

    for (materialized_routes.items) |route| {
        const snapshot_route = try cloneRouteSnapshot(alloc, route);
        errdefer snapshot_route.deinit(alloc);
        try routes_snapshot.append(alloc, snapshot_route);
    }

    return routes_snapshot;
}

pub fn snapshotRouteTraffic(alloc: std.mem.Allocator) !std.ArrayList(RouteTrafficSnapshot) {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    var traffic_snapshot: std.ArrayList(RouteTrafficSnapshot) = .empty;
    errdefer {
        for (traffic_snapshot.items) |entry| entry.deinit(alloc);
        traffic_snapshot.deinit(alloc);
    }

    var it = route_traffic.iterator();
    while (it.next()) |entry| {
        try traffic_snapshot.append(alloc, .{
            .traffic_role = entry.value_ptr.traffic_role,
            .route_name = try alloc.dupe(u8, entry.value_ptr.route_name),
            .service_name = try alloc.dupe(u8, entry.value_ptr.service_name),
            .backend_service = try alloc.dupe(u8, entry.value_ptr.backend_service),
            .requests_total = entry.value_ptr.requests_total,
            .responses_2xx_total = entry.value_ptr.responses_2xx_total,
            .responses_4xx_total = entry.value_ptr.responses_4xx_total,
            .responses_5xx_total = entry.value_ptr.responses_5xx_total,
            .retries_total = entry.value_ptr.retries_total,
            .upstream_failures_total = entry.value_ptr.upstream_failures_total,
        });
    }

    return traffic_snapshot;
}

pub fn snapshotRouteConfigs(alloc: std.mem.Allocator) !std.ArrayList(router.Route) {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    var routes_snapshot: std.ArrayList(router.Route) = .empty;
    errdefer {
        for (routes_snapshot.items) |route| {
            alloc.free(route.name);
            alloc.free(route.service);
            alloc.free(route.vip_address);
            if (route.match.host) |host| alloc.free(host);
            alloc.free(route.match.path_prefix);
            if (route.rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
            for (route.method_matches) |method_match| method_match.deinit(alloc);
            if (route.method_matches.len > 0) alloc.free(route.method_matches);
            for (route.header_matches) |header_match| header_match.deinit(alloc);
            if (route.header_matches.len > 0) alloc.free(route.header_matches);
            for (route.backend_services) |backend| backend.deinit(alloc);
            if (route.backend_services.len > 0) alloc.free(route.backend_services);
            if (route.mirror_service) |mirror_service| alloc.free(mirror_service);
        }
        routes_snapshot.deinit(alloc);
    }

    for (materialized_routes.items) |route| {
        try routes_snapshot.append(alloc, .{
            .name = try alloc.dupe(u8, route.name),
            .service = try alloc.dupe(u8, route.service),
            .vip_address = try alloc.dupe(u8, route.vip_address),
            .match = .{
                .host = if (route.match.host) |host| try alloc.dupe(u8, host) else null,
                .path_prefix = try alloc.dupe(u8, route.match.path_prefix),
            },
            .rewrite_prefix = if (route.rewrite_prefix) |rewrite_prefix| try alloc.dupe(u8, rewrite_prefix) else null,
            .method_matches = try cloneMethodMatches(alloc, route.method_matches),
            .header_matches = try cloneHeaderMatches(alloc, route.header_matches),
            .backend_services = try cloneBackendTargets(alloc, route.backend_services),
            .mirror_service = if (route.mirror_service) |mirror_service| try alloc.dupe(u8, mirror_service) else null,
            .eligible_endpoints = route.eligible_endpoints,
            .healthy_endpoints = route.healthy_endpoints,
            .degraded = route.degraded,
            .retries = route.retries,
            .connect_timeout_ms = route.connect_timeout_ms,
            .request_timeout_ms = route.request_timeout_ms,
            .http2_idle_timeout_ms = route.http2_idle_timeout_ms,
            .preserve_host = route.preserve_host,
        });
    }

    return routes_snapshot;
}

pub fn snapshotServiceRoutes(alloc: std.mem.Allocator, service_name: []const u8) !std.ArrayList(RouteSnapshot) {
    {
        const service = try service_registry_runtime.snapshotService(alloc, service_name);
        service.deinit(alloc);
    }

    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    var routes_snapshot: std.ArrayList(RouteSnapshot) = .empty;
    errdefer {
        for (routes_snapshot.items) |route| route.deinit(alloc);
        routes_snapshot.deinit(alloc);
    }

    for (materialized_routes.items) |route| {
        if (!std.mem.eql(u8, route.service, service_name)) continue;

        const snapshot_route = try cloneRouteSnapshot(alloc, route);
        errdefer snapshot_route.deinit(alloc);
        try routes_snapshot.append(alloc, snapshot_route);
    }

    return routes_snapshot;
}

pub fn resolveRoute(alloc: std.mem.Allocator, method: []const u8, host: []const u8, path: []const u8) !RouteSnapshot {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    const matched = router.matchRoute(materialized_routes.items, method, host, path, &.{}) orelse return error.RouteNotFound;
    return cloneRouteSnapshot(alloc, matched);
}

pub fn resolveUpstream(alloc: std.mem.Allocator, service_name: []const u8) !upstream_mod.Upstream {
    return resolveUpstreamWithPolicy(alloc, service_name, default_circuit_policy);
}

pub fn resolveUpstreamWithPolicy(alloc: std.mem.Allocator, service_name: []const u8, cb_policy: proxy_policy.CircuitBreakerPolicy) !upstream_mod.Upstream {
    const service = try service_registry_runtime.snapshotService(alloc, service_name);
    defer service.deinit(alloc);

    var endpoints = try service_registry_runtime.snapshotServiceEndpoints(alloc, service_name);
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(alloc);
        endpoints.deinit(alloc);
    }

    var candidates: std.ArrayList(upstream_mod.Upstream) = .empty;
    defer {
        for (candidates.items) |candidate| candidate.deinit(alloc);
        candidates.deinit(alloc);
    }

    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    const now_ms = nowRealMilliseconds();
    const target_port = service.http_proxy_target_port;
    for (endpoints.items) |endpoint| {
        const port: u16 = target_port orelse if (endpoint.port < 0) 0 else @intCast(endpoint.port);
        try candidates.append(alloc, .{
            .service = try alloc.dupe(u8, service_name),
            .endpoint_id = try alloc.dupe(u8, endpoint.endpoint_id),
            .address = try alloc.dupe(u8, endpoint.ip_address),
            .port = port,
            .eligible = endpoint.eligible and endpointAllowsRequestLocked(endpoint.endpoint_id, now_ms, cb_policy),
        });
    }

    const selected = upstream_mod.selectFirstEligible(candidates.items) orelse return error.NoHealthyUpstream;
    return .{
        .service = try alloc.dupe(u8, selected.service),
        .endpoint_id = try alloc.dupe(u8, selected.endpoint_id),
        .address = try alloc.dupe(u8, selected.address),
        .port = selected.port,
        .eligible = selected.eligible,
    };
}

pub fn selectBackendService(route: router.Route, request_key: u64, attempt: u8) []const u8 {
    return selectBackendServiceFromTargets(route.service, route.backend_services, request_key, attempt);
}

pub fn selectSnapshotBackendService(route: RouteSnapshot, request_key: u64, attempt: u8) []const u8 {
    return selectBackendServiceFromTargets(route.service, route.backend_services, request_key, attempt);
}

fn endpointAllowsRequestLocked(endpoint_id: []const u8, now_ms: i64, cb_policy: proxy_policy.CircuitBreakerPolicy) bool {
    const circuit = endpoint_circuits.getPtr(endpoint_id) orelse return true;

    switch (circuit.state) {
        .closed => return true,
        .open => {
            const opened_at_ms = circuit.opened_at_ms orelse return false;
            if (!proxy_policy.shouldAllowHalfOpen(cb_policy, opened_at_ms, now_ms)) return false;

            circuit.state = .half_open;
            circuit.half_open_in_flight = true;
            return true;
        },
        .half_open => {
            if (circuit.half_open_in_flight) return false;
            circuit.half_open_in_flight = true;
            return true;
        },
    }
}

fn selectBackendServiceFromTargets(
    default_service: []const u8,
    backends: []const router.BackendTarget,
    request_key: u64,
    attempt: u8,
) []const u8 {
    if (backends.len == 0) return default_service;

    var total_weight: u64 = 0;
    for (backends) |backend| total_weight += backend.weight;
    if (total_weight == 0) return default_service;

    const bucket = (request_key +% (@as(u64, attempt) *% 7919)) % total_weight;
    var cursor: u64 = 0;
    for (backends) |backend| {
        cursor += backend.weight;
        if (bucket < cursor) return backend.service_name;
    }

    return backends[backends.len - 1].service_name;
}

test "selectBackendService uses weighted backend targets" {
    const route = router.Route{
        .name = "api:default",
        .service = "api",
        .vip_address = "10.43.0.2",
        .match = .{ .host = "api.internal", .path_prefix = "/" },
        .backend_services = &.{
            .{ .service_name = "api", .weight = 90 },
            .{ .service_name = "api-canary", .weight = 10 },
        },
    };

    try std.testing.expectEqualStrings("api", selectBackendService(route, 0, 0));
    try std.testing.expectEqualStrings("api", selectBackendService(route, 89, 0));
    try std.testing.expectEqualStrings("api-canary", selectBackendService(route, 90, 0));
    try std.testing.expectEqualStrings("api-canary", selectBackendService(route, 99, 0));
}

fn calculateDegradedReason(route_state: ?RouteStatusState, route_degraded: bool, steering_ready: bool) RouteDegradedReason {
    if (route_state) |state| {
        if (state.degraded_reason != .none) return state.degraded_reason;
    }
    if (route_degraded) return .service_state;
    if (!steering_ready) return .steering_not_ready;
    return .none;
}

fn cloneRouteSnapshot(alloc: std.mem.Allocator, route: router.Route) !RouteSnapshot {
    const route_state = route_statuses.get(route.name);
    const steering_state = try steering_runtime.snapshotServiceStatus(alloc, route.service);
    const vip_traffic_mode: VipTrafficMode = if (steering_state.ready) .l7_proxy else .l4_fallback;
    const degraded_reason = calculateDegradedReason(route_state, route.degraded, steering_state.ready);

    return .{
        .name = try alloc.dupe(u8, route.name),
        .service = try alloc.dupe(u8, route.service),
        .vip_address = try alloc.dupe(u8, route.vip_address),
        .host = try alloc.dupe(u8, route.match.host orelse ""),
        .path_prefix = try alloc.dupe(u8, route.match.path_prefix),
        .rewrite_prefix = if (route.rewrite_prefix) |rewrite_prefix| try alloc.dupe(u8, rewrite_prefix) else null,
        .method_matches = try cloneMethodMatches(alloc, route.method_matches),
        .header_matches = try cloneHeaderMatches(alloc, route.header_matches),
        .backend_services = try cloneBackendTargets(alloc, route.backend_services),
        .mirror_service = if (route.mirror_service) |mirror_service| try alloc.dupe(u8, mirror_service) else null,
        .eligible_endpoints = route.eligible_endpoints,
        .healthy_endpoints = route.healthy_endpoints,
        .degraded = degraded_reason != .none,
        .degraded_reason = degraded_reason,
        .last_failure_kind = if (route_state) |state| state.last_failure_kind else null,
        .last_failure_at = if (route_state) |state| state.last_failure_at else null,
        .retries = route.retries,
        .connect_timeout_ms = route.connect_timeout_ms,
        .request_timeout_ms = route.request_timeout_ms,
        .http2_idle_timeout_ms = route.http2_idle_timeout_ms,
        .preserve_host = route.preserve_host,
        .retry_on_5xx = route.retry_on_5xx,
        .circuit_breaker_threshold = route.circuit_breaker_threshold,
        .circuit_breaker_timeout_ms = route.circuit_breaker_timeout_ms,
        .vip_traffic_mode = vip_traffic_mode,
        .steering_desired_ports = steering_state.desired_ports,
        .steering_applied_ports = steering_state.applied_ports,
        .steering_ready = steering_state.ready,
        .steering_blocked = steering_state.blocked,
        .steering_drifted = steering_state.drifted,
        .steering_blocked_reason = steering_state.blocked_reason,
    };
}

fn cloneHeaderMatches(alloc: std.mem.Allocator, matches: anytype) ![]const router.HeaderMatch {
    var cloned: std.ArrayList(router.HeaderMatch) = .empty;
    errdefer {
        for (cloned.items) |header_match| header_match.deinit(alloc);
        cloned.deinit(alloc);
    }

    for (matches) |header_match| {
        try cloned.append(alloc, .{
            .name = try alloc.dupe(u8, header_match.name),
            .value = try alloc.dupe(u8, header_match.value),
        });
    }
    return cloned.toOwnedSlice(alloc);
}

fn cloneMethodMatches(alloc: std.mem.Allocator, matches: anytype) ![]const router.MethodMatch {
    var cloned: std.ArrayList(router.MethodMatch) = .empty;
    errdefer {
        for (cloned.items) |method_match| method_match.deinit(alloc);
        cloned.deinit(alloc);
    }

    for (matches) |method_match| {
        try cloned.append(alloc, .{
            .method = try alloc.dupe(u8, method_match.method),
        });
    }
    return cloned.toOwnedSlice(alloc);
}

fn cloneBackendTargets(alloc: std.mem.Allocator, backends: anytype) ![]const router.BackendTarget {
    var cloned: std.ArrayList(router.BackendTarget) = .empty;
    errdefer {
        for (cloned.items) |backend| backend.deinit(alloc);
        cloned.deinit(alloc);
    }

    for (backends) |backend| {
        try cloned.append(alloc, .{
            .service_name = try alloc.dupe(u8, backend.service_name),
            .weight = backend.weight,
        });
    }
    return cloned.toOwnedSlice(alloc);
}

fn syncLocked() !void {
    var services = try service_registry_runtime.snapshotServices(std.heap.page_allocator);
    defer {
        for (services.items) |service| service.deinit(std.heap.page_allocator);
        services.deinit(std.heap.page_allocator);
    }

    clearLastErrorLocked();
    deinitRoutesLocked();
    errdefer {
        deinitRoutesLocked();
        configured_services = 0;
        routes = 0;
        last_sync_at = null;
    }

    var next_configured_services: u32 = 0;
    var next_routes: u32 = 0;
    for (services.items) |service| {
        if (service.http_routes.len == 0) continue;
        next_configured_services += 1;
        for (service.http_routes) |service_route| {
            next_routes += 1;
            const route = router.Route{
                .name = try std.fmt.allocPrint(std.heap.page_allocator, "{s}:{s}", .{
                    service.service_name,
                    service_route.route_name,
                }),
                .service = try std.heap.page_allocator.dupe(u8, service.service_name),
                .vip_address = try std.heap.page_allocator.dupe(u8, service.vip_address),
                .match = .{
                    .host = try std.heap.page_allocator.dupe(u8, service_route.host),
                    .path_prefix = try std.heap.page_allocator.dupe(u8, service_route.path_prefix),
                },
                .rewrite_prefix = if (service_route.rewrite_prefix) |rewrite_prefix| try std.heap.page_allocator.dupe(u8, rewrite_prefix) else null,
                .method_matches = try cloneMethodMatches(std.heap.page_allocator, service_route.match_methods),
                .header_matches = try cloneHeaderMatches(std.heap.page_allocator, service_route.match_headers),
                .backend_services = try cloneBackendTargets(std.heap.page_allocator, service_route.backend_services),
                .mirror_service = if (service_route.mirror_service) |mirror_service| try std.heap.page_allocator.dupe(u8, mirror_service) else null,
                .eligible_endpoints = @intCast(service.eligible_endpoints),
                .healthy_endpoints = @intCast(service.healthy_endpoints),
                .degraded = service.degraded,
                .retries = service_route.retries,
                .connect_timeout_ms = service_route.connect_timeout_ms,
                .request_timeout_ms = service_route.request_timeout_ms,
                .http2_idle_timeout_ms = service_route.http2_idle_timeout_ms,
                .preserve_host = service_route.preserve_host,
                .retry_on_5xx = service_route.retry_on_5xx,
                .circuit_breaker_threshold = service_route.circuit_breaker_threshold,
                .circuit_breaker_timeout_ms = service_route.circuit_breaker_timeout_ms,
            };
            errdefer {
                std.heap.page_allocator.free(route.name);
                std.heap.page_allocator.free(route.service);
                std.heap.page_allocator.free(route.vip_address);
                if (route.match.host) |owned_host| std.heap.page_allocator.free(owned_host);
                std.heap.page_allocator.free(route.match.path_prefix);
                if (route.rewrite_prefix) |rewrite_prefix| std.heap.page_allocator.free(rewrite_prefix);
                for (route.method_matches) |method_match| method_match.deinit(std.heap.page_allocator);
                if (route.method_matches.len > 0) std.heap.page_allocator.free(route.method_matches);
                for (route.header_matches) |header_match| header_match.deinit(std.heap.page_allocator);
                if (route.header_matches.len > 0) std.heap.page_allocator.free(route.header_matches);
                for (route.backend_services) |backend| backend.deinit(std.heap.page_allocator);
                if (route.backend_services.len > 0) std.heap.page_allocator.free(route.backend_services);
                if (route.mirror_service) |mirror_service| std.heap.page_allocator.free(mirror_service);
            }
            try materialized_routes.append(std.heap.page_allocator, route);
        }
    }

    configured_services = next_configured_services;
    routes = next_routes;
    pruneRouteStatusesLocked();
    running = next_configured_services > 0;
    last_sync_at = if (next_configured_services > 0) nowRealSeconds() else null;
}

fn deinitRoutesLocked() void {
    for (materialized_routes.items) |route| {
        std.heap.page_allocator.free(route.name);
        std.heap.page_allocator.free(route.service);
        std.heap.page_allocator.free(route.vip_address);
        if (route.match.host) |host| std.heap.page_allocator.free(host);
        std.heap.page_allocator.free(route.match.path_prefix);
        if (route.rewrite_prefix) |rewrite_prefix| std.heap.page_allocator.free(rewrite_prefix);
        for (route.method_matches) |method_match| method_match.deinit(std.heap.page_allocator);
        if (route.method_matches.len > 0) std.heap.page_allocator.free(route.method_matches);
        for (route.header_matches) |header_match| header_match.deinit(std.heap.page_allocator);
        if (route.header_matches.len > 0) std.heap.page_allocator.free(route.header_matches);
        for (route.backend_services) |backend| backend.deinit(std.heap.page_allocator);
        if (route.backend_services.len > 0) std.heap.page_allocator.free(route.backend_services);
        if (route.mirror_service) |mirror_service| std.heap.page_allocator.free(mirror_service);
    }
    materialized_routes.clearAndFree(std.heap.page_allocator);
}

fn deinitCircuitsLocked() void {
    var it = endpoint_circuits.iterator();
    while (it.next()) |entry| {
        std.heap.page_allocator.free(entry.key_ptr.*);
    }
    endpoint_circuits.clearAndFree(std.heap.page_allocator);
}

fn ensureRouteStatusLocked(route_name: []const u8) ?*RouteStatusState {
    if (route_statuses.getPtr(route_name)) |state| return state;

    const key_copy = std.heap.page_allocator.dupe(u8, route_name) catch return null;
    errdefer std.heap.page_allocator.free(key_copy);

    route_statuses.put(std.heap.page_allocator, key_copy, .{}) catch return null;
    return route_statuses.getPtr(key_copy).?;
}

fn pruneRouteStatusesLocked() void {
    var next_statuses: std.StringHashMapUnmanaged(RouteStatusState) = .{};
    var it = route_statuses.iterator();
    while (it.next()) |entry| {
        if (!routeExistsLocked(entry.key_ptr.*)) continue;

        const key_copy = std.heap.page_allocator.dupe(u8, entry.key_ptr.*) catch continue;
        next_statuses.put(std.heap.page_allocator, key_copy, entry.value_ptr.*) catch {
            std.heap.page_allocator.free(key_copy);
        };
    }

    deinitRouteStatusesLocked();
    route_statuses = next_statuses;
}

fn routeExistsLocked(route_name: []const u8) bool {
    for (materialized_routes.items) |route| {
        if (std.mem.eql(u8, route.name, route_name)) return true;
    }
    return false;
}

fn deinitRouteStatusesLocked() void {
    var it = route_statuses.iterator();
    while (it.next()) |entry| {
        std.heap.page_allocator.free(entry.key_ptr.*);
    }
    route_statuses.clearAndFree(std.heap.page_allocator);
}

fn deinitRouteTrafficLocked() void {
    var it = route_traffic.iterator();
    while (it.next()) |entry| {
        std.heap.page_allocator.free(entry.key_ptr.*);
        std.heap.page_allocator.free(entry.value_ptr.route_name);
        std.heap.page_allocator.free(entry.value_ptr.service_name);
        std.heap.page_allocator.free(entry.value_ptr.backend_service);
    }
    route_traffic.clearAndFree(std.heap.page_allocator);
}

fn ensureRouteTrafficLocked(role: RouteTrafficRole, route_name: []const u8, service_name: []const u8, backend_service: []const u8) ?*RouteTrafficState {
    const key = std.fmt.allocPrint(std.heap.page_allocator, "{s}\x1f{s}\x1f{s}", .{ route_name, backend_service, role.label() }) catch return null;
    errdefer std.heap.page_allocator.free(key);

    const result = route_traffic.getOrPut(std.heap.page_allocator, key) catch return null;
    if (!result.found_existing) {
        result.value_ptr.* = .{
            .traffic_role = role,
            .route_name = std.heap.page_allocator.dupe(u8, route_name) catch {
                std.heap.page_allocator.free(result.key_ptr.*);
                _ = route_traffic.remove(key);
                return null;
            },
            .service_name = std.heap.page_allocator.dupe(u8, service_name) catch {
                std.heap.page_allocator.free(result.value_ptr.route_name);
                std.heap.page_allocator.free(result.key_ptr.*);
                _ = route_traffic.remove(key);
                return null;
            },
            .backend_service = std.heap.page_allocator.dupe(u8, backend_service) catch {
                std.heap.page_allocator.free(result.value_ptr.route_name);
                std.heap.page_allocator.free(result.value_ptr.service_name);
                std.heap.page_allocator.free(result.key_ptr.*);
                _ = route_traffic.remove(key);
                return null;
            },
        };
    } else {
        std.heap.page_allocator.free(key);
    }
    return result.value_ptr;
}

fn degradedReasonForFailure(kind: RouteFailureKind) RouteDegradedReason {
    return switch (kind) {
        .no_eligible_upstream => .no_eligible_upstream,
        .connect => .connect_failure,
        .send => .send_failure,
        .receive => .receive_failure,
        .invalid_response => .invalid_response,
    };
}

fn clearLastErrorLocked() void {
    if (last_error) |message| std.heap.page_allocator.free(message);
    last_error = null;
}

fn setLastErrorLocked(err: anyerror) void {
    clearLastErrorLocked();
    last_error = std.fmt.allocPrint(std.heap.page_allocator, "{}", .{err}) catch null;
    running = false;
}

test "bootstrap tracks configured proxy routes from service state" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .http_proxy_retries = 2,
        .http_proxy_connect_timeout_ms = 1500,
        .http_proxy_request_timeout_ms = 5000,
        .http_proxy_preserve_host = true,
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.createService(.{
        .service_name = "worker",
        .vip_address = "10.43.0.3",
        .lb_policy = "consistent_hash",
        .created_at = 1001,
        .updated_at = 1001,
    });

    bootstrapIfEnabled();

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);

    try std.testing.expect(state.enabled);
    try std.testing.expect(state.running);
    try std.testing.expectEqual(@as(u32, 1), state.configured_services);
    try std.testing.expectEqual(@as(u32, 1), state.routes);
    try std.testing.expect(state.last_sync_at != null);
    try std.testing.expect(state.last_error == null);

    var routes_snapshot = try snapshotRoutes(std.testing.allocator);
    defer {
        for (routes_snapshot.items) |route| route.deinit(std.testing.allocator);
        routes_snapshot.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), routes_snapshot.items.len);
    try std.testing.expectEqualStrings("api", routes_snapshot.items[0].service);
    try std.testing.expectEqualStrings("10.43.0.2", routes_snapshot.items[0].vip_address);
    try std.testing.expectEqualStrings("api.internal", routes_snapshot.items[0].host);
    try std.testing.expectEqualStrings("/v1", routes_snapshot.items[0].path_prefix);
    try std.testing.expectEqual(@as(u32, 0), routes_snapshot.items[0].eligible_endpoints);
    try std.testing.expect(routes_snapshot.items[0].degraded);
}

test "bootstrap no longer depends on l7 proxy compatibility flag" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{ .service_registry_v2 = true });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .created_at = 1000,
        .updated_at = 1000,
    });

    bootstrapIfEnabled();

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);

    try std.testing.expect(state.enabled);
    try std.testing.expect(state.running);
    try std.testing.expectEqual(@as(u32, 1), state.configured_services);
    try std.testing.expectEqual(@as(u32, 1), state.routes);
    try std.testing.expect(state.last_sync_at != null);
}

test "snapshotServiceRoutes filters routes by service" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.createService(.{
        .service_name = "web",
        .vip_address = "10.43.0.3",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "web.internal",
        .http_proxy_path_prefix = "/",
        .created_at = 1001,
        .updated_at = 1001,
    });

    bootstrapIfEnabled();

    var routes_snapshot = try snapshotServiceRoutes(std.testing.allocator, "api");
    defer {
        for (routes_snapshot.items) |route| route.deinit(std.testing.allocator);
        routes_snapshot.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), routes_snapshot.items.len);
    try std.testing.expectEqualStrings("api.internal", routes_snapshot.items[0].host);
}

test "materialized routes include service endpoint readiness counts" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

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
        .endpoint_id = "ctr-1:0",
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

    bootstrapIfEnabled();

    var routes_snapshot = try snapshotServiceRoutes(std.testing.allocator, "api");
    defer {
        for (routes_snapshot.items) |route| route.deinit(std.testing.allocator);
        routes_snapshot.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), routes_snapshot.items.len);
    try std.testing.expectEqual(@as(u32, 1), routes_snapshot.items[0].eligible_endpoints);
    try std.testing.expectEqual(@as(u32, 0), routes_snapshot.items[0].healthy_endpoints);
    try std.testing.expect(routes_snapshot.items[0].degraded);
    try std.testing.expectEqual(RouteDegradedReason.steering_not_ready, routes_snapshot.items[0].degraded_reason);
    try std.testing.expectEqual(VipTrafficMode.l4_fallback, routes_snapshot.items[0].vip_traffic_mode);
    try std.testing.expect(routes_snapshot.items[0].last_failure_kind == null);
    try std.testing.expect(routes_snapshot.items[0].last_failure_at == null);
}

test "materialized routes mark steering as degraded when VIP cutover is enabled" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .dns_returns_vip = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

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
        .endpoint_id = "ctr-1:0",
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

    bootstrapIfEnabled();

    var routes_snapshot = try snapshotServiceRoutes(std.testing.allocator, "api");
    defer {
        for (routes_snapshot.items) |route| route.deinit(std.testing.allocator);
        routes_snapshot.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), routes_snapshot.items.len);
    try std.testing.expect(routes_snapshot.items[0].degraded);
    try std.testing.expectEqual(RouteDegradedReason.steering_not_ready, routes_snapshot.items[0].degraded_reason);
    try std.testing.expectEqual(VipTrafficMode.l4_fallback, routes_snapshot.items[0].vip_traffic_mode);
    try std.testing.expect(!routes_snapshot.items[0].steering_ready);
    try std.testing.expect(routes_snapshot.items[0].steering_blocked);
    try std.testing.expect(!routes_snapshot.items[0].steering_drifted);
    try std.testing.expectEqual(steering_runtime.BlockedReason.listener_not_running, routes_snapshot.items[0].steering_blocked_reason);
}

test "resolveRoute matches by host and path" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .created_at = 1000,
        .updated_at = 1000,
    });

    bootstrapIfEnabled();

    const route = try resolveRoute(std.testing.allocator, "GET", "api.internal", "/v1/users");
    defer route.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("api", route.service);
    try std.testing.expectEqualStrings("/v1", route.path_prefix);
}

test "resolveRoute prefers method-specific route" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
        .http_routes = &.{
            .{
                .service_name = "api",
                .route_name = "default",
                .host = "api.internal",
                .path_prefix = "/v1",
                .match_headers = &.{},
                .backend_services = &.{},
                .retries = 0,
                .connect_timeout_ms = 1000,
                .request_timeout_ms = 5000,
                .http2_idle_timeout_ms = 30000,
                .route_order = 0,
                .created_at = 1000,
                .updated_at = 1000,
            },
            .{
                .service_name = "api",
                .route_name = "write",
                .host = "api.internal",
                .path_prefix = "/v1",
                .match_methods = &.{
                    .{
                        .service_name = "api",
                        .route_name = "write",
                        .method = "POST",
                        .match_order = 0,
                        .created_at = 1000,
                        .updated_at = 1000,
                    },
                },
                .match_headers = &.{},
                .backend_services = &.{},
                .retries = 0,
                .connect_timeout_ms = 1000,
                .request_timeout_ms = 5000,
                .http2_idle_timeout_ms = 30000,
                .route_order = 1,
                .created_at = 1000,
                .updated_at = 1000,
            },
        },
    });

    bootstrapIfEnabled();

    const route = try resolveRoute(std.testing.allocator, "POST", "api.internal", "/v1/users");
    defer route.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("api", route.service);
    try std.testing.expectEqualStrings("POST", route.method_matches[0].method);
}

test "resolveUpstream returns the first eligible endpoint" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

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
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-2",
        .container_id = "ctr-2",
        .node_id = null,
        .ip_address = "10.42.0.10",
        .port = 8081,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1001,
        .last_seen_at = 1001,
    });

    const upstream = try resolveUpstream(std.testing.allocator, "api");
    defer upstream.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("api-2", upstream.endpoint_id);
    try std.testing.expectEqualStrings("10.42.0.10", upstream.address);
    try std.testing.expectEqual(@as(u16, 8081), upstream.port);
}

test "snapshot exposes L7 proxy observability counters" {
    resetForTest();
    defer resetForTest();

    recordRequestStart();
    recordRequestStart();
    recordRouteRequestStart("edge:default", "edge", "edge");
    recordResponse(.ok);
    recordRouteResponseCode("edge:default", "edge", "edge", 200);
    recordResponse(.bad_request);
    recordResponse(.bad_gateway);
    recordRetry();
    recordRouteRetry("edge:default", "edge", "edge");
    recordMirrorRouteRequestStart("edge:default", "edge", "edge-shadow");
    recordMirrorRouteResponseCode("edge:default", "edge", "edge-shadow", 202);
    recordMirrorRouteUpstreamFailure("edge:default", "edge", "edge-shadow");
    recordLoopRejection();
    recordUpstreamFailure(.connect);
    recordRouteUpstreamFailure("edge:default", "edge", "edge");
    recordUpstreamFailure(.receive);
    recordUpstreamFailure(.other);

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 2), state.requests_total);
    try std.testing.expectEqual(@as(u64, 1), state.responses_2xx_total);
    try std.testing.expectEqual(@as(u64, 1), state.responses_4xx_total);
    try std.testing.expectEqual(@as(u64, 1), state.responses_5xx_total);
    try std.testing.expectEqual(@as(u64, 1), state.retries_total);
    try std.testing.expectEqual(@as(u64, 1), state.loop_rejections_total);
    try std.testing.expectEqual(@as(u64, 1), state.upstream_connect_failures_total);
    try std.testing.expectEqual(@as(u64, 0), state.upstream_send_failures_total);
    try std.testing.expectEqual(@as(u64, 1), state.upstream_receive_failures_total);
    try std.testing.expectEqual(@as(u64, 1), state.upstream_other_failures_total);
    try std.testing.expectEqual(@as(u64, 0), state.circuit_trips_total);
    try std.testing.expectEqual(@as(u32, 0), state.circuit_open_endpoints);
    try std.testing.expectEqual(@as(u32, 0), state.circuit_half_open_endpoints);

    var route_traffic_snapshot = try snapshotRouteTraffic(std.testing.allocator);
    defer {
        for (route_traffic_snapshot.items) |entry| entry.deinit(std.testing.allocator);
        route_traffic_snapshot.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 2), route_traffic_snapshot.items.len);
    try std.testing.expectEqual(RouteTrafficRole.primary, route_traffic_snapshot.items[0].traffic_role);
    try std.testing.expectEqualStrings("edge:default", route_traffic_snapshot.items[0].route_name);
    try std.testing.expectEqualStrings("edge", route_traffic_snapshot.items[0].service_name);
    try std.testing.expectEqualStrings("edge", route_traffic_snapshot.items[0].backend_service);
    try std.testing.expectEqual(@as(u64, 1), route_traffic_snapshot.items[0].requests_total);
    try std.testing.expectEqual(@as(u64, 1), route_traffic_snapshot.items[0].responses_2xx_total);
    try std.testing.expectEqual(@as(u64, 1), route_traffic_snapshot.items[0].retries_total);
    try std.testing.expectEqual(@as(u64, 1), route_traffic_snapshot.items[0].upstream_failures_total);
    try std.testing.expectEqual(RouteTrafficRole.mirror, route_traffic_snapshot.items[1].traffic_role);
    try std.testing.expectEqualStrings("edge-shadow", route_traffic_snapshot.items[1].backend_service);
    try std.testing.expectEqual(@as(u64, 1), route_traffic_snapshot.items[1].requests_total);
    try std.testing.expectEqual(@as(u64, 1), route_traffic_snapshot.items[1].responses_2xx_total);
    try std.testing.expectEqual(@as(u64, 1), route_traffic_snapshot.items[1].upstream_failures_total);
}

test "resolveUpstream skips endpoints with open circuits" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

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
        .ip_address = "10.42.0.9",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-2",
        .container_id = "ctr-2",
        .node_id = null,
        .ip_address = "10.42.0.10",
        .port = 8081,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1001,
        .last_seen_at = 1001,
    });

    recordEndpointFailure("api-1", .{});
    recordEndpointFailure("api-1", .{});
    recordEndpointFailure("api-1", .{});

    const upstream = try resolveUpstream(std.testing.allocator, "api");
    defer upstream.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("api-2", upstream.endpoint_id);

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 1), state.circuit_trips_total);
    try std.testing.expectEqual(@as(u32, 1), state.circuit_open_endpoints);
    try std.testing.expectEqual(@as(u32, 0), state.circuit_half_open_endpoints);
}

test "per-route circuit breaker threshold controls trip point" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

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
        .ip_address = "10.42.0.9",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });

    const high_threshold: proxy_policy.CircuitBreakerPolicy = .{ .failure_threshold = 5 };

    recordEndpointFailure("api-1", high_threshold);
    recordEndpointFailure("api-1", high_threshold);
    recordEndpointFailure("api-1", high_threshold);

    // 3 failures with threshold=5 should NOT trip the circuit
    const upstream1 = try resolveUpstream(std.testing.allocator, "api");
    defer upstream1.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("api-1", upstream1.endpoint_id);

    recordEndpointFailure("api-1", high_threshold);
    recordEndpointFailure("api-1", high_threshold);

    // 5 failures with threshold=5 SHOULD trip the circuit
    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 1), state.circuit_trips_total);
    try std.testing.expectEqual(@as(u32, 1), state.circuit_open_endpoints);
}

test "route snapshots retain runtime failure details after recovery" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

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
        .ip_address = "10.42.0.9",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });

    bootstrapIfEnabled();
    recordRouteFailure("api:default", .receive);

    {
        var routes_snapshot = try snapshotServiceRoutes(std.testing.allocator, "api");
        defer {
            for (routes_snapshot.items) |route| route.deinit(std.testing.allocator);
            routes_snapshot.deinit(std.testing.allocator);
        }

        try std.testing.expectEqual(@as(usize, 1), routes_snapshot.items.len);
        try std.testing.expect(routes_snapshot.items[0].degraded);
        try std.testing.expectEqual(RouteDegradedReason.receive_failure, routes_snapshot.items[0].degraded_reason);
        try std.testing.expectEqual(RouteFailureKind.receive, routes_snapshot.items[0].last_failure_kind.?);
        try std.testing.expect(routes_snapshot.items[0].last_failure_at != null);
    }

    recordRouteRecovered("api:default");

    {
        var routes_snapshot = try snapshotServiceRoutes(std.testing.allocator, "api");
        defer {
            for (routes_snapshot.items) |route| route.deinit(std.testing.allocator);
            routes_snapshot.deinit(std.testing.allocator);
        }

        try std.testing.expectEqual(@as(usize, 1), routes_snapshot.items.len);
        try std.testing.expect(routes_snapshot.items[0].degraded);
        try std.testing.expectEqual(RouteDegradedReason.steering_not_ready, routes_snapshot.items[0].degraded_reason);
        try std.testing.expectEqual(RouteFailureKind.receive, routes_snapshot.items[0].last_failure_kind.?);
        try std.testing.expect(routes_snapshot.items[0].last_failure_at != null);
    }
}
