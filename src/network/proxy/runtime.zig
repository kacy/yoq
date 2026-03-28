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

pub const RouteSnapshot = struct {
    name: []const u8,
    service: []const u8,
    vip_address: []const u8,
    host: []const u8,
    path_prefix: []const u8,
    eligible_endpoints: u32,
    healthy_endpoints: u32,
    degraded: bool,
    degraded_reason: RouteDegradedReason,
    last_failure_kind: ?RouteFailureKind,
    last_failure_at: ?i64,
    retries: u8,
    connect_timeout_ms: u32,
    request_timeout_ms: u32,
    preserve_host: bool,
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

var mutex: std.Thread.Mutex = .{};
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

pub fn resetForTest() void {
    mutex.lock();
    defer mutex.unlock();

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
    clearLastErrorLocked();
}

pub fn bootstrapIfEnabled() void {
    if (!service_rollout.current().l7_proxy_http) return;

    mutex.lock();
    defer mutex.unlock();

    syncLocked() catch |err| {
        setLastErrorLocked(err);
        log.warn("l7 proxy runtime: bootstrap failed: {}", .{err});
    };
}

pub fn snapshot(alloc: std.mem.Allocator) !Snapshot {
    mutex.lock();
    defer mutex.unlock();

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
        .enabled = service_rollout.current().l7_proxy_http,
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

pub fn recordRequestStart() void {
    mutex.lock();
    defer mutex.unlock();
    requests_total += 1;
}

pub fn recordResponse(status: http.StatusCode) void {
    recordResponseCode(@intFromEnum(status));
}

pub fn recordResponseCode(status_code: u16) void {
    mutex.lock();
    defer mutex.unlock();

    switch (status_code) {
        200...299 => responses_2xx_total += 1,
        400...499 => responses_4xx_total += 1,
        500...599 => responses_5xx_total += 1,
        else => {},
    }
}

pub fn recordRetry() void {
    mutex.lock();
    defer mutex.unlock();
    retries_total += 1;
}

pub fn recordLoopRejection() void {
    mutex.lock();
    defer mutex.unlock();
    loop_rejections_total += 1;
}

pub fn recordUpstreamFailure(kind: UpstreamFailureKind) void {
    mutex.lock();
    defer mutex.unlock();

    switch (kind) {
        .connect => upstream_connect_failures_total += 1,
        .send => upstream_send_failures_total += 1,
        .receive => upstream_receive_failures_total += 1,
        .other => upstream_other_failures_total += 1,
    }
}

pub fn recordEndpointSuccess(endpoint_id: []const u8) void {
    mutex.lock();
    defer mutex.unlock();

    const circuit = endpoint_circuits.getPtr(endpoint_id) orelse return;
    circuit.* = .{};
}

pub fn recordEndpointFailure(endpoint_id: []const u8) void {
    mutex.lock();
    defer mutex.unlock();

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
            if (proxy_policy.shouldTripCircuit(default_circuit_policy, circuit.consecutive_failures)) {
                circuit.state = .open;
                circuit.opened_at_ms = std.time.milliTimestamp();
                circuit.half_open_in_flight = false;
                circuit_trips_total += 1;
            }
        },
        .half_open => {
            circuit.state = .open;
            circuit.opened_at_ms = std.time.milliTimestamp();
            circuit.half_open_in_flight = false;
            circuit.consecutive_failures = default_circuit_policy.failure_threshold;
            circuit_trips_total += 1;
        },
        .open => {
            circuit.opened_at_ms = std.time.milliTimestamp();
            circuit.half_open_in_flight = false;
        },
    }
}

pub fn recordRouteFailure(route_name: []const u8, kind: RouteFailureKind) void {
    mutex.lock();
    defer mutex.unlock();

    const state = ensureRouteStatusLocked(route_name) orelse return;
    state.degraded_reason = degradedReasonForFailure(kind);
    state.last_failure_kind = kind;
    state.last_failure_at = std.time.timestamp();
}

pub fn recordRouteRecovered(route_name: []const u8) void {
    mutex.lock();
    defer mutex.unlock();

    const state = route_statuses.getPtr(route_name) orelse return;
    state.degraded_reason = .none;
}

pub fn snapshotRoutes(alloc: std.mem.Allocator) !std.ArrayList(RouteSnapshot) {
    mutex.lock();
    defer mutex.unlock();

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

pub fn snapshotRouteConfigs(alloc: std.mem.Allocator) !std.ArrayList(router.Route) {
    mutex.lock();
    defer mutex.unlock();

    var routes_snapshot: std.ArrayList(router.Route) = .empty;
    errdefer {
        for (routes_snapshot.items) |route| {
            alloc.free(route.name);
            alloc.free(route.service);
            alloc.free(route.vip_address);
            if (route.match.host) |host| alloc.free(host);
            alloc.free(route.match.path_prefix);
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
            .eligible_endpoints = route.eligible_endpoints,
            .healthy_endpoints = route.healthy_endpoints,
            .degraded = route.degraded,
            .retries = route.retries,
            .connect_timeout_ms = route.connect_timeout_ms,
            .request_timeout_ms = route.request_timeout_ms,
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

    mutex.lock();
    defer mutex.unlock();

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

pub fn resolveRoute(alloc: std.mem.Allocator, host: []const u8, path: []const u8) !RouteSnapshot {
    mutex.lock();
    defer mutex.unlock();

    const matched = router.matchRoute(materialized_routes.items, host, path) orelse return error.RouteNotFound;
    return cloneRouteSnapshot(alloc, matched);
}

pub fn resolveUpstream(alloc: std.mem.Allocator, service_name: []const u8) !upstream_mod.Upstream {
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

    mutex.lock();
    defer mutex.unlock();

    const now_ms = std.time.milliTimestamp();
    for (endpoints.items) |endpoint| {
        const port: u16 = if (endpoint.port < 0) 0 else @intCast(endpoint.port);
        try candidates.append(alloc, .{
            .service = try alloc.dupe(u8, service_name),
            .endpoint_id = try alloc.dupe(u8, endpoint.endpoint_id),
            .address = try alloc.dupe(u8, endpoint.ip_address),
            .port = port,
            .eligible = endpoint.eligible and endpointAllowsRequestLocked(endpoint.endpoint_id, now_ms),
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

fn endpointAllowsRequestLocked(endpoint_id: []const u8, now_ms: i64) bool {
    const circuit = endpoint_circuits.getPtr(endpoint_id) orelse return true;

    switch (circuit.state) {
        .closed => return true,
        .open => {
            const opened_at_ms = circuit.opened_at_ms orelse return false;
            if (!proxy_policy.shouldAllowHalfOpen(default_circuit_policy, opened_at_ms, now_ms)) return false;

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

fn cloneRouteSnapshot(alloc: std.mem.Allocator, route: router.Route) !RouteSnapshot {
    const route_state = route_statuses.get(route.name);
    const steering_state = try steering_runtime.snapshotServiceStatus(alloc, route.service);
    const steering_required = service_rollout.current().dns_returns_vip;
    const degraded_reason: RouteDegradedReason = if (route_state) |state|
        if (state.degraded_reason != .none)
            state.degraded_reason
        else if (route.degraded)
            .service_state
        else if (steering_required and !steering_state.ready)
            .steering_not_ready
        else
            .none
    else if (route.degraded)
        .service_state
    else if (steering_required and !steering_state.ready)
        .steering_not_ready
    else
        .none;

    return .{
        .name = try alloc.dupe(u8, route.name),
        .service = try alloc.dupe(u8, route.service),
        .vip_address = try alloc.dupe(u8, route.vip_address),
        .host = try alloc.dupe(u8, route.match.host orelse ""),
        .path_prefix = try alloc.dupe(u8, route.match.path_prefix),
        .eligible_endpoints = route.eligible_endpoints,
        .healthy_endpoints = route.healthy_endpoints,
        .degraded = degraded_reason != .none,
        .degraded_reason = degraded_reason,
        .last_failure_kind = if (route_state) |state| state.last_failure_kind else null,
        .last_failure_at = if (route_state) |state| state.last_failure_at else null,
        .retries = route.retries,
        .connect_timeout_ms = route.connect_timeout_ms,
        .request_timeout_ms = route.request_timeout_ms,
        .preserve_host = route.preserve_host,
        .steering_desired_ports = steering_state.desired_ports,
        .steering_applied_ports = steering_state.applied_ports,
        .steering_ready = steering_state.ready,
        .steering_blocked = steering_state.blocked,
        .steering_drifted = steering_state.drifted,
        .steering_blocked_reason = steering_state.blocked_reason,
    };
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
        const host = service.http_proxy_host orelse continue;
        next_configured_services += 1;
        next_routes += 1;
        const route = router.Route{
            .name = try std.fmt.allocPrint(std.heap.page_allocator, "{s}:{s}", .{
                service.service_name,
                service.http_proxy_path_prefix orelse "/",
            }),
            .service = try std.heap.page_allocator.dupe(u8, service.service_name),
            .vip_address = try std.heap.page_allocator.dupe(u8, service.vip_address),
            .match = .{
                .host = try std.heap.page_allocator.dupe(u8, host),
                .path_prefix = try std.heap.page_allocator.dupe(u8, service.http_proxy_path_prefix orelse "/"),
            },
            .eligible_endpoints = @intCast(service.eligible_endpoints),
            .healthy_endpoints = @intCast(service.healthy_endpoints),
            .degraded = service.degraded,
            .retries = service.http_proxy_retries orelse 0,
            .connect_timeout_ms = service.http_proxy_connect_timeout_ms orelse 1000,
            .request_timeout_ms = service.http_proxy_request_timeout_ms orelse 5000,
            .preserve_host = service.http_proxy_preserve_host orelse true,
        };
        errdefer {
            std.heap.page_allocator.free(route.name);
            std.heap.page_allocator.free(route.service);
            std.heap.page_allocator.free(route.vip_address);
            if (route.match.host) |owned_host| std.heap.page_allocator.free(owned_host);
            std.heap.page_allocator.free(route.match.path_prefix);
        }
        try materialized_routes.append(std.heap.page_allocator, route);
    }

    configured_services = next_configured_services;
    routes = next_routes;
    pruneRouteStatusesLocked();
    running = true;
    last_sync_at = std.time.timestamp();
}

fn deinitRoutesLocked() void {
    for (materialized_routes.items) |route| {
        std.heap.page_allocator.free(route.name);
        std.heap.page_allocator.free(route.service);
        std.heap.page_allocator.free(route.vip_address);
        if (route.match.host) |host| std.heap.page_allocator.free(host);
        std.heap.page_allocator.free(route.match.path_prefix);
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

test "bootstrap is inert when l7 proxy flag is disabled" {
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

    try std.testing.expect(!state.enabled);
    try std.testing.expect(!state.running);
    try std.testing.expectEqual(@as(u32, 0), state.configured_services);
    try std.testing.expectEqual(@as(u32, 0), state.routes);
    try std.testing.expect(state.last_sync_at == null);
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
    try std.testing.expect(!routes_snapshot.items[0].degraded);
    try std.testing.expectEqual(RouteDegradedReason.none, routes_snapshot.items[0].degraded_reason);
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

    const route = try resolveRoute(std.testing.allocator, "api.internal", "/v1/users");
    defer route.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("api", route.service);
    try std.testing.expectEqualStrings("/v1", route.path_prefix);
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
    recordResponse(.ok);
    recordResponse(.bad_request);
    recordResponse(.bad_gateway);
    recordRetry();
    recordLoopRejection();
    recordUpstreamFailure(.connect);
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

    recordEndpointFailure("api-1");
    recordEndpointFailure("api-1");
    recordEndpointFailure("api-1");

    const upstream = try resolveUpstream(std.testing.allocator, "api");
    defer upstream.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("api-2", upstream.endpoint_id);

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 1), state.circuit_trips_total);
    try std.testing.expectEqual(@as(u32, 1), state.circuit_open_endpoints);
    try std.testing.expectEqual(@as(u32, 0), state.circuit_half_open_endpoints);
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

    bootstrapIfEnabled();
    recordRouteFailure("api:/", .receive);

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

    recordRouteRecovered("api:/");

    {
        var routes_snapshot = try snapshotServiceRoutes(std.testing.allocator, "api");
        defer {
            for (routes_snapshot.items) |route| route.deinit(std.testing.allocator);
            routes_snapshot.deinit(std.testing.allocator);
        }

        try std.testing.expectEqual(@as(usize, 1), routes_snapshot.items.len);
        try std.testing.expect(!routes_snapshot.items[0].degraded);
        try std.testing.expectEqual(RouteDegradedReason.none, routes_snapshot.items[0].degraded_reason);
        try std.testing.expectEqual(RouteFailureKind.receive, routes_snapshot.items[0].last_failure_kind.?);
        try std.testing.expect(routes_snapshot.items[0].last_failure_at != null);
    }
}
