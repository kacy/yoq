const std = @import("std");
const spec = @import("../manifest/spec.zig");

const Allocator = std.mem.Allocator;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

pub const Error = error{
    OutOfMemory,
    ServiceNotFound,
    EndpointNotFound,
};

pub const ObservedHealth = enum {
    unknown,
    healthy,
    unhealthy,

    pub fn label(self: ObservedHealth) []const u8 {
        return switch (self) {
            .unknown => "unknown",
            .healthy => "healthy",
            .unhealthy => "unhealthy",
        };
    }
};

pub const ReconcileStatus = enum {
    idle,
    pending,
    failed,

    pub fn label(self: ReconcileStatus) []const u8 {
        return switch (self) {
            .idle => "idle",
            .pending => "pending",
            .failed => "failed",
        };
    }
};

pub const ProbeApply = enum {
    applied,
    stale_generation,
};

pub const ActionKind = enum {
    reconcile_service,
};

pub const ActionReason = enum {
    boot_snapshot_loaded,
    endpoint_registered,
    endpoint_removed,
    endpoint_admin_changed,
    probe_result,
    reconcile_requested,
};

pub const Action = struct {
    kind: ActionKind = .reconcile_service,
    reason: ActionReason,
    service_name_buf: [128]u8 = [_]u8{0} ** 128,
    service_name_len: u8 = 0,

    pub fn serviceName(self: *const Action) []const u8 {
        return self.service_name_buf[0..self.service_name_len];
    }
};

pub const ServiceDefinition = struct {
    service_name: []const u8,
    vip_address: []const u8,
    lb_policy: []const u8,
    http_routes: []const HttpRouteDefinition = &.{},
    http_proxy_host: ?[]const u8 = null,
    http_proxy_path_prefix: ?[]const u8 = null,
    http_proxy_rewrite_prefix: ?[]const u8 = null,
    http_proxy_retries: ?u8 = null,
    http_proxy_connect_timeout_ms: ?u32 = null,
    http_proxy_request_timeout_ms: ?u32 = null,
    http_proxy_http2_idle_timeout_ms: ?u32 = null,
    http_proxy_target_port: ?u16 = null,
    http_proxy_preserve_host: ?bool = null,
    http_proxy_retry_on_5xx: ?bool = null,
    http_proxy_circuit_breaker_threshold: ?u8 = null,
    http_proxy_circuit_breaker_timeout_ms: ?u32 = null,
    http_proxy_mirror_service: ?[]const u8 = null,
    /// service-to-service mTLS posture for traffic *to* this service.
    /// copied verbatim from the manifest's `service.<name>.tls.peer`.
    peer_mode: spec.TlsConfig.PeerMode = .off,
};

pub const HttpRouteDefinition = struct {
    route_name: []const u8,
    host: []const u8,
    path_prefix: []const u8 = "/",
    rewrite_prefix: ?[]const u8 = null,
    match_methods: []const HttpMethodMatch = &.{},
    match_headers: []const HttpHeaderMatch = &.{},
    backend_services: []const HttpRouteBackend = &.{},
    mirror_service: ?[]const u8 = null,
    retries: u8 = 0,
    connect_timeout_ms: u32 = 1000,
    request_timeout_ms: u32 = 5000,
    http2_idle_timeout_ms: u32 = 30000,
    target_port: ?u16 = null,
    preserve_host: bool = true,
    retry_on_5xx: bool = true,
    circuit_breaker_threshold: u8 = 3,
    circuit_breaker_timeout_ms: u32 = 30_000,
};

pub const HttpMethodMatch = struct {
    method: []const u8,

    pub fn deinit(self: HttpMethodMatch, alloc: Allocator) void {
        alloc.free(self.method);
    }
};

pub const HttpHeaderMatch = struct {
    name: []const u8,
    value: []const u8,

    pub fn deinit(self: HttpHeaderMatch, alloc: Allocator) void {
        alloc.free(self.name);
        alloc.free(self.value);
    }
};

pub const HttpRouteBackend = struct {
    service_name: []const u8,
    weight: u8,

    pub fn deinit(self: HttpRouteBackend, alloc: Allocator) void {
        alloc.free(self.service_name);
    }
};

pub const EndpointDefinition = struct {
    endpoint_id: []const u8,
    container_id: []const u8,
    node_id: ?i64,
    ip_address: []const u8,
    port: i64,
    weight: i64,
    admin_state: []const u8,
    generation: i64,
    registered_at: i64,
    last_seen_at: i64,
};

pub const EndpointSnapshot = struct {
    endpoint_id: []const u8,
    container_id: []const u8,
    node_id: ?i64,
    ip_address: []const u8,
    port: i64,
    weight: i64,
    admin_state: []const u8,
    generation: i64,
    registered_at: i64,
    last_seen_at: i64,
    observed_health: []const u8,
    eligible: bool,
    readiness_required: bool,
    last_transition_at: ?i64,

    pub fn deinit(self: EndpointSnapshot, alloc: Allocator) void {
        alloc.free(self.endpoint_id);
        alloc.free(self.container_id);
        alloc.free(self.ip_address);
        alloc.free(self.admin_state);
        alloc.free(self.observed_health);
    }
};

pub const ServiceSnapshot = struct {
    service_name: []const u8,
    vip_address: []const u8,
    lb_policy: []const u8,
    http_routes: []const HttpRouteSnapshot,
    http_proxy_host: ?[]const u8,
    http_proxy_path_prefix: ?[]const u8,
    http_proxy_rewrite_prefix: ?[]const u8,
    http_proxy_retries: ?u8,
    http_proxy_connect_timeout_ms: ?u32,
    http_proxy_request_timeout_ms: ?u32,
    http_proxy_http2_idle_timeout_ms: ?u32,
    http_proxy_target_port: ?u16,
    http_proxy_preserve_host: ?bool,
    http_proxy_retry_on_5xx: ?bool,
    http_proxy_circuit_breaker_threshold: ?u8,
    http_proxy_circuit_breaker_timeout_ms: ?u32,
    http_proxy_mirror_service: ?[]const u8,
    peer_mode: spec.TlsConfig.PeerMode = .off,
    total_endpoints: usize,
    eligible_endpoints: usize,
    healthy_endpoints: usize,
    draining_endpoints: usize,
    last_reconcile_status: []const u8,
    last_reconcile_error: ?[]const u8,
    last_reconcile_requested_at: ?i64,
    overflow: bool,
    degraded: bool,

    pub fn deinit(self: ServiceSnapshot, alloc: Allocator) void {
        alloc.free(self.service_name);
        alloc.free(self.vip_address);
        alloc.free(self.lb_policy);
        for (self.http_routes) |route| route.deinit(alloc);
        alloc.free(self.http_routes);
        if (self.http_proxy_host) |host| alloc.free(host);
        if (self.http_proxy_path_prefix) |path_prefix| alloc.free(path_prefix);
        if (self.http_proxy_rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
        if (self.http_proxy_mirror_service) |mirror_service| alloc.free(mirror_service);
        alloc.free(self.last_reconcile_status);
        if (self.last_reconcile_error) |message| alloc.free(message);
    }
};

pub const HttpRouteSnapshot = struct {
    route_name: []const u8,
    host: []const u8,
    path_prefix: []const u8,
    rewrite_prefix: ?[]const u8,
    match_methods: []const HttpMethodMatch,
    match_headers: []const HttpHeaderMatch,
    backend_services: []const HttpRouteBackend,
    mirror_service: ?[]const u8,
    retries: u8,
    connect_timeout_ms: u32,
    request_timeout_ms: u32,
    http2_idle_timeout_ms: u32,
    target_port: ?u16,
    preserve_host: bool,
    retry_on_5xx: bool = true,
    circuit_breaker_threshold: u8 = 3,
    circuit_breaker_timeout_ms: u32 = 30_000,

    pub fn deinit(self: HttpRouteSnapshot, alloc: Allocator) void {
        alloc.free(self.route_name);
        alloc.free(self.host);
        alloc.free(self.path_prefix);
        if (self.rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
        for (self.match_methods) |method_match| method_match.deinit(alloc);
        if (self.match_methods.len > 0) alloc.free(self.match_methods);
        for (self.match_headers) |header_match| header_match.deinit(alloc);
        if (self.match_headers.len > 0) alloc.free(self.match_headers);
        for (self.backend_services) |backend| backend.deinit(alloc);
        if (self.backend_services.len > 0) alloc.free(self.backend_services);
        if (self.mirror_service) |mirror_service| alloc.free(mirror_service);
    }
};

const EndpointState = struct {
    endpoint_id: []const u8,
    container_id: []const u8,
    node_id: ?i64,
    ip_address: []const u8,
    port: i64,
    weight: i64,
    admin_state: []const u8,
    generation: i64,
    registered_at: i64,
    last_seen_at: i64,
    observed_health: ObservedHealth = .unknown,
    readiness_required: bool = false,
    node_lost: bool = false,
    last_transition_at: ?i64 = null,

    fn deinit(self: EndpointState, alloc: Allocator) void {
        alloc.free(self.endpoint_id);
        alloc.free(self.container_id);
        alloc.free(self.ip_address);
        alloc.free(self.admin_state);
    }
};

const ServiceState = struct {
    service_name: []const u8,
    vip_address: []const u8,
    lb_policy: []const u8,
    http_routes: std.ArrayList(HttpRouteState) = .empty,
    http_proxy_host: ?[]const u8 = null,
    http_proxy_path_prefix: ?[]const u8 = null,
    http_proxy_rewrite_prefix: ?[]const u8 = null,
    http_proxy_retries: ?u8 = null,
    http_proxy_connect_timeout_ms: ?u32 = null,
    http_proxy_request_timeout_ms: ?u32 = null,
    http_proxy_http2_idle_timeout_ms: ?u32 = null,
    http_proxy_target_port: ?u16 = null,
    http_proxy_preserve_host: ?bool = null,
    http_proxy_retry_on_5xx: ?bool = null,
    http_proxy_circuit_breaker_threshold: ?u8 = null,
    http_proxy_circuit_breaker_timeout_ms: ?u32 = null,
    http_proxy_mirror_service: ?[]const u8 = null,
    peer_mode: spec.TlsConfig.PeerMode = .off,
    endpoints: std.ArrayList(EndpointState) = .empty,
    last_reconcile_status: ReconcileStatus = .idle,
    last_reconcile_error: ?[]const u8 = null,
    last_reconcile_requested_at: ?i64 = null,
    overflow: bool = false,

    fn deinit(self: *ServiceState, alloc: Allocator) void {
        alloc.free(self.service_name);
        alloc.free(self.vip_address);
        alloc.free(self.lb_policy);
        for (self.http_routes.items) |route| route.deinit(alloc);
        self.http_routes.deinit(alloc);
        if (self.http_proxy_host) |host| alloc.free(host);
        if (self.http_proxy_path_prefix) |path_prefix| alloc.free(path_prefix);
        if (self.http_proxy_rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
        if (self.http_proxy_mirror_service) |mirror_service| alloc.free(mirror_service);
        if (self.last_reconcile_error) |message| alloc.free(message);
        for (self.endpoints.items) |endpoint| endpoint.deinit(alloc);
        self.endpoints.deinit(alloc);
    }
};

const HttpRouteState = struct {
    route_name: []const u8,
    host: []const u8,
    path_prefix: []const u8,
    rewrite_prefix: ?[]const u8,
    match_methods: []const HttpMethodMatch,
    match_headers: []const HttpHeaderMatch,
    backend_services: []const HttpRouteBackend,
    mirror_service: ?[]const u8,
    retries: u8,
    connect_timeout_ms: u32,
    request_timeout_ms: u32,
    http2_idle_timeout_ms: u32,
    target_port: ?u16,
    preserve_host: bool,
    retry_on_5xx: bool = true,
    circuit_breaker_threshold: u8 = 3,
    circuit_breaker_timeout_ms: u32 = 30_000,

    fn deinit(self: HttpRouteState, alloc: Allocator) void {
        alloc.free(self.route_name);
        alloc.free(self.host);
        alloc.free(self.path_prefix);
        if (self.rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
        for (self.match_methods) |method_match| method_match.deinit(alloc);
        if (self.match_methods.len > 0) alloc.free(self.match_methods);
        for (self.match_headers) |header_match| header_match.deinit(alloc);
        if (self.match_headers.len > 0) alloc.free(self.match_headers);
        for (self.backend_services) |backend| backend.deinit(alloc);
        if (self.backend_services.len > 0) alloc.free(self.backend_services);
        if (self.mirror_service) |mirror_service| alloc.free(mirror_service);
    }
};

pub const Registry = struct {
    alloc: Allocator,
    services: std.ArrayList(ServiceState) = .empty,

    pub fn init(alloc: Allocator) Registry {
        return .{
            .alloc = alloc,
            .services = .empty,
        };
    }

    pub fn deinit(self: *Registry) void {
        for (self.services.items) |*service| service.deinit(self.alloc);
        self.services.deinit(self.alloc);
    }

    pub fn upsertService(self: *Registry, definition: ServiceDefinition) Error!void {
        if (self.findServiceIndex(definition.service_name)) |service_index| {
            var service = &self.services.items[service_index];
            try replaceOwned(self.alloc, &service.vip_address, definition.vip_address);
            try replaceOwned(self.alloc, &service.lb_policy, definition.lb_policy);
            try replaceRoutesFromDefinition(self.alloc, &service.http_routes, definition);
            try assignCompatProxyFields(self.alloc, service, definition);
            return;
        }

        var service = ServiceState{
            .service_name = &.{},
            .vip_address = &.{},
            .lb_policy = &.{},
        };
        errdefer service.deinit(self.alloc);

        service.service_name = try self.alloc.dupe(u8, definition.service_name);
        service.vip_address = try self.alloc.dupe(u8, definition.vip_address);
        service.lb_policy = try self.alloc.dupe(u8, definition.lb_policy);
        service.http_routes = try cloneRoutesFromDefinition(self.alloc, definition);
        try assignCompatProxyFields(self.alloc, &service, definition);
        try self.services.append(self.alloc, service);
    }

    pub fn removeService(self: *Registry, service_name: []const u8) bool {
        const service_index = self.findServiceIndex(service_name) orelse return false;
        var service = self.services.orderedRemove(service_index);
        service.deinit(self.alloc);
        return true;
    }

    pub fn replaceServiceEndpoints(self: *Registry, service_name: []const u8, definitions: []const EndpointDefinition) Error!void {
        const service_index = self.findServiceIndex(service_name) orelse return Error.ServiceNotFound;
        var service = &self.services.items[service_index];

        var next_endpoints: std.ArrayList(EndpointState) = .empty;
        errdefer deinitEndpoints(self.alloc, &next_endpoints);

        for (definitions) |definition| {
            var endpoint = try cloneEndpoint(self.alloc, definition);
            errdefer endpoint.deinit(self.alloc);
            if (findEndpoint(service.endpoints.items, definition.endpoint_id)) |existing| {
                endpoint.readiness_required = existing.readiness_required;
                endpoint.node_lost = existing.node_lost;
                if (existing.generation == definition.generation) {
                    endpoint.observed_health = existing.observed_health;
                    endpoint.last_transition_at = existing.last_transition_at;
                }
            }
            try next_endpoints.append(self.alloc, endpoint);
        }

        deinitEndpoints(self.alloc, &service.endpoints);
        service.endpoints = next_endpoints;
    }

    pub fn removeEndpointsByContainer(self: *Registry, container_id: []const u8) usize {
        var removed: usize = 0;
        for (self.services.items) |*service| {
            var idx: usize = 0;
            while (idx < service.endpoints.items.len) {
                if (std.mem.eql(u8, service.endpoints.items[idx].container_id, container_id)) {
                    var endpoint = service.endpoints.orderedRemove(idx);
                    endpoint.deinit(self.alloc);
                    removed += 1;
                    continue;
                }
                idx += 1;
            }
        }
        return removed;
    }

    pub fn removeServiceEndpoint(self: *Registry, service_name: []const u8, endpoint_id: []const u8) Error!Action {
        const service = try self.getServiceMut(service_name);
        const endpoint_index = findEndpointIndex(service.endpoints.items, endpoint_id) orelse return Error.EndpointNotFound;
        var endpoint = service.endpoints.orderedRemove(endpoint_index);
        endpoint.deinit(self.alloc);
        return buildAction(service_name, .endpoint_removed);
    }

    pub fn markEndpointAdminState(self: *Registry, service_name: []const u8, endpoint_id: []const u8, admin_state: []const u8) Error!Action {
        const endpoint = try self.getEndpointMut(service_name, endpoint_id);
        try replaceOwned(self.alloc, &endpoint.admin_state, admin_state);
        endpoint.last_transition_at = nowRealSeconds();
        return buildAction(service_name, .endpoint_admin_changed);
    }

    pub fn noteProbeResult(self: *Registry, service_name: []const u8, endpoint_id: []const u8, healthy: bool) Error!Action {
        const endpoint = try self.getEndpointMut(service_name, endpoint_id);
        endpoint.observed_health = if (healthy) .healthy else .unhealthy;
        endpoint.last_transition_at = nowRealSeconds();
        return buildAction(service_name, .probe_result);
    }

    pub fn markEndpointPending(self: *Registry, service_name: []const u8, endpoint_id: []const u8, generation: i64) Error!ProbeApply {
        const endpoint = try self.getEndpointMut(service_name, endpoint_id);
        if (endpoint.generation != generation) return .stale_generation;
        endpoint.readiness_required = true;
        endpoint.observed_health = .unknown;
        endpoint.last_transition_at = nowRealSeconds();
        return .applied;
    }

    pub fn noteProbeResultForGeneration(
        self: *Registry,
        service_name: []const u8,
        endpoint_id: []const u8,
        generation: i64,
        healthy: bool,
    ) Error!ProbeApply {
        const endpoint = try self.getEndpointMut(service_name, endpoint_id);
        if (endpoint.generation != generation) return .stale_generation;
        endpoint.observed_health = if (healthy) .healthy else .unhealthy;
        endpoint.last_transition_at = nowRealSeconds();
        return .applied;
    }

    pub fn requestReconcile(self: *Registry, service_name: []const u8) Error!Action {
        const service = try self.getServiceMut(service_name);
        service.last_reconcile_status = .pending;
        service.last_reconcile_requested_at = nowRealSeconds();
        if (service.last_reconcile_error) |message| {
            self.alloc.free(message);
            service.last_reconcile_error = null;
        }
        return buildAction(service_name, .reconcile_requested);
    }

    pub fn ensureEndpointExists(self: *const Registry, service_name: []const u8, endpoint_id: []const u8) Error!void {
        const service_index = self.findServiceIndex(service_name) orelse return Error.ServiceNotFound;
        if (findEndpointIndex(self.services.items[service_index].endpoints.items, endpoint_id) == null) {
            return Error.EndpointNotFound;
        }
    }

    pub fn noteNodeLost(self: *Registry, node_id: i64) usize {
        var changed: usize = 0;
        const now = nowRealSeconds();
        for (self.services.items) |*service| {
            for (service.endpoints.items) |*endpoint| {
                if (endpoint.node_id != node_id) continue;
                if (endpoint.node_lost) continue;
                endpoint.node_lost = true;
                endpoint.last_transition_at = now;
                changed += 1;
            }
        }
        return changed;
    }

    pub fn noteNodeRecovered(self: *Registry, node_id: i64) usize {
        var changed: usize = 0;
        const now = nowRealSeconds();
        for (self.services.items) |*service| {
            for (service.endpoints.items) |*endpoint| {
                if (endpoint.node_id != node_id) continue;
                if (!endpoint.node_lost) continue;
                endpoint.node_lost = false;
                endpoint.last_transition_at = now;
                changed += 1;
            }
        }
        return changed;
    }

    pub fn markReconcileSucceeded(self: *Registry, service_name: []const u8) Error!void {
        const service = try self.getServiceMut(service_name);
        service.last_reconcile_status = .idle;
        if (service.last_reconcile_error) |message| {
            self.alloc.free(message);
            service.last_reconcile_error = null;
        }
    }

    pub fn markReconcileFailed(self: *Registry, service_name: []const u8, message: []const u8) Error!void {
        const service = try self.getServiceMut(service_name);
        service.last_reconcile_status = .failed;
        if (service.last_reconcile_error) |current| self.alloc.free(current);
        service.last_reconcile_error = try self.alloc.dupe(u8, message);
    }

    pub fn snapshotServices(self: *const Registry, alloc: Allocator) Error!std.ArrayList(ServiceSnapshot) {
        var services: std.ArrayList(ServiceSnapshot) = .empty;
        errdefer deinitServiceSnapshots(alloc, &services);

        for (self.services.items) |service| {
            const snapshot = try cloneServiceSnapshot(alloc, &service);
            errdefer snapshot.deinit(alloc);
            try services.append(alloc, snapshot);
        }
        return services;
    }

    pub fn snapshotService(self: *const Registry, alloc: Allocator, service_name: []const u8) Error!ServiceSnapshot {
        const service_index = self.findServiceIndex(service_name) orelse return Error.ServiceNotFound;
        return cloneServiceSnapshot(alloc, &self.services.items[service_index]);
    }

    pub fn snapshotServiceEndpoints(self: *const Registry, alloc: Allocator, service_name: []const u8) Error!std.ArrayList(EndpointSnapshot) {
        const service_index = self.findServiceIndex(service_name) orelse return Error.ServiceNotFound;
        const service = &self.services.items[service_index];

        var endpoints: std.ArrayList(EndpointSnapshot) = .empty;
        errdefer deinitEndpointSnapshots(alloc, &endpoints);

        for (service.endpoints.items) |endpoint| {
            const snapshot = try cloneEndpointSnapshot(alloc, &endpoint);
            errdefer snapshot.deinit(alloc);
            try endpoints.append(alloc, snapshot);
        }
        return endpoints;
    }

    fn getServiceMut(self: *Registry, service_name: []const u8) Error!*ServiceState {
        const service_index = self.findServiceIndex(service_name) orelse return Error.ServiceNotFound;
        return &self.services.items[service_index];
    }

    fn getEndpointMut(self: *Registry, service_name: []const u8, endpoint_id: []const u8) Error!*EndpointState {
        const service = try self.getServiceMut(service_name);
        const endpoint_index = findEndpointIndex(service.endpoints.items, endpoint_id) orelse return Error.EndpointNotFound;
        return &service.endpoints.items[endpoint_index];
    }

    fn findServiceIndex(self: *const Registry, service_name: []const u8) ?usize {
        for (self.services.items, 0..) |service, idx| {
            if (std.mem.eql(u8, service.service_name, service_name)) return idx;
        }
        return null;
    }
};

fn findEndpoint(endpoints: []const EndpointState, endpoint_id: []const u8) ?*const EndpointState {
    for (endpoints) |*endpoint| {
        if (std.mem.eql(u8, endpoint.endpoint_id, endpoint_id)) return endpoint;
    }
    return null;
}

fn findEndpointIndex(endpoints: []const EndpointState, endpoint_id: []const u8) ?usize {
    for (endpoints, 0..) |endpoint, idx| {
        if (std.mem.eql(u8, endpoint.endpoint_id, endpoint_id)) return idx;
    }
    return null;
}

fn cloneEndpoint(alloc: Allocator, definition: EndpointDefinition) Error!EndpointState {
    const owned_endpoint_id = try alloc.dupe(u8, definition.endpoint_id);
    errdefer alloc.free(owned_endpoint_id);
    const owned_container_id = try alloc.dupe(u8, definition.container_id);
    errdefer alloc.free(owned_container_id);
    const owned_ip_address = try alloc.dupe(u8, definition.ip_address);
    errdefer alloc.free(owned_ip_address);
    const owned_admin_state = try alloc.dupe(u8, definition.admin_state);
    errdefer alloc.free(owned_admin_state);

    return .{
        .endpoint_id = owned_endpoint_id,
        .container_id = owned_container_id,
        .node_id = definition.node_id,
        .ip_address = owned_ip_address,
        .port = definition.port,
        .weight = definition.weight,
        .admin_state = owned_admin_state,
        .generation = definition.generation,
        .registered_at = definition.registered_at,
        .last_seen_at = definition.last_seen_at,
    };
}

fn cloneEndpointSnapshot(alloc: Allocator, endpoint: *const EndpointState) Error!EndpointSnapshot {
    const owned_endpoint_id = try alloc.dupe(u8, endpoint.endpoint_id);
    errdefer alloc.free(owned_endpoint_id);
    const owned_container_id = try alloc.dupe(u8, endpoint.container_id);
    errdefer alloc.free(owned_container_id);
    const owned_ip_address = try alloc.dupe(u8, endpoint.ip_address);
    errdefer alloc.free(owned_ip_address);
    const owned_admin_state = try alloc.dupe(u8, endpoint.admin_state);
    errdefer alloc.free(owned_admin_state);
    const owned_observed_health = try alloc.dupe(u8, endpoint.observed_health.label());
    errdefer alloc.free(owned_observed_health);

    return .{
        .endpoint_id = owned_endpoint_id,
        .container_id = owned_container_id,
        .node_id = endpoint.node_id,
        .ip_address = owned_ip_address,
        .port = endpoint.port,
        .weight = endpoint.weight,
        .admin_state = owned_admin_state,
        .generation = endpoint.generation,
        .registered_at = endpoint.registered_at,
        .last_seen_at = endpoint.last_seen_at,
        .observed_health = owned_observed_health,
        .eligible = isEndpointEligible(endpoint),
        .readiness_required = endpoint.readiness_required,
        .last_transition_at = endpoint.last_transition_at,
    };
}

fn cloneServiceSnapshot(alloc: Allocator, service: *const ServiceState) Error!ServiceSnapshot {
    var total_endpoints: usize = 0;
    var eligible_endpoints: usize = 0;
    var healthy_endpoints: usize = 0;
    var draining_endpoints: usize = 0;

    for (service.endpoints.items) |endpoint| {
        total_endpoints += 1;
        if (std.mem.eql(u8, endpoint.admin_state, "draining")) draining_endpoints += 1;
        if (endpoint.observed_health == .healthy) healthy_endpoints += 1;
        if (isEndpointEligible(&endpoint)) eligible_endpoints += 1;
    }

    const routes = try cloneRouteSnapshots(alloc, service.http_routes.items);
    errdefer {
        for (routes) |route| route.deinit(alloc);
        alloc.free(routes);
    }

    const owned_service_name = try alloc.dupe(u8, service.service_name);
    errdefer alloc.free(owned_service_name);
    const owned_vip_address = try alloc.dupe(u8, service.vip_address);
    errdefer alloc.free(owned_vip_address);
    const owned_lb_policy = try alloc.dupe(u8, service.lb_policy);
    errdefer alloc.free(owned_lb_policy);
    const owned_http_proxy_host = if (service.http_proxy_host) |host| try alloc.dupe(u8, host) else null;
    errdefer if (owned_http_proxy_host) |value| alloc.free(value);
    const owned_http_proxy_path_prefix = if (service.http_proxy_path_prefix) |path_prefix| try alloc.dupe(u8, path_prefix) else null;
    errdefer if (owned_http_proxy_path_prefix) |value| alloc.free(value);
    const owned_http_proxy_rewrite_prefix = if (service.http_proxy_rewrite_prefix) |rewrite_prefix| try alloc.dupe(u8, rewrite_prefix) else null;
    errdefer if (owned_http_proxy_rewrite_prefix) |value| alloc.free(value);
    const owned_http_proxy_mirror_service = if (service.http_proxy_mirror_service) |mirror_service| try alloc.dupe(u8, mirror_service) else null;
    errdefer if (owned_http_proxy_mirror_service) |value| alloc.free(value);
    const owned_last_reconcile_status = try alloc.dupe(u8, service.last_reconcile_status.label());
    errdefer alloc.free(owned_last_reconcile_status);
    const owned_last_reconcile_error = if (service.last_reconcile_error) |message| try alloc.dupe(u8, message) else null;
    errdefer if (owned_last_reconcile_error) |value| alloc.free(value);

    return .{
        .service_name = owned_service_name,
        .vip_address = owned_vip_address,
        .lb_policy = owned_lb_policy,
        .http_routes = routes,
        .http_proxy_host = owned_http_proxy_host,
        .http_proxy_path_prefix = owned_http_proxy_path_prefix,
        .http_proxy_rewrite_prefix = owned_http_proxy_rewrite_prefix,
        .http_proxy_retries = service.http_proxy_retries,
        .http_proxy_connect_timeout_ms = service.http_proxy_connect_timeout_ms,
        .http_proxy_request_timeout_ms = service.http_proxy_request_timeout_ms,
        .http_proxy_http2_idle_timeout_ms = service.http_proxy_http2_idle_timeout_ms,
        .http_proxy_target_port = service.http_proxy_target_port,
        .http_proxy_preserve_host = service.http_proxy_preserve_host,
        .http_proxy_retry_on_5xx = service.http_proxy_retry_on_5xx,
        .http_proxy_circuit_breaker_threshold = service.http_proxy_circuit_breaker_threshold,
        .http_proxy_circuit_breaker_timeout_ms = service.http_proxy_circuit_breaker_timeout_ms,
        .http_proxy_mirror_service = owned_http_proxy_mirror_service,
        .peer_mode = service.peer_mode,
        .total_endpoints = total_endpoints,
        .eligible_endpoints = eligible_endpoints,
        .healthy_endpoints = healthy_endpoints,
        .draining_endpoints = draining_endpoints,
        .last_reconcile_status = owned_last_reconcile_status,
        .last_reconcile_error = owned_last_reconcile_error,
        .last_reconcile_requested_at = service.last_reconcile_requested_at,
        .overflow = service.overflow,
        .degraded = service.overflow or service.last_reconcile_status == .failed or eligible_endpoints == 0,
    };
}

fn cloneRoutesFromDefinition(alloc: Allocator, definition: ServiceDefinition) Error!std.ArrayList(HttpRouteState) {
    var routes: std.ArrayList(HttpRouteState) = .empty;
    errdefer deinitRoutes(alloc, &routes);

    if (definition.http_routes.len > 0) {
        for (definition.http_routes) |route| {
            const owned_route_name = try alloc.dupe(u8, route.route_name);
            errdefer alloc.free(owned_route_name);
            const owned_host = try alloc.dupe(u8, route.host);
            errdefer alloc.free(owned_host);
            const owned_path_prefix = try alloc.dupe(u8, route.path_prefix);
            errdefer alloc.free(owned_path_prefix);
            const owned_rewrite_prefix = if (route.rewrite_prefix) |rewrite_prefix| try alloc.dupe(u8, rewrite_prefix) else null;
            errdefer if (owned_rewrite_prefix) |value| alloc.free(value);
            const owned_match_methods = try cloneMethodMatches(alloc, route.match_methods);
            errdefer {
                for (owned_match_methods) |item| item.deinit(alloc);
                alloc.free(owned_match_methods);
            }
            const owned_match_headers = try cloneHeaderMatches(alloc, route.match_headers);
            errdefer {
                for (owned_match_headers) |item| item.deinit(alloc);
                alloc.free(owned_match_headers);
            }
            const owned_backend_services = try cloneRouteBackends(alloc, route.backend_services);
            errdefer {
                for (owned_backend_services) |item| item.deinit(alloc);
                alloc.free(owned_backend_services);
            }
            const owned_mirror_service = if (route.mirror_service) |mirror_service| try alloc.dupe(u8, mirror_service) else null;
            errdefer if (owned_mirror_service) |value| alloc.free(value);

            try routes.append(alloc, .{
                .route_name = owned_route_name,
                .host = owned_host,
                .path_prefix = owned_path_prefix,
                .rewrite_prefix = owned_rewrite_prefix,
                .match_methods = owned_match_methods,
                .match_headers = owned_match_headers,
                .backend_services = owned_backend_services,
                .mirror_service = owned_mirror_service,
                .retries = route.retries,
                .connect_timeout_ms = route.connect_timeout_ms,
                .request_timeout_ms = route.request_timeout_ms,
                .http2_idle_timeout_ms = route.http2_idle_timeout_ms,
                .target_port = route.target_port,
                .preserve_host = route.preserve_host,
                .retry_on_5xx = route.retry_on_5xx,
                .circuit_breaker_threshold = route.circuit_breaker_threshold,
                .circuit_breaker_timeout_ms = route.circuit_breaker_timeout_ms,
            });
        }
        return routes;
    }

    if (definition.http_proxy_host) |host| {
        const owned_route_name = try alloc.dupe(u8, "default");
        errdefer alloc.free(owned_route_name);
        const owned_host = try alloc.dupe(u8, host);
        errdefer alloc.free(owned_host);
        const owned_path_prefix = try alloc.dupe(u8, definition.http_proxy_path_prefix orelse "/");
        errdefer alloc.free(owned_path_prefix);
        const owned_rewrite_prefix = if (definition.http_proxy_rewrite_prefix) |rewrite_prefix| try alloc.dupe(u8, rewrite_prefix) else null;
        errdefer if (owned_rewrite_prefix) |value| alloc.free(value);
        const owned_backend_services = try defaultRouteBackends(alloc, definition.service_name);
        errdefer {
            for (owned_backend_services) |item| item.deinit(alloc);
            alloc.free(owned_backend_services);
        }
        const owned_mirror_service = if (definition.http_proxy_mirror_service) |mirror_service| try alloc.dupe(u8, mirror_service) else null;
        errdefer if (owned_mirror_service) |value| alloc.free(value);

        try routes.append(alloc, .{
            .route_name = owned_route_name,
            .host = owned_host,
            .path_prefix = owned_path_prefix,
            .rewrite_prefix = owned_rewrite_prefix,
            .match_methods = &.{},
            .match_headers = &.{},
            .backend_services = owned_backend_services,
            .mirror_service = owned_mirror_service,
            .retries = definition.http_proxy_retries orelse 0,
            .connect_timeout_ms = definition.http_proxy_connect_timeout_ms orelse 1000,
            .request_timeout_ms = definition.http_proxy_request_timeout_ms orelse 5000,
            .http2_idle_timeout_ms = definition.http_proxy_http2_idle_timeout_ms orelse 30000,
            .target_port = definition.http_proxy_target_port,
            .preserve_host = definition.http_proxy_preserve_host orelse true,
            .retry_on_5xx = definition.http_proxy_retry_on_5xx orelse true,
            .circuit_breaker_threshold = definition.http_proxy_circuit_breaker_threshold orelse 3,
            .circuit_breaker_timeout_ms = definition.http_proxy_circuit_breaker_timeout_ms orelse 30_000,
        });
    }

    return routes;
}

fn replaceRoutesFromDefinition(alloc: Allocator, current: *std.ArrayList(HttpRouteState), definition: ServiceDefinition) Error!void {
    const next = try cloneRoutesFromDefinition(alloc, definition);
    deinitRoutes(alloc, current);
    current.* = next;
}

fn cloneRouteSnapshots(alloc: Allocator, routes: []const HttpRouteState) Error![]const HttpRouteSnapshot {
    var snapshots: std.ArrayList(HttpRouteSnapshot) = .empty;
    errdefer {
        for (snapshots.items) |route| route.deinit(alloc);
        snapshots.deinit(alloc);
    }

    for (routes) |route| {
        const owned_route_name = try alloc.dupe(u8, route.route_name);
        errdefer alloc.free(owned_route_name);
        const owned_host = try alloc.dupe(u8, route.host);
        errdefer alloc.free(owned_host);
        const owned_path_prefix = try alloc.dupe(u8, route.path_prefix);
        errdefer alloc.free(owned_path_prefix);
        const owned_rewrite_prefix = if (route.rewrite_prefix) |rewrite_prefix| try alloc.dupe(u8, rewrite_prefix) else null;
        errdefer if (owned_rewrite_prefix) |value| alloc.free(value);
        const owned_match_methods = try cloneMethodMatches(alloc, route.match_methods);
        errdefer {
            for (owned_match_methods) |item| item.deinit(alloc);
            alloc.free(owned_match_methods);
        }
        const owned_match_headers = try cloneHeaderMatches(alloc, route.match_headers);
        errdefer {
            for (owned_match_headers) |item| item.deinit(alloc);
            alloc.free(owned_match_headers);
        }
        const owned_backend_services = try cloneRouteBackends(alloc, route.backend_services);
        errdefer {
            for (owned_backend_services) |item| item.deinit(alloc);
            alloc.free(owned_backend_services);
        }
        const owned_mirror_service = if (route.mirror_service) |mirror_service| try alloc.dupe(u8, mirror_service) else null;
        errdefer if (owned_mirror_service) |value| alloc.free(value);

        try snapshots.append(alloc, .{
            .route_name = owned_route_name,
            .host = owned_host,
            .path_prefix = owned_path_prefix,
            .rewrite_prefix = owned_rewrite_prefix,
            .match_methods = owned_match_methods,
            .match_headers = owned_match_headers,
            .backend_services = owned_backend_services,
            .mirror_service = owned_mirror_service,
            .retries = route.retries,
            .connect_timeout_ms = route.connect_timeout_ms,
            .request_timeout_ms = route.request_timeout_ms,
            .http2_idle_timeout_ms = route.http2_idle_timeout_ms,
            .target_port = route.target_port,
            .preserve_host = route.preserve_host,
            .retry_on_5xx = route.retry_on_5xx,
            .circuit_breaker_threshold = route.circuit_breaker_threshold,
            .circuit_breaker_timeout_ms = route.circuit_breaker_timeout_ms,
        });
    }

    return snapshots.toOwnedSlice(alloc);
}

fn assignCompatProxyFields(alloc: Allocator, service: *ServiceState, definition: ServiceDefinition) Error!void {
    if (service.http_routes.items.len > 0) {
        const primary = service.http_routes.items[0];
        try replaceOptionalOwned(alloc, &service.http_proxy_host, primary.host);
        try replaceOptionalOwned(alloc, &service.http_proxy_path_prefix, primary.path_prefix);
        try replaceOptionalOwned(alloc, &service.http_proxy_rewrite_prefix, primary.rewrite_prefix);
        service.http_proxy_retries = primary.retries;
        service.http_proxy_connect_timeout_ms = primary.connect_timeout_ms;
        service.http_proxy_request_timeout_ms = primary.request_timeout_ms;
        service.http_proxy_http2_idle_timeout_ms = primary.http2_idle_timeout_ms;
        service.http_proxy_target_port = primary.target_port;
        service.http_proxy_preserve_host = primary.preserve_host;
        service.http_proxy_retry_on_5xx = primary.retry_on_5xx;
        service.http_proxy_circuit_breaker_threshold = primary.circuit_breaker_threshold;
        service.http_proxy_circuit_breaker_timeout_ms = primary.circuit_breaker_timeout_ms;
        try replaceOptionalOwned(alloc, &service.http_proxy_mirror_service, primary.mirror_service);
        return;
    }

    try replaceOptionalOwned(alloc, &service.http_proxy_host, definition.http_proxy_host);
    try replaceOptionalOwned(alloc, &service.http_proxy_path_prefix, definition.http_proxy_path_prefix);
    try replaceOptionalOwned(alloc, &service.http_proxy_rewrite_prefix, definition.http_proxy_rewrite_prefix);
    service.http_proxy_retries = definition.http_proxy_retries;
    service.http_proxy_connect_timeout_ms = definition.http_proxy_connect_timeout_ms;
    service.http_proxy_request_timeout_ms = definition.http_proxy_request_timeout_ms;
    service.http_proxy_http2_idle_timeout_ms = definition.http_proxy_http2_idle_timeout_ms;
    service.http_proxy_target_port = definition.http_proxy_target_port;
    service.http_proxy_preserve_host = definition.http_proxy_preserve_host;
    service.http_proxy_retry_on_5xx = definition.http_proxy_retry_on_5xx;
    service.http_proxy_circuit_breaker_threshold = definition.http_proxy_circuit_breaker_threshold;
    service.http_proxy_circuit_breaker_timeout_ms = definition.http_proxy_circuit_breaker_timeout_ms;
    try replaceOptionalOwned(alloc, &service.http_proxy_mirror_service, definition.http_proxy_mirror_service);
    service.peer_mode = definition.peer_mode;
}

fn isEndpointEligible(endpoint: *const EndpointState) bool {
    if (!std.mem.eql(u8, endpoint.admin_state, "active")) return false;
    if (endpoint.node_lost) return false;
    if (endpoint.readiness_required) return endpoint.observed_health == .healthy;
    return endpoint.observed_health != .unhealthy;
}

fn cloneMethodMatches(alloc: Allocator, matches: []const HttpMethodMatch) Error![]const HttpMethodMatch {
    var cloned: std.ArrayList(HttpMethodMatch) = .empty;
    errdefer {
        for (cloned.items) |method_match| method_match.deinit(alloc);
        cloned.deinit(alloc);
    }

    for (matches) |method_match| {
        const owned_method = try alloc.dupe(u8, method_match.method);
        errdefer alloc.free(owned_method);

        try cloned.append(alloc, .{
            .method = owned_method,
        });
    }
    return cloned.toOwnedSlice(alloc);
}

fn cloneHeaderMatches(alloc: Allocator, matches: []const HttpHeaderMatch) Error![]const HttpHeaderMatch {
    var cloned: std.ArrayList(HttpHeaderMatch) = .empty;
    errdefer {
        for (cloned.items) |header_match| header_match.deinit(alloc);
        cloned.deinit(alloc);
    }

    for (matches) |header_match| {
        const owned_name = try alloc.dupe(u8, header_match.name);
        errdefer alloc.free(owned_name);
        const owned_value = try alloc.dupe(u8, header_match.value);
        errdefer alloc.free(owned_value);

        try cloned.append(alloc, .{
            .name = owned_name,
            .value = owned_value,
        });
    }
    return cloned.toOwnedSlice(alloc);
}

fn cloneRouteBackends(alloc: Allocator, backends: []const HttpRouteBackend) Error![]const HttpRouteBackend {
    var cloned: std.ArrayList(HttpRouteBackend) = .empty;
    errdefer {
        for (cloned.items) |backend| backend.deinit(alloc);
        cloned.deinit(alloc);
    }

    for (backends) |backend| {
        const owned_service_name = try alloc.dupe(u8, backend.service_name);
        errdefer alloc.free(owned_service_name);

        try cloned.append(alloc, .{
            .service_name = owned_service_name,
            .weight = backend.weight,
        });
    }
    return cloned.toOwnedSlice(alloc);
}

fn defaultRouteBackends(alloc: Allocator, service_name: []const u8) Error![]const HttpRouteBackend {
    const backends = try alloc.alloc(HttpRouteBackend, 1);
    errdefer alloc.free(backends);
    backends[0] = .{
        .service_name = try alloc.dupe(u8, service_name),
        .weight = 100,
    };
    return backends;
}

fn replaceOwned(alloc: Allocator, current: *[]const u8, next: []const u8) Error!void {
    if (std.mem.eql(u8, current.*, next)) return;
    const owned = try alloc.dupe(u8, next);
    alloc.free(current.*);
    current.* = owned;
}

fn replaceOptionalOwned(alloc: Allocator, current: *?[]const u8, next: ?[]const u8) Error!void {
    if (current.*) |existing| {
        if (next) |candidate| {
            if (std.mem.eql(u8, existing, candidate)) return;
            const owned = try alloc.dupe(u8, candidate);
            alloc.free(existing);
            current.* = owned;
            return;
        }
        alloc.free(existing);
        current.* = null;
        return;
    }

    if (next) |candidate| {
        current.* = try alloc.dupe(u8, candidate);
    }
}

fn deinitRoutes(alloc: Allocator, routes: *std.ArrayList(HttpRouteState)) void {
    for (routes.items) |route| route.deinit(alloc);
    routes.deinit(alloc);
}

fn buildAction(service_name: []const u8, reason: ActionReason) Action {
    var action = Action{ .reason = reason };
    const len = @min(service_name.len, action.service_name_buf.len);
    action.service_name_len = @intCast(len);
    @memcpy(action.service_name_buf[0..len], service_name[0..len]);
    return action;
}

fn deinitEndpoints(alloc: Allocator, endpoints: *std.ArrayList(EndpointState)) void {
    for (endpoints.items) |endpoint| endpoint.deinit(alloc);
    endpoints.deinit(alloc);
}

fn deinitEndpointSnapshots(alloc: Allocator, endpoints: *std.ArrayList(EndpointSnapshot)) void {
    for (endpoints.items) |endpoint| endpoint.deinit(alloc);
    endpoints.deinit(alloc);
}

fn deinitServiceSnapshots(alloc: Allocator, services: *std.ArrayList(ServiceSnapshot)) void {
    for (services.items) |service| service.deinit(alloc);
    services.deinit(alloc);
}

const allocation_test_service = ServiceDefinition{
    .service_name = "api",
    .vip_address = "10.43.0.2",
    .lb_policy = "consistent_hash",
    .http_routes = &.{
        .{
            .route_name = "public",
            .host = "api.example.com",
            .path_prefix = "/v1",
            .rewrite_prefix = "/internal",
            .match_methods = &.{ .{ .method = "GET" }, .{ .method = "POST" } },
            .match_headers = &.{ .{ .name = "x-tenant", .value = "blue" }, .{ .name = "x-version", .value = "2" } },
            .backend_services = &.{ .{ .service_name = "api", .weight = 80 }, .{ .service_name = "canary", .weight = 20 } },
            .mirror_service = "shadow",
            .retries = 2,
            .connect_timeout_ms = 1500,
            .request_timeout_ms = 6500,
            .http2_idle_timeout_ms = 45000,
            .target_port = 8080,
            .preserve_host = false,
            .retry_on_5xx = false,
            .circuit_breaker_threshold = 5,
            .circuit_breaker_timeout_ms = 60000,
        },
        .{ .route_name = "health", .host = "health.example.com" },
    },
};

const allocation_test_endpoints = [_]EndpointDefinition{
    .{
        .endpoint_id = "ctr-1:8080",
        .container_id = "ctr-1",
        .node_id = 7,
        .ip_address = "10.42.0.9",
        .port = 8080,
        .weight = 80,
        .admin_state = "active",
        .generation = 2,
        .registered_at = 1000,
        .last_seen_at = 1100,
    },
    .{
        .endpoint_id = "ctr-2:8080",
        .container_id = "ctr-2",
        .node_id = null,
        .ip_address = "10.42.0.10",
        .port = 8080,
        .weight = 20,
        .admin_state = "draining",
        .generation = 1,
        .registered_at = 900,
        .last_seen_at = 1050,
    },
};

fn expectAllocationTestRoutes(routes: []const HttpRouteSnapshot) !void {
    try std.testing.expectEqual(@as(usize, 2), routes.len);
    for (allocation_test_service.http_routes, routes) |expected, actual| {
        try std.testing.expectEqualStrings(expected.route_name, actual.route_name);
        try std.testing.expectEqualStrings(expected.host, actual.host);
        try std.testing.expectEqualStrings(expected.path_prefix, actual.path_prefix);
        try std.testing.expectEqualDeep(expected.rewrite_prefix, actual.rewrite_prefix);
        try std.testing.expectEqualDeep(expected.match_methods, actual.match_methods);
        try std.testing.expectEqualDeep(expected.match_headers, actual.match_headers);
        try std.testing.expectEqualDeep(expected.backend_services, actual.backend_services);
        try std.testing.expectEqualDeep(expected.mirror_service, actual.mirror_service);
        try std.testing.expectEqual(expected.retries, actual.retries);
        try std.testing.expectEqual(expected.connect_timeout_ms, actual.connect_timeout_ms);
        try std.testing.expectEqual(expected.request_timeout_ms, actual.request_timeout_ms);
        try std.testing.expectEqual(expected.http2_idle_timeout_ms, actual.http2_idle_timeout_ms);
        try std.testing.expectEqual(expected.target_port, actual.target_port);
        try std.testing.expectEqual(expected.preserve_host, actual.preserve_host);
        try std.testing.expectEqual(expected.retry_on_5xx, actual.retry_on_5xx);
        try std.testing.expectEqual(expected.circuit_breaker_threshold, actual.circuit_breaker_threshold);
        try std.testing.expectEqual(expected.circuit_breaker_timeout_ms, actual.circuit_breaker_timeout_ms);
    }
}

fn checkServiceInsertionAllocationFailures(alloc: Allocator) !void {
    var registry = Registry.init(alloc);
    defer registry.deinit();
    registry.upsertService(allocation_test_service) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), registry.services.items.len);
        return err;
    };

    const snapshot = try registry.snapshotService(std.testing.allocator, "api");
    defer snapshot.deinit(std.testing.allocator);
    try expectAllocationTestRoutes(snapshot.http_routes);
    try std.testing.expectEqualStrings("api.example.com", snapshot.http_proxy_host.?);
    try std.testing.expectEqualStrings("/internal", snapshot.http_proxy_rewrite_prefix.?);
    try std.testing.expectEqualStrings("shadow", snapshot.http_proxy_mirror_service.?);
    try std.testing.expectEqual(@as(?u32, 45000), snapshot.http_proxy_http2_idle_timeout_ms);
}

test "service insertion cleans up every allocation failure before publishing" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkServiceInsertionAllocationFailures, .{});
}

fn checkLegacyRouteAllocationFailures(alloc: Allocator, use_defaults: bool) !void {
    var registry = Registry.init(alloc);
    defer registry.deinit();
    const definition = ServiceDefinition{
        .service_name = "legacy",
        .vip_address = "10.43.0.3",
        .lb_policy = "round_robin",
        .http_proxy_host = "legacy.example.com",
        .http_proxy_path_prefix = if (use_defaults) null else "/old",
        .http_proxy_rewrite_prefix = if (use_defaults) null else "/new",
        .http_proxy_mirror_service = if (use_defaults) null else "shadow",
        .http_proxy_retries = if (use_defaults) null else 2,
        .http_proxy_target_port = if (use_defaults) null else 8080,
    };
    registry.upsertService(definition) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), registry.services.items.len);
        return err;
    };
    const snapshot = try registry.snapshotService(std.testing.allocator, "legacy");
    defer snapshot.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), snapshot.http_routes.len);
    const route = snapshot.http_routes[0];
    try std.testing.expectEqualStrings("default", route.route_name);
    try std.testing.expectEqualStrings("legacy.example.com", route.host);
    try std.testing.expectEqualStrings(if (use_defaults) "/" else "/old", route.path_prefix);
    try std.testing.expectEqualDeep(definition.http_proxy_rewrite_prefix, route.rewrite_prefix);
    try std.testing.expectEqualDeep(definition.http_proxy_mirror_service, route.mirror_service);
    try std.testing.expectEqual(@as(usize, 0), route.match_methods.len);
    try std.testing.expectEqual(@as(usize, 0), route.match_headers.len);
    try std.testing.expectEqual(@as(usize, 1), route.backend_services.len);
    try std.testing.expectEqualStrings("legacy", route.backend_services[0].service_name);
    try std.testing.expectEqual(@as(u8, 100), route.backend_services[0].weight);
    try std.testing.expectEqual(definition.http_proxy_retries orelse 0, route.retries);
    try std.testing.expectEqual(definition.http_proxy_target_port, route.target_port);
    try std.testing.expectEqual(@as(u32, 1000), route.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 5000), route.request_timeout_ms);
    try std.testing.expectEqual(@as(u32, 30000), route.http2_idle_timeout_ms);
    try std.testing.expect(route.preserve_host);
    try std.testing.expect(route.retry_on_5xx);
    try std.testing.expectEqual(@as(u8, 3), route.circuit_breaker_threshold);
    try std.testing.expectEqual(@as(u32, 30000), route.circuit_breaker_timeout_ms);
}

test "legacy route insertion cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkLegacyRouteAllocationFailures, .{true});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkLegacyRouteAllocationFailures, .{false});
}

fn checkEndpointReplacementAllocationFailures(alloc: Allocator) !void {
    var registry = Registry.init(alloc);
    defer registry.deinit();
    try registry.upsertService(.{ .service_name = "api", .vip_address = "10.43.0.2", .lb_policy = "round_robin" });
    try registry.replaceServiceEndpoints("api", allocation_test_endpoints[0..1]);
    _ = try registry.noteProbeResult("api", "ctr-1:8080", true);

    registry.replaceServiceEndpoints("api", &allocation_test_endpoints) catch |err| {
        const endpoints = registry.services.items[0].endpoints.items;
        try std.testing.expectEqual(@as(usize, 1), endpoints.len);
        try std.testing.expectEqualStrings("ctr-1:8080", endpoints[0].endpoint_id);
        try std.testing.expectEqual(ObservedHealth.healthy, endpoints[0].observed_health);
        return err;
    };
    const endpoints = registry.services.items[0].endpoints.items;
    try std.testing.expectEqual(@as(usize, 2), endpoints.len);
    try std.testing.expectEqual(ObservedHealth.healthy, endpoints[0].observed_health);
    try std.testing.expectEqualStrings("ctr-2:8080", endpoints[1].endpoint_id);
    try std.testing.expectEqualStrings("draining", endpoints[1].admin_state);
}

test "endpoint replacement cleans up every allocation failure and preserves old endpoints" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkEndpointReplacementAllocationFailures, .{});
}

fn checkServiceSnapshotAllocationFailures(alloc: Allocator, registry: *const Registry, list: bool) !void {
    if (list) {
        var snapshots = try registry.snapshotServices(alloc);
        defer deinitServiceSnapshots(alloc, &snapshots);
        try std.testing.expectEqual(@as(usize, 2), snapshots.items.len);
        try expectAllocationTestRoutes(snapshots.items[0].http_routes);
        try std.testing.expectEqualStrings("worker", snapshots.items[1].service_name);
        try std.testing.expectEqual(@as(usize, 0), snapshots.items[1].http_routes.len);
        try std.testing.expect(snapshots.items[1].http_proxy_host == null);
        try std.testing.expect(snapshots.items[1].last_reconcile_error == null);
    } else {
        const snapshot = try registry.snapshotService(alloc, "api");
        defer snapshot.deinit(alloc);
        try expectAllocationTestRoutes(snapshot.http_routes);
        try std.testing.expectEqualStrings("api", snapshot.service_name);
        try std.testing.expectEqualStrings("10.43.0.2", snapshot.vip_address);
        try std.testing.expectEqualStrings("consistent_hash", snapshot.lb_policy);
        try std.testing.expectEqualStrings("api.example.com", snapshot.http_proxy_host.?);
        try std.testing.expectEqualStrings("/v1", snapshot.http_proxy_path_prefix.?);
        try std.testing.expectEqualStrings("/internal", snapshot.http_proxy_rewrite_prefix.?);
        try std.testing.expectEqualStrings("shadow", snapshot.http_proxy_mirror_service.?);
        try std.testing.expectEqualStrings("failed", snapshot.last_reconcile_status);
        try std.testing.expectEqualStrings("map update failed", snapshot.last_reconcile_error.?);
        try std.testing.expectEqual(@as(usize, 2), snapshot.total_endpoints);
        try std.testing.expectEqual(@as(usize, 1), snapshot.eligible_endpoints);
        try std.testing.expectEqual(@as(usize, 1), snapshot.healthy_endpoints);
        try std.testing.expectEqual(@as(usize, 1), snapshot.draining_endpoints);
        try std.testing.expect(snapshot.degraded);
    }
}

test "service snapshots clean up every allocation failure" {
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();
    try registry.upsertService(allocation_test_service);
    try registry.upsertService(.{ .service_name = "worker", .vip_address = "10.43.0.3", .lb_policy = "round_robin" });
    try registry.replaceServiceEndpoints("api", &allocation_test_endpoints);
    _ = try registry.noteProbeResult("api", "ctr-1:8080", true);
    try registry.markReconcileFailed("api", "map update failed");
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkServiceSnapshotAllocationFailures, .{ &registry, false });
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkServiceSnapshotAllocationFailures, .{ &registry, true });
}

fn checkEndpointSnapshotAllocationFailures(alloc: Allocator, registry: *const Registry) !void {
    var snapshots = try registry.snapshotServiceEndpoints(alloc, "api");
    defer deinitEndpointSnapshots(alloc, &snapshots);
    try std.testing.expectEqual(@as(usize, 2), snapshots.items.len);
    for (allocation_test_endpoints, snapshots.items) |expected, actual| {
        try std.testing.expectEqualStrings(expected.endpoint_id, actual.endpoint_id);
        try std.testing.expectEqualStrings(expected.container_id, actual.container_id);
        try std.testing.expectEqual(expected.node_id, actual.node_id);
        try std.testing.expectEqualStrings(expected.ip_address, actual.ip_address);
        try std.testing.expectEqual(expected.port, actual.port);
        try std.testing.expectEqual(expected.weight, actual.weight);
        try std.testing.expectEqualStrings(expected.admin_state, actual.admin_state);
        try std.testing.expectEqual(expected.generation, actual.generation);
        try std.testing.expectEqual(expected.registered_at, actual.registered_at);
        try std.testing.expectEqual(expected.last_seen_at, actual.last_seen_at);
    }
    try std.testing.expectEqualStrings("healthy", snapshots.items[0].observed_health);
    try std.testing.expect(snapshots.items[0].eligible);
    try std.testing.expect(snapshots.items[0].last_transition_at != null);
    try std.testing.expectEqualStrings("unknown", snapshots.items[1].observed_health);
    try std.testing.expect(!snapshots.items[1].eligible);
    try std.testing.expect(snapshots.items[1].last_transition_at == null);
}

test "endpoint snapshots clean up every allocation failure" {
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();
    try registry.upsertService(.{ .service_name = "api", .vip_address = "10.43.0.2", .lb_policy = "round_robin" });
    try registry.replaceServiceEndpoints("api", &allocation_test_endpoints);
    _ = try registry.noteProbeResult("api", "ctr-1:8080", true);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkEndpointSnapshotAllocationFailures, .{&registry});
}

fn checkCollectionGrowthAllocationFailures(alloc: Allocator, registry: *const Registry, definition: ServiceDefinition) !void {
    var routes = try cloneRoutesFromDefinition(alloc, definition);
    defer deinitRoutes(alloc, &routes);
    try std.testing.expectEqual(@as(usize, 20), routes.items.len);
    try std.testing.expectEqualStrings("item-19", routes.items[19].route_name);

    var services = try registry.snapshotServices(alloc);
    defer deinitServiceSnapshots(alloc, &services);
    try std.testing.expectEqual(@as(usize, 20), services.items.len);
    try std.testing.expectEqualStrings("item-19", services.items[19].service_name);
    try std.testing.expectEqual(@as(usize, 20), services.items[0].http_routes.len);
    try std.testing.expectEqualStrings("item-19", services.items[0].http_routes[19].route_name);

    var endpoints = try registry.snapshotServiceEndpoints(alloc, "api");
    defer deinitEndpointSnapshots(alloc, &endpoints);
    try std.testing.expectEqual(@as(usize, 20), endpoints.items.len);
    try std.testing.expectEqualStrings("item-19", endpoints.items[19].endpoint_id);
}

test "registry collection growth cleans up every allocation failure" {
    var names: [20][16]u8 = undefined;
    var routes: [20]HttpRouteDefinition = undefined;
    var endpoints: [20]EndpointDefinition = undefined;
    for (&names, &routes, &endpoints, 0..) |*name_buf, *route, *endpoint, index| {
        const name = try std.fmt.bufPrint(name_buf, "item-{d}", .{index});
        route.* = .{ .route_name = name, .host = "api.example.com" };
        endpoint.* = allocation_test_endpoints[0];
        endpoint.endpoint_id = name;
    }
    const definition = ServiceDefinition{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "round_robin",
        .http_routes = &routes,
    };
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();
    try registry.upsertService(definition);
    for (routes[1..]) |route| {
        try registry.upsertService(.{
            .service_name = route.route_name,
            .vip_address = "10.43.0.3",
            .lb_policy = "round_robin",
        });
    }
    try registry.replaceServiceEndpoints("api", &endpoints);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkCollectionGrowthAllocationFailures, .{ &registry, definition });
}

test "replaceServiceEndpoints preserves observed health for matching endpoint ids" {
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();

    try registry.upsertService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
    });
    try registry.replaceServiceEndpoints("api", &.{
        .{
            .endpoint_id = "ctr-1:0",
            .container_id = "ctr-1",
            .node_id = null,
            .ip_address = "10.42.0.9",
            .port = 0,
            .weight = 1,
            .admin_state = "active",
            .generation = 1,
            .registered_at = 1000,
            .last_seen_at = 1000,
        },
    });
    _ = try registry.noteProbeResult("api", "ctr-1:0", true);

    try registry.replaceServiceEndpoints("api", &.{
        .{
            .endpoint_id = "ctr-1:0",
            .container_id = "ctr-1",
            .node_id = null,
            .ip_address = "10.42.0.19",
            .port = 0,
            .weight = 1,
            .admin_state = "active",
            .generation = 1,
            .registered_at = 1001,
            .last_seen_at = 1002,
        },
    });

    var endpoints = try registry.snapshotServiceEndpoints(std.testing.allocator, "api");
    defer deinitEndpointSnapshots(std.testing.allocator, &endpoints);

    try std.testing.expectEqual(@as(usize, 1), endpoints.items.len);
    try std.testing.expectEqualStrings("healthy", endpoints.items[0].observed_health);
    try std.testing.expectEqualStrings("10.42.0.19", endpoints.items[0].ip_address);
    try std.testing.expect(endpoints.items[0].eligible);
}

test "markEndpointPending makes health-gated endpoints ineligible until healthy" {
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();

    try registry.upsertService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
    });
    try registry.replaceServiceEndpoints("api", &.{
        .{
            .endpoint_id = "ctr-1:0",
            .container_id = "ctr-1",
            .node_id = null,
            .ip_address = "10.42.0.9",
            .port = 0,
            .weight = 1,
            .admin_state = "active",
            .generation = 1,
            .registered_at = 1000,
            .last_seen_at = 1000,
        },
    });

    try std.testing.expectEqual(ProbeApply.applied, try registry.markEndpointPending("api", "ctr-1:0", 1));

    var pending = try registry.snapshotServiceEndpoints(std.testing.allocator, "api");
    defer deinitEndpointSnapshots(std.testing.allocator, &pending);
    try std.testing.expect(pending.items[0].readiness_required);
    try std.testing.expect(!pending.items[0].eligible);

    try std.testing.expectEqual(ProbeApply.applied, try registry.noteProbeResultForGeneration("api", "ctr-1:0", 1, true));

    var healthy = try registry.snapshotServiceEndpoints(std.testing.allocator, "api");
    defer deinitEndpointSnapshots(std.testing.allocator, &healthy);
    try std.testing.expect(healthy.items[0].eligible);
}

test "generation changes reset observed health and reject stale probe results" {
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();

    try registry.upsertService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
    });
    try registry.replaceServiceEndpoints("api", &.{
        .{
            .endpoint_id = "ctr-1:0",
            .container_id = "ctr-1",
            .node_id = null,
            .ip_address = "10.42.0.9",
            .port = 0,
            .weight = 1,
            .admin_state = "active",
            .generation = 1,
            .registered_at = 1000,
            .last_seen_at = 1000,
        },
    });
    try std.testing.expectEqual(ProbeApply.applied, try registry.markEndpointPending("api", "ctr-1:0", 1));
    try std.testing.expectEqual(ProbeApply.applied, try registry.noteProbeResultForGeneration("api", "ctr-1:0", 1, true));

    try registry.replaceServiceEndpoints("api", &.{
        .{
            .endpoint_id = "ctr-1:0",
            .container_id = "ctr-1",
            .node_id = null,
            .ip_address = "10.42.0.19",
            .port = 0,
            .weight = 1,
            .admin_state = "active",
            .generation = 2,
            .registered_at = 1001,
            .last_seen_at = 1002,
        },
    });

    try std.testing.expectEqual(ProbeApply.stale_generation, try registry.noteProbeResultForGeneration("api", "ctr-1:0", 1, false));

    var endpoints = try registry.snapshotServiceEndpoints(std.testing.allocator, "api");
    defer deinitEndpointSnapshots(std.testing.allocator, &endpoints);
    try std.testing.expectEqualStrings("unknown", endpoints.items[0].observed_health);
    try std.testing.expect(!endpoints.items[0].eligible);
}

test "removeEndpointsByContainer removes matching endpoints from every service" {
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();

    try registry.upsertService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
    });
    try registry.upsertService(.{
        .service_name = "web",
        .vip_address = "10.43.0.3",
        .lb_policy = "consistent_hash",
    });
    try registry.replaceServiceEndpoints("api", &.{
        .{
            .endpoint_id = "ctr-1:0",
            .container_id = "ctr-1",
            .node_id = null,
            .ip_address = "10.42.0.9",
            .port = 0,
            .weight = 1,
            .admin_state = "active",
            .generation = 1,
            .registered_at = 1000,
            .last_seen_at = 1000,
        },
    });
    try registry.replaceServiceEndpoints("web", &.{
        .{
            .endpoint_id = "ctr-1:0",
            .container_id = "ctr-1",
            .node_id = null,
            .ip_address = "10.42.0.9",
            .port = 0,
            .weight = 1,
            .admin_state = "active",
            .generation = 1,
            .registered_at = 1000,
            .last_seen_at = 1000,
        },
        .{
            .endpoint_id = "ctr-2:0",
            .container_id = "ctr-2",
            .node_id = null,
            .ip_address = "10.42.0.10",
            .port = 0,
            .weight = 1,
            .admin_state = "active",
            .generation = 1,
            .registered_at = 1001,
            .last_seen_at = 1001,
        },
    });

    try std.testing.expectEqual(@as(usize, 2), registry.removeEndpointsByContainer("ctr-1"));

    var api_endpoints = try registry.snapshotServiceEndpoints(std.testing.allocator, "api");
    defer deinitEndpointSnapshots(std.testing.allocator, &api_endpoints);
    try std.testing.expectEqual(@as(usize, 0), api_endpoints.items.len);

    var web_endpoints = try registry.snapshotServiceEndpoints(std.testing.allocator, "web");
    defer deinitEndpointSnapshots(std.testing.allocator, &web_endpoints);
    try std.testing.expectEqual(@as(usize, 1), web_endpoints.items.len);
    try std.testing.expectEqualStrings("ctr-2", web_endpoints.items[0].container_id);
}

test "requestReconcile marks the service pending" {
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();

    try registry.upsertService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
    });

    const action = try registry.requestReconcile("api");
    try std.testing.expectEqual(ActionKind.reconcile_service, action.kind);
    try std.testing.expectEqual(ActionReason.reconcile_requested, action.reason);
    try std.testing.expectEqualStrings("api", action.serviceName());

    const snapshot = try registry.snapshotService(std.testing.allocator, "api");
    defer snapshot.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("pending", snapshot.last_reconcile_status);
    try std.testing.expect(snapshot.last_reconcile_requested_at != null);
}

test "service snapshots include optional http proxy policy" {
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();

    try registry.upsertService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .http_proxy_retries = 2,
        .http_proxy_connect_timeout_ms = 1500,
        .http_proxy_request_timeout_ms = 5000,
        .http_proxy_http2_idle_timeout_ms = 30000,
        .http_proxy_preserve_host = false,
    });

    const snapshot = try registry.snapshotService(std.testing.allocator, "api");
    defer snapshot.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("api.internal", snapshot.http_proxy_host.?);
    try std.testing.expectEqualStrings("/v1", snapshot.http_proxy_path_prefix.?);
    try std.testing.expectEqual(@as(?u8, 2), snapshot.http_proxy_retries);
    try std.testing.expectEqual(@as(?u32, 1500), snapshot.http_proxy_connect_timeout_ms);
    try std.testing.expectEqual(@as(?u32, 5000), snapshot.http_proxy_request_timeout_ms);
    try std.testing.expectEqual(@as(?u32, 30000), snapshot.http_proxy_http2_idle_timeout_ms);
    try std.testing.expectEqual(@as(?bool, false), snapshot.http_proxy_preserve_host);
}

test "node loss and recovery toggle endpoint eligibility" {
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();

    try registry.upsertService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
    });
    try registry.replaceServiceEndpoints("api", &.{
        .{
            .endpoint_id = "ctr-1:0",
            .container_id = "ctr-1",
            .node_id = 7,
            .ip_address = "10.42.0.9",
            .port = 0,
            .weight = 1,
            .admin_state = "active",
            .generation = 1,
            .registered_at = 1000,
            .last_seen_at = 1000,
        },
    });

    try std.testing.expectEqual(@as(usize, 1), registry.noteNodeLost(7));

    var after_loss = try registry.snapshotServiceEndpoints(std.testing.allocator, "api");
    defer deinitEndpointSnapshots(std.testing.allocator, &after_loss);
    try std.testing.expect(!after_loss.items[0].eligible);

    try std.testing.expectEqual(@as(usize, 1), registry.noteNodeRecovered(7));

    var after_recovery = try registry.snapshotServiceEndpoints(std.testing.allocator, "api");
    defer deinitEndpointSnapshots(std.testing.allocator, &after_recovery);
    try std.testing.expect(after_recovery.items[0].eligible);
}

test "markReconcileFailed and markReconcileSucceeded update service detail" {
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();

    try registry.upsertService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
    });

    try registry.markReconcileFailed("api", "map update failed");
    var failed = try registry.snapshotService(std.testing.allocator, "api");
    defer failed.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("failed", failed.last_reconcile_status);
    try std.testing.expectEqualStrings("map update failed", failed.last_reconcile_error.?);

    try registry.markReconcileSucceeded("api");
    var recovered = try registry.snapshotService(std.testing.allocator, "api");
    defer recovered.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("idle", recovered.last_reconcile_status);
    try std.testing.expect(recovered.last_reconcile_error == null);
}
