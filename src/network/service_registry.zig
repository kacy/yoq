const std = @import("std");

const Allocator = std.mem.Allocator;

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
    http_proxy_target_port: ?u16 = null,
    http_proxy_preserve_host: ?bool = null,
};

pub const HttpRouteDefinition = struct {
    route_name: []const u8,
    host: []const u8,
    path_prefix: []const u8 = "/",
    rewrite_prefix: ?[]const u8 = null,
    match_headers: []const HttpHeaderMatch = &.{},
    retries: u8 = 0,
    connect_timeout_ms: u32 = 1000,
    request_timeout_ms: u32 = 5000,
    target_port: ?u16 = null,
    preserve_host: bool = true,
};

pub const HttpHeaderMatch = struct {
    name: []const u8,
    value: []const u8,

    pub fn deinit(self: HttpHeaderMatch, alloc: Allocator) void {
        alloc.free(self.name);
        alloc.free(self.value);
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
    http_proxy_target_port: ?u16,
    http_proxy_preserve_host: ?bool,
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
        alloc.free(self.last_reconcile_status);
        if (self.last_reconcile_error) |message| alloc.free(message);
    }
};

pub const HttpRouteSnapshot = struct {
    route_name: []const u8,
    host: []const u8,
    path_prefix: []const u8,
    rewrite_prefix: ?[]const u8,
    match_headers: []const HttpHeaderMatch,
    retries: u8,
    connect_timeout_ms: u32,
    request_timeout_ms: u32,
    target_port: ?u16,
    preserve_host: bool,

    pub fn deinit(self: HttpRouteSnapshot, alloc: Allocator) void {
        alloc.free(self.route_name);
        alloc.free(self.host);
        alloc.free(self.path_prefix);
        if (self.rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
        for (self.match_headers) |header_match| header_match.deinit(alloc);
        if (self.match_headers.len > 0) alloc.free(self.match_headers);
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
    http_proxy_target_port: ?u16 = null,
    http_proxy_preserve_host: ?bool = null,
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
    match_headers: []const HttpHeaderMatch,
    retries: u8,
    connect_timeout_ms: u32,
    request_timeout_ms: u32,
    target_port: ?u16,
    preserve_host: bool,

    fn deinit(self: HttpRouteState, alloc: Allocator) void {
        alloc.free(self.route_name);
        alloc.free(self.host);
        alloc.free(self.path_prefix);
        if (self.rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
        for (self.match_headers) |header_match| header_match.deinit(alloc);
        if (self.match_headers.len > 0) alloc.free(self.match_headers);
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

        try self.services.append(self.alloc, .{
            .service_name = try self.alloc.dupe(u8, definition.service_name),
            .vip_address = try self.alloc.dupe(u8, definition.vip_address),
            .lb_policy = try self.alloc.dupe(u8, definition.lb_policy),
            .http_routes = try cloneRoutesFromDefinition(self.alloc, definition),
        });
        try assignCompatProxyFields(self.alloc, &self.services.items[self.services.items.len - 1], definition);
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
        endpoint.last_transition_at = std.time.timestamp();
        return buildAction(service_name, .endpoint_admin_changed);
    }

    pub fn noteProbeResult(self: *Registry, service_name: []const u8, endpoint_id: []const u8, healthy: bool) Error!Action {
        const endpoint = try self.getEndpointMut(service_name, endpoint_id);
        endpoint.observed_health = if (healthy) .healthy else .unhealthy;
        endpoint.last_transition_at = std.time.timestamp();
        return buildAction(service_name, .probe_result);
    }

    pub fn markEndpointPending(self: *Registry, service_name: []const u8, endpoint_id: []const u8, generation: i64) Error!ProbeApply {
        const endpoint = try self.getEndpointMut(service_name, endpoint_id);
        if (endpoint.generation != generation) return .stale_generation;
        endpoint.readiness_required = true;
        endpoint.observed_health = .unknown;
        endpoint.last_transition_at = std.time.timestamp();
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
        endpoint.last_transition_at = std.time.timestamp();
        return .applied;
    }

    pub fn requestReconcile(self: *Registry, service_name: []const u8) Error!Action {
        const service = try self.getServiceMut(service_name);
        service.last_reconcile_status = .pending;
        service.last_reconcile_requested_at = std.time.timestamp();
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
        const now = std.time.timestamp();
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
        const now = std.time.timestamp();
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
            try services.append(alloc, try cloneServiceSnapshot(alloc, &service));
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
            try endpoints.append(alloc, try cloneEndpointSnapshot(alloc, &endpoint));
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
    return .{
        .endpoint_id = try alloc.dupe(u8, definition.endpoint_id),
        .container_id = try alloc.dupe(u8, definition.container_id),
        .node_id = definition.node_id,
        .ip_address = try alloc.dupe(u8, definition.ip_address),
        .port = definition.port,
        .weight = definition.weight,
        .admin_state = try alloc.dupe(u8, definition.admin_state),
        .generation = definition.generation,
        .registered_at = definition.registered_at,
        .last_seen_at = definition.last_seen_at,
    };
}

fn cloneEndpointSnapshot(alloc: Allocator, endpoint: *const EndpointState) Error!EndpointSnapshot {
    return .{
        .endpoint_id = try alloc.dupe(u8, endpoint.endpoint_id),
        .container_id = try alloc.dupe(u8, endpoint.container_id),
        .node_id = endpoint.node_id,
        .ip_address = try alloc.dupe(u8, endpoint.ip_address),
        .port = endpoint.port,
        .weight = endpoint.weight,
        .admin_state = try alloc.dupe(u8, endpoint.admin_state),
        .generation = endpoint.generation,
        .registered_at = endpoint.registered_at,
        .last_seen_at = endpoint.last_seen_at,
        .observed_health = try alloc.dupe(u8, endpoint.observed_health.label()),
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

    return .{
        .service_name = try alloc.dupe(u8, service.service_name),
        .vip_address = try alloc.dupe(u8, service.vip_address),
        .lb_policy = try alloc.dupe(u8, service.lb_policy),
        .http_routes = routes,
        .http_proxy_host = if (service.http_proxy_host) |host| try alloc.dupe(u8, host) else null,
        .http_proxy_path_prefix = if (service.http_proxy_path_prefix) |path_prefix| try alloc.dupe(u8, path_prefix) else null,
        .http_proxy_rewrite_prefix = if (service.http_proxy_rewrite_prefix) |rewrite_prefix| try alloc.dupe(u8, rewrite_prefix) else null,
        .http_proxy_retries = service.http_proxy_retries,
        .http_proxy_connect_timeout_ms = service.http_proxy_connect_timeout_ms,
        .http_proxy_request_timeout_ms = service.http_proxy_request_timeout_ms,
        .http_proxy_target_port = service.http_proxy_target_port,
        .http_proxy_preserve_host = service.http_proxy_preserve_host,
        .total_endpoints = total_endpoints,
        .eligible_endpoints = eligible_endpoints,
        .healthy_endpoints = healthy_endpoints,
        .draining_endpoints = draining_endpoints,
        .last_reconcile_status = try alloc.dupe(u8, service.last_reconcile_status.label()),
        .last_reconcile_error = if (service.last_reconcile_error) |message| try alloc.dupe(u8, message) else null,
        .last_reconcile_requested_at = service.last_reconcile_requested_at,
        .overflow = service.overflow,
        .degraded = service.overflow or service.last_reconcile_status == .failed or eligible_endpoints == 0,
    };
}

fn cloneRoutesFromDefinition(alloc: Allocator, definition: ServiceDefinition) Error!std.ArrayList(HttpRouteState) {
    var routes: std.ArrayList(HttpRouteState) = .empty;
    errdefer {
        for (routes.items) |route| route.deinit(alloc);
        routes.deinit(alloc);
    }

    if (definition.http_routes.len > 0) {
        for (definition.http_routes) |route| {
            try routes.append(alloc, .{
                .route_name = try alloc.dupe(u8, route.route_name),
                .host = try alloc.dupe(u8, route.host),
                .path_prefix = try alloc.dupe(u8, route.path_prefix),
                .rewrite_prefix = if (route.rewrite_prefix) |rewrite_prefix| try alloc.dupe(u8, rewrite_prefix) else null,
                .match_headers = try cloneHeaderMatches(alloc, route.match_headers),
                .retries = route.retries,
                .connect_timeout_ms = route.connect_timeout_ms,
                .request_timeout_ms = route.request_timeout_ms,
                .target_port = route.target_port,
                .preserve_host = route.preserve_host,
            });
        }
        return routes;
    }

    if (definition.http_proxy_host) |host| {
        try routes.append(alloc, .{
            .route_name = try alloc.dupe(u8, "default"),
            .host = try alloc.dupe(u8, host),
            .path_prefix = try alloc.dupe(u8, definition.http_proxy_path_prefix orelse "/"),
            .rewrite_prefix = if (definition.http_proxy_rewrite_prefix) |rewrite_prefix| try alloc.dupe(u8, rewrite_prefix) else null,
            .match_headers = &.{},
            .retries = definition.http_proxy_retries orelse 0,
            .connect_timeout_ms = definition.http_proxy_connect_timeout_ms orelse 1000,
            .request_timeout_ms = definition.http_proxy_request_timeout_ms orelse 5000,
            .target_port = definition.http_proxy_target_port,
            .preserve_host = definition.http_proxy_preserve_host orelse true,
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
        try snapshots.append(alloc, .{
            .route_name = try alloc.dupe(u8, route.route_name),
            .host = try alloc.dupe(u8, route.host),
            .path_prefix = try alloc.dupe(u8, route.path_prefix),
            .rewrite_prefix = if (route.rewrite_prefix) |rewrite_prefix| try alloc.dupe(u8, rewrite_prefix) else null,
            .match_headers = try cloneHeaderMatches(alloc, route.match_headers),
            .retries = route.retries,
            .connect_timeout_ms = route.connect_timeout_ms,
            .request_timeout_ms = route.request_timeout_ms,
            .target_port = route.target_port,
            .preserve_host = route.preserve_host,
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
        service.http_proxy_target_port = primary.target_port;
        service.http_proxy_preserve_host = primary.preserve_host;
        return;
    }

    try replaceOptionalOwned(alloc, &service.http_proxy_host, definition.http_proxy_host);
    try replaceOptionalOwned(alloc, &service.http_proxy_path_prefix, definition.http_proxy_path_prefix);
    try replaceOptionalOwned(alloc, &service.http_proxy_rewrite_prefix, definition.http_proxy_rewrite_prefix);
    service.http_proxy_retries = definition.http_proxy_retries;
    service.http_proxy_connect_timeout_ms = definition.http_proxy_connect_timeout_ms;
    service.http_proxy_request_timeout_ms = definition.http_proxy_request_timeout_ms;
    service.http_proxy_target_port = definition.http_proxy_target_port;
    service.http_proxy_preserve_host = definition.http_proxy_preserve_host;
}

fn isEndpointEligible(endpoint: *const EndpointState) bool {
    if (!std.mem.eql(u8, endpoint.admin_state, "active")) return false;
    if (endpoint.node_lost) return false;
    if (endpoint.readiness_required) return endpoint.observed_health == .healthy;
    return endpoint.observed_health != .unhealthy;
}

fn cloneHeaderMatches(alloc: Allocator, matches: []const HttpHeaderMatch) Error![]const HttpHeaderMatch {
    var cloned: std.ArrayList(HttpHeaderMatch) = .empty;
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
        .http_proxy_preserve_host = false,
    });

    const snapshot = try registry.snapshotService(std.testing.allocator, "api");
    defer snapshot.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("api.internal", snapshot.http_proxy_host.?);
    try std.testing.expectEqualStrings("/v1", snapshot.http_proxy_path_prefix.?);
    try std.testing.expectEqual(@as(?u8, 2), snapshot.http_proxy_retries);
    try std.testing.expectEqual(@as(?u32, 1500), snapshot.http_proxy_connect_timeout_ms);
    try std.testing.expectEqual(@as(?u32, 5000), snapshot.http_proxy_request_timeout_ms);
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
