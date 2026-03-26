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
        alloc.free(self.last_reconcile_status);
        if (self.last_reconcile_error) |message| alloc.free(message);
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
    endpoints: std.ArrayList(EndpointState) = .empty,
    last_reconcile_status: ReconcileStatus = .idle,
    last_reconcile_error: ?[]const u8 = null,
    last_reconcile_requested_at: ?i64 = null,
    overflow: bool = false,

    fn deinit(self: *ServiceState, alloc: Allocator) void {
        alloc.free(self.service_name);
        alloc.free(self.vip_address);
        alloc.free(self.lb_policy);
        if (self.last_reconcile_error) |message| alloc.free(message);
        for (self.endpoints.items) |endpoint| endpoint.deinit(alloc);
        self.endpoints.deinit(alloc);
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
            return;
        }

        try self.services.append(self.alloc, .{
            .service_name = try self.alloc.dupe(u8, definition.service_name),
            .vip_address = try self.alloc.dupe(u8, definition.vip_address),
            .lb_policy = try self.alloc.dupe(u8, definition.lb_policy),
        });
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
                endpoint.observed_health = existing.observed_health;
                endpoint.node_lost = existing.node_lost;
                endpoint.last_transition_at = existing.last_transition_at;
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

    return .{
        .service_name = try alloc.dupe(u8, service.service_name),
        .vip_address = try alloc.dupe(u8, service.vip_address),
        .lb_policy = try alloc.dupe(u8, service.lb_policy),
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

fn isEndpointEligible(endpoint: *const EndpointState) bool {
    if (!std.mem.eql(u8, endpoint.admin_state, "active")) return false;
    if (endpoint.node_lost) return false;
    return endpoint.observed_health != .unhealthy;
}

fn replaceOwned(alloc: Allocator, current: *[]const u8, next: []const u8) Error!void {
    if (std.mem.eql(u8, current.*, next)) return;
    const owned = try alloc.dupe(u8, next);
    alloc.free(current.*);
    current.* = owned;
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
