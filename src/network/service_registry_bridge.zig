const std = @import("std");
const dns = @import("dns.zig");
const dns_registry = @import("dns/registry_support.zig");
const log = @import("../lib/log.zig");
const proxy_control_plane = @import("proxy/control_plane.zig");
const rollout = @import("service_rollout.zig");
const service_reconciler = @import("service_reconciler.zig");
const service_registry_runtime = @import("service_registry_runtime.zig");
const store = @import("../state/store.zig");

// Service discovery bridge: route container and health events through one
// module that persists endpoints, updates runtime state, and refreshes the
// reconciler-driven DNS/L7 control plane.

pub const BridgeOperation = enum {
    container_register,
    container_unregister,
    endpoint_healthy,
    endpoint_unhealthy,

    pub fn label(self: BridgeOperation) []const u8 {
        return switch (self) {
            .container_register => "container_register",
            .container_unregister => "container_unregister",
            .endpoint_healthy => "endpoint_healthy",
            .endpoint_unhealthy => "endpoint_unhealthy",
        };
    }
};

pub const FaultMode = enum {
    none,
    skip_legacy_apply,
    skip_shadow_record,

    pub fn label(self: FaultMode) []const u8 {
        return switch (self) {
            .none => "none",
            .skip_legacy_apply => "skip_legacy_apply",
            .skip_shadow_record => "skip_shadow_record",
        };
    }
};

var fault_mutex: std.Thread.Mutex = .{};
var fault_modes: [@typeInfo(BridgeOperation).@"enum".fields.len]FaultMode = [_]FaultMode{.none} ** @typeInfo(BridgeOperation).@"enum".fields.len;
var fault_counts: [@typeInfo(BridgeOperation).@"enum".fields.len]u64 = [_]u64{0} ** @typeInfo(BridgeOperation).@"enum".fields.len;

pub fn registerContainerService(service_name: []const u8, container_id: []const u8, container_ip: [4]u8, node_id: ?i64) void {
    var endpoint_id_buf: [96]u8 = undefined;
    const endpoint_id = activeEndpointId(container_id, &endpoint_id_buf);
    persistEndpoint(service_name, endpoint_id, container_id, container_ip, node_id);
    service_registry_runtime.syncServiceFromStore(service_name);

    const operation: BridgeOperation = .container_register;
    const mode = activeFaultMode(operation);
    if (!rollout.current().service_registry_reconciler) {
        switch (mode) {
            .none, .skip_shadow_record => dns.registerService(service_name, container_id, container_ip),
            .skip_legacy_apply => noteFaultInjection(operation),
        }
    }
    switch (mode) {
        .none, .skip_legacy_apply => service_reconciler.noteContainerRegisteredFrom(.container_runtime, service_name, container_id, container_ip),
        .skip_shadow_record => noteFaultInjection(operation),
    }
    refreshL7ControlPlane();
}

pub fn unregisterContainerService(container_id: []const u8) void {
    store.removeServiceEndpointsByContainer(container_id) catch |err| {
        log.warn("service registry bridge: failed to remove persisted endpoints for container {s}: {}", .{ container_id, err });
    };
    service_registry_runtime.removeContainer(container_id);

    const operation: BridgeOperation = .container_unregister;
    const mode = activeFaultMode(operation);
    if (!rollout.current().service_registry_reconciler) {
        switch (mode) {
            .none, .skip_shadow_record => dns.unregisterService(container_id),
            .skip_legacy_apply => noteFaultInjection(operation),
        }
    }
    switch (mode) {
        .none, .skip_legacy_apply => service_reconciler.noteContainerUnregisteredFrom(.container_runtime, container_id),
        .skip_shadow_record => noteFaultInjection(operation),
    }
    refreshL7ControlPlane();
}

pub fn markEndpointHealthy(service_name: []const u8, container_id: []const u8, container_ip: [4]u8) void {
    const operation: BridgeOperation = .endpoint_healthy;
    const mode = activeFaultMode(operation);
    if (!rollout.current().service_registry_reconciler) {
        switch (mode) {
            .none, .skip_shadow_record => dns.registerService(service_name, container_id, container_ip),
            .skip_legacy_apply => noteFaultInjection(operation),
        }
    }
    switch (mode) {
        .none, .skip_legacy_apply => service_reconciler.noteEndpointHealthyFrom(.health_checker, service_name, container_id, container_ip),
        .skip_shadow_record => noteFaultInjection(operation),
    }
    refreshL7ControlPlane();
}

pub fn markEndpointUnhealthy(service_name: []const u8, container_id: []const u8, container_ip: [4]u8) void {
    const operation: BridgeOperation = .endpoint_unhealthy;
    const mode = activeFaultMode(operation);
    if (!rollout.current().service_registry_reconciler) {
        switch (mode) {
            .none, .skip_shadow_record => dns.unregisterService(container_id),
            .skip_legacy_apply => noteFaultInjection(operation),
        }
    }
    switch (mode) {
        .none, .skip_legacy_apply => service_reconciler.noteEndpointUnhealthyFrom(.health_checker, service_name, container_id, container_ip),
        .skip_shadow_record => noteFaultInjection(operation),
    }
    refreshL7ControlPlane();
}

pub fn faultInjectionCount(operation: BridgeOperation) u64 {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    return fault_counts[@intFromEnum(operation)];
}

pub fn faultMode(operation: BridgeOperation) FaultMode {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    return fault_modes[@intFromEnum(operation)];
}

pub fn setFaultModeForTest(operation: BridgeOperation, mode: FaultMode) void {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    fault_modes[@intFromEnum(operation)] = mode;
}

pub fn resetFaultsForTest() void {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    fault_modes = [_]FaultMode{.none} ** fault_modes.len;
    fault_counts = [_]u64{0} ** fault_counts.len;
}

fn activeFaultMode(operation: BridgeOperation) FaultMode {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    return fault_modes[@intFromEnum(operation)];
}

fn noteFaultInjection(operation: BridgeOperation) void {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    fault_counts[@intFromEnum(operation)] += 1;
    log.warn("service registry bridge: injected fault mode={s} operation={s}", .{
        fault_modes[@intFromEnum(operation)].label(),
        operation.label(),
    });
}

fn refreshL7ControlPlane() void {
    proxy_control_plane.refreshIfEnabled();
}

fn persistEndpoint(service_name: []const u8, endpoint_id: []const u8, container_id: []const u8, container_ip: [4]u8, node_id: ?i64) void {
    const alloc = std.heap.page_allocator;
    const service = store.ensureService(alloc, service_name, "consistent_hash") catch |err| {
        log.warn("service registry bridge: failed to ensure persisted service {s}: {}", .{ service_name, err });
        return;
    };
    defer service.deinit(alloc);

    var ip_buf: [16]u8 = undefined;
    const ip_address = @import("ip.zig").formatIp(container_ip, &ip_buf);
    const now = std.time.timestamp();
    const persisted_node_id = resolveNodeId(service_name, endpoint_id, node_id);
    const existing = store.getServiceEndpoint(alloc, service_name, endpoint_id) catch |err| switch (err) {
        store.StoreError.NotFound => null,
        else => {
            log.warn("service registry bridge: failed to load existing endpoint {s} for service {s}: {}", .{ endpoint_id, service_name, err });
            return;
        },
    };
    defer if (existing) |record| record.deinit(alloc);

    const generation = if (existing) |record|
        if (std.mem.eql(u8, record.container_id, container_id) and
            record.node_id == persisted_node_id and
            std.mem.eql(u8, record.ip_address, ip_address) and
            record.port == 0)
            record.generation
        else
            record.generation + 1
    else
        1;
    const registered_at = if (existing) |record|
        if (generation == record.generation) record.registered_at else now
    else
        now;
    const admin_state = if (existing) |record|
        if (generation == record.generation or !std.mem.eql(u8, record.admin_state, "removed")) record.admin_state else "active"
    else
        "active";

    store.upsertServiceEndpoint(.{
        .service_name = service_name,
        .endpoint_id = endpoint_id,
        .container_id = container_id,
        .node_id = persisted_node_id,
        .ip_address = ip_address,
        .port = 0,
        .weight = 1,
        .admin_state = admin_state,
        .generation = generation,
        .registered_at = registered_at,
        .last_seen_at = now,
    }) catch |err| {
        log.warn("service registry bridge: failed to persist endpoint {s} for service {s}: {}", .{ endpoint_id, service_name, err });
    };
}

fn resolveNodeId(service_name: []const u8, endpoint_id: []const u8, node_id: ?i64) ?i64 {
    if (node_id) |resolved| return resolved;

    const alloc = std.heap.page_allocator;
    var endpoints = store.listServiceEndpoints(alloc, service_name) catch return null;
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(alloc);
        endpoints.deinit(alloc);
    }

    for (endpoints.items) |endpoint| {
        if (!std.mem.eql(u8, endpoint.endpoint_id, endpoint_id)) continue;
        return endpoint.node_id;
    }
    return null;
}

fn activeEndpointId(container_id: []const u8, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{s}:0", .{container_id}) catch container_id;
}

test "container bridge preserves legacy DNS and shadow events" {
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    try store.initTestDb();
    defer store.deinitTestDb();
    resetFaultsForTest();
    defer resetFaultsForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    service_reconciler.resetForTest();

    registerContainerService("api", "abc123", .{ 10, 42, 0, 9 }, null);

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 42, 0, 9 }), dns.lookupService("api"));
    try std.testing.expectEqual(@as(u64, 1), service_reconciler.eventCount(.container_registered));
    try std.testing.expectEqual(@as(u64, 1), service_reconciler.eventCountBySource(.container_runtime, .container_registered));
    const alloc = std.testing.allocator;
    const service = try store.getService(alloc, "api");
    defer service.deinit(alloc);
    try std.testing.expectEqualStrings("10.43.0.2", service.vip_address);

    var endpoints = try store.listServiceEndpoints(alloc, "api");
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(alloc);
        endpoints.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 1), endpoints.items.len);
    try std.testing.expectEqualStrings("abc123:0", endpoints.items[0].endpoint_id);
    try std.testing.expectEqualStrings("10.42.0.9", endpoints.items[0].ip_address);

    unregisterContainerService("abc123");

    try std.testing.expectEqual(@as(?[4]u8, null), dns.lookupService("api"));
    try std.testing.expectEqual(@as(u64, 1), service_reconciler.eventCount(.container_unregistered));
    try std.testing.expectEqual(@as(u64, 1), service_reconciler.eventCountBySource(.container_runtime, .container_unregistered));
    var remaining = try store.listServiceEndpoints(alloc, "api");
    defer {
        for (remaining.items) |endpoint| endpoint.deinit(alloc);
        remaining.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 0), remaining.items.len);
}

test "endpoint bridge keeps legacy DNS in legacy rollout mode" {
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    resetFaultsForTest();
    defer resetFaultsForTest();
    rollout.setForTest(.{});
    defer rollout.resetForTest();
    service_reconciler.resetForTest();

    markEndpointHealthy("web", "def456", .{ 10, 42, 0, 10 });

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 42, 0, 10 }), dns.lookupService("web"));
    try std.testing.expectEqual(@as(u64, 0), service_reconciler.eventCount(.endpoint_healthy));
    try std.testing.expectError(store.StoreError.NotFound, store.getService(std.testing.allocator, "web"));

    markEndpointUnhealthy("web", "def456", .{ 10, 42, 0, 10 });

    try std.testing.expectEqual(@as(?[4]u8, null), dns.lookupService("web"));
    try std.testing.expectEqual(@as(u64, 0), service_reconciler.eventCount(.endpoint_unhealthy));
}

test "bridge can skip legacy apply while preserving shadow event" {
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    resetFaultsForTest();
    defer resetFaultsForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    service_reconciler.resetForTest();

    setFaultModeForTest(.container_register, .skip_legacy_apply);
    registerContainerService("api", "abc123", .{ 10, 42, 0, 9 }, null);

    try std.testing.expectEqual(@as(?[4]u8, null), dns.lookupService("api"));
    try std.testing.expectEqual(@as(u64, 1), service_reconciler.eventCountBySource(.container_runtime, .container_registered));
    try std.testing.expectEqual(@as(u64, 1), faultInjectionCount(.container_register));
}

test "bridge can skip shadow record while preserving legacy apply" {
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    resetFaultsForTest();
    defer resetFaultsForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    service_reconciler.resetForTest();

    setFaultModeForTest(.endpoint_healthy, .skip_shadow_record);
    markEndpointHealthy("web", "def456", .{ 10, 42, 0, 10 });

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 42, 0, 10 }), dns.lookupService("web"));
    try std.testing.expectEqual(@as(u64, 0), service_reconciler.eventCountBySource(.health_checker, .endpoint_healthy));
    try std.testing.expectEqual(@as(u64, 1), faultInjectionCount(.endpoint_healthy));
}

test "fault mode accessor returns configured mode" {
    resetFaultsForTest();
    defer resetFaultsForTest();

    try std.testing.expectEqual(FaultMode.none, faultMode(.container_register));
    setFaultModeForTest(.container_register, .skip_legacy_apply);
    try std.testing.expectEqual(FaultMode.skip_legacy_apply, faultMode(.container_register));
}

test "authoritative reconciler owns legacy DNS writes when enabled" {
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    resetFaultsForTest();
    defer resetFaultsForTest();
    rollout.setForTest(.{ .service_registry_v2 = true, .service_registry_reconciler = true });
    defer rollout.resetForTest();
    service_reconciler.resetForTest();

    setFaultModeForTest(.container_register, .skip_legacy_apply);
    registerContainerService("api", "abc123", .{ 10, 42, 0, 9 }, null);

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 42, 0, 9 }), dns.lookupService("api"));
    try std.testing.expectEqual(@as(u64, 0), faultInjectionCount(.container_register));

    var mirrored = try store.lookupServiceNames(std.testing.allocator, "api");
    defer {
        for (mirrored.items) |ip_text| std.testing.allocator.free(ip_text);
        mirrored.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), mirrored.items.len);
    try std.testing.expectEqualStrings("10.42.0.9", mirrored.items[0]);
}

test "health bridge preserves existing node id for endpoint" {
    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    resetFaultsForTest();
    defer resetFaultsForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    service_reconciler.resetForTest();

    registerContainerService("api", "abc123", .{ 10, 42, 7, 9 }, 7);
    markEndpointHealthy("api", "abc123", .{ 10, 42, 7, 9 });

    var endpoints = try store.listServiceEndpoints(std.testing.allocator, "api");
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(std.testing.allocator);
        endpoints.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), endpoints.items.len);
    try std.testing.expectEqual(@as(?i64, 7), endpoints.items[0].node_id);
    try std.testing.expectEqualStrings("active", endpoints.items[0].admin_state);
}

test "health bridge does not overwrite persisted admin_state on probe transitions" {
    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    resetFaultsForTest();
    defer resetFaultsForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    service_reconciler.resetForTest();

    registerContainerService("api", "abc123", .{ 10, 42, 0, 9 }, null);
    try store.markServiceEndpointAdminState("api", "abc123:0", "draining");

    markEndpointHealthy("api", "abc123", .{ 10, 42, 0, 9 });

    const endpoint = try store.getServiceEndpoint(std.testing.allocator, "api", "abc123:0");
    defer endpoint.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("draining", endpoint.admin_state);
}
