const std = @import("std");
const log = @import("../lib/log.zig");
const rollout = @import("service_rollout.zig");
const service_registry = @import("service_registry.zig");
const store = @import("../state/store.zig");

const Allocator = std.mem.Allocator;

pub const ServiceSnapshot = service_registry.ServiceSnapshot;
pub const EndpointSnapshot = service_registry.EndpointSnapshot;
pub const RuntimeError = service_registry.Error || error{
    StoreReadFailed,
    StoreWriteFailed,
};

var mutex: std.Thread.Mutex = .{};
var initialized: bool = false;
var registry: service_registry.Registry = undefined;

pub fn resetForTest() void {
    mutex.lock();
    defer mutex.unlock();

    if (initialized) {
        registry.deinit();
        initialized = false;
    }
}

pub fn syncServiceFromStore(service_name: []const u8) void {
    if (rollout.mode() == .legacy) return;

    mutex.lock();
    defer mutex.unlock();

    ensureInitializedLocked() catch |err| {
        log.warn("service registry runtime: failed to initialize before syncing {s}: {}", .{ service_name, err });
        return;
    };

    syncServiceFromStoreLocked(service_name) catch |err| {
        log.warn("service registry runtime: failed to sync service {s}: {}", .{ service_name, err });
    };
}

pub fn removeContainer(container_id: []const u8) void {
    if (rollout.mode() == .legacy) return;

    mutex.lock();
    defer mutex.unlock();

    ensureInitializedLocked() catch |err| {
        log.warn("service registry runtime: failed to initialize before removing {s}: {}", .{ container_id, err });
        return;
    };

    _ = registry.removeEndpointsByContainer(container_id);
}

pub fn noteProbeResult(service_name: []const u8, endpoint_id: []const u8, healthy: bool) void {
    if (rollout.mode() == .legacy) return;

    mutex.lock();
    defer mutex.unlock();

    ensureInitializedLocked() catch |err| {
        log.warn("service registry runtime: failed to initialize before probe result for {s}: {}", .{ service_name, err });
        return;
    };

    _ = registry.noteProbeResult(service_name, endpoint_id, healthy) catch |err| {
        log.warn("service registry runtime: failed to apply probe result for {s}/{s}: {}", .{ service_name, endpoint_id, err });
        return;
    };
}

pub fn requestReconcile(service_name: []const u8) RuntimeError!void {
    mutex.lock();
    defer mutex.unlock();

    try ensureInitializedLocked();
    _ = try registry.requestReconcile(service_name);
}

pub fn noteNodeLost(node_id: i64) !usize {
    mutex.lock();
    defer mutex.unlock();

    try ensureInitializedLocked();
    return registry.noteNodeLost(node_id);
}

pub fn noteNodeRecovered(node_id: i64) !usize {
    mutex.lock();
    defer mutex.unlock();

    try ensureInitializedLocked();
    return registry.noteNodeRecovered(node_id);
}

pub fn markReconcileSucceeded(service_name: []const u8) RuntimeError!void {
    mutex.lock();
    defer mutex.unlock();

    try ensureInitializedLocked();
    try registry.markReconcileSucceeded(service_name);
}

pub fn markReconcileFailed(service_name: []const u8, message: []const u8) RuntimeError!void {
    mutex.lock();
    defer mutex.unlock();

    try ensureInitializedLocked();
    try registry.markReconcileFailed(service_name, message);
}

pub fn snapshotServices(alloc: Allocator) !std.ArrayList(ServiceSnapshot) {
    mutex.lock();
    defer mutex.unlock();

    try ensureInitializedLocked();
    return registry.snapshotServices(alloc);
}

pub fn snapshotService(alloc: Allocator, service_name: []const u8) !ServiceSnapshot {
    mutex.lock();
    defer mutex.unlock();

    try ensureInitializedLocked();
    return registry.snapshotService(alloc, service_name);
}

pub fn snapshotServiceEndpoints(alloc: Allocator, service_name: []const u8) !std.ArrayList(EndpointSnapshot) {
    mutex.lock();
    defer mutex.unlock();

    try ensureInitializedLocked();
    return registry.snapshotServiceEndpoints(alloc, service_name);
}

pub fn drainEndpoint(service_name: []const u8, endpoint_id: []const u8) RuntimeError!void {
    mutex.lock();
    defer mutex.unlock();

    try ensureInitializedLocked();
    try registry.ensureEndpointExists(service_name, endpoint_id);

    store.markServiceEndpointAdminState(service_name, endpoint_id, "draining") catch return error.StoreWriteFailed;
    try syncServiceFromStoreLocked(service_name);
}

pub fn deleteEndpoint(service_name: []const u8, endpoint_id: []const u8) RuntimeError!void {
    mutex.lock();
    defer mutex.unlock();

    try ensureInitializedLocked();
    try registry.ensureEndpointExists(service_name, endpoint_id);

    store.removeServiceEndpoint(service_name, endpoint_id) catch return error.StoreWriteFailed;
    try syncServiceFromStoreLocked(service_name);
}

fn ensureInitializedLocked() !void {
    if (initialized) return;

    var next_registry = service_registry.Registry.init(std.heap.page_allocator);
    errdefer next_registry.deinit();

    try loadSnapshotInto(&next_registry);

    registry = next_registry;
    initialized = true;
}

fn loadSnapshotInto(next_registry: *service_registry.Registry) !void {
    const alloc = std.heap.page_allocator;
    var services = store.listServices(alloc) catch return error.StoreReadFailed;
    defer {
        for (services.items) |service| service.deinit(alloc);
        services.deinit(alloc);
    }

    for (services.items) |service| {
        try next_registry.upsertService(.{
            .service_name = service.service_name,
            .vip_address = service.vip_address,
            .lb_policy = service.lb_policy,
        });

        var endpoints = store.listServiceEndpoints(alloc, service.service_name) catch return error.StoreReadFailed;
        defer {
            for (endpoints.items) |endpoint| endpoint.deinit(alloc);
            endpoints.deinit(alloc);
        }

        var definitions: std.ArrayList(service_registry.EndpointDefinition) = .empty;
        defer definitions.deinit(alloc);
        for (endpoints.items) |endpoint| {
            try definitions.append(alloc, .{
                .endpoint_id = endpoint.endpoint_id,
                .container_id = endpoint.container_id,
                .node_id = endpoint.node_id,
                .ip_address = endpoint.ip_address,
                .port = endpoint.port,
                .weight = endpoint.weight,
                .admin_state = endpoint.admin_state,
                .generation = endpoint.generation,
                .registered_at = endpoint.registered_at,
                .last_seen_at = endpoint.last_seen_at,
            });
        }

        try next_registry.replaceServiceEndpoints(service.service_name, definitions.items);
    }
}

fn syncServiceFromStoreLocked(service_name: []const u8) !void {
    const alloc = std.heap.page_allocator;
    const service = store.getService(alloc, service_name) catch |err| switch (err) {
        store.StoreError.NotFound => {
            _ = registry.removeService(service_name);
            return;
        },
        else => return error.StoreReadFailed,
    };
    defer service.deinit(alloc);

    try registry.upsertService(.{
        .service_name = service.service_name,
        .vip_address = service.vip_address,
        .lb_policy = service.lb_policy,
    });

    var endpoints = store.listServiceEndpoints(alloc, service_name) catch return error.StoreReadFailed;
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(alloc);
        endpoints.deinit(alloc);
    }

    var definitions: std.ArrayList(service_registry.EndpointDefinition) = .empty;
    defer definitions.deinit(alloc);
    for (endpoints.items) |endpoint| {
        try definitions.append(alloc, .{
            .endpoint_id = endpoint.endpoint_id,
            .container_id = endpoint.container_id,
            .node_id = endpoint.node_id,
            .ip_address = endpoint.ip_address,
            .port = endpoint.port,
            .weight = endpoint.weight,
            .admin_state = endpoint.admin_state,
            .generation = endpoint.generation,
            .registered_at = endpoint.registered_at,
            .last_seen_at = endpoint.last_seen_at,
        });
    }

    try registry.replaceServiceEndpoints(service_name, definitions.items);
}

test "runtime bootstraps from persisted services" {
    try store.initTestDb();
    defer store.deinitTestDb();
    resetForTest();
    defer resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
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
    });

    const snapshot = try snapshotService(std.testing.allocator, "api");
    defer snapshot.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("10.43.0.2", snapshot.vip_address);
    try std.testing.expectEqual(@as(usize, 1), snapshot.total_endpoints);
    try std.testing.expectEqual(@as(usize, 1), snapshot.eligible_endpoints);
}

test "runtime sync preserves probe health across persisted refresh" {
    try store.initTestDb();
    defer store.deinitTestDb();
    resetForTest();
    defer resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
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
    });

    syncServiceFromStore("api");
    noteProbeResult("api", "ctr-1:0", true);

    try store.upsertServiceEndpoint(.{
        .service_name = "api",
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
    });

    syncServiceFromStore("api");

    var endpoints = try snapshotServiceEndpoints(std.testing.allocator, "api");
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(std.testing.allocator);
        endpoints.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), endpoints.items.len);
    try std.testing.expectEqualStrings("healthy", endpoints.items[0].observed_health);
    try std.testing.expectEqualStrings("10.42.0.19", endpoints.items[0].ip_address);
}

test "runtime can mark reconcile failure and recovery" {
    try store.initTestDb();
    defer store.deinitTestDb();
    resetForTest();
    defer resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });

    try markReconcileFailed("api", "sync failed");
    var failed = try snapshotService(std.testing.allocator, "api");
    defer failed.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("failed", failed.last_reconcile_status);
    try std.testing.expectEqualStrings("sync failed", failed.last_reconcile_error.?);

    try markReconcileSucceeded("api");
    var recovered = try snapshotService(std.testing.allocator, "api");
    defer recovered.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("idle", recovered.last_reconcile_status);
    try std.testing.expect(recovered.last_reconcile_error == null);
}
