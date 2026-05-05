const std = @import("std");
const common = @import("common.zig");
const service_core = @import("services_core.zig");
const service_endpoints = @import("services_endpoints.zig");
const service_names = @import("services_names.zig");
const service_policies = @import("services_policies.zig");
const service_types = @import("services_types.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const ServiceNameRecord = service_types.ServiceNameRecord;
pub const ServiceRecord = service_types.ServiceRecord;
pub const ServiceHttpRouteRecord = service_types.ServiceHttpRouteRecord;
pub const ServiceHttpRouteMethodRecord = service_types.ServiceHttpRouteMethodRecord;
pub const ServiceHttpRouteHeaderRecord = service_types.ServiceHttpRouteHeaderRecord;
pub const ServiceHttpRouteInput = service_types.ServiceHttpRouteInput;
pub const ServiceHttpRouteMethodInput = service_types.ServiceHttpRouteMethodInput;
pub const ServiceHttpRouteHeaderInput = service_types.ServiceHttpRouteHeaderInput;
pub const ServiceHttpRouteBackendRecord = service_types.ServiceHttpRouteBackendRecord;
pub const ServiceHttpRouteBackendInput = service_types.ServiceHttpRouteBackendInput;
pub const ServiceEndpointRecord = service_types.ServiceEndpointRecord;
pub const NetworkPolicyRecord = service_types.NetworkPolicyRecord;

pub fn createService(record: ServiceRecord) StoreError!void {
    return service_core.create(record);
}

pub fn ensureService(alloc: Allocator, service_name: []const u8, lb_policy: []const u8) StoreError!ServiceRecord {
    return service_core.ensure(alloc, service_name, lb_policy);
}

pub fn syncServiceConfig(
    alloc: Allocator,
    service_name: []const u8,
    lb_policy: []const u8,
    routes: []const ServiceHttpRouteInput,
) StoreError!ServiceRecord {
    return service_core.syncConfig(alloc, service_name, lb_policy, routes);
}

pub fn getService(alloc: Allocator, service_name: []const u8) StoreError!ServiceRecord {
    return service_core.get(alloc, service_name);
}

pub fn listServices(alloc: Allocator) StoreError!std.ArrayList(ServiceRecord) {
    return service_core.list(alloc);
}

pub fn getServiceEndpoint(alloc: Allocator, service_name: []const u8, endpoint_id: []const u8) StoreError!ServiceEndpointRecord {
    return service_endpoints.get(alloc, service_name, endpoint_id);
}

pub fn upsertServiceEndpoint(record: ServiceEndpointRecord) StoreError!void {
    return service_endpoints.upsert(record);
}

pub fn removeServiceEndpoint(service_name: []const u8, endpoint_id: []const u8) StoreError!void {
    return service_endpoints.remove(service_name, endpoint_id);
}

pub fn markServiceEndpointAdminState(service_name: []const u8, endpoint_id: []const u8, admin_state: []const u8) StoreError!void {
    return service_endpoints.markAdminState(service_name, endpoint_id, admin_state);
}

pub fn listServiceEndpoints(alloc: Allocator, service_name: []const u8) StoreError!std.ArrayList(ServiceEndpointRecord) {
    return service_endpoints.list(alloc, service_name);
}

pub fn listServiceEndpointsByNode(alloc: Allocator, node_id: i64) StoreError!std.ArrayList(ServiceEndpointRecord) {
    return service_endpoints.listByNode(alloc, node_id);
}

pub fn removeServiceEndpointsByContainer(container_id: []const u8) StoreError!void {
    return service_endpoints.removeByContainer(container_id);
}

pub fn removeServiceEndpointsByNode(node_id: i64) StoreError!void {
    return service_endpoints.removeByNode(node_id);
}

pub fn registerServiceName(name: []const u8, container_id: []const u8, ip_address: []const u8) StoreError!void {
    return service_names.register(name, container_id, ip_address);
}

pub fn unregisterServiceName(container_id: []const u8) StoreError!void {
    return service_names.unregister(container_id);
}

pub fn removeServiceNamesByName(name: []const u8) StoreError!void {
    return service_names.removeByName(name);
}

pub fn lookupServiceNames(alloc: Allocator, name: []const u8) StoreError!std.ArrayList([]const u8) {
    return service_names.lookupNames(alloc, name);
}

pub fn lookupServiceAddresses(alloc: Allocator, name: []const u8) StoreError!std.ArrayList([]const u8) {
    return service_names.lookupAddresses(alloc, name);
}

pub fn listServiceNames(alloc: Allocator) StoreError!std.ArrayList(ServiceNameRecord) {
    return service_names.list(alloc);
}

pub fn addNetworkPolicy(source: []const u8, target: []const u8, action: []const u8) StoreError!void {
    return service_policies.add(source, target, action);
}

pub fn removeNetworkPolicy(source: []const u8, target: []const u8) StoreError!void {
    return service_policies.remove(source, target);
}

pub fn listNetworkPolicies(alloc: Allocator) StoreError!std.ArrayList(NetworkPolicyRecord) {
    return service_policies.list(alloc);
}

pub fn getServicePolicies(alloc: Allocator, source: []const u8) StoreError!std.ArrayList(NetworkPolicyRecord) {
    return service_policies.listForSource(alloc, source);
}

test "upsertServiceEndpoint updates an existing endpoint" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });

    try upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "ctr-1:8080",
        .container_id = "ctr-1",
        .node_id = 7,
        .ip_address = "10.42.0.9",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    try upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "ctr-1:8080",
        .container_id = "ctr-1b",
        .node_id = 8,
        .ip_address = "10.42.0.19",
        .port = 8080,
        .weight = 2,
        .admin_state = "draining",
        .generation = 2,
        .registered_at = 1001,
        .last_seen_at = 1002,
    });

    const alloc = std.testing.allocator;
    var endpoints = try listServiceEndpoints(alloc, "api");
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(alloc);
        endpoints.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), endpoints.items.len);
    try std.testing.expectEqualStrings("ctr-1b", endpoints.items[0].container_id);
    try std.testing.expectEqual(@as(?i64, 8), endpoints.items[0].node_id);
    try std.testing.expectEqualStrings("10.42.0.19", endpoints.items[0].ip_address);
    try std.testing.expectEqual(@as(i64, 2), endpoints.items[0].weight);
    try std.testing.expectEqualStrings("draining", endpoints.items[0].admin_state);
    try std.testing.expectEqual(@as(i64, 2), endpoints.items[0].generation);
}

test "service endpoint queries support service and node cleanup flows" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try createService(.{
        .service_name = "web",
        .vip_address = "10.43.0.20",
        .lb_policy = "consistent_hash",
        .created_at = 1001,
        .updated_at = 1001,
    });

    try upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-1:8080",
        .container_id = "api-1",
        .node_id = 3,
        .ip_address = "10.42.0.11",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    try upsertServiceEndpoint(.{
        .service_name = "web",
        .endpoint_id = "web-1:8080",
        .container_id = "web-1",
        .node_id = 3,
        .ip_address = "10.42.0.12",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1001,
        .last_seen_at = 1001,
    });

    try markServiceEndpointAdminState("api", "api-1:8080", "removed");

    const alloc = std.testing.allocator;
    var node_endpoints = try listServiceEndpointsByNode(alloc, 3);
    defer {
        for (node_endpoints.items) |endpoint| endpoint.deinit(alloc);
        node_endpoints.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 2), node_endpoints.items.len);
    try std.testing.expectEqualStrings("removed", node_endpoints.items[0].admin_state);
    try std.testing.expectEqualStrings("active", node_endpoints.items[1].admin_state);

    try removeServiceEndpointsByContainer("api-1");

    var api_endpoints = try listServiceEndpoints(alloc, "api");
    defer {
        for (api_endpoints.items) |endpoint| endpoint.deinit(alloc);
        api_endpoints.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 0), api_endpoints.items.len);

    try removeServiceEndpointsByNode(3);

    var remaining = try listServiceEndpointsByNode(alloc, 3);
    defer {
        for (remaining.items) |endpoint| endpoint.deinit(alloc);
        remaining.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 0), remaining.items.len);
}

test "lookupServiceAddresses prefers service VIPs over legacy name rows" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try registerServiceName("api", "ctr-1", "10.42.0.11");

    const alloc = std.testing.allocator;
    var addresses = try lookupServiceAddresses(alloc, "api");
    defer {
        for (addresses.items) |ip| alloc.free(ip);
        addresses.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), addresses.items.len);
    try std.testing.expectEqualStrings("10.43.0.10", addresses.items[0]);
}

test "service name register and lookup" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try registerServiceName("web", "abc123", "10.42.0.2");

    const alloc = std.testing.allocator;
    var ips = try lookupServiceNames(alloc, "web");
    defer {
        for (ips.items) |ip| alloc.free(ip);
        ips.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), ips.items.len);
    try std.testing.expectEqualStrings("10.42.0.2", ips.items[0]);
}

test "service name unregister removes entries" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try registerServiceName("db", "xyz789", "10.42.0.3");
    try unregisterServiceName("xyz789");

    const alloc = std.testing.allocator;
    var ips = try lookupServiceNames(alloc, "db");
    defer ips.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 0), ips.items.len);
}

test "service name lookup returns empty for unknown" {
    try common.initTestDb();
    defer common.deinitTestDb();

    const alloc = std.testing.allocator;
    var ips = try lookupServiceNames(alloc, "nonexistent");
    defer ips.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 0), ips.items.len);
}

test "network policy add list get and remove" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try addNetworkPolicy("api", "db", "allow");
    try addNetworkPolicy("web", "db", "deny");

    const alloc = std.testing.allocator;
    var all = try listNetworkPolicies(alloc);
    defer {
        for (all.items) |policy| policy.deinit(alloc);
        all.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 2), all.items.len);

    var api_policies = try getServicePolicies(alloc, "api");
    defer {
        for (api_policies.items) |policy| policy.deinit(alloc);
        api_policies.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), api_policies.items.len);
    try std.testing.expectEqualStrings("api", api_policies.items[0].source_service);
    try std.testing.expectEqualStrings("db", api_policies.items[0].target_service);
    try std.testing.expectEqualStrings("allow", api_policies.items[0].action);

    try removeNetworkPolicy("api", "db");

    var remaining = try listNetworkPolicies(alloc);
    defer {
        for (remaining.items) |policy| policy.deinit(alloc);
        remaining.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), remaining.items.len);
    try std.testing.expectEqualStrings("web", remaining.items[0].source_service);
}
