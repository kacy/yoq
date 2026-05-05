const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const network_ip = @import("../../network/ip.zig");
const service_endpoints = @import("services_endpoints.zig");
const service_names = @import("services_names.zig");
const service_policies = @import("services_policies.zig");
const service_routes = @import("services_routes.zig");
const service_types = @import("services_types.zig");
const service_observability = @import("../../network/service_observability.zig");
const vip_allocator = @import("../../network/vip_allocator.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

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

const service_columns = service_types.service_columns;
const ServiceRow = service_types.ServiceRow;
const rowToServiceRecord = service_types.rowToServiceRecord;

pub fn createService(record: ServiceRecord) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return createServiceInDb(lease.db, record);
}

fn createServiceInDb(db: *sqlite.Db, record: ServiceRecord) StoreError!void {
    db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return StoreError.WriteFailed;
    var committed = false;
    errdefer if (!committed) db.exec("ROLLBACK;", .{}, .{}) catch {};
    db.exec(
        "INSERT INTO services (" ++ service_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            record.service_name,
            record.vip_address,
            record.lb_policy,
            record.http_proxy_host,
            record.http_proxy_path_prefix,
            record.http_proxy_rewrite_prefix,
            record.http_proxy_retries,
            record.http_proxy_connect_timeout_ms,
            record.http_proxy_request_timeout_ms,
            record.http_proxy_http2_idle_timeout_ms,
            record.http_proxy_target_port,
            if (record.http_proxy_preserve_host) |preserve_host| @as(?i64, @intFromBool(preserve_host)) else null,
            if (record.http_proxy_retry_on_5xx) |retry_on_5xx| @as(?i64, @intFromBool(retry_on_5xx)) else null,
            record.http_proxy_circuit_breaker_threshold,
            record.http_proxy_circuit_breaker_timeout_ms,
            record.http_proxy_mirror_service,
            record.created_at,
            record.updated_at,
        },
    ) catch return StoreError.WriteFailed;
    try service_routes.syncFromRecords(db, record.service_name, record.updated_at, record.http_routes);
    db.exec("COMMIT;", .{}, .{}) catch return StoreError.WriteFailed;
    committed = true;
}

pub fn ensureService(alloc: Allocator, service_name: []const u8, lb_policy: []const u8) StoreError!ServiceRecord {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return ensureServiceInDb(lease.db, alloc, service_name, lb_policy);
}

fn ensureServiceInDb(db: *sqlite.Db, alloc: Allocator, service_name: []const u8, lb_policy: []const u8) StoreError!ServiceRecord {
    db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return StoreError.WriteFailed;

    var committed = false;
    errdefer if (!committed) db.exec("ROLLBACK;", .{}, .{}) catch {};

    if (db.oneAlloc(
        ServiceRow,
        alloc,
        "SELECT " ++ service_columns ++ " FROM services WHERE service_name = ?;",
        .{},
        .{service_name},
    ) catch return StoreError.ReadFailed) |row| {
        const routes = try service_routes.listForDb(alloc, db, service_name);
        const record = rowToServiceRecord(row, routes);
        db.exec("COMMIT;", .{}, .{}) catch {
            record.deinit(alloc);
            return StoreError.WriteFailed;
        };
        committed = true;
        return record;
    }

    const vip = vip_allocator.allocate(db) catch {
        service_observability.noteVipAllocFailure();
        return StoreError.WriteFailed;
    };
    var vip_buf: [16]u8 = undefined;
    const vip_address = network_ip.formatIp(vip, &vip_buf);
    const now = nowRealSeconds();

    db.exec(
        "INSERT INTO services (service_name, vip_address, lb_policy, created_at, updated_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ service_name, vip_address, lb_policy, now, now },
    ) catch return StoreError.WriteFailed;

    db.exec("COMMIT;", .{}, .{}) catch return StoreError.WriteFailed;
    committed = true;

    const service_name_copy = alloc.dupe(u8, service_name) catch return StoreError.ReadFailed;
    errdefer alloc.free(service_name_copy);
    const vip_copy = alloc.dupe(u8, vip_address) catch return StoreError.ReadFailed;
    errdefer alloc.free(vip_copy);
    const lb_policy_copy = alloc.dupe(u8, lb_policy) catch return StoreError.ReadFailed;

    return .{
        .service_name = service_name_copy,
        .vip_address = vip_copy,
        .lb_policy = lb_policy_copy,
        .http_routes = alloc.alloc(ServiceHttpRouteRecord, 0) catch return StoreError.ReadFailed,
        .http_proxy_host = null,
        .http_proxy_path_prefix = null,
        .http_proxy_rewrite_prefix = null,
        .http_proxy_retries = null,
        .http_proxy_connect_timeout_ms = null,
        .http_proxy_request_timeout_ms = null,
        .http_proxy_http2_idle_timeout_ms = null,
        .http_proxy_target_port = null,
        .http_proxy_preserve_host = null,
        .created_at = now,
        .updated_at = now,
    };
}

pub fn syncServiceConfig(
    alloc: Allocator,
    service_name: []const u8,
    lb_policy: []const u8,
    routes: []const ServiceHttpRouteInput,
) StoreError!ServiceRecord {
    var existing = try ensureService(alloc, service_name, lb_policy);
    defer existing.deinit(alloc);

    {
        var lease = try common.leaseDb();
        defer lease.deinit();

        const now = nowRealSeconds();
        lease.db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return StoreError.WriteFailed;
        var committed = false;
        errdefer if (!committed) lease.db.exec("ROLLBACK;", .{}, .{}) catch {};
        lease.db.exec(
            "UPDATE services SET lb_policy = ?, updated_at = ? WHERE service_name = ?;",
            .{},
            .{ lb_policy, now, service_name },
        ) catch return StoreError.WriteFailed;
        try service_routes.replaceInDb(lease.db, service_name, now, routes);
        try service_routes.syncDerivedFields(lease.db, service_name, now, routes);
        lease.db.exec("COMMIT;", .{}, .{}) catch return StoreError.WriteFailed;
        committed = true;
    }

    return getService(alloc, service_name);
}

fn getServiceInDb(db: *sqlite.Db, alloc: Allocator, service_name: []const u8) StoreError!ServiceRecord {
    const row = (db.oneAlloc(
        ServiceRow,
        alloc,
        "SELECT " ++ service_columns ++ " FROM services WHERE service_name = ?;",
        .{},
        .{service_name},
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;
    const routes = try service_routes.listForDb(alloc, db, service_name);
    return rowToServiceRecord(row, routes);
}

pub fn getService(alloc: Allocator, service_name: []const u8) StoreError!ServiceRecord {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return getServiceInDb(lease.db, alloc, service_name);
}

fn listServicesInDb(db: *sqlite.Db, alloc: Allocator) StoreError!std.ArrayList(ServiceRecord) {
    var services: std.ArrayList(ServiceRecord) = .empty;
    var stmt = db.prepare(
        "SELECT " ++ service_columns ++ " FROM services ORDER BY service_name;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ServiceRow, .{}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        const routes = try service_routes.listForDb(alloc, db, row.service_name.data);
        services.append(alloc, rowToServiceRecord(row, routes)) catch return StoreError.ReadFailed;
    }
    return services;
}

pub fn listServices(alloc: Allocator) StoreError!std.ArrayList(ServiceRecord) {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return listServicesInDb(lease.db, alloc);
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

test "createService and getService round-trip" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .http_proxy_retries = 2,
        .http_proxy_connect_timeout_ms = 1500,
        .http_proxy_request_timeout_ms = 5000,
        .http_proxy_http2_idle_timeout_ms = 30000,
        .http_proxy_target_port = 8080,
        .http_proxy_preserve_host = true,
        .http_proxy_mirror_service = "api-shadow",
        .created_at = 1000,
        .updated_at = 1000,
    });

    const alloc = std.testing.allocator;
    const service = try getService(alloc, "api");
    defer service.deinit(alloc);

    try std.testing.expectEqualStrings("api", service.service_name);
    try std.testing.expectEqualStrings("10.43.0.10", service.vip_address);
    try std.testing.expectEqualStrings("consistent_hash", service.lb_policy);
    try std.testing.expectEqualStrings("api.internal", service.http_proxy_host.?);
    try std.testing.expectEqualStrings("/v1", service.http_proxy_path_prefix.?);
    try std.testing.expectEqual(@as(?i64, 2), service.http_proxy_retries);
    try std.testing.expectEqual(@as(?i64, 1500), service.http_proxy_connect_timeout_ms);
    try std.testing.expectEqual(@as(?i64, 5000), service.http_proxy_request_timeout_ms);
    try std.testing.expectEqual(@as(?i64, 30000), service.http_proxy_http2_idle_timeout_ms);
    try std.testing.expectEqual(@as(?i64, 8080), service.http_proxy_target_port);
    try std.testing.expectEqual(@as(?bool, true), service.http_proxy_preserve_host);
    try std.testing.expectEqualStrings("api-shadow", service.http_proxy_mirror_service.?);
    try std.testing.expectEqual(@as(i64, 1000), service.created_at);
}

test "listServices returns services ordered by name" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try createService(.{
        .service_name = "web",
        .vip_address = "10.43.0.20",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .created_at = 1001,
        .updated_at = 1001,
    });

    const alloc = std.testing.allocator;
    var services = try listServices(alloc);
    defer {
        for (services.items) |service| service.deinit(alloc);
        services.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 2), services.items.len);
    try std.testing.expectEqualStrings("api", services.items[0].service_name);
    try std.testing.expectEqualStrings("web", services.items[1].service_name);
}

test "ensureService allocates once and returns the existing VIP thereafter" {
    try common.initTestDb();
    defer common.deinitTestDb();

    const alloc = std.testing.allocator;

    const first = try ensureService(alloc, "api", "consistent_hash");
    defer first.deinit(alloc);
    try std.testing.expectEqualStrings("10.43.0.2", first.vip_address);

    const second = try ensureService(alloc, "api", "consistent_hash");
    defer second.deinit(alloc);
    try std.testing.expectEqualStrings("10.43.0.2", second.vip_address);

    var services = try listServices(alloc);
    defer {
        for (services.items) |service| service.deinit(alloc);
        services.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 1), services.items.len);
}

test "syncServiceConfig updates proxy policy without changing vip" {
    try common.initTestDb();
    defer common.deinitTestDb();

    const alloc = std.testing.allocator;

    const first = try ensureService(alloc, "api", "consistent_hash");
    defer first.deinit(alloc);

    const updated = try syncServiceConfig(
        alloc,
        "api",
        "consistent_hash",
        &.{
            .{
                .route_name = "default",
                .host = "api.internal",
                .path_prefix = "/v1",
                .mirror_service = "api-shadow",
                .retries = 2,
                .connect_timeout_ms = 1500,
                .request_timeout_ms = 5000,
                .http2_idle_timeout_ms = 45000,
                .target_port = 8080,
                .preserve_host = false,
            },
        },
    );
    defer updated.deinit(alloc);

    try std.testing.expectEqualStrings(first.vip_address, updated.vip_address);
    try std.testing.expectEqualStrings("api.internal", updated.http_proxy_host.?);
    try std.testing.expectEqualStrings("/v1", updated.http_proxy_path_prefix.?);
    try std.testing.expectEqual(@as(?i64, 45000), updated.http_proxy_http2_idle_timeout_ms);
    try std.testing.expectEqual(@as(?i64, 8080), updated.http_proxy_target_port);
    try std.testing.expectEqual(@as(?bool, false), updated.http_proxy_preserve_host);
    try std.testing.expectEqualStrings("api-shadow", updated.http_proxy_mirror_service.?);
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
