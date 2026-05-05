const std = @import("std");
const common = @import("common.zig");
const service_core = @import("services_core.zig");
const types = @import("services_types.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;
const ServiceEndpointRecord = types.ServiceEndpointRecord;

pub fn get(alloc: Allocator, service_name: []const u8, endpoint_id: []const u8) StoreError!ServiceEndpointRecord {
    var lease = try common.leaseDb();
    defer lease.deinit();

    const row = (lease.db.oneAlloc(
        types.ServiceEndpointRow,
        alloc,
        "SELECT " ++ types.endpoint_columns ++ " FROM service_endpoints WHERE service_name = ? AND endpoint_id = ?;",
        .{},
        .{ service_name, endpoint_id },
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;
    return types.rowToServiceEndpointRecord(row);
}

pub fn upsert(record: ServiceEndpointRecord) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec(
        "INSERT INTO service_endpoints (" ++ types.endpoint_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" ++
            " ON CONFLICT(service_name, endpoint_id) DO UPDATE SET" ++
            " container_id = excluded.container_id," ++
            " node_id = excluded.node_id," ++
            " ip_address = excluded.ip_address," ++
            " port = excluded.port," ++
            " weight = excluded.weight," ++
            " admin_state = excluded.admin_state," ++
            " generation = excluded.generation," ++
            " registered_at = excluded.registered_at," ++
            " last_seen_at = excluded.last_seen_at;",
        .{},
        .{
            record.service_name,
            record.endpoint_id,
            record.container_id,
            record.node_id,
            record.ip_address,
            record.port,
            record.weight,
            record.admin_state,
            record.generation,
            record.registered_at,
            record.last_seen_at,
        },
    ) catch return StoreError.WriteFailed;
}

pub fn remove(service_name: []const u8, endpoint_id: []const u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec(
        "DELETE FROM service_endpoints WHERE service_name = ? AND endpoint_id = ?;",
        .{},
        .{ service_name, endpoint_id },
    ) catch return StoreError.WriteFailed;
}

pub fn markAdminState(service_name: []const u8, endpoint_id: []const u8, admin_state: []const u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec(
        "UPDATE service_endpoints SET admin_state = ? WHERE service_name = ? AND endpoint_id = ?;",
        .{},
        .{ admin_state, service_name, endpoint_id },
    ) catch return StoreError.WriteFailed;
}

pub fn list(alloc: Allocator, service_name: []const u8) StoreError!std.ArrayList(ServiceEndpointRecord) {
    return query(
        alloc,
        "SELECT " ++ types.endpoint_columns ++ " FROM service_endpoints WHERE service_name = ? ORDER BY registered_at DESC;",
        .{service_name},
    );
}

pub fn listByNode(alloc: Allocator, node_id: i64) StoreError!std.ArrayList(ServiceEndpointRecord) {
    return query(
        alloc,
        "SELECT " ++ types.endpoint_columns ++ " FROM service_endpoints WHERE node_id = ? ORDER BY service_name, endpoint_id;",
        .{node_id},
    );
}

pub fn removeByContainer(container_id: []const u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec(
        "DELETE FROM service_endpoints WHERE container_id = ?;",
        .{},
        .{container_id},
    ) catch return StoreError.WriteFailed;
}

pub fn removeByNode(node_id: i64) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec(
        "DELETE FROM service_endpoints WHERE node_id = ?;",
        .{},
        .{node_id},
    ) catch return StoreError.WriteFailed;
}

fn query(alloc: Allocator, comptime sql: []const u8, args: anytype) StoreError!std.ArrayList(ServiceEndpointRecord) {
    var lease = try common.leaseDb();
    defer lease.deinit();

    var endpoints: std.ArrayList(ServiceEndpointRecord) = .empty;
    var stmt = lease.db.prepare(sql) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(types.ServiceEndpointRow, args) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        endpoints.append(alloc, types.rowToServiceEndpointRecord(row)) catch return StoreError.ReadFailed;
    }
    return endpoints;
}

test "upsert updates an existing endpoint" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try service_core.create(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });

    try upsert(.{
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
    try upsert(.{
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
    var endpoints = try list(alloc, "api");
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

test "queries support service and node cleanup flows" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try service_core.create(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try service_core.create(.{
        .service_name = "web",
        .vip_address = "10.43.0.20",
        .lb_policy = "consistent_hash",
        .created_at = 1001,
        .updated_at = 1001,
    });

    try upsert(.{
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
    try upsert(.{
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

    try markAdminState("api", "api-1:8080", "removed");

    const alloc = std.testing.allocator;
    var node_endpoints = try listByNode(alloc, 3);
    defer {
        for (node_endpoints.items) |endpoint| endpoint.deinit(alloc);
        node_endpoints.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 2), node_endpoints.items.len);
    try std.testing.expectEqualStrings("removed", node_endpoints.items[0].admin_state);
    try std.testing.expectEqualStrings("active", node_endpoints.items[1].admin_state);

    try removeByContainer("api-1");

    var api_endpoints = try list(alloc, "api");
    defer {
        for (api_endpoints.items) |endpoint| endpoint.deinit(alloc);
        api_endpoints.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 0), api_endpoints.items.len);

    try removeByNode(3);

    var remaining = try listByNode(alloc, 3);
    defer {
        for (remaining.items) |endpoint| endpoint.deinit(alloc);
        remaining.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 0), remaining.items.len);
}
