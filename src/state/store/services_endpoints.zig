const std = @import("std");
const common = @import("common.zig");
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
