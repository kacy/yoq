const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const network_ip = @import("../../network/ip.zig");
const route_types = @import("services_route_types.zig");
const service_routes = @import("services_routes.zig");
const service_types = @import("services_types.zig");
const service_observability = @import("../../network/service_observability.zig");
const vip_allocator = @import("../../network/vip_allocator.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

const ServiceHttpRouteInput = route_types.ServiceHttpRouteInput;
const ServiceHttpRouteRecord = route_types.ServiceHttpRouteRecord;
const ServiceRecord = service_types.ServiceRecord;
const ServiceRow = service_types.ServiceRow;
const rowToServiceRecord = service_types.rowToServiceRecord;
const service_columns = service_types.service_columns;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

pub fn create(record: ServiceRecord) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return createInDb(lease.db, record);
}

fn createInDb(db: *sqlite.Db, record: ServiceRecord) StoreError!void {
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

pub fn ensure(alloc: Allocator, service_name: []const u8, lb_policy: []const u8) StoreError!ServiceRecord {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return ensureInDb(lease.db, alloc, service_name, lb_policy);
}

fn ensureInDb(db: *sqlite.Db, alloc: Allocator, service_name: []const u8, lb_policy: []const u8) StoreError!ServiceRecord {
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
    errdefer alloc.free(lb_policy_copy);
    const http_routes = alloc.alloc(ServiceHttpRouteRecord, 0) catch return StoreError.ReadFailed;

    return .{
        .service_name = service_name_copy,
        .vip_address = vip_copy,
        .lb_policy = lb_policy_copy,
        .http_routes = http_routes,
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

pub fn syncConfig(
    alloc: Allocator,
    service_name: []const u8,
    lb_policy: []const u8,
    routes: []const ServiceHttpRouteInput,
) StoreError!ServiceRecord {
    var existing = try ensure(alloc, service_name, lb_policy);
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

    return get(alloc, service_name);
}

pub fn get(alloc: Allocator, service_name: []const u8) StoreError!ServiceRecord {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return getInDb(lease.db, alloc, service_name);
}

fn getInDb(db: *sqlite.Db, alloc: Allocator, service_name: []const u8) StoreError!ServiceRecord {
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

pub fn list(alloc: Allocator) StoreError!std.ArrayList(ServiceRecord) {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return listInDb(lease.db, alloc);
}

fn listInDb(db: *sqlite.Db, alloc: Allocator) StoreError!std.ArrayList(ServiceRecord) {
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

test "create and get round-trip" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try create(.{
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
    const service = try get(alloc, "api");
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

test "list returns services ordered by name" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try create(.{
        .service_name = "web",
        .vip_address = "10.43.0.20",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try create(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .created_at = 1001,
        .updated_at = 1001,
    });

    const alloc = std.testing.allocator;
    var services = try list(alloc);
    defer {
        for (services.items) |service| service.deinit(alloc);
        services.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 2), services.items.len);
    try std.testing.expectEqualStrings("api", services.items[0].service_name);
    try std.testing.expectEqualStrings("web", services.items[1].service_name);
}

test "ensure allocates once and returns the existing VIP thereafter" {
    try common.initTestDb();
    defer common.deinitTestDb();

    const alloc = std.testing.allocator;

    const first = try ensure(alloc, "api", "consistent_hash");
    defer first.deinit(alloc);
    try std.testing.expectEqualStrings("10.43.0.2", first.vip_address);

    const second = try ensure(alloc, "api", "consistent_hash");
    defer second.deinit(alloc);
    try std.testing.expectEqualStrings("10.43.0.2", second.vip_address);

    var services = try list(alloc);
    defer {
        for (services.items) |service| service.deinit(alloc);
        services.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 1), services.items.len);
}

test "syncConfig updates proxy policy without changing vip" {
    try common.initTestDb();
    defer common.deinitTestDb();

    const alloc = std.testing.allocator;

    const first = try ensure(alloc, "api", "consistent_hash");
    defer first.deinit(alloc);

    const updated = try syncConfig(
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
