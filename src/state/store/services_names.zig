const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const service_core = @import("services_core.zig");
const name_types = @import("services_name_types.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

const ServiceNameIpRow = name_types.ServiceNameIpRow;
const ServiceNameRecord = name_types.ServiceNameRecord;
const ServiceNameRow = name_types.ServiceNameRow;
const rowToServiceNameRecord = name_types.rowToServiceNameRecord;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

pub fn register(name: []const u8, container_id: []const u8, ip_address: []const u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec(
        "INSERT OR REPLACE INTO service_names (name, container_id, ip_address, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ name, container_id, ip_address, nowRealSeconds() },
    ) catch return StoreError.WriteFailed;
}

pub fn unregister(container_id: []const u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec(
        "DELETE FROM service_names WHERE container_id = ?;",
        .{},
        .{container_id},
    ) catch return StoreError.WriteFailed;
}

pub fn removeByName(name: []const u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec(
        "DELETE FROM service_names WHERE name = ?;",
        .{},
        .{name},
    ) catch return StoreError.WriteFailed;
}

fn lookupNamesInDb(db: *sqlite.Db, alloc: Allocator, name: []const u8) StoreError!std.ArrayList([]const u8) {
    var ips: std.ArrayList([]const u8) = .empty;
    var stmt = db.prepare(
        "SELECT ip_address FROM service_names WHERE name = ? ORDER BY registered_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ServiceNameIpRow, .{name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        ips.append(alloc, row.ip_address.data) catch return StoreError.ReadFailed;
    }
    return ips;
}

pub fn lookupNames(alloc: Allocator, name: []const u8) StoreError!std.ArrayList([]const u8) {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return lookupNamesInDb(lease.db, alloc, name);
}

pub fn lookupAddresses(alloc: Allocator, name: []const u8) StoreError!std.ArrayList([]const u8) {
    var lease = try common.leaseDb();
    defer lease.deinit();

    var ips: std.ArrayList([]const u8) = .empty;

    var stmt = lease.db.prepare(
        "SELECT vip_address FROM services WHERE service_name = ? LIMIT 1;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(struct { vip_address: sqlite.Text }, .{name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        ips.append(alloc, row.vip_address.data) catch return StoreError.ReadFailed;
    }

    if (ips.items.len > 0) return ips;
    return lookupNamesInDb(lease.db, alloc, name);
}

pub fn list(alloc: Allocator) StoreError!std.ArrayList(ServiceNameRecord) {
    var lease = try common.leaseDb();
    defer lease.deinit();

    var names: std.ArrayList(ServiceNameRecord) = .empty;
    var stmt = lease.db.prepare(
        "SELECT name, container_id, ip_address, registered_at FROM service_names ORDER BY name, registered_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ServiceNameRow, .{}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        names.append(alloc, rowToServiceNameRecord(row)) catch return StoreError.ReadFailed;
    }
    return names;
}

test "lookupAddresses prefers service VIPs over legacy name rows" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try service_core.create(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try register("api", "ctr-1", "10.42.0.11");

    const alloc = std.testing.allocator;
    var addresses = try lookupAddresses(alloc, "api");
    defer {
        for (addresses.items) |ip| alloc.free(ip);
        addresses.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), addresses.items.len);
    try std.testing.expectEqualStrings("10.43.0.10", addresses.items[0]);
}

test "register and lookup" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try register("web", "abc123", "10.42.0.2");

    const alloc = std.testing.allocator;
    var ips = try lookupNames(alloc, "web");
    defer {
        for (ips.items) |ip| alloc.free(ip);
        ips.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), ips.items.len);
    try std.testing.expectEqualStrings("10.42.0.2", ips.items[0]);
}

test "unregister removes entries" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try register("db", "xyz789", "10.42.0.3");
    try unregister("xyz789");

    const alloc = std.testing.allocator;
    var ips = try lookupNames(alloc, "db");
    defer ips.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 0), ips.items.len);
}

test "lookup returns empty for unknown" {
    try common.initTestDb();
    defer common.deinitTestDb();

    const alloc = std.testing.allocator;
    var ips = try lookupNames(alloc, "nonexistent");
    defer ips.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 0), ips.items.len);
}
