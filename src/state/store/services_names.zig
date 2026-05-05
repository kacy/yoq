const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const service_types = @import("services_types.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

const ServiceNameIpRow = service_types.ServiceNameIpRow;
const ServiceNameRecord = service_types.ServiceNameRecord;
const ServiceNameRow = service_types.ServiceNameRow;
const rowToServiceNameRecord = service_types.rowToServiceNameRecord;

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
