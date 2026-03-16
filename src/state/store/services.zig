const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const schema = @import("../schema.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

const ServiceNameRow = struct {
    ip_address: sqlite.Text,
};

pub const NetworkPolicyRecord = struct {
    source_service: []const u8,
    target_service: []const u8,
    action: []const u8,
    created_at: i64,

    pub fn deinit(self: NetworkPolicyRecord, alloc: Allocator) void {
        alloc.free(self.source_service);
        alloc.free(self.target_service);
        alloc.free(self.action);
    }
};

const NetworkPolicyRow = struct {
    source_service: sqlite.Text,
    target_service: sqlite.Text,
    action: sqlite.Text,
    created_at: i64,
};

pub fn registerServiceName(name: []const u8, container_id: []const u8, ip_address: []const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "INSERT OR REPLACE INTO service_names (name, container_id, ip_address, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ name, container_id, ip_address, @as(i64, std.time.timestamp()) },
    ) catch return StoreError.WriteFailed;
}

pub fn unregisterServiceName(container_id: []const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "DELETE FROM service_names WHERE container_id = ?;",
        .{},
        .{container_id},
    ) catch return StoreError.WriteFailed;
}

pub fn lookupServiceNames(alloc: Allocator, name: []const u8) StoreError!std.ArrayList([]const u8) {
    const db = try common.getDb();
    var ips: std.ArrayList([]const u8) = .empty;
    var stmt = db.prepare(
        "SELECT ip_address FROM service_names WHERE name = ? ORDER BY registered_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ServiceNameRow, .{name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        ips.append(alloc, row.ip_address.data) catch return StoreError.ReadFailed;
    }
    return ips;
}

pub fn addNetworkPolicy(source: []const u8, target: []const u8, action: []const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "INSERT OR REPLACE INTO network_policies (source_service, target_service, action, created_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ source, target, action, @as(i64, std.time.timestamp()) },
    ) catch return StoreError.WriteFailed;
}

pub fn removeNetworkPolicy(source: []const u8, target: []const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "DELETE FROM network_policies WHERE source_service = ? AND target_service = ?;",
        .{},
        .{ source, target },
    ) catch return StoreError.WriteFailed;
}

pub fn listNetworkPolicies(alloc: Allocator) StoreError!std.ArrayList(NetworkPolicyRecord) {
    return queryNetworkPolicies(
        alloc,
        "SELECT source_service, target_service, action, created_at FROM network_policies ORDER BY created_at;",
        .{},
    );
}

pub fn getServicePolicies(alloc: Allocator, source: []const u8) StoreError!std.ArrayList(NetworkPolicyRecord) {
    return queryNetworkPolicies(
        alloc,
        "SELECT source_service, target_service, action, created_at FROM network_policies WHERE source_service = ? ORDER BY created_at;",
        .{source},
    );
}

fn queryNetworkPolicies(alloc: Allocator, comptime query: []const u8, args: anytype) StoreError!std.ArrayList(NetworkPolicyRecord) {
    const db = try common.getDb();
    var policies: std.ArrayList(NetworkPolicyRecord) = .empty;
    var stmt = db.prepare(query) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(NetworkPolicyRow, args) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        policies.append(alloc, .{
            .source_service = row.source_service.data,
            .target_service = row.target_service.data,
            .action = row.action.data,
            .created_at = row.created_at,
        }) catch return StoreError.ReadFailed;
    }
    return policies;
}

test "service name register and lookup" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO service_names (name, container_id, ip_address, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "web", "abc123", "10.42.0.2", @as(i64, 100) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(ServiceNameRow, alloc, "SELECT ip_address FROM service_names WHERE name = ?;", .{}, .{"web"}) catch unreachable).?;
    defer alloc.free(row.ip_address.data);

    try std.testing.expectEqualStrings("10.42.0.2", row.ip_address.data);
}

test "service name unregister removes entries" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO service_names (name, container_id, ip_address, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "db", "xyz789", "10.42.0.3", @as(i64, 100) },
    ) catch unreachable;
    db.exec("DELETE FROM service_names WHERE container_id = ?;", .{}, .{"xyz789"}) catch unreachable;

    const CountRow = struct { count: i64 };
    const result = (db.one(CountRow, "SELECT COUNT(*) AS count FROM service_names;", .{}, .{}) catch unreachable).?;
    try std.testing.expectEqual(@as(i64, 0), result.count);
}

test "service name lookup returns empty for unknown" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const alloc = std.testing.allocator;
    const row = db.oneAlloc(ServiceNameRow, alloc, "SELECT ip_address FROM service_names WHERE name = ?;", .{}, .{"nonexistent"}) catch unreachable;
    try std.testing.expect(row == null);
}
