const std = @import("std");
const common = @import("common.zig");
const service_types = @import("services_types.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

const NetworkPolicyRecord = service_types.NetworkPolicyRecord;
const NetworkPolicyRow = service_types.NetworkPolicyRow;
const rowToNetworkPolicyRecord = service_types.rowToNetworkPolicyRecord;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

pub fn add(source: []const u8, target: []const u8, action: []const u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec(
        "INSERT OR REPLACE INTO network_policies (source_service, target_service, action, created_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ source, target, action, nowRealSeconds() },
    ) catch return StoreError.WriteFailed;
}

pub fn remove(source: []const u8, target: []const u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec(
        "DELETE FROM network_policies WHERE source_service = ? AND target_service = ?;",
        .{},
        .{ source, target },
    ) catch return StoreError.WriteFailed;
}

pub fn list(alloc: Allocator) StoreError!std.ArrayList(NetworkPolicyRecord) {
    return query(
        alloc,
        "SELECT source_service, target_service, action, created_at FROM network_policies ORDER BY created_at;",
        .{},
    );
}

pub fn listForSource(alloc: Allocator, source: []const u8) StoreError!std.ArrayList(NetworkPolicyRecord) {
    return query(
        alloc,
        "SELECT source_service, target_service, action, created_at FROM network_policies WHERE source_service = ? ORDER BY created_at;",
        .{source},
    );
}

fn query(alloc: Allocator, comptime sql: []const u8, args: anytype) StoreError!std.ArrayList(NetworkPolicyRecord) {
    var lease = try common.leaseDb();
    defer lease.deinit();

    var policies: std.ArrayList(NetworkPolicyRecord) = .empty;
    var stmt = lease.db.prepare(sql) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(NetworkPolicyRow, args) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        policies.append(alloc, rowToNetworkPolicyRecord(row)) catch return StoreError.ReadFailed;
    }
    return policies;
}

test "add list get and remove" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try add("api", "db", "allow");
    try add("web", "db", "deny");

    const alloc = std.testing.allocator;
    var all = try list(alloc);
    defer {
        for (all.items) |policy| policy.deinit(alloc);
        all.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 2), all.items.len);

    var api_policies = try listForSource(alloc, "api");
    defer {
        for (api_policies.items) |policy| policy.deinit(alloc);
        api_policies.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), api_policies.items.len);
    try std.testing.expectEqualStrings("api", api_policies.items[0].source_service);
    try std.testing.expectEqualStrings("db", api_policies.items[0].target_service);
    try std.testing.expectEqualStrings("allow", api_policies.items[0].action);

    try remove("api", "db");

    var remaining = try list(alloc);
    defer {
        for (remaining.items) |policy| policy.deinit(alloc);
        remaining.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), remaining.items.len);
    try std.testing.expectEqualStrings("web", remaining.items[0].source_service);
}
