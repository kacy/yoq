const std = @import("std");
const sqlite = @import("sqlite");
const service_names = @import("services_names.zig");
const common = @import("common.zig");
const policy_types = @import("services_policy_types.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

const NetworkPolicyRecord = policy_types.NetworkPolicyRecord;
const NetworkPolicyRow = policy_types.NetworkPolicyRow;
const rowToNetworkPolicyRecord = policy_types.rowToNetworkPolicyRecord;

/// A consistent read of policy definitions and endpoint identities. The normal
/// constructor owns the shared-store lease; callers with a committed database
/// connection can instead borrow it for the duration of the read transaction.
pub const ReadSnapshot = struct {
    db: *sqlite.Db,
    lease: ?common.DbLease = null,

    pub fn begin() StoreError!ReadSnapshot {
        var lease = try common.leaseDb();
        errdefer lease.deinit();
        var result = try beginInDb(lease.db);
        result.lease = lease;
        return result;
    }

    pub fn beginInDb(db: *sqlite.Db) StoreError!ReadSnapshot {
        db.exec("BEGIN;", .{}, .{}) catch return StoreError.ReadFailed;
        return .{ .db = db };
    }

    pub fn deinit(self: *ReadSnapshot) void {
        self.db.exec("ROLLBACK;", .{}, .{}) catch {};
        if (self.lease) |*lease| lease.deinit();
    }

    pub fn policies(self: *ReadSnapshot, alloc: Allocator) StoreError!std.ArrayList(NetworkPolicyRecord) {
        return queryInDb(self.db, alloc, "SELECT source_service, target_service, action, created_at FROM network_policies ORDER BY created_at;", .{});
    }

    pub fn addresses(self: *ReadSnapshot, alloc: Allocator, name: []const u8, role: service_names.PolicyAddressRole) StoreError!std.ArrayList([]const u8) {
        return service_names.lookupPolicyAddressesInDb(self.db, alloc, name, role);
    }
};

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

    return queryInDb(lease.db, alloc, sql, args);
}

fn queryInDb(db: *sqlite.Db, alloc: Allocator, comptime sql: []const u8, args: anytype) StoreError!std.ArrayList(NetworkPolicyRecord) {
    var policies: std.ArrayList(NetworkPolicyRecord) = .empty;
    errdefer {
        for (policies.items) |policy| policy.deinit(alloc);
        policies.deinit(alloc);
    }
    var stmt = db.prepare(sql) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(NetworkPolicyRow, args) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        const record = rowToNetworkPolicyRecord(row);
        policies.append(alloc, record) catch {
            record.deinit(alloc);
            return StoreError.ReadFailed;
        };
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

test "policy read snapshot keeps endpoint identities consistent across external commits" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var directory: [4096]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &directory);
    const path = try std.fmt.allocPrintSentinel(alloc, "{s}/policy.db", .{directory[0..len]}, 0);
    defer alloc.free(path);
    var reader = try sqlite.Db.init(.{ .mode = .{ .File = path }, .open_flags = .{ .write = true, .create = true } });
    defer reader.deinit();
    try @import("../schema.zig").init(&reader);
    try reader.exec("INSERT INTO network_policies (source_service,target_service,action,created_at) VALUES ('api','web','deny',1);", .{}, .{});
    try reader.exec("INSERT INTO service_names (name,container_id,ip_address,registered_at) VALUES ('api','api-1','10.42.0.1',1);", .{}, .{});
    var writer = try sqlite.Db.init(.{ .mode = .{ .File = path }, .open_flags = .{ .write = true } });
    defer writer.deinit();
    {
        var snapshot = try ReadSnapshot.beginInDb(&reader);
        defer snapshot.deinit();
        var policies = try snapshot.policies(alloc);
        defer {
            for (policies.items) |record| record.deinit(alloc);
            policies.deinit(alloc);
        }
        try std.testing.expectEqualStrings("deny", policies.items[0].action);
        try writer.exec("BEGIN;", .{}, .{});
        try writer.exec("UPDATE network_policies SET action='allow';", .{}, .{});
        try writer.exec("UPDATE service_names SET ip_address='10.42.0.2';", .{}, .{});
        try writer.exec("COMMIT;", .{}, .{});
        var addresses = try snapshot.addresses(alloc, "api", .source);
        defer {
            for (addresses.items) |address| alloc.free(address);
            addresses.deinit(alloc);
        }
        try std.testing.expectEqualStrings("10.42.0.1", addresses.items[0]);
    }
    var next = try ReadSnapshot.beginInDb(&reader);
    defer next.deinit();
    var addresses = try next.addresses(alloc, "api", .source);
    defer {
        for (addresses.items) |address| alloc.free(address);
        addresses.deinit(alloc);
    }
    try std.testing.expectEqualStrings("10.42.0.2", addresses.items[0]);
}
