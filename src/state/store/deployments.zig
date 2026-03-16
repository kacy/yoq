const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const schema = @import("../schema.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const DeploymentRecord = struct {
    id: []const u8,
    service_name: []const u8,
    manifest_hash: []const u8,
    config_snapshot: []const u8,
    status: []const u8,
    message: ?[]const u8,
    created_at: i64,

    pub fn deinit(self: DeploymentRecord, alloc: Allocator) void {
        alloc.free(self.id);
        alloc.free(self.service_name);
        alloc.free(self.manifest_hash);
        alloc.free(self.config_snapshot);
        alloc.free(self.status);
        if (self.message) |message| alloc.free(message);
    }
};

const deployment_columns =
    "id, service_name, manifest_hash, config_snapshot, status, message, created_at";

const DeploymentRow = struct {
    id: sqlite.Text,
    service_name: sqlite.Text,
    manifest_hash: sqlite.Text,
    config_snapshot: sqlite.Text,
    status: sqlite.Text,
    message: ?sqlite.Text,
    created_at: i64,
};

fn rowToRecord(row: DeploymentRow) DeploymentRecord {
    return .{
        .id = row.id.data,
        .service_name = row.service_name.data,
        .manifest_hash = row.manifest_hash.data,
        .config_snapshot = row.config_snapshot.data,
        .status = row.status.data,
        .message = if (row.message) |message| message.data else null,
        .created_at = row.created_at,
    };
}

pub fn saveDeployment(record: DeploymentRecord) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "INSERT INTO deployments (" ++ deployment_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            record.id,
            record.service_name,
            record.manifest_hash,
            record.config_snapshot,
            record.status,
            record.message,
            record.created_at,
        },
    ) catch return StoreError.WriteFailed;
}

fn queryOne(alloc: Allocator, comptime query: []const u8, args: anytype) StoreError!DeploymentRecord {
    const db = try common.getDb();
    const row = (db.oneAlloc(DeploymentRow, alloc, query, .{}, args) catch return StoreError.ReadFailed) orelse
        return StoreError.NotFound;
    return rowToRecord(row);
}

pub fn getDeployment(alloc: Allocator, id: []const u8) StoreError!DeploymentRecord {
    return queryOne(alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE id = ?;", .{id});
}

pub fn listDeployments(alloc: Allocator, service_name: []const u8) StoreError!std.ArrayList(DeploymentRecord) {
    const db = try common.getDb();
    var deployments: std.ArrayList(DeploymentRecord) = .empty;
    var stmt = db.prepare(
        "SELECT " ++ deployment_columns ++ " FROM deployments WHERE service_name = ? ORDER BY created_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(DeploymentRow, .{service_name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        deployments.append(alloc, rowToRecord(row)) catch return StoreError.ReadFailed;
    }
    return deployments;
}

pub fn updateDeploymentStatus(id: []const u8, status: []const u8, message: ?[]const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "UPDATE deployments SET status = ?, message = ? WHERE id = ?;",
        .{},
        .{ status, message, id },
    ) catch return StoreError.WriteFailed;
}

pub fn getLatestDeployment(alloc: Allocator, service_name: []const u8) StoreError!DeploymentRecord {
    return queryOne(
        alloc,
        "SELECT " ++ deployment_columns ++ " FROM deployments WHERE service_name = ? ORDER BY created_at DESC LIMIT 1;",
        .{service_name},
    );
}

pub fn getLastSuccessfulDeployment(alloc: Allocator, service_name: []const u8) StoreError!DeploymentRecord {
    return queryOne(
        alloc,
        "SELECT " ++ deployment_columns ++ " FROM deployments WHERE service_name = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1;",
        .{service_name},
    );
}

test "deployment record round-trip via sqlite" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO deployments (" ++ deployment_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep001", "web", "sha256:abc", "{\"image\":\"nginx:latest\"}", "completed", "initial deploy", @as(i64, 1000) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(DeploymentRow, alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE id = ?;", .{}, .{"dep001"}) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("dep001", record.id);
    try std.testing.expectEqualStrings("web", record.service_name);
    try std.testing.expectEqualStrings("sha256:abc", record.manifest_hash);
    try std.testing.expectEqualStrings("{\"image\":\"nginx:latest\"}", record.config_snapshot);
    try std.testing.expectEqualStrings("completed", record.status);
    try std.testing.expectEqualStrings("initial deploy", record.message.?);
    try std.testing.expectEqual(@as(i64, 1000), record.created_at);
}

test "deployment with null message" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep002", "api", "sha256:def", "{}", "pending", @as(i64, 2000) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(DeploymentRow, alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE id = ?;", .{}, .{"dep002"}) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expect(record.message == null);
}

test "deployment list ordered by timestamp desc" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec("INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?);", .{}, .{ "dep-old", "web", "sha256:old", "{}", "completed", @as(i64, 100) }) catch unreachable;
    db.exec("INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?);", .{}, .{ "dep-new", "web", "sha256:new", "{}", "completed", @as(i64, 200) }) catch unreachable;

    const alloc = std.testing.allocator;
    var stmt = db.prepare("SELECT " ++ deployment_columns ++ " FROM deployments WHERE service_name = ? ORDER BY created_at DESC;") catch unreachable;
    defer stmt.deinit();

    var results: std.ArrayList(DeploymentRecord) = .empty;
    defer {
        for (results.items) |record| record.deinit(alloc);
        results.deinit(alloc);
    }

    var iter = stmt.iterator(DeploymentRow, .{"web"}) catch unreachable;
    while (iter.nextAlloc(alloc, .{}) catch unreachable) |row| {
        results.append(alloc, rowToRecord(row)) catch unreachable;
    }

    try std.testing.expectEqual(@as(usize, 2), results.items.len);
    try std.testing.expectEqualStrings("dep-new", results.items[0].id);
    try std.testing.expectEqualStrings("dep-old", results.items[1].id);
}

test "deployment status update" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec("INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?);", .{}, .{ "dep-upd", "web", "sha256:abc", "{}", "pending", @as(i64, 100) }) catch unreachable;
    db.exec("UPDATE deployments SET status = ?, message = ? WHERE id = ?;", .{}, .{ "completed", "all containers healthy", "dep-upd" }) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(DeploymentRow, alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE id = ?;", .{}, .{"dep-upd"}) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("completed", record.status);
    try std.testing.expectEqualStrings("all containers healthy", record.message.?);
}

test "deployment latest returns most recent" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec("INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?);", .{}, .{ "dep-1", "web", "sha256:first", "{}", "completed", @as(i64, 100) }) catch unreachable;
    db.exec("INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?);", .{}, .{ "dep-2", "web", "sha256:second", "{}", "in_progress", @as(i64, 200) }) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(DeploymentRow, alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE service_name = ? ORDER BY created_at DESC LIMIT 1;", .{}, .{"web"}) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("dep-2", record.id);
}

test "deployment not found returns null" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const alloc = std.testing.allocator;
    const row = db.oneAlloc(DeploymentRow, alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE id = ?;", .{}, .{"nonexistent"}) catch unreachable;
    try std.testing.expect(row == null);
}
