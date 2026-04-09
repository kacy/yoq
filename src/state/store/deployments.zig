const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const schema = @import("../schema.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const DeploymentRecord = struct {
    id: []const u8,
    app_name: ?[]const u8 = null,
    service_name: []const u8,
    trigger: ?[]const u8 = null,
    source_release_id: ?[]const u8 = null,
    manifest_hash: []const u8,
    config_snapshot: []const u8,
    status: []const u8,
    message: ?[]const u8,
    created_at: i64,

    pub fn deinit(self: DeploymentRecord, alloc: Allocator) void {
        alloc.free(self.id);
        if (self.app_name) |app_name| alloc.free(app_name);
        alloc.free(self.service_name);
        if (self.trigger) |trigger| alloc.free(trigger);
        if (self.source_release_id) |source_release_id| alloc.free(source_release_id);
        alloc.free(self.manifest_hash);
        alloc.free(self.config_snapshot);
        alloc.free(self.status);
        if (self.message) |message| alloc.free(message);
    }
};

const deployment_columns =
    "id, app_name, service_name, trigger, source_release_id, manifest_hash, config_snapshot, status, message, created_at";

const DeploymentRow = struct {
    id: sqlite.Text,
    app_name: ?sqlite.Text,
    service_name: sqlite.Text,
    trigger: ?sqlite.Text,
    source_release_id: ?sqlite.Text,
    manifest_hash: sqlite.Text,
    config_snapshot: sqlite.Text,
    status: sqlite.Text,
    message: ?sqlite.Text,
    created_at: i64,
};

fn rowToRecord(row: DeploymentRow) DeploymentRecord {
    return .{
        .id = row.id.data,
        .app_name = if (row.app_name) |app_name| app_name.data else null,
        .service_name = row.service_name.data,
        .trigger = if (row.trigger) |trigger| trigger.data else null,
        .source_release_id = if (row.source_release_id) |source_release_id| source_release_id.data else null,
        .manifest_hash = row.manifest_hash.data,
        .config_snapshot = row.config_snapshot.data,
        .status = row.status.data,
        .message = if (row.message) |message| message.data else null,
        .created_at = row.created_at,
    };
}

pub fn saveDeployment(record: DeploymentRecord) StoreError!void {
    const db = try common.getDb();
    return saveDeploymentInDb(db, record);
}

pub fn saveDeploymentInDb(db: *sqlite.Db, record: DeploymentRecord) StoreError!void {
    db.exec(
        "INSERT INTO deployments (" ++ deployment_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            record.id,
            record.app_name,
            record.service_name,
            record.trigger,
            record.source_release_id,
            record.manifest_hash,
            record.config_snapshot,
            record.status,
            record.message,
            record.created_at,
        },
    ) catch return StoreError.WriteFailed;
}

fn queryOneInDb(
    db: *sqlite.Db,
    alloc: Allocator,
    comptime query: []const u8,
    args: anytype,
) StoreError!DeploymentRecord {
    const row = (db.oneAlloc(DeploymentRow, alloc, query, .{}, args) catch return StoreError.ReadFailed) orelse
        return StoreError.NotFound;
    return rowToRecord(row);
}

fn queryOne(alloc: Allocator, comptime query: []const u8, args: anytype) StoreError!DeploymentRecord {
    const db = try common.getDb();
    return queryOneInDb(db, alloc, query, args);
}

fn listQueryInDb(
    db: *sqlite.Db,
    alloc: Allocator,
    comptime query: []const u8,
    args: anytype,
) StoreError!std.ArrayList(DeploymentRecord) {
    var deployments: std.ArrayList(DeploymentRecord) = .empty;
    var stmt = db.prepare(query) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(DeploymentRow, args) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        deployments.append(alloc, rowToRecord(row)) catch return StoreError.ReadFailed;
    }
    return deployments;
}

pub fn getDeployment(alloc: Allocator, id: []const u8) StoreError!DeploymentRecord {
    return queryOne(alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE id = ?;", .{id});
}

pub fn getDeploymentInDb(db: *sqlite.Db, alloc: Allocator, id: []const u8) StoreError!DeploymentRecord {
    return queryOneInDb(db, alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE id = ?;", .{id});
}

pub fn listDeployments(alloc: Allocator, service_name: []const u8) StoreError!std.ArrayList(DeploymentRecord) {
    const db = try common.getDb();
    return listQueryInDb(
        db,
        alloc,
        "SELECT " ++ deployment_columns ++ " FROM deployments WHERE service_name = ? ORDER BY created_at DESC, rowid DESC;",
        .{service_name},
    );
}

pub fn listDeploymentsByApp(alloc: Allocator, app_name: []const u8) StoreError!std.ArrayList(DeploymentRecord) {
    const db = try common.getDb();
    return listDeploymentsByAppInDb(db, alloc, app_name);
}

pub fn listDeploymentsByAppInDb(
    db: *sqlite.Db,
    alloc: Allocator,
    app_name: []const u8,
) StoreError!std.ArrayList(DeploymentRecord) {
    return listQueryInDb(
        db,
        alloc,
        "SELECT " ++ deployment_columns ++ " FROM deployments WHERE app_name = ? ORDER BY created_at DESC, rowid DESC;",
        .{app_name},
    );
}

pub fn updateDeploymentStatus(id: []const u8, status: []const u8, message: ?[]const u8) StoreError!void {
    const db = try common.getDb();
    return updateDeploymentStatusInDb(db, id, status, message);
}

pub fn updateDeploymentStatusInDb(
    db: *sqlite.Db,
    id: []const u8,
    status: []const u8,
    message: ?[]const u8,
) StoreError!void {
    db.exec(
        "UPDATE deployments SET status = ?, message = ? WHERE id = ?;",
        .{},
        .{ status, message, id },
    ) catch return StoreError.WriteFailed;
}

pub fn getLatestDeployment(alloc: Allocator, service_name: []const u8) StoreError!DeploymentRecord {
    return queryOne(
        alloc,
        "SELECT " ++ deployment_columns ++ " FROM deployments WHERE service_name = ? ORDER BY created_at DESC, rowid DESC LIMIT 1;",
        .{service_name},
    );
}

pub fn getLatestDeploymentByApp(alloc: Allocator, app_name: []const u8) StoreError!DeploymentRecord {
    const db = try common.getDb();
    return getLatestDeploymentByAppInDb(db, alloc, app_name);
}

pub fn getLatestDeploymentByAppInDb(
    db: *sqlite.Db,
    alloc: Allocator,
    app_name: []const u8,
) StoreError!DeploymentRecord {
    return queryOneInDb(
        db,
        alloc,
        "SELECT " ++ deployment_columns ++ " FROM deployments WHERE app_name = ? ORDER BY created_at DESC, rowid DESC LIMIT 1;",
        .{app_name},
    );
}

pub fn getLastSuccessfulDeployment(alloc: Allocator, service_name: []const u8) StoreError!DeploymentRecord {
    return queryOne(
        alloc,
        "SELECT " ++ deployment_columns ++ " FROM deployments WHERE service_name = ? AND status = 'completed' ORDER BY created_at DESC, rowid DESC LIMIT 1;",
        .{service_name},
    );
}

pub fn getLastSuccessfulDeploymentByApp(alloc: Allocator, app_name: []const u8) StoreError!DeploymentRecord {
    return queryOne(
        alloc,
        "SELECT " ++ deployment_columns ++ " FROM deployments WHERE app_name = ? AND status = 'completed' ORDER BY created_at DESC, rowid DESC LIMIT 1;",
        .{app_name},
    );
}

test "deployment record round-trip via sqlite" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO deployments (" ++ deployment_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep001", "demo-app", "web", "apply", null, "sha256:abc", "{\"image\":\"nginx:latest\"}", "completed", "initial deploy", @as(i64, 1000) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(DeploymentRow, alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE id = ?;", .{}, .{"dep001"}) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("dep001", record.id);
    try std.testing.expectEqualStrings("demo-app", record.app_name.?);
    try std.testing.expectEqualStrings("web", record.service_name);
    try std.testing.expectEqualStrings("apply", record.trigger.?);
    try std.testing.expect(record.source_release_id == null);
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
        "INSERT INTO deployments (id, app_name, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep002", null, "api", "sha256:def", "{}", "pending", @as(i64, 2000) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(DeploymentRow, alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE id = ?;", .{}, .{"dep002"}) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expect(record.message == null);
    try std.testing.expect(record.app_name == null);
    try std.testing.expectEqualStrings("apply", record.trigger.?);
    try std.testing.expect(record.source_release_id == null);
}

test "deployment stores rollback transition metadata" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO deployments (" ++ deployment_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep-rb", "demo-app", "demo-app", "rollback", "dep-1", "sha256:rb", "{}", "completed", "rollback completed", @as(i64, 2100) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(DeploymentRow, alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE id = ?;", .{}, .{"dep-rb"}) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("rollback", record.trigger.?);
    try std.testing.expectEqualStrings("dep-1", record.source_release_id.?);
}

test "deployment list ordered by timestamp desc" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec("INSERT INTO deployments (id, app_name, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);", .{}, .{ "dep-old", "demo-app", "web", "sha256:old", "{}", "completed", @as(i64, 100) }) catch unreachable;
    db.exec("INSERT INTO deployments (id, app_name, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);", .{}, .{ "dep-new", "demo-app", "web", "sha256:new", "{}", "completed", @as(i64, 200) }) catch unreachable;

    const alloc = std.testing.allocator;
    var stmt = db.prepare("SELECT " ++ deployment_columns ++ " FROM deployments WHERE service_name = ? ORDER BY created_at DESC, rowid DESC;") catch unreachable;
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

    db.exec("INSERT INTO deployments (id, app_name, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);", .{}, .{ "dep-upd", "demo-app", "web", "sha256:abc", "{}", "pending", @as(i64, 100) }) catch unreachable;
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

    db.exec("INSERT INTO deployments (id, app_name, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);", .{}, .{ "dep-1", "demo-app", "web", "sha256:first", "{}", "completed", @as(i64, 100) }) catch unreachable;
    db.exec("INSERT INTO deployments (id, app_name, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);", .{}, .{ "dep-2", "demo-app", "web", "sha256:second", "{}", "in_progress", @as(i64, 200) }) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(DeploymentRow, alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE service_name = ? ORDER BY created_at DESC, rowid DESC LIMIT 1;", .{}, .{"web"}) catch unreachable).?;
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

test "deployment app queries return only matching app records" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec("INSERT INTO deployments (id, app_name, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);", .{}, .{ "dep-a", "app-a", "web", "sha256:a", "{}", "completed", @as(i64, 100) }) catch unreachable;
    db.exec("INSERT INTO deployments (id, app_name, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);", .{}, .{ "dep-b", "app-b", "api", "sha256:b", "{}", "completed", @as(i64, 200) }) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(DeploymentRow, alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE app_name = ? ORDER BY created_at DESC, rowid DESC LIMIT 1;", .{}, .{"app-a"}) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("dep-a", record.id);
    try std.testing.expectEqualStrings("app-a", record.app_name.?);
}

test "deployment latest prefers later insert when timestamps tie" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec("INSERT INTO deployments (id, app_name, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);", .{}, .{ "dep-1", "demo-app", "demo-app", "sha256:first", "{}", "completed", @as(i64, 100) }) catch unreachable;
    db.exec("INSERT INTO deployments (id, app_name, service_name, manifest_hash, config_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);", .{}, .{ "dep-2", "demo-app", "demo-app", "sha256:second", "{}", "completed", @as(i64, 100) }) catch unreachable;

    const alloc = std.testing.allocator;

    var deployments = try listDeploymentsByAppInDb(&db, alloc, "demo-app");
    defer {
        for (deployments.items) |record| record.deinit(alloc);
        deployments.deinit(alloc);
    }

    try std.testing.expectEqualStrings("dep-2", deployments.items[0].id);
    try std.testing.expectEqualStrings("dep-1", deployments.items[1].id);

    const latest = try getLatestDeploymentByAppInDb(&db, alloc, "demo-app");
    defer latest.deinit(alloc);

    try std.testing.expectEqualStrings("dep-2", latest.id);
}
