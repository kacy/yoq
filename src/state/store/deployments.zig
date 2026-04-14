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
    completed_targets: usize = 0,
    failed_targets: usize = 0,
    status: []const u8,
    message: ?[]const u8,
    failure_details_json: ?[]const u8 = null,
    rollout_targets_json: ?[]const u8 = null,
    rollout_control_state: ?[]const u8 = null,
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
        if (self.failure_details_json) |failure_details_json| alloc.free(failure_details_json);
        if (self.rollout_targets_json) |rollout_targets_json| alloc.free(rollout_targets_json);
        if (self.rollout_control_state) |rollout_control_state| alloc.free(rollout_control_state);
    }
};

const deployment_columns =
    "id, app_name, service_name, trigger, source_release_id, manifest_hash, config_snapshot, completed_targets, failed_targets, status, message, failure_details_json, rollout_targets_json, rollout_control_state, created_at";

const DeploymentRow = struct {
    id: sqlite.Text,
    app_name: ?sqlite.Text,
    service_name: sqlite.Text,
    trigger: ?sqlite.Text,
    source_release_id: ?sqlite.Text,
    manifest_hash: sqlite.Text,
    config_snapshot: sqlite.Text,
    completed_targets: i64,
    failed_targets: i64,
    status: sqlite.Text,
    message: ?sqlite.Text,
    failure_details_json: ?sqlite.Text,
    rollout_targets_json: ?sqlite.Text,
    rollout_control_state: ?sqlite.Text,
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
        .completed_targets = @intCast(@max(@as(i64, 0), row.completed_targets)),
        .failed_targets = @intCast(@max(@as(i64, 0), row.failed_targets)),
        .status = row.status.data,
        .message = if (row.message) |message| message.data else null,
        .failure_details_json = if (row.failure_details_json) |failure_details_json| failure_details_json.data else null,
        .rollout_targets_json = if (row.rollout_targets_json) |rollout_targets_json| rollout_targets_json.data else null,
        .rollout_control_state = if (row.rollout_control_state) |rollout_control_state| rollout_control_state.data else null,
        .created_at = row.created_at,
    };
}

pub fn saveDeployment(record: DeploymentRecord) StoreError!void {
    const db = try common.getDb();
    return saveDeploymentInDb(db, record);
}

pub fn saveDeploymentInDb(db: *sqlite.Db, record: DeploymentRecord) StoreError!void {
    db.exec(
        "INSERT INTO deployments (" ++ deployment_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            record.id,
            record.app_name,
            record.service_name,
            record.trigger,
            record.source_release_id,
            record.manifest_hash,
            record.config_snapshot,
            @as(i64, @intCast(record.completed_targets)),
            @as(i64, @intCast(record.failed_targets)),
            record.status,
            record.message,
            record.failure_details_json,
            record.rollout_targets_json,
            record.rollout_control_state,
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

pub fn listLatestDeploymentsByApp(alloc: Allocator) StoreError!std.ArrayList(DeploymentRecord) {
    const db = try common.getDb();
    return listLatestDeploymentsByAppInDb(db, alloc);
}

pub fn listLatestDeploymentsByAppInDb(
    db: *sqlite.Db,
    alloc: Allocator,
) StoreError!std.ArrayList(DeploymentRecord) {
    var deployments: std.ArrayList(DeploymentRecord) = .empty;
    errdefer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(alloc);

    var stmt = db.prepare(
        "SELECT " ++ deployment_columns ++ " FROM deployments WHERE app_name IS NOT NULL ORDER BY created_at DESC, rowid DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(DeploymentRow, .{}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        const record = rowToRecord(row);
        const app_name = record.app_name orelse {
            record.deinit(alloc);
            continue;
        };
        const gop = seen.getOrPut(alloc, app_name) catch {
            record.deinit(alloc);
            return StoreError.ReadFailed;
        };
        if (gop.found_existing) {
            record.deinit(alloc);
            continue;
        }
        deployments.append(alloc, record) catch {
            record.deinit(alloc);
            return StoreError.ReadFailed;
        };
    }

    return deployments;
}

pub fn updateDeploymentStatus(id: []const u8, status: []const u8, message: ?[]const u8) StoreError!void {
    const db = try common.getDb();
    return updateDeploymentStatusInDb(db, id, status, message, null);
}

pub fn updateDeploymentStatusInDb(
    db: *sqlite.Db,
    id: []const u8,
    status: []const u8,
    message: ?[]const u8,
    failure_details_json: ?[]const u8,
    rollout_targets_json: ?[]const u8,
) StoreError!void {
    return updateDeploymentProgressInDb(db, id, status, message, 0, 0, failure_details_json, rollout_targets_json);
}

pub fn updateDeploymentProgress(
    id: []const u8,
    status: []const u8,
    message: ?[]const u8,
    completed_targets: usize,
    failed_targets: usize,
    failure_details_json: ?[]const u8,
    rollout_targets_json: ?[]const u8,
) StoreError!void {
    const db = try common.getDb();
    return updateDeploymentProgressInDb(db, id, status, message, completed_targets, failed_targets, failure_details_json, rollout_targets_json);
}

pub fn updateDeploymentProgressInDb(
    db: *sqlite.Db,
    id: []const u8,
    status: []const u8,
    message: ?[]const u8,
    completed_targets: usize,
    failed_targets: usize,
    failure_details_json: ?[]const u8,
    rollout_targets_json: ?[]const u8,
) StoreError!void {
    db.exec(
        "UPDATE deployments SET status = ?, message = ?, completed_targets = ?, failed_targets = ?, failure_details_json = ?, rollout_targets_json = ? WHERE id = ?;",
        .{},
        .{ status, message, @as(i64, @intCast(completed_targets)), @as(i64, @intCast(failed_targets)), failure_details_json, rollout_targets_json, id },
    ) catch return StoreError.WriteFailed;
}

pub fn updateDeploymentRolloutControlState(id: []const u8, control_state: []const u8) StoreError!void {
    const db = try common.getDb();
    return updateDeploymentRolloutControlStateInDb(db, id, control_state);
}

pub fn updateDeploymentRolloutControlStateInDb(
    db: *sqlite.Db,
    id: []const u8,
    control_state: []const u8,
) StoreError!void {
    db.exec(
        "UPDATE deployments SET rollout_control_state = ? WHERE id = ?;",
        .{},
        .{ control_state, id },
    ) catch return StoreError.WriteFailed;
}

pub fn getActiveDeploymentByApp(alloc: Allocator, app_name: []const u8) StoreError!DeploymentRecord {
    const db = try common.getDb();
    return getActiveDeploymentByAppInDb(db, alloc, app_name);
}

pub fn getActiveDeploymentByAppInDb(
    db: *sqlite.Db,
    alloc: Allocator,
    app_name: []const u8,
) StoreError!DeploymentRecord {
    return queryOneInDb(
        db,
        alloc,
        "SELECT " ++ deployment_columns ++ " FROM deployments WHERE app_name = ? AND status IN ('pending', 'in_progress') ORDER BY created_at DESC, rowid DESC LIMIT 1;",
        .{app_name},
    );
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

pub fn getPreviousSuccessfulDeploymentByApp(
    alloc: Allocator,
    app_name: []const u8,
    exclude_id: []const u8,
) StoreError!DeploymentRecord {
    const db = try common.getDb();
    return getPreviousSuccessfulDeploymentByAppInDb(db, alloc, app_name, exclude_id);
}

pub fn getPreviousSuccessfulDeploymentByAppInDb(
    db: *sqlite.Db,
    alloc: Allocator,
    app_name: []const u8,
    exclude_id: []const u8,
) StoreError!DeploymentRecord {
    return queryOneInDb(
        db,
        alloc,
        "SELECT " ++ deployment_columns ++ " FROM deployments WHERE app_name = ? AND status = 'completed' AND id != ? ORDER BY created_at DESC, rowid DESC LIMIT 1;",
        .{ app_name, exclude_id },
    );
}

pub fn getRollbackTargetDeploymentByApp(
    alloc: Allocator,
    app_name: []const u8,
    explicit_release_id: ?[]const u8,
) StoreError!DeploymentRecord {
    const db = try common.getDb();
    return getRollbackTargetDeploymentByAppInDb(db, alloc, app_name, explicit_release_id);
}

pub fn getRollbackTargetDeploymentByAppInDb(
    db: *sqlite.Db,
    alloc: Allocator,
    app_name: []const u8,
    explicit_release_id: ?[]const u8,
) StoreError!DeploymentRecord {
    if (explicit_release_id) |release_id| {
        const dep = try getDeploymentInDb(db, alloc, release_id);
        errdefer dep.deinit(alloc);
        if (dep.app_name == null or !std.mem.eql(u8, dep.app_name.?, app_name)) {
            return StoreError.NotFound;
        }
        return dep;
    }

    const latest = try getLatestDeploymentByAppInDb(db, alloc, app_name);
    defer latest.deinit(alloc);
    return getPreviousSuccessfulDeploymentByAppInDb(db, alloc, app_name, latest.id);
}

test "deployment record round-trip via sqlite" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO deployments (" ++ deployment_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep001", "demo-app", "web", "apply", null, "sha256:abc", "{\"image\":\"nginx:latest\"}", @as(i64, 1), @as(i64, 0), "completed", "initial deploy", null, null, "active", @as(i64, 1000) },
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
    try std.testing.expectEqual(@as(usize, 1), record.completed_targets);
    try std.testing.expectEqual(@as(usize, 0), record.failed_targets);
    try std.testing.expectEqualStrings("completed", record.status);
    try std.testing.expectEqualStrings("initial deploy", record.message.?);
    try std.testing.expect(record.failure_details_json == null);
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
        "INSERT INTO deployments (" ++ deployment_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep-rb", "demo-app", "demo-app", "rollback", "dep-1", "sha256:rb", "{}", @as(i64, 1), @as(i64, 0), "completed", "rollback completed", null, null, "active", @as(i64, 2100) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(DeploymentRow, alloc, "SELECT " ++ deployment_columns ++ " FROM deployments WHERE id = ?;", .{}, .{"dep-rb"}) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("rollback", record.trigger.?);
    try std.testing.expectEqualStrings("dep-1", record.source_release_id.?);
    try std.testing.expectEqual(@as(usize, 1), record.completed_targets);
    try std.testing.expectEqual(@as(usize, 0), record.failed_targets);
}

test "getActiveDeploymentByAppInDb returns latest pending or in progress release" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try saveDeploymentInDb(&db, .{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{}",
        .status = "completed",
        .message = null,
        .created_at = 100,
        .rollout_control_state = "active",
    });
    try saveDeploymentInDb(&db, .{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{}",
        .status = "pending",
        .message = null,
        .created_at = 200,
        .rollout_control_state = "paused",
    });
    try saveDeploymentInDb(&db, .{
        .id = "dep-3",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:333",
        .config_snapshot = "{}",
        .status = "in_progress",
        .message = null,
        .created_at = 300,
        .rollout_control_state = "active",
    });

    const active = try getActiveDeploymentByAppInDb(&db, std.testing.allocator, "demo-app");
    defer active.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("dep-3", active.id);
    try std.testing.expectEqualStrings("active", active.rollout_control_state.?);
}

test "getPreviousSuccessfulDeploymentByAppInDb excludes current release" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try saveDeploymentInDb(&db, .{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{}",
        .status = "completed",
        .message = null,
        .created_at = 100,
    });
    try saveDeploymentInDb(&db, .{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{}",
        .status = "failed",
        .message = null,
        .created_at = 200,
    });
    try saveDeploymentInDb(&db, .{
        .id = "dep-3",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:333",
        .config_snapshot = "{}",
        .status = "completed",
        .message = null,
        .created_at = 300,
    });

    const previous = try getPreviousSuccessfulDeploymentByAppInDb(&db, std.testing.allocator, "demo-app", "dep-3");
    defer previous.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("dep-1", previous.id);
    try std.testing.expectEqualStrings("completed", previous.status);
}

test "getRollbackTargetDeploymentByAppInDb defaults to the previous successful release" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try saveDeploymentInDb(&db, .{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\",\"image\":\"nginx:1\"}]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 100,
    });
    try saveDeploymentInDb(&db, .{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\",\"image\":\"nginx:2\"}]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 200,
    });

    const target = try getRollbackTargetDeploymentByAppInDb(&db, std.testing.allocator, "demo-app", null);
    defer target.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("dep-1", target.id);
}

test "getRollbackTargetDeploymentByAppInDb honors an explicit release id" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try saveDeploymentInDb(&db, .{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 100,
    });
    try saveDeploymentInDb(&db, .{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "rollback",
        .source_release_id = "dep-1",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{}",
        .status = "completed",
        .message = "rollback completed",
        .created_at = 200,
    });

    const target = try getRollbackTargetDeploymentByAppInDb(&db, std.testing.allocator, "demo-app", "dep-2");
    defer target.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("dep-2", target.id);
}

test "listLatestDeploymentsByAppInDb returns one latest row per app" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try saveDeploymentInDb(&db, .{
        .id = "dep-1",
        .app_name = "app-a",
        .service_name = "app-a",
        .trigger = "apply",
        .manifest_hash = "sha256:a1",
        .config_snapshot = "{}",
        .status = "completed",
        .message = null,
        .created_at = 100,
    });
    try saveDeploymentInDb(&db, .{
        .id = "dep-2",
        .app_name = "app-b",
        .service_name = "app-b",
        .trigger = "apply",
        .manifest_hash = "sha256:b1",
        .config_snapshot = "{}",
        .status = "completed",
        .message = null,
        .created_at = 150,
    });
    try saveDeploymentInDb(&db, .{
        .id = "dep-3",
        .app_name = "app-a",
        .service_name = "app-a",
        .trigger = "apply",
        .manifest_hash = "sha256:a2",
        .config_snapshot = "{}",
        .status = "failed",
        .message = null,
        .created_at = 200,
    });

    var latest = try listLatestDeploymentsByAppInDb(&db, std.testing.allocator);
    defer {
        for (latest.items) |dep| dep.deinit(std.testing.allocator);
        latest.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 2), latest.items.len);
    try std.testing.expectEqualStrings("dep-3", latest.items[0].id);
    try std.testing.expectEqualStrings("app-a", latest.items[0].app_name.?);
    try std.testing.expectEqualStrings("dep-2", latest.items[1].id);
    try std.testing.expectEqualStrings("app-b", latest.items[1].app_name.?);
}

test "listLatestDeploymentsByAppInDb returns empty list when no app releases exist" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    var latest = try listLatestDeploymentsByAppInDb(&db, std.testing.allocator);
    defer latest.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), latest.items.len);
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
