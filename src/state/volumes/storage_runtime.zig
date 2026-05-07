const std = @import("std");
const sqlite = @import("sqlite");
const paths = @import("../../lib/paths.zig");
const spec = @import("../../manifest/spec.zig");
const common = @import("common.zig");
const mount_support = @import("mount_support.zig");
const store_common = @import("../store/common.zig");

pub fn create(
    db: *sqlite.Db,
    app_name: []const u8,
    vol: spec.Volume,
    timestamp: i64,
    node_id: ?[]const u8,
) common.VolumeError!void {
    var buf: [paths.max_path]u8 = undefined;
    const vol_path = try common.resolveVolumePath(&buf, app_name, vol.name, vol.driver);

    const prepared = try mount_support.prepareVolumePath(vol_path, vol.driver);
    errdefer mount_support.rollbackPreparedVolume(vol_path, vol.driver, prepared);
    const effective_node_id = mount_support.driverNodeId(vol.driver, node_id);

    db.exec(
        "INSERT OR IGNORE INTO volumes (name, app_name, driver, path, status, node_id, created_at)" ++
            " VALUES (?, ?, ?, ?, 'created', ?, ?);",
        .{},
        .{
            sqlite.Text{ .data = vol.name },
            sqlite.Text{ .data = app_name },
            sqlite.Text{ .data = vol.driver.driverName() },
            sqlite.Text{ .data = vol_path },
            effective_node_id,
            timestamp,
        },
    ) catch return common.VolumeError.DbError;
}

pub fn createManaged(
    app_name: []const u8,
    vol: spec.Volume,
    timestamp: i64,
    node_id: ?[]const u8,
) common.VolumeError!void {
    var lease = store_common.leaseDb() catch return common.VolumeError.DbError;
    defer lease.deinit();

    return create(lease.db, app_name, vol, timestamp, node_id);
}

pub fn getVolumePath(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    app_name: []const u8,
    vol_name: []const u8,
) common.VolumeError!?[]const u8 {
    const Row = struct { path: sqlite.Text };
    const row = db.oneAlloc(
        Row,
        alloc,
        "SELECT path FROM volumes WHERE name = ? AND app_name = ?;",
        .{},
        .{ sqlite.Text{ .data = vol_name }, sqlite.Text{ .data = app_name } },
    ) catch return common.VolumeError.DbError;

    if (row) |r| {
        return r.path.data;
    }
    return null;
}

pub fn destroy(
    db: *sqlite.Db,
    app_name: []const u8,
    vol_name: []const u8,
) common.VolumeError!void {
    const row = (try lookupVolumeDriverAndPath(db, app_name, vol_name)) orelse return;
    defer {
        std.heap.page_allocator.free(row.driver.data);
        std.heap.page_allocator.free(row.path.data);
    }

    db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return common.VolumeError.DbError;
    var transaction_open = true;
    errdefer if (transaction_open) db.exec("ROLLBACK;", .{}, .{}) catch {};

    db.exec(
        "DELETE FROM volumes WHERE name = ? AND app_name = ?;",
        .{},
        .{ sqlite.Text{ .data = vol_name }, sqlite.Text{ .data = app_name } },
    ) catch return common.VolumeError.DbError;

    try mount_support.cleanupManagedVolume(row.driver.data, row.path.data);
    db.exec("COMMIT;", .{}, .{}) catch return common.VolumeError.DbError;
    transaction_open = false;
}

pub fn list(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    app_name: []const u8,
) common.VolumeError![]common.VolumeRecord {
    var result: std.ArrayListUnmanaged(common.VolumeRecord) = .empty;
    errdefer {
        for (result.items) |rec| rec.deinit(alloc);
        result.deinit(alloc);
    }

    const Row = struct { name: sqlite.Text, app_name: sqlite.Text, driver: sqlite.Text, path: sqlite.Text, status: sqlite.Text };

    var stmt = db.prepare(
        "SELECT name, app_name, driver, path, status FROM volumes WHERE app_name = ?;",
    ) catch return common.VolumeError.DbError;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{sqlite.Text{ .data = app_name }}) catch return common.VolumeError.DbError;
    while (iter.nextAlloc(alloc, .{}) catch return common.VolumeError.DbError) |row| {
        result.append(alloc, .{
            .name = row.name.data,
            .app_name = row.app_name.data,
            .driver = row.driver.data,
            .path = row.path.data,
            .status = row.status.data,
        }) catch return common.VolumeError.OutOfMemory;
    }

    return result.toOwnedSlice(alloc) catch return common.VolumeError.OutOfMemory;
}

pub fn getVolumesByApp(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    app_name: []const u8,
) common.VolumeError![]common.VolumeConstraint {
    var result: std.ArrayListUnmanaged(common.VolumeConstraint) = .empty;
    errdefer result.deinit(alloc);

    const Row = struct { driver: sqlite.Text, node_id: ?sqlite.Text };

    var stmt = db.prepare(
        "SELECT driver, node_id FROM volumes WHERE app_name = ?;",
    ) catch return common.VolumeError.DbError;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{sqlite.Text{ .data = app_name }}) catch return common.VolumeError.DbError;
    while (iter.nextAlloc(alloc, .{}) catch return common.VolumeError.DbError) |row| {
        result.append(alloc, .{
            .driver = row.driver.data,
            .node_id = if (row.node_id) |n| n.data else null,
        }) catch return common.VolumeError.OutOfMemory;
    }

    return result.toOwnedSlice(alloc) catch return common.VolumeError.OutOfMemory;
}

fn lookupVolumeDriverAndPath(
    db: *sqlite.Db,
    app_name: []const u8,
    vol_name: []const u8,
) common.VolumeError!?common.VolumeLookupRow {
    const alloc = std.heap.page_allocator;
    return (db.oneAlloc(
        common.VolumeLookupRow,
        alloc,
        "SELECT driver, path FROM volumes WHERE name = ? AND app_name = ?;",
        .{},
        .{ sqlite.Text{ .data = vol_name }, sqlite.Text{ .data = app_name } },
    ) catch return common.VolumeError.DbError);
}
