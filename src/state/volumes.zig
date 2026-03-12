// volumes — volume lifecycle management
//
// creates, resolves, and destroys managed volumes. volumes are
// directories on the host that get bind-mounted into containers.
//
// two drivers:
//   local: managed dir under ~/.local/share/yoq/volumes/<app>/<name>/
//   host:  user-specified host directory (not managed by yoq)

const std = @import("std");
const sqlite = @import("sqlite");
const paths = @import("../lib/paths.zig");
const log = @import("../lib/log.zig");
const spec = @import("../manifest/spec.zig");

pub const VolumeError = error{
    DbError,
    PathTooLong,
    HomeDirNotFound,
    IoError,
};

pub const VolumeRecord = struct {
    name: []const u8,
    app_name: []const u8,
    driver: []const u8,
    path: []const u8,
    status: []const u8,

    pub fn deinit(self: VolumeRecord, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.app_name);
        alloc.free(self.driver);
        alloc.free(self.path);
        alloc.free(self.status);
    }
};

/// resolve the filesystem path for a volume.
/// local: ~/.local/share/yoq/volumes/<app_name>/<vol_name>/
/// host: the configured path directly
pub fn resolveVolumePath(
    buf: *[paths.max_path]u8,
    app_name: []const u8,
    vol_name: []const u8,
    driver: spec.VolumeDriver,
) VolumeError![]const u8 {
    return switch (driver) {
        .local => paths.dataPathFmt(buf, "volumes/{s}/{s}", .{ app_name, vol_name }) catch |err| switch (err) {
            error.HomeDirNotFound => VolumeError.HomeDirNotFound,
            error.PathTooLong => VolumeError.PathTooLong,
        },
        .host => |h| h.path,
    };
}

/// create a volume: mkdir + INSERT into db. idempotent — skips if already exists.
pub fn create(
    db: *sqlite.Db,
    app_name: []const u8,
    vol: spec.Volume,
    timestamp: i64,
) VolumeError!void {
    var buf: [paths.max_path]u8 = undefined;
    const vol_path = try resolveVolumePath(&buf, app_name, vol.name, vol.driver);

    // ensure the directory exists (for local driver)
    switch (vol.driver) {
        .local => {
            std.fs.cwd().makePath(vol_path) catch |e| {
                log.err("volumes: failed to create directory {s}: {}", .{ vol_path, e });
                return VolumeError.IoError;
            };
        },
        .host => {},
    }

    // idempotent insert
    db.exec(
        "INSERT OR IGNORE INTO volumes (name, app_name, driver, path, status, created_at)" ++
            " VALUES (?, ?, ?, ?, 'created', ?);",
        .{},
        .{
            sqlite.Text{ .data = vol.name },
            sqlite.Text{ .data = app_name },
            sqlite.Text{ .data = vol.driver.driverName() },
            sqlite.Text{ .data = vol_path },
            timestamp,
        },
    ) catch {
        return VolumeError.DbError;
    };
}

/// look up the path of a volume from the database.
pub fn getVolumePath(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    app_name: []const u8,
    vol_name: []const u8,
) VolumeError!?[]const u8 {
    const Row = struct { path: sqlite.Text };
    const row = db.oneAlloc(
        Row,
        alloc,
        "SELECT path FROM volumes WHERE name = ? AND app_name = ?;",
        .{},
        .{ sqlite.Text{ .data = vol_name }, sqlite.Text{ .data = app_name } },
    ) catch return VolumeError.DbError;

    if (row) |r| {
        return r.path.data;
    }
    return null;
}

/// destroy a volume: rmdir (local only) + DELETE from db.
pub fn destroy(
    db: *sqlite.Db,
    app_name: []const u8,
    vol_name: []const u8,
) VolumeError!void {
    // look up driver and path before deleting
    const alloc = std.heap.page_allocator;
    const Row = struct { driver: sqlite.Text, path: sqlite.Text };
    const row = (db.oneAlloc(
        Row,
        alloc,
        "SELECT driver, path FROM volumes WHERE name = ? AND app_name = ?;",
        .{},
        .{ sqlite.Text{ .data = vol_name }, sqlite.Text{ .data = app_name } },
    ) catch return VolumeError.DbError) orelse return;
    defer {
        alloc.free(row.driver.data);
        alloc.free(row.path.data);
    }

    // only remove directories for local driver
    if (std.mem.eql(u8, row.driver.data, "local")) {
        std.fs.cwd().deleteTree(row.path.data) catch |e| {
            log.warn("volumes: failed to remove directory {s}: {}", .{ row.path.data, e });
        };
    }

    db.exec(
        "DELETE FROM volumes WHERE name = ? AND app_name = ?;",
        .{},
        .{ sqlite.Text{ .data = vol_name }, sqlite.Text{ .data = app_name } },
    ) catch return VolumeError.DbError;
}

/// list all volumes for an app.
pub fn list(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    app_name: []const u8,
) VolumeError![]VolumeRecord {
    var result: std.ArrayListUnmanaged(VolumeRecord) = .empty;
    errdefer {
        for (result.items) |rec| rec.deinit(alloc);
        result.deinit(alloc);
    }

    const Row = struct { name: sqlite.Text, app_name: sqlite.Text, driver: sqlite.Text, path: sqlite.Text, status: sqlite.Text };

    var stmt = db.prepare(
        "SELECT name, app_name, driver, path, status FROM volumes WHERE app_name = ?;",
    ) catch return VolumeError.DbError;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{sqlite.Text{ .data = app_name }}) catch return VolumeError.DbError;
    while (iter.nextAlloc(alloc, .{}) catch return VolumeError.DbError) |row| {
        result.append(alloc, .{
            .name = row.name.data,
            .app_name = row.app_name.data,
            .driver = row.driver.data,
            .path = row.path.data,
            .status = row.status.data,
        }) catch return VolumeError.DbError;
    }

    return result.toOwnedSlice(alloc) catch return VolumeError.DbError;
}

// -- tests --

const schema = @import("schema.zig");

test "create and get volume path — local driver" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const vol = spec.Volume{ .name = "data", .driver = .{ .local = .{} } };
    try create(&db, "myapp", vol, 1000);

    const alloc = std.testing.allocator;
    const path = (try getVolumePath(alloc, &db, "myapp", "data")).?;
    defer alloc.free(path);

    try std.testing.expect(std.mem.endsWith(u8, path, "volumes/myapp/data"));
}

test "create is idempotent" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const vol = spec.Volume{ .name = "data", .driver = .{ .local = .{} } };
    try create(&db, "myapp", vol, 1000);
    try create(&db, "myapp", vol, 2000); // should not error
}

test "create host volume stores configured path" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const vol = spec.Volume{ .name = "ext", .driver = .{ .host = .{ .path = "/mnt/storage" } } };
    try create(&db, "myapp", vol, 1000);

    const alloc = std.testing.allocator;
    const path = (try getVolumePath(alloc, &db, "myapp", "ext")).?;
    defer alloc.free(path);

    try std.testing.expectEqualStrings("/mnt/storage", path);
}

test "getVolumePath returns null for missing volume" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const alloc = std.testing.allocator;
    const path = try getVolumePath(alloc, &db, "myapp", "nonexistent");
    try std.testing.expect(path == null);
}

test "destroy removes volume record" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    // create a host volume (no directory to manage)
    const vol = spec.Volume{ .name = "ext", .driver = .{ .host = .{ .path = "/mnt/storage" } } };
    try create(&db, "myapp", vol, 1000);

    try destroy(&db, "myapp", "ext");

    const alloc = std.testing.allocator;
    const path = try getVolumePath(alloc, &db, "myapp", "ext");
    try std.testing.expect(path == null);
}

test "destroy nonexistent volume is no-op" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try destroy(&db, "myapp", "nonexistent"); // should not error
}

test "list volumes for app" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const vol1 = spec.Volume{ .name = "data", .driver = .{ .local = .{} } };
    const vol2 = spec.Volume{ .name = "ext", .driver = .{ .host = .{ .path = "/mnt/storage" } } };
    try create(&db, "myapp", vol1, 1000);
    try create(&db, "myapp", vol2, 1000);

    // create a volume for a different app to verify filtering
    const vol3 = spec.Volume{ .name = "other", .driver = .{ .local = .{} } };
    try create(&db, "otherapp", vol3, 1000);

    const alloc = std.testing.allocator;
    const vols = try list(alloc, &db, "myapp");
    defer {
        for (vols) |rec| rec.deinit(alloc);
        alloc.free(vols);
    }

    try std.testing.expectEqual(@as(usize, 2), vols.len);
}

test "list volumes for app with no volumes" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const alloc = std.testing.allocator;
    const vols = try list(alloc, &db, "myapp");
    defer alloc.free(vols);

    try std.testing.expectEqual(@as(usize, 0), vols.len);
}

test "resolveVolumePath — local driver" {
    var buf: [paths.max_path]u8 = undefined;
    const path = resolveVolumePath(&buf, "myapp", "data", .{ .local = .{} }) catch return;
    try std.testing.expect(std.mem.endsWith(u8, path, "volumes/myapp/data"));
}

test "resolveVolumePath — host driver" {
    var buf: [paths.max_path]u8 = undefined;
    const path = try resolveVolumePath(&buf, "myapp", "data", .{ .host = .{ .path = "/mnt/data" } });
    try std.testing.expectEqualStrings("/mnt/data", path);
}
