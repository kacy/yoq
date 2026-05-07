// volumes — volume lifecycle management
//
// this file keeps the stable public API and tests while the
// implementation lives in smaller modules under `state/volumes/`.

const std = @import("std");
const sqlite = @import("sqlite");
const paths = @import("../lib/paths.zig");
const spec = @import("../manifest/spec.zig");

const common = @import("volumes/common.zig");
const mount_support = @import("volumes/mount_support.zig");
const storage_runtime = @import("volumes/storage_runtime.zig");

pub const VolumeError = common.VolumeError;
pub const VolumeRecord = common.VolumeRecord;
pub const VolumeConstraint = common.VolumeConstraint;
pub const resolveVolumePath = common.resolveVolumePath;
pub const create = storage_runtime.create;
pub const createManaged = storage_runtime.createManaged;
pub const getVolumePath = storage_runtime.getVolumePath;
pub const destroy = storage_runtime.destroy;
pub const list = storage_runtime.list;
pub const getVolumesByApp = storage_runtime.getVolumesByApp;
pub const validateParallelFs = mount_support.validateParallelFs;
pub const isParallelFsMagic = mount_support.isParallelFsMagic;

const isMounted = mount_support.isMounted;

const schema = @import("schema.zig");

test "create and get volume path — local driver" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const vol = spec.Volume{ .name = "data", .driver = .{ .local = .{} } };
    try create(&db, "myapp", vol, 1000, null);

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
    try create(&db, "myapp", vol, 1000, null);
    try create(&db, "myapp", vol, 2000, null);
}

test "create host volume stores configured path" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const vol = spec.Volume{ .name = "ext", .driver = .{ .host = .{ .path = "/mnt/storage" } } };
    try create(&db, "myapp", vol, 1000, null);

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

    const vol = spec.Volume{ .name = "ext", .driver = .{ .host = .{ .path = "/mnt/storage" } } };
    try create(&db, "myapp", vol, 1000, null);

    try destroy(&db, "myapp", "ext");

    const alloc = std.testing.allocator;
    const path = try getVolumePath(alloc, &db, "myapp", "ext");
    try std.testing.expect(path == null);
}

test "destroy nonexistent volume is no-op" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try destroy(&db, "myapp", "nonexistent");
}

test "list volumes for app" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const vol1 = spec.Volume{ .name = "data", .driver = .{ .local = .{} } };
    const vol2 = spec.Volume{ .name = "ext", .driver = .{ .host = .{ .path = "/mnt/storage" } } };
    try create(&db, "myapp", vol1, 1000, null);
    try create(&db, "myapp", vol2, 1000, null);

    const vol3 = spec.Volume{ .name = "other", .driver = .{ .local = .{} } };
    try create(&db, "otherapp", vol3, 1000, null);

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

test "resolveVolumePath — nfs driver" {
    var buf: [paths.max_path]u8 = undefined;
    const path = resolveVolumePath(&buf, "myapp", "shared", .{ .nfs = .{
        .server = "10.0.0.1",
        .path = "/exports/data",
        .options = null,
    } }) catch return;
    try std.testing.expect(std.mem.endsWith(u8, path, "mounts/nfs/myapp/shared"));
}

test "isMounted returns false for non-existent path" {
    try std.testing.expect(!isMounted("/nonexistent/path/that/does/not/exist"));
}

test "nfs volume DB round-trip" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO volumes (name, app_name, driver, path, status, created_at)" ++
            " VALUES (?, ?, ?, ?, 'created', ?);",
        .{},
        .{
            sqlite.Text{ .data = "nfsdata" },
            sqlite.Text{ .data = "myapp" },
            sqlite.Text{ .data = "nfs" },
            sqlite.Text{ .data = "/tmp/test/mounts/nfs/myapp/nfsdata" },
            @as(i64, 1000),
        },
    ) catch return;

    const alloc = std.testing.allocator;
    const path = (try getVolumePath(alloc, &db, "myapp", "nfsdata")).?;
    defer alloc.free(path);

    try std.testing.expectEqualStrings("/tmp/test/mounts/nfs/myapp/nfsdata", path);
}

test "isParallelFsMagic — known types" {
    try std.testing.expect(isParallelFsMagic(@as(u32, 0x0BD00BD0)));
    try std.testing.expect(isParallelFsMagic(@as(u32, 0x47504653)));
    try std.testing.expect(isParallelFsMagic(@as(u32, 0x19830326)));
}

test "isParallelFsMagic — non-parallel types" {
    try std.testing.expect(!isParallelFsMagic(@as(u32, 0xEF53)));
    try std.testing.expect(!isParallelFsMagic(@as(u32, 0x58465342)));
    try std.testing.expect(!isParallelFsMagic(@as(u32, 0x01021994)));
}

test "resolveVolumePath — parallel driver" {
    var buf: [paths.max_path]u8 = undefined;
    const path = try resolveVolumePath(&buf, "myapp", "scratch", .{ .parallel = .{ .mount_path = "/mnt/lustre/data" } });
    try std.testing.expectEqualStrings("/mnt/lustre/data", path);
}
