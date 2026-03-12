// volumes — volume lifecycle management
//
// creates, resolves, and destroys managed volumes. volumes are
// directories on the host that get bind-mounted into containers.
//
// three drivers:
//   local: managed dir under ~/.local/share/yoq/volumes/<app>/<name>/
//   host:  user-specified host directory (not managed by yoq)
//   nfs:   kernel NFS v4.1 mount under ~/.local/share/yoq/mounts/nfs/<app>/<name>/

const std = @import("std");
const sqlite = @import("sqlite");
const linux = std.os.linux;
const paths = @import("../lib/paths.zig");
const log = @import("../lib/log.zig");
const spec = @import("../manifest/spec.zig");
const syscall_util = @import("../lib/syscall.zig");

// errno constants for mount/unmount idempotency
const ENOENT = 2;
const EBUSY = 16;
const EINVAL = 22;

pub const VolumeError = error{
    DbError,
    OutOfMemory,
    PathTooLong,
    HomeDirNotFound,
    IoError,
    MountFailed,
    UnmountFailed,
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
/// nfs:   ~/.local/share/yoq/mounts/nfs/<app_name>/<vol_name>/
/// host:  the configured path directly
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
        .nfs => paths.dataPathFmt(buf, "mounts/nfs/{s}/{s}", .{ app_name, vol_name }) catch |err| switch (err) {
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

    // ensure the directory exists and mount if needed
    switch (vol.driver) {
        .local => {
            std.fs.cwd().makePath(vol_path) catch |e| {
                log.err("volumes: failed to create directory {s}: {}", .{ vol_path, e });
                return VolumeError.IoError;
            };
        },
        .nfs => |n| {
            std.fs.cwd().makePath(vol_path) catch |e| {
                log.err("volumes: failed to create NFS mountpoint {s}: {}", .{ vol_path, e });
                return VolumeError.IoError;
            };
            mountNfs(vol_path, n.server, n.path, n.options) catch |e| {
                log.err("volumes: NFS mount failed for {s}: {}", .{ vol_path, e });
                std.fs.cwd().deleteTree(vol_path) catch {};
                return e;
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

    // unmount NFS before removing directory
    if (std.mem.eql(u8, row.driver.data, "nfs")) {
        unmountNfs(row.path.data) catch |e| {
            log.warn("volumes: NFS unmount failed for {s}: {}", .{ row.path.data, e });
        };
    }

    // remove managed directories (local and nfs — not host)
    if (std.mem.eql(u8, row.driver.data, "local") or std.mem.eql(u8, row.driver.data, "nfs")) {
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
        }) catch return VolumeError.OutOfMemory;
    }

    return result.toOwnedSlice(alloc) catch return VolumeError.OutOfMemory;
}

/// check if a path is currently mounted by reading /proc/mounts.
fn isMounted(path: []const u8) bool {
    const file = std.fs.cwd().openFile("/proc/mounts", .{}) catch return false;
    defer file.close();

    var buf: [8192]u8 = undefined;
    var leftover_len: usize = 0;

    while (true) {
        const bytes_read = file.read(buf[leftover_len..]) catch return false;
        if (bytes_read == 0) {
            // process any remaining data without trailing newline
            if (leftover_len > 0) {
                if (checkMountLine(buf[0..leftover_len], path)) return true;
            }
            break;
        }
        const total = leftover_len + bytes_read;

        // scan complete lines in the buffer
        var content = buf[0..total];
        while (std.mem.indexOf(u8, content, "\n")) |nl| {
            const line = content[0..nl];
            if (checkMountLine(line, path)) return true;
            content = content[nl + 1 ..];
        }

        // carry over incomplete line to next iteration
        leftover_len = content.len;
        if (leftover_len > 0) {
            std.mem.copyForwards(u8, &buf, content);
        }
    }
    return false;
}

/// parse a /proc/mounts line and check if the mountpoint matches path.
fn checkMountLine(line: []const u8, path: []const u8) bool {
    // /proc/mounts format: device mountpoint fstype options dump pass
    const first_space = std.mem.indexOf(u8, line, " ") orelse return false;
    const after_device = line[first_space + 1 ..];
    const mountpoint = if (std.mem.indexOf(u8, after_device, " ")) |second_space|
        after_device[0..second_space]
    else
        after_device;
    return std.mem.eql(u8, mountpoint, path);
}

/// mount an NFS share using the kernel mount(2) syscall.
/// type is "nfs4", default options "vers=4.1".
/// idempotent: returns success if already mounted (EBUSY).
fn mountNfs(
    mountpoint: []const u8,
    server: []const u8,
    export_path: []const u8,
    options: ?[]const u8,
) VolumeError!void {
    // build null-terminated source: "server:/export/path\0"
    var source_buf: [paths.max_path]u8 = undefined;
    const source_z = std.fmt.bufPrint(&source_buf, "{s}:{s}\x00", .{ server, export_path }) catch
        return VolumeError.PathTooLong;

    // null-terminated mountpoint
    var mp_buf: [paths.max_path]u8 = undefined;
    const mp_z = std.fmt.bufPrint(&mp_buf, "{s}\x00", .{mountpoint}) catch
        return VolumeError.PathTooLong;

    // null-terminated options
    const default_opts = "vers=4.1";
    const opts = options orelse default_opts;
    var opts_buf: [1024]u8 = undefined;
    const opts_z = std.fmt.bufPrint(&opts_buf, "{s}\x00", .{opts}) catch
        return VolumeError.PathTooLong;

    const fstype = "nfs4\x00";

    const rc = linux.syscall5(
        .mount,
        @intFromPtr(source_z.ptr),
        @intFromPtr(mp_z.ptr),
        @intFromPtr(fstype.ptr),
        0, // flags
        @intFromPtr(opts_z.ptr),
    );

    if (syscall_util.isError(rc)) {
        const errno = syscall_util.getErrno(rc);
        // EBUSY (16) = already mounted — treat as success for idempotency
        if (errno == EBUSY) return;
        log.err("volumes: mount(2) failed for NFS {s}:{s} on {s}: errno={}", .{
            server, export_path, mountpoint, errno,
        });
        return VolumeError.MountFailed;
    }
}

/// unmount an NFS share using umount2(MNT_DETACH) for stale mount resilience.
/// idempotent: returns success if not mounted (EINVAL/ENOENT).
fn unmountNfs(mountpoint: []const u8) VolumeError!void {
    var mp_buf: [paths.max_path]u8 = undefined;
    const mp_z = std.fmt.bufPrint(&mp_buf, "{s}\x00", .{mountpoint}) catch
        return VolumeError.PathTooLong;

    const MNT_DETACH = 0x00000002;
    const rc = linux.syscall2(
        .umount2,
        @intFromPtr(mp_z.ptr),
        MNT_DETACH,
    );

    if (syscall_util.isError(rc)) {
        const errno = syscall_util.getErrno(rc);
        // EINVAL (22) or ENOENT (2) = not mounted — treat as success
        if (errno == EINVAL or errno == ENOENT) return;
        log.err("volumes: umount2 failed for {s}: errno={}", .{ mountpoint, errno });
        return VolumeError.UnmountFailed;
    }
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

    // NFS create will fail (no real NFS server), but we can test the DB path
    // by inserting directly and verifying getVolumePath
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
