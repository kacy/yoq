const std = @import("std");
const sqlite = @import("sqlite");
const store = @import("../state/store/common.zig");
const volumes = @import("../state/volumes.zig");
const mount_support = @import("../state/volumes/mount_support.zig");
const cli = @import("../lib/cli.zig");
const cmd = @import("../lib/cmd.zig");
const container = @import("container.zig");

// Standalone volumes use a separate namespace from manifest-managed apps.
const app_name = ".containers";
pub const VolumeError = error{ InvalidName, InvalidMount, NotFound, InUse, DbError, CopyFailed, OutOfMemory } || volumes.VolumeError;

pub const Record = struct {
    name: []const u8,
    path: []const u8,
    anonymous: bool,
    references: u64,
    created_at: i64,

    pub fn deinit(self: Record, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.path);
    }
};

fn begin(db: *sqlite.Db) VolumeError!void {
    db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return error.DbError;
}

fn commit(db: *sqlite.Db) VolumeError!void {
    db.exec("COMMIT;", .{}, .{}) catch return error.DbError;
}

fn rollback(db: *sqlite.Db) void {
    db.exec("ROLLBACK;", .{}, .{}) catch {};
}

pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 128 or !std.ascii.isAlphanumeric(name[0])) return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') return false;
    return true;
}

fn createInDb(db: *sqlite.Db, name: []const u8, anonymous: bool) VolumeError!void {
    if (!validName(name)) return error.InvalidName;
    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    try volumes.create(db, app_name, .{ .name = name, .driver = .{ .local = .{} } }, now, null);
    db.exec("INSERT OR IGNORE INTO local_volumes (name, anonymous, created_at) VALUES (?, ?, ?);", .{}, .{
        sqlite.Text{ .data = name }, @as(i64, if (anonymous) 1 else 0), now,
    }) catch return error.DbError;
}

pub fn create(alloc: std.mem.Allocator, requested_name: ?[]const u8) VolumeError!Record {
    var id: [12]u8 = undefined;
    var name_buf: [17]u8 = undefined;
    const name = requested_name orelse blk: {
        container.generateId(&id) catch return error.IoError;
        break :blk std.fmt.bufPrint(&name_buf, "anon-{s}", .{id}) catch unreachable;
    };
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    try begin(lease.db);
    errdefer rollback(lease.db);
    try createInDb(lease.db, name, requested_name == null);
    const record = try inspectInDb(alloc, lease.db, name);
    errdefer record.deinit(alloc);
    try commit(lease.db);
    return record;
}

const Row = struct { name: sqlite.Text, path: sqlite.Text, anonymous: i64, references: i64, created_at: i64 };
const select_records = "SELECT lv.name, v.path, lv.anonymous, " ++
    "(SELECT COUNT(*) FROM local_volume_refs r WHERE r.volume_name = lv.name) AS refs, lv.created_at " ++
    "FROM local_volumes lv JOIN volumes v ON v.name = lv.name AND v.app_name = '.containers' ";

fn recordFromRow(row: Row) Record {
    return .{ .name = row.name.data, .path = row.path.data, .anonymous = row.anonymous != 0, .references = @intCast(row.references), .created_at = row.created_at };
}

fn inspectInDb(alloc: std.mem.Allocator, db: *sqlite.Db, name: []const u8) VolumeError!Record {
    const row = (db.oneAlloc(Row, alloc, select_records ++ "WHERE lv.name = ?;", .{}, .{sqlite.Text{ .data = name }}) catch return error.DbError) orelse return error.NotFound;
    return recordFromRow(row);
}

pub fn inspect(alloc: std.mem.Allocator, name: []const u8) VolumeError!Record {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    return inspectInDb(alloc, lease.db, name);
}

pub fn list(alloc: std.mem.Allocator) VolumeError![]Record {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    var result: std.ArrayList(Record) = .empty;
    errdefer {
        for (result.items) |record| record.deinit(alloc);
        result.deinit(alloc);
    }
    var stmt = lease.db.prepare(select_records ++ "ORDER BY lv.name;") catch return error.DbError;
    defer stmt.deinit();
    var iter = stmt.iterator(Row, .{}) catch return error.DbError;
    while (iter.nextAlloc(alloc, .{}) catch return error.DbError) |row| {
        const record = recordFromRow(row);
        result.append(alloc, record) catch {
            record.deinit(alloc);
            return error.OutOfMemory;
        };
    }
    return result.toOwnedSlice(alloc) catch return error.OutOfMemory;
}

fn removeInDb(db: *sqlite.Db, record: Record) VolumeError!void {
    if (record.references != 0) return error.InUse;
    // Keep the database transaction open through filesystem cleanup. A failed
    // cleanup leaves the volume record available for a later retry.
    const exists = blk: {
        std.Io.Dir.cwd().access(std.Options.debug_io, record.path, .{}) catch |err| switch (err) {
            error.FileNotFound => break :blk false,
            else => return error.IoError,
        };
        break :blk true;
    };
    if (exists) try mount_support.cleanupManagedVolume("local", record.path);
    db.exec("DELETE FROM volumes WHERE name = ? AND app_name = ?;", .{}, .{ sqlite.Text{ .data = record.name }, sqlite.Text{ .data = app_name } }) catch return error.DbError;
    db.exec("DELETE FROM local_volumes WHERE name = ?;", .{}, .{sqlite.Text{ .data = record.name }}) catch return error.DbError;
}

pub fn remove(name: []const u8) VolumeError!void {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    try begin(lease.db);
    errdefer rollback(lease.db);
    const record = try inspectInDb(std.heap.page_allocator, lease.db, name);
    defer record.deinit(std.heap.page_allocator);
    try removeInDb(lease.db, record);
    try commit(lease.db);
}

/// Reserve a volume reference before saving or starting the container. The
/// caller owns both strings in the returned bind mount.
pub fn resolveMount(alloc: std.mem.Allocator, id: []const u8, spec: cli.VolumeMountSpec) VolumeError!container.BindMount {
    if (!container.isValidContainerId(id) or spec.kind != .volume or spec.target.len == 0 or spec.target[0] != '/') return error.InvalidMount;
    var random_id: [12]u8 = undefined;
    var name_buf: [17]u8 = undefined;
    const anonymous = spec.source.len == 0;
    const name = if (!anonymous) spec.source else blk: {
        container.generateId(&random_id) catch return error.IoError;
        break :blk std.fmt.bufPrint(&name_buf, "anon-{s}", .{random_id}) catch unreachable;
    };
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    try begin(lease.db);
    errdefer rollback(lease.db);
    try createInDb(lease.db, name, anonymous);
    lease.db.exec("INSERT INTO local_volume_refs (container_id, target, volume_name, nocopy) VALUES (?, ?, ?, ?);", .{}, .{
        sqlite.Text{ .data = id }, sqlite.Text{ .data = spec.target }, sqlite.Text{ .data = name }, @as(i64, if (spec.volume_nocopy) 1 else 0),
    }) catch return error.DbError;
    const record = try inspectInDb(alloc, lease.db, name);
    defer record.deinit(alloc);
    const source = std.Io.Dir.cwd().realPathFileAlloc(std.Options.debug_io, record.path, alloc) catch return error.IoError;
    errdefer alloc.free(source);
    const target = alloc.dupe(u8, spec.target) catch return error.OutOfMemory;
    errdefer alloc.free(target);
    try commit(lease.db);
    return .{ .source = source, .target = target, .read_only = spec.read_only };
}

/// Release references only after the container's mounts are gone. Ordinary
/// removal retains volumes; --rm or rm -v may remove unreferenced anonymous ones.
pub fn releaseContainer(id: []const u8, remove_anonymous: bool) VolumeError!void {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    const alloc = std.heap.page_allocator;
    try begin(lease.db);
    errdefer rollback(lease.db);
    const Ref = struct { volume_name: sqlite.Text };
    var stmt = lease.db.prepare("SELECT DISTINCT volume_name FROM local_volume_refs WHERE container_id = ?;") catch return error.DbError;
    defer stmt.deinit();
    const refs = stmt.all(Ref, alloc, .{}, .{sqlite.Text{ .data = id }}) catch return error.DbError;
    defer {
        for (refs) |ref| alloc.free(ref.volume_name.data);
        alloc.free(refs);
    }
    for (refs) |ref| {
        lease.db.exec("DELETE FROM local_volume_refs WHERE container_id = ? AND volume_name = ?;", .{}, .{ sqlite.Text{ .data = id }, ref.volume_name }) catch return error.DbError;
        const record = try inspectInDb(alloc, lease.db, ref.volume_name.data);
        defer record.deinit(alloc);
        if (remove_anonymous and record.anonymous and record.references == 0) try removeInDb(lease.db, record);
    }
    try commit(lease.db);
}

/// Populate empty volumes from the prepared, merged rootfs before installing
/// bind mounts. Copying through a sibling directory keeps failed copies out of
/// the volume. Existing data is never replaced.
pub fn initializeContainer(io: std.Io, alloc: std.mem.Allocator, id: []const u8, rootfs: []const u8) VolumeError!void {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    const InitRow = struct { name: sqlite.Text, target: sqlite.Text, path: sqlite.Text };
    var stmt = lease.db.prepare(
        "SELECT lv.name, r.target, v.path FROM local_volume_refs r " ++
            "JOIN local_volumes lv ON lv.name = r.volume_name " ++
            "JOIN volumes v ON v.name = lv.name AND v.app_name = '.containers' " ++
            "WHERE r.container_id = ? AND r.nocopy = 0 AND lv.initialized = 0 ORDER BY r.target;",
    ) catch return error.DbError;
    defer stmt.deinit();
    const rows = stmt.all(InitRow, alloc, .{}, .{sqlite.Text{ .data = id }}) catch return error.DbError;
    defer {
        for (rows) |row| {
            alloc.free(row.name.data);
            alloc.free(row.target.data);
            alloc.free(row.path.data);
        }
        alloc.free(rows);
    }
    for (rows) |row| {
        try begin(lease.db);
        errdefer rollback(lease.db);
        // Recheck after acquiring the write lock: another container may have
        // populated this shared volume since the initial query.
        const initialized = (lease.db.one(i64, "SELECT initialized FROM local_volumes WHERE name = ?;", .{}, .{row.name}) catch return error.DbError) orelse return error.NotFound;
        if (initialized == 0) {
            const completed = try initializeEmptyVolume(io, alloc, rootfs, row.target.data, row.path.data, id);
            if (completed) lease.db.exec("UPDATE local_volumes SET initialized = 1 WHERE name = ?;", .{}, .{row.name}) catch return error.DbError;
        }
        try commit(lease.db);
    }
}

fn initializeEmptyVolume(io: std.Io, alloc: std.mem.Allocator, rootfs: []const u8, target: []const u8, destination: []const u8, id: []const u8) VolumeError!bool {
    var dir = std.Io.Dir.cwd().openDir(io, destination, .{ .iterate = true }) catch return error.CopyFailed;
    defer dir.close(io);
    var iterator = dir.iterate();
    if ((iterator.next(io) catch return error.CopyFailed) != null) return true;

    const root = std.Io.Dir.cwd().realPathFileAlloc(io, rootfs, alloc) catch return error.CopyFailed;
    defer alloc.free(root);
    const source_input = std.fs.path.resolve(alloc, &.{ root, std.mem.trimStart(u8, target, "/") }) catch return error.OutOfMemory;
    defer alloc.free(source_input);
    const source = std.Io.Dir.cwd().realPathFileAlloc(io, source_input, alloc) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return error.CopyFailed,
    };
    defer alloc.free(source);
    if (!std.mem.eql(u8, root, "/") and !std.mem.eql(u8, source, root) and !(std.mem.startsWith(u8, source, root) and source.len > root.len and source[root.len] == '/')) return error.CopyFailed;
    const stat = std.Io.Dir.cwd().statFile(io, source, .{}) catch return error.CopyFailed;
    if (stat.kind != .directory) return error.CopyFailed;

    const staging = std.fmt.allocPrint(alloc, "{s}.init-{s}", .{ destination, id }) catch return error.OutOfMemory;
    defer alloc.free(staging);
    std.Io.Dir.cwd().deleteTree(io, staging) catch return error.CopyFailed;
    std.Io.Dir.cwd().createDirPath(io, staging) catch return error.CopyFailed;
    defer std.Io.Dir.cwd().deleteTree(io, staging) catch {};
    const contents = std.fmt.allocPrint(alloc, "{s}/.", .{source}) catch return error.OutOfMemory;
    defer alloc.free(contents);
    var argv: cmd.ArgList = .{null} ** cmd.max_args;
    argv[0] = "cp";
    argv[1] = "-a";
    argv[2] = "--";
    argv[3] = contents;
    argv[4] = staging;
    cmd.exec(&argv) catch return error.CopyFailed;
    // rename atomically replaces the empty destination directory. It refuses
    // replacement if another writer has added a file in the meantime.
    std.Io.Dir.cwd().rename(staging, std.Io.Dir.cwd(), destination, io) catch return error.CopyFailed;
    return true;
}

test "standalone volumes keep named data and remove anonymous data only when requested" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    var id: [12]u8 = undefined;
    try container.generateId(&id);
    var name_buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "named-{s}", .{id});
    const mount = try resolveMount(alloc, &id, .{ .kind = .volume, .source = name, .target = "/data", .read_only = false });
    defer alloc.free(mount.source);
    defer alloc.free(mount.target);
    defer remove(name) catch {};
    try std.testing.expectError(error.InUse, remove(name));
    try releaseContainer(&id, true);
    const kept = try inspect(alloc, name);
    defer kept.deinit(alloc);
    try std.testing.expectEqual(@as(u64, 0), kept.references);
    try std.testing.expect(!kept.anonymous);

    const anonymous = try resolveMount(alloc, &id, .{ .kind = .volume, .source = "", .target = "/temporary", .read_only = false });
    defer alloc.free(anonymous.source);
    defer alloc.free(anonymous.target);
    const anon_name = std.fs.path.basename(anonymous.source);
    try releaseContainer(&id, false);
    const retained = try inspect(alloc, anon_name);
    defer retained.deinit(alloc);
    try std.testing.expect(retained.anonymous);
    const attached = try resolveMount(alloc, &id, .{ .kind = .volume, .source = anon_name, .target = "/temporary", .read_only = false });
    defer alloc.free(attached.source);
    defer alloc.free(attached.target);
    try releaseContainer(&id, true);
    try std.testing.expectError(error.NotFound, inspect(alloc, anon_name));
}

test "standalone volume initialization preserves data across later containers" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "image/data");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "image/data/default.txt", .data = "original" });
    const rootfs = try tmp.dir.realPathFileAlloc(std.testing.io, "image", alloc);
    defer alloc.free(rootfs);
    var id: [12]u8 = undefined;
    try container.generateId(&id);
    const mount = try resolveMount(alloc, &id, .{ .kind = .volume, .source = "", .target = "/data", .read_only = false });
    defer alloc.free(mount.source);
    defer alloc.free(mount.target);
    defer releaseContainer(&id, true) catch {};
    try initializeContainer(std.testing.io, alloc, &id, rootfs);
    var dir = try std.Io.Dir.cwd().openDir(std.testing.io, mount.source, .{});
    defer dir.close(std.testing.io);
    const copied = try dir.readFileAlloc(std.testing.io, "default.txt", alloc, .limited(100));
    defer alloc.free(copied);
    try std.testing.expectEqualStrings("original", copied);
    try dir.writeFile(std.testing.io, .{ .sub_path = "default.txt", .data = "changed" });
    try initializeContainer(std.testing.io, alloc, &id, rootfs);
    const retained = try dir.readFileAlloc(std.testing.io, "default.txt", alloc, .limited(100));
    defer alloc.free(retained);
    try std.testing.expectEqualStrings("changed", retained);
}

test "standalone volume names cannot be empty or contain path components" {
    for ([_][]const u8{ "", ".", "..", "/tmp/data", "a/b", "-name", "a" ** 129 }) |name| try std.testing.expect(!validName(name));
    try std.testing.expect(validName("data_1.cache"));
}

pub fn needsInitialization(id: []const u8) VolumeError!bool {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    const count = lease.db.one(
        i64,
        "SELECT COUNT(*) FROM local_volume_refs r JOIN local_volumes v ON v.name = r.volume_name " ++
            "WHERE r.container_id = ? AND r.nocopy = 0 AND v.initialized = 0;",
        .{},
        .{sqlite.Text{ .data = id }},
    ) catch return error.DbError;
    return (count orelse 0) != 0;
}
