// store — persistent container state
//
// stores container metadata in a SQLite database so we can list
// containers, check their status, and recover after restarts.
// database lives at ~/.local/share/yoq/yoq.db.
//
// all container state goes through this module — no other code
// touches the database directly.

const std = @import("std");
const sqlite = @import("sqlite");
const schema = @import("schema.zig");

pub const StoreError = error{
    WriteFailed,
    ReadFailed,
    NotFound,
    DbOpenFailed,
};

/// persisted container record
pub const ContainerRecord = struct {
    id: []const u8,
    rootfs: []const u8,
    command: []const u8,
    hostname: []const u8,
    status: []const u8,
    pid: ?i32,
    exit_code: ?u8,
    ip_address: ?[]const u8 = null,
    veth_host: ?[]const u8 = null,
    created_at: i64,

    /// free all heap-allocated string fields
    pub fn deinit(self: ContainerRecord, alloc: std.mem.Allocator) void {
        alloc.free(self.id);
        alloc.free(self.rootfs);
        alloc.free(self.command);
        alloc.free(self.hostname);
        alloc.free(self.status);
        if (self.ip_address) |ip| alloc.free(ip);
        if (self.veth_host) |veth| alloc.free(veth);
    }
};

/// row type for reading full container records from sqlite.
/// uses sqlite.Text for string columns so zig-sqlite knows
/// to read them as text.
const ContainerRow = struct {
    id: sqlite.Text,
    rootfs: sqlite.Text,
    command: sqlite.Text,
    hostname: sqlite.Text,
    status: sqlite.Text,
    pid: ?i64,
    exit_code: ?i64,
    ip_address: ?sqlite.Text,
    veth_host: ?sqlite.Text,
    created_at: i64,
};

/// row type for id-only queries
const IdRow = struct {
    id: sqlite.Text,
};

/// convert a sqlite row to a ContainerRecord.
/// zig-sqlite already allocated the text fields with the query allocator,
/// so we just copy the pointers into our record struct.
fn rowToRecord(row: ContainerRow) ContainerRecord {
    return ContainerRecord{
        .id = row.id.data,
        .rootfs = row.rootfs.data,
        .command = row.command.data,
        .hostname = row.hostname.data,
        .status = row.status.data,
        .pid = if (row.pid) |p| @intCast(p) else null,
        .exit_code = if (row.exit_code) |e| @intCast(e) else null,
        .ip_address = if (row.ip_address) |ip| ip.data else null,
        .veth_host = if (row.veth_host) |veth| veth.data else null,
        .created_at = row.created_at,
    };
}

/// open the store database, creating it and the schema if needed.
pub fn openDb() StoreError!sqlite.Db {
    var path_buf: [512]u8 = undefined;
    const path = schema.defaultDbPath(&path_buf) catch return StoreError.DbOpenFailed;
    var db = sqlite.Db.init(.{
        .mode = .{ .File = path },
        .open_flags = .{ .write = true, .create = true },
    }) catch return StoreError.DbOpenFailed;

    schema.init(&db) catch {
        db.deinit();
        return StoreError.DbOpenFailed;
    };
    return db;
}

/// save (insert or replace) a container record
pub fn save(record: ContainerRecord) StoreError!void {
    var db = try openDb();
    defer db.deinit();

    const pid: ?i64 = if (record.pid) |p| @intCast(p) else null;
    const exit_code: ?i64 = if (record.exit_code) |e| @intCast(e) else null;

    db.exec(
        "INSERT OR REPLACE INTO containers (id, rootfs, command, hostname, status, pid, exit_code, ip_address, veth_host, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            record.id,
            record.rootfs,
            record.command,
            record.hostname,
            record.status,
            pid,
            exit_code,
            record.ip_address,
            record.veth_host,
            record.created_at,
        },
    ) catch return StoreError.WriteFailed;
}

/// load a single container record by id.
/// caller owns the returned strings (allocated with alloc).
pub fn load(alloc: std.mem.Allocator, id: []const u8) StoreError!ContainerRecord {
    var db = try openDb();
    defer db.deinit();

    const row = (db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT id, rootfs, command, hostname, status, pid, exit_code, ip_address, veth_host, created_at" ++
            " FROM containers WHERE id = ?;",
        .{},
        .{id},
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;

    return rowToRecord(row);
}

/// delete a container record
pub fn remove(id: []const u8) StoreError!void {
    var db = try openDb();
    defer db.deinit();

    db.exec("DELETE FROM containers WHERE id = ?;", .{}, .{id}) catch
        return StoreError.WriteFailed;
}

/// list all container IDs, newest first
pub fn listIds(alloc: std.mem.Allocator) StoreError!std.ArrayList([]const u8) {
    var db = try openDb();
    defer db.deinit();

    var ids: std.ArrayList([]const u8) = .empty;

    var stmt = db.prepare("SELECT id FROM containers ORDER BY created_at DESC;") catch
        return StoreError.ReadFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(IdRow, .{}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        // zig-sqlite allocated the text data with our alloc, so just take ownership
        ids.append(alloc, row.id.data) catch return StoreError.ReadFailed;
    }

    return ids;
}

/// update status and process info for a container
pub fn updateStatus(id: []const u8, status: []const u8, pid: ?i32, exit_code: ?u8) StoreError!void {
    var db = try openDb();
    defer db.deinit();

    const pid_val: ?i64 = if (pid) |p| @intCast(p) else null;
    const exit_val: ?i64 = if (exit_code) |e| @intCast(e) else null;

    db.exec(
        "UPDATE containers SET status = ?, pid = ?, exit_code = ? WHERE id = ?;",
        .{},
        .{ status, pid_val, exit_val, id },
    ) catch return StoreError.WriteFailed;
}

/// update network info for a container
pub fn updateNetwork(id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) StoreError!void {
    var db = try openDb();
    defer db.deinit();

    db.exec(
        "UPDATE containers SET ip_address = ?, veth_host = ? WHERE id = ?;",
        .{},
        .{ ip_address, veth_host, id },
    ) catch return StoreError.WriteFailed;
}

// -- image records --

/// persisted image record
pub const ImageRecord = struct {
    id: []const u8,
    repository: []const u8,
    tag: []const u8,
    manifest_digest: []const u8,
    config_digest: []const u8,
    total_size: i64,
    created_at: i64,

    /// free all heap-allocated string fields
    pub fn deinit(self: ImageRecord, alloc: std.mem.Allocator) void {
        alloc.free(self.id);
        alloc.free(self.repository);
        alloc.free(self.tag);
        alloc.free(self.manifest_digest);
        alloc.free(self.config_digest);
    }
};

/// row type for reading image records from sqlite
const ImageRow = struct {
    id: sqlite.Text,
    repository: sqlite.Text,
    tag: sqlite.Text,
    manifest_digest: sqlite.Text,
    config_digest: sqlite.Text,
    total_size: i64,
    created_at: i64,
};

fn imageRowToRecord(row: ImageRow) ImageRecord {
    return ImageRecord{
        .id = row.id.data,
        .repository = row.repository.data,
        .tag = row.tag.data,
        .manifest_digest = row.manifest_digest.data,
        .config_digest = row.config_digest.data,
        .total_size = row.total_size,
        .created_at = row.created_at,
    };
}

/// save an image record
pub fn saveImage(record: ImageRecord) StoreError!void {
    var db = try openDb();
    defer db.deinit();

    db.exec(
        "INSERT OR REPLACE INTO images (id, repository, tag, manifest_digest, config_digest, total_size, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            record.id,
            record.repository,
            record.tag,
            record.manifest_digest,
            record.config_digest,
            record.total_size,
            record.created_at,
        },
    ) catch return StoreError.WriteFailed;
}

/// load an image record by id (manifest digest).
/// caller owns the returned strings.
pub fn loadImage(alloc: std.mem.Allocator, id: []const u8) StoreError!ImageRecord {
    var db = try openDb();
    defer db.deinit();

    const row = (db.oneAlloc(
        ImageRow,
        alloc,
        "SELECT id, repository, tag, manifest_digest, config_digest, total_size, created_at" ++
            " FROM images WHERE id = ?;",
        .{},
        .{id},
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;

    return imageRowToRecord(row);
}

/// find an image by repository and tag.
/// caller owns the returned strings.
pub fn findImage(alloc: std.mem.Allocator, repository: []const u8, tag: []const u8) StoreError!ImageRecord {
    var db = try openDb();
    defer db.deinit();

    const row = (db.oneAlloc(
        ImageRow,
        alloc,
        "SELECT id, repository, tag, manifest_digest, config_digest, total_size, created_at" ++
            " FROM images WHERE repository = ? AND tag = ?;",
        .{},
        .{ repository, tag },
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;

    return imageRowToRecord(row);
}

/// list all image records, newest first.
/// caller owns the returned list and records.
pub fn listImages(alloc: std.mem.Allocator) StoreError!std.ArrayList(ImageRecord) {
    var db = try openDb();
    defer db.deinit();

    var images: std.ArrayList(ImageRecord) = .empty;

    var stmt = db.prepare(
        "SELECT id, repository, tag, manifest_digest, config_digest, total_size, created_at" ++
            " FROM images ORDER BY created_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(ImageRow, .{}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        images.append(alloc, imageRowToRecord(row)) catch return StoreError.ReadFailed;
    }

    return images;
}

/// delete an image record
pub fn removeImage(id: []const u8) StoreError!void {
    var db = try openDb();
    defer db.deinit();

    db.exec("DELETE FROM images WHERE id = ?;", .{}, .{id}) catch
        return StoreError.WriteFailed;
}

// -- build cache --

/// a cached build step result
pub const BuildCacheEntry = struct {
    cache_key: []const u8,
    layer_digest: []const u8,
    diff_id: []const u8,
    layer_size: i64,
    created_at: i64,

    pub fn deinit(self: BuildCacheEntry, alloc: std.mem.Allocator) void {
        alloc.free(self.cache_key);
        alloc.free(self.layer_digest);
        alloc.free(self.diff_id);
    }
};

/// sqlite row type for build_cache queries
const BuildCacheRow = struct {
    cache_key: sqlite.Text,
    layer_digest: sqlite.Text,
    diff_id: sqlite.Text,
    layer_size: i64,
    created_at: i64,
};

fn cacheRowToEntry(row: BuildCacheRow) BuildCacheEntry {
    return BuildCacheEntry{
        .cache_key = row.cache_key.data,
        .layer_digest = row.layer_digest.data,
        .diff_id = row.diff_id.data,
        .layer_size = row.layer_size,
        .created_at = row.created_at,
    };
}

/// look up a build cache entry by cache key.
/// returns null if no cached result exists.
pub fn lookupBuildCache(alloc: std.mem.Allocator, cache_key: []const u8) StoreError!?BuildCacheEntry {
    var db = try openDb();
    defer db.deinit();

    const row = (db.oneAlloc(
        BuildCacheRow,
        alloc,
        "SELECT cache_key, layer_digest, diff_id, layer_size, created_at" ++
            " FROM build_cache WHERE cache_key = ?;",
        .{},
        .{cache_key},
    ) catch return StoreError.ReadFailed) orelse return null;

    return cacheRowToEntry(row);
}

/// store a build cache entry. replaces existing entry with the same key.
pub fn storeBuildCache(entry: BuildCacheEntry) StoreError!void {
    var db = try openDb();
    defer db.deinit();

    db.exec(
        "INSERT OR REPLACE INTO build_cache (cache_key, layer_digest, diff_id, layer_size, created_at)" ++
            " VALUES (?, ?, ?, ?, ?);",
        .{},
        .{
            entry.cache_key,
            entry.layer_digest,
            entry.diff_id,
            entry.layer_size,
            entry.created_at,
        },
    ) catch return StoreError.WriteFailed;
}

// -- service names --

/// register a service name for DNS discovery.
/// if the same name+container_id already exists, it is replaced.
pub fn registerServiceName(name: []const u8, container_id: []const u8, ip_address: []const u8) StoreError!void {
    var db = try openDb();
    defer db.deinit();

    db.exec(
        "INSERT OR REPLACE INTO service_names (name, container_id, ip_address, registered_at)" ++
            " VALUES (?, ?, ?, ?);",
        .{},
        .{ name, container_id, ip_address, @as(i64, std.time.timestamp()) },
    ) catch return StoreError.WriteFailed;
}

/// unregister all service names for a container.
/// called on container stop/rm.
pub fn unregisterServiceName(container_id: []const u8) StoreError!void {
    var db = try openDb();
    defer db.deinit();

    db.exec(
        "DELETE FROM service_names WHERE container_id = ?;",
        .{},
        .{container_id},
    ) catch return StoreError.WriteFailed;
}

/// row type for service name queries
const ServiceNameRow = struct {
    ip_address: sqlite.Text,
};

/// look up IP addresses for a service name.
/// returns all IPs registered under this name (supports multiple containers).
pub fn lookupServiceNames(alloc: std.mem.Allocator, name: []const u8) StoreError!std.ArrayList([]const u8) {
    var db = try openDb();
    defer db.deinit();

    var ips: std.ArrayList([]const u8) = .empty;

    var stmt = db.prepare(
        "SELECT ip_address FROM service_names WHERE name = ? ORDER BY registered_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(ServiceNameRow, .{name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        ips.append(alloc, row.ip_address.data) catch return StoreError.ReadFailed;
    }

    return ips;
}

// -- tests --

test "container record defaults" {
    const record = ContainerRecord{
        .id = "abc123",
        .rootfs = "/tmp/rootfs",
        .command = "/bin/sh",
        .hostname = "test",
        .status = "created",
        .pid = null,
        .exit_code = null,
        .created_at = 1234567890,
    };

    try std.testing.expectEqualStrings("abc123", record.id);
    try std.testing.expect(record.pid == null);
    try std.testing.expect(record.exit_code == null);
}

test "save and load round-trip via sqlite" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    // insert
    db.exec(
        "INSERT INTO containers (id, rootfs, command, hostname, status, pid, exit_code, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "abc123", "/tmp/rootfs", "/bin/sh", "myhost", "running", @as(i64, 42), @as(?i64, null), @as(i64, 1234567890) },
    ) catch unreachable;

    // read back
    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT id, rootfs, command, hostname, status, pid, exit_code, created_at FROM containers WHERE id = ?;",
        .{},
        .{"abc123"},
    ) catch unreachable).?;
    defer {
        alloc.free(row.id.data);
        alloc.free(row.rootfs.data);
        alloc.free(row.command.data);
        alloc.free(row.hostname.data);
        alloc.free(row.status.data);
    }

    try std.testing.expectEqualStrings("abc123", row.id.data);
    try std.testing.expectEqualStrings("/tmp/rootfs", row.rootfs.data);
    try std.testing.expectEqualStrings("/bin/sh", row.command.data);
    try std.testing.expectEqualStrings("myhost", row.hostname.data);
    try std.testing.expectEqualStrings("running", row.status.data);
    try std.testing.expectEqual(@as(?i64, 42), row.pid);
    try std.testing.expect(row.exit_code == null);
    try std.testing.expectEqual(@as(i64, 1234567890), row.created_at);
}

test "list ids returns newest first" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO containers (id, rootfs, command, created_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "older", "/r", "/sh", @as(i64, 100) },
    ) catch unreachable;
    db.exec(
        "INSERT INTO containers (id, rootfs, command, created_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "newer", "/r", "/sh", @as(i64, 200) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const first = (db.oneAlloc(
        IdRow,
        alloc,
        "SELECT id FROM containers ORDER BY created_at DESC;",
        .{},
        .{},
    ) catch unreachable).?;
    defer alloc.free(first.id.data);
    try std.testing.expectEqualStrings("newer", first.id.data);
}

test "delete removes record" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO containers (id, rootfs, command, created_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "del1", "/r", "/sh", @as(i64, 100) },
    ) catch unreachable;

    db.exec("DELETE FROM containers WHERE id = ?;", .{}, .{"del1"}) catch unreachable;

    const CountRow = struct { count: i64 };
    const result = (db.one(CountRow, "SELECT COUNT(*) AS count FROM containers;", .{}, .{}) catch unreachable).?;
    try std.testing.expectEqual(@as(i64, 0), result.count);
}

test "image record round-trip via sqlite" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    // insert
    db.exec(
        "INSERT INTO images (id, repository, tag, manifest_digest, config_digest, total_size, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "sha256:abc", "library/nginx", "latest", "sha256:abc", "sha256:def", @as(i64, 2048), @as(i64, 1700000000) },
    ) catch unreachable;

    // read back
    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        ImageRow,
        alloc,
        "SELECT id, repository, tag, manifest_digest, config_digest, total_size, created_at FROM images WHERE id = ?;",
        .{},
        .{"sha256:abc"},
    ) catch unreachable).?;
    defer {
        alloc.free(row.id.data);
        alloc.free(row.repository.data);
        alloc.free(row.tag.data);
        alloc.free(row.manifest_digest.data);
        alloc.free(row.config_digest.data);
    }

    try std.testing.expectEqualStrings("sha256:abc", row.id.data);
    try std.testing.expectEqualStrings("library/nginx", row.repository.data);
    try std.testing.expectEqualStrings("latest", row.tag.data);
    try std.testing.expectEqual(@as(i64, 2048), row.total_size);
}

test "build cache store and lookup" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    // insert a cache entry
    db.exec(
        "INSERT INTO build_cache (cache_key, layer_digest, diff_id, layer_size, created_at)" ++
            " VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "sha256:key1", "sha256:layer1", "sha256:diff1", @as(i64, 4096), @as(i64, 1700000000) },
    ) catch unreachable;

    // read it back
    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        BuildCacheRow,
        alloc,
        "SELECT cache_key, layer_digest, diff_id, layer_size, created_at" ++
            " FROM build_cache WHERE cache_key = ?;",
        .{},
        .{"sha256:key1"},
    ) catch unreachable).?;
    defer {
        alloc.free(row.cache_key.data);
        alloc.free(row.layer_digest.data);
        alloc.free(row.diff_id.data);
    }

    try std.testing.expectEqualStrings("sha256:key1", row.cache_key.data);
    try std.testing.expectEqualStrings("sha256:layer1", row.layer_digest.data);
    try std.testing.expectEqualStrings("sha256:diff1", row.diff_id.data);
    try std.testing.expectEqual(@as(i64, 4096), row.layer_size);
}

test "build cache miss returns null row" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const alloc = std.testing.allocator;
    const row = db.oneAlloc(
        BuildCacheRow,
        alloc,
        "SELECT cache_key, layer_digest, diff_id, layer_size, created_at" ++
            " FROM build_cache WHERE cache_key = ?;",
        .{},
        .{"sha256:nonexistent"},
    ) catch unreachable;

    try std.testing.expect(row == null);
}

test "build cache replace on conflict" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    // insert initial entry
    db.exec(
        "INSERT INTO build_cache (cache_key, layer_digest, diff_id, layer_size, created_at)" ++
            " VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "sha256:key1", "sha256:old_layer", "sha256:old_diff", @as(i64, 1024), @as(i64, 100) },
    ) catch unreachable;

    // replace with new entry
    db.exec(
        "INSERT OR REPLACE INTO build_cache (cache_key, layer_digest, diff_id, layer_size, created_at)" ++
            " VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "sha256:key1", "sha256:new_layer", "sha256:new_diff", @as(i64, 2048), @as(i64, 200) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        BuildCacheRow,
        alloc,
        "SELECT cache_key, layer_digest, diff_id, layer_size, created_at" ++
            " FROM build_cache WHERE cache_key = ?;",
        .{},
        .{"sha256:key1"},
    ) catch unreachable).?;
    defer {
        alloc.free(row.cache_key.data);
        alloc.free(row.layer_digest.data);
        alloc.free(row.diff_id.data);
    }

    try std.testing.expectEqualStrings("sha256:new_layer", row.layer_digest.data);
    try std.testing.expectEqual(@as(i64, 2048), row.layer_size);
}

test "update status" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO containers (id, rootfs, command, status, created_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "upd1", "/r", "/sh", "created", @as(i64, 100) },
    ) catch unreachable;

    db.exec(
        "UPDATE containers SET status = ?, pid = ? WHERE id = ?;",
        .{},
        .{ "running", @as(i64, 1234), "upd1" },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const Row = struct { status: sqlite.Text, pid: ?i64 };
    const row = (db.oneAlloc(Row, alloc, "SELECT status, pid FROM containers WHERE id = ?;", .{}, .{"upd1"}) catch unreachable).?;
    defer alloc.free(row.status.data);
    try std.testing.expectEqualStrings("running", row.status.data);
    try std.testing.expectEqual(@as(?i64, 1234), row.pid);
}

test "service name register and lookup" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO service_names (name, container_id, ip_address, registered_at)" ++
            " VALUES (?, ?, ?, ?);",
        .{},
        .{ "web", "abc123", "10.42.0.2", @as(i64, 100) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        ServiceNameRow,
        alloc,
        "SELECT ip_address FROM service_names WHERE name = ?;",
        .{},
        .{"web"},
    ) catch unreachable).?;
    defer alloc.free(row.ip_address.data);

    try std.testing.expectEqualStrings("10.42.0.2", row.ip_address.data);
}

test "service name unregister removes entries" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO service_names (name, container_id, ip_address, registered_at)" ++
            " VALUES (?, ?, ?, ?);",
        .{},
        .{ "db", "xyz789", "10.42.0.3", @as(i64, 100) },
    ) catch unreachable;

    db.exec("DELETE FROM service_names WHERE container_id = ?;", .{}, .{"xyz789"}) catch unreachable;

    const CountRow = struct { count: i64 };
    const result = (db.one(CountRow, "SELECT COUNT(*) AS count FROM service_names;", .{}, .{}) catch unreachable).?;
    try std.testing.expectEqual(@as(i64, 0), result.count);
}

test "service name lookup returns empty for unknown" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const alloc = std.testing.allocator;
    const row = db.oneAlloc(
        ServiceNameRow,
        alloc,
        "SELECT ip_address FROM service_names WHERE name = ?;",
        .{},
        .{"nonexistent"},
    ) catch unreachable;

    try std.testing.expect(row == null);
}
