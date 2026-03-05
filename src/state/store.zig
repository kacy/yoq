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
    app_name: ?[]const u8 = null,
    created_at: i64,

    /// free all heap-allocated string fields
    pub fn deinit(self: ContainerRecord, alloc: std.mem.Allocator) void {
        alloc.free(self.id);
        alloc.free(self.rootfs);
        alloc.free(self.command);
        alloc.free(self.hostname);
        alloc.free(self.status);
        if (self.ip_address) |ip_val| alloc.free(ip_val);
        if (self.veth_host) |veth| alloc.free(veth);
        if (self.app_name) |app| alloc.free(app);
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
    app_name: ?sqlite.Text,
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
        .ip_address = if (row.ip_address) |ip_val| ip_val.data else null,
        .veth_host = if (row.veth_host) |veth| veth.data else null,
        .app_name = if (row.app_name) |app| app.data else null,
        .created_at = row.created_at,
    };
}

// -- persistent connection --
// keeps a single SQLite connection open for the lifetime of the process.
// avoids reopening and reinitializing schema on every operation, which
// causes lock contention under concurrent API requests.

var global_db: ?sqlite.Db = null;
var db_mutex: std.Thread.Mutex = .{};

/// get the shared database connection, opening it on first call.
/// caller must call releaseDb() when done (via defer).
fn getDb() StoreError!*sqlite.Db {
    db_mutex.lock();

    if (global_db == null) {
        var path_buf: [512]u8 = undefined;
        const path = schema.defaultDbPath(&path_buf) catch {
            db_mutex.unlock();
            return StoreError.DbOpenFailed;
        };
        global_db = sqlite.Db.init(.{
            .mode = .{ .File = path },
            .open_flags = .{ .write = true, .create = true },
        }) catch {
            db_mutex.unlock();
            return StoreError.DbOpenFailed;
        };

        schema.init(&global_db.?) catch {
            global_db.?.deinit();
            global_db = null;
            db_mutex.unlock();
            return StoreError.DbOpenFailed;
        };
    }

    return &global_db.?;
}

/// release the database mutex. call this via defer after getDb().
fn releaseDb() void {
    db_mutex.unlock();
}

/// close the shared database connection. call on clean shutdown.
pub fn closeDb() void {
    db_mutex.lock();
    defer db_mutex.unlock();
    if (global_db) |*db| {
        db.deinit();
        global_db = null;
    }
}

/// open a fresh database connection (not the shared one).
/// used by callers that need their own connection, e.g. network
/// cleanup in main.zig which may run concurrently with the API.
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
    const db = try getDb();
    defer releaseDb();

    const pid: ?i64 = if (record.pid) |p| @intCast(p) else null;
    const exit_code: ?i64 = if (record.exit_code) |e| @intCast(e) else null;

    db.exec(
        "INSERT OR REPLACE INTO containers (id, rootfs, command, hostname, status, pid, exit_code, ip_address, veth_host, app_name, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
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
            record.app_name,
            record.created_at,
        },
    ) catch return StoreError.WriteFailed;
}

/// load a single container record by id.
/// caller owns the returned strings (allocated with alloc).
pub fn load(alloc: std.mem.Allocator, id: []const u8) StoreError!ContainerRecord {
    const db = try getDb();
    defer releaseDb();

    const row = (db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT id, rootfs, command, hostname, status, pid, exit_code, ip_address, veth_host, app_name, created_at" ++
            " FROM containers WHERE id = ?;",
        .{},
        .{id},
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;

    return rowToRecord(row);
}

/// delete a container record
pub fn remove(id: []const u8) StoreError!void {
    const db = try getDb();
    defer releaseDb();

    db.exec("DELETE FROM containers WHERE id = ?;", .{}, .{id}) catch
        return StoreError.WriteFailed;
}

/// list all container IDs, newest first
pub fn listIds(alloc: std.mem.Allocator) StoreError!std.ArrayList([]const u8) {
    const db = try getDb();
    defer releaseDb();

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
    const db = try getDb();
    defer releaseDb();

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
    const db = try getDb();
    defer releaseDb();

    db.exec(
        "UPDATE containers SET ip_address = ?, veth_host = ? WHERE id = ?;",
        .{},
        .{ ip_address, veth_host, id },
    ) catch return StoreError.WriteFailed;
}

// -- app queries --

/// list container IDs belonging to an app, newest first.
/// caller owns the returned list and strings.
pub fn listAppContainerIds(alloc: std.mem.Allocator, app_name: []const u8) StoreError!std.ArrayList([]const u8) {
    const db = try getDb();
    defer releaseDb();

    var ids: std.ArrayList([]const u8) = .empty;

    var stmt = db.prepare("SELECT id FROM containers WHERE app_name = ? ORDER BY created_at DESC;") catch
        return StoreError.ReadFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(IdRow, .{app_name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        ids.append(alloc, row.id.data) catch return StoreError.ReadFailed;
    }

    return ids;
}

/// find a container by app_name + hostname (service name).
/// returns null if not found. caller owns the returned record.
pub fn findAppContainer(alloc: std.mem.Allocator, app_name: []const u8, hostname: []const u8) StoreError!?ContainerRecord {
    const db = try getDb();
    defer releaseDb();

    const row = (db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT id, rootfs, command, hostname, status, pid, exit_code, ip_address, veth_host, app_name, created_at" ++
            " FROM containers WHERE app_name = ? AND hostname = ? ORDER BY created_at DESC LIMIT 1;",
        .{},
        .{ app_name, hostname },
    ) catch return StoreError.ReadFailed) orelse return null;

    return rowToRecord(row);
}

/// list all container records (for status reporting).
/// caller owns the returned list and records.
pub fn listAll(alloc: std.mem.Allocator) StoreError!std.ArrayList(ContainerRecord) {
    const db = try getDb();
    defer releaseDb();

    var records: std.ArrayList(ContainerRecord) = .empty;

    var stmt = db.prepare(
        "SELECT id, rootfs, command, hostname, status, pid, exit_code, ip_address, veth_host, app_name, created_at" ++
            " FROM containers ORDER BY hostname, created_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(ContainerRow, .{}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        records.append(alloc, rowToRecord(row)) catch return StoreError.ReadFailed;
    }

    return records;
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
    const db = try getDb();
    defer releaseDb();

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
    const db = try getDb();
    defer releaseDb();

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
    const db = try getDb();
    defer releaseDb();

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
    const db = try getDb();
    defer releaseDb();

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
    const db = try getDb();
    defer releaseDb();

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
    const db = try getDb();
    defer releaseDb();

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
    const db = try getDb();
    defer releaseDb();

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
    const db = try getDb();
    defer releaseDb();

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
    const db = try getDb();
    defer releaseDb();

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
    const db = try getDb();
    defer releaseDb();

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

// -- deployments --

/// persisted deployment record. tracks each rollout of a service
/// so we can show history and rollback to a previous config.
pub const DeploymentRecord = struct {
    id: []const u8,
    service_name: []const u8,
    manifest_hash: []const u8,
    config_snapshot: []const u8,
    status: []const u8,
    message: ?[]const u8,
    created_at: i64,

    pub fn deinit(self: DeploymentRecord, alloc: std.mem.Allocator) void {
        alloc.free(self.id);
        alloc.free(self.service_name);
        alloc.free(self.manifest_hash);
        alloc.free(self.config_snapshot);
        alloc.free(self.status);
        if (self.message) |msg| alloc.free(msg);
    }
};

/// sqlite row type for deployment queries
const DeploymentRow = struct {
    id: sqlite.Text,
    service_name: sqlite.Text,
    manifest_hash: sqlite.Text,
    config_snapshot: sqlite.Text,
    status: sqlite.Text,
    message: ?sqlite.Text,
    created_at: i64,
};

fn deploymentRowToRecord(row: DeploymentRow) DeploymentRecord {
    return .{
        .id = row.id.data,
        .service_name = row.service_name.data,
        .manifest_hash = row.manifest_hash.data,
        .config_snapshot = row.config_snapshot.data,
        .status = row.status.data,
        .message = if (row.message) |msg| msg.data else null,
        .created_at = row.created_at,
    };
}

/// save a new deployment record.
pub fn saveDeployment(record: DeploymentRecord) StoreError!void {
    const db = try getDb();
    defer releaseDb();

    db.exec(
        "INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, message, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?);",
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

/// load a deployment record by id.
/// caller owns the returned strings.
pub fn getDeployment(alloc: std.mem.Allocator, id: []const u8) StoreError!DeploymentRecord {
    const db = try getDb();
    defer releaseDb();

    const row = (db.oneAlloc(
        DeploymentRow,
        alloc,
        "SELECT id, service_name, manifest_hash, config_snapshot, status, message, created_at" ++
            " FROM deployments WHERE id = ?;",
        .{},
        .{id},
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;

    return deploymentRowToRecord(row);
}

/// list deployments for a service, newest first.
/// caller owns the returned list and records.
pub fn listDeployments(alloc: std.mem.Allocator, service_name: []const u8) StoreError!std.ArrayList(DeploymentRecord) {
    const db = try getDb();
    defer releaseDb();

    var deployments: std.ArrayList(DeploymentRecord) = .empty;

    var stmt = db.prepare(
        "SELECT id, service_name, manifest_hash, config_snapshot, status, message, created_at" ++
            " FROM deployments WHERE service_name = ? ORDER BY created_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(DeploymentRow, .{service_name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        deployments.append(alloc, deploymentRowToRecord(row)) catch return StoreError.ReadFailed;
    }

    return deployments;
}

/// update a deployment's status and optional message.
pub fn updateDeploymentStatus(id: []const u8, status: []const u8, message: ?[]const u8) StoreError!void {
    const db = try getDb();
    defer releaseDb();

    db.exec(
        "UPDATE deployments SET status = ?, message = ? WHERE id = ?;",
        .{},
        .{ status, message, id },
    ) catch return StoreError.WriteFailed;
}

/// get the most recent deployment for a service.
/// caller owns the returned record.
pub fn getLatestDeployment(alloc: std.mem.Allocator, service_name: []const u8) StoreError!DeploymentRecord {
    const db = try getDb();
    defer releaseDb();

    const row = (db.oneAlloc(
        DeploymentRow,
        alloc,
        "SELECT id, service_name, manifest_hash, config_snapshot, status, message, created_at" ++
            " FROM deployments WHERE service_name = ? ORDER BY created_at DESC LIMIT 1;",
        .{},
        .{service_name},
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;

    return deploymentRowToRecord(row);
}

/// get the most recent successful deployment for a service.
/// useful for rollback — finds the last known-good config.
/// caller owns the returned record.
pub fn getLastSuccessfulDeployment(alloc: std.mem.Allocator, service_name: []const u8) StoreError!DeploymentRecord {
    const db = try getDb();
    defer releaseDb();

    const row = (db.oneAlloc(
        DeploymentRow,
        alloc,
        "SELECT id, service_name, manifest_hash, config_snapshot, status, message, created_at" ++
            " FROM deployments WHERE service_name = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1;",
        .{},
        .{service_name},
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;

    return deploymentRowToRecord(row);
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
        "SELECT id, rootfs, command, hostname, status, pid, exit_code, ip_address, veth_host, app_name, created_at" ++
            " FROM containers WHERE id = ?;",
        .{},
        .{"abc123"},
    ) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("abc123", record.id);
    try std.testing.expectEqualStrings("/tmp/rootfs", record.rootfs);
    try std.testing.expectEqualStrings("/bin/sh", record.command);
    try std.testing.expectEqualStrings("myhost", record.hostname);
    try std.testing.expectEqualStrings("running", record.status);
    try std.testing.expectEqual(@as(?i32, 42), record.pid);
    try std.testing.expect(record.exit_code == null);
    try std.testing.expect(record.app_name == null);
    try std.testing.expectEqual(@as(i64, 1234567890), record.created_at);
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

test "app_name stored and retrieved" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO containers (id, rootfs, command, hostname, status, app_name, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "app1", "/r", "/sh", "web", "running", "myapp", @as(i64, 100) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT id, rootfs, command, hostname, status, pid, exit_code, ip_address, veth_host, app_name, created_at" ++
            " FROM containers WHERE id = ?;",
        .{},
        .{"app1"},
    ) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("myapp", record.app_name.?);
    try std.testing.expectEqualStrings("web", record.hostname);
}

test "app_name null by default" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO containers (id, rootfs, command, created_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "noapp", "/r", "/sh", @as(i64, 100) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT id, rootfs, command, hostname, status, pid, exit_code, ip_address, veth_host, app_name, created_at" ++
            " FROM containers WHERE id = ?;",
        .{},
        .{"noapp"},
    ) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expect(record.app_name == null);
}

test "list app container ids" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    // insert containers for two different apps
    db.exec(
        "INSERT INTO containers (id, rootfs, command, hostname, app_name, created_at) VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "/r", "/sh", "web", "myapp", @as(i64, 100) },
    ) catch unreachable;
    db.exec(
        "INSERT INTO containers (id, rootfs, command, hostname, app_name, created_at) VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "a2", "/r", "/sh", "db", "myapp", @as(i64, 200) },
    ) catch unreachable;
    db.exec(
        "INSERT INTO containers (id, rootfs, command, hostname, app_name, created_at) VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "b1", "/r", "/sh", "api", "other", @as(i64, 150) },
    ) catch unreachable;

    const alloc = std.testing.allocator;

    // query for myapp — should get a2 first (newest), then a1
    var stmt = db.prepare("SELECT id FROM containers WHERE app_name = ? ORDER BY created_at DESC;") catch unreachable;
    defer stmt.deinit();

    var ids: std.ArrayList([]const u8) = .empty;
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    var iter = stmt.iterator(IdRow, .{"myapp"}) catch unreachable;
    while (iter.nextAlloc(alloc, .{}) catch unreachable) |row| {
        ids.append(alloc, row.id.data) catch unreachable;
    }

    try std.testing.expectEqual(@as(usize, 2), ids.items.len);
    try std.testing.expectEqualStrings("a2", ids.items[0]);
    try std.testing.expectEqualStrings("a1", ids.items[1]);
}

test "find app container by hostname" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO containers (id, rootfs, command, hostname, status, app_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "f1", "/r", "/sh", "web", "running", "myapp", @as(i64, 100) },
    ) catch unreachable;
    db.exec(
        "INSERT INTO containers (id, rootfs, command, hostname, status, app_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "f2", "/r", "/sh", "db", "running", "myapp", @as(i64, 200) },
    ) catch unreachable;

    const alloc = std.testing.allocator;

    // find the db container
    const row = (db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT id, rootfs, command, hostname, status, pid, exit_code, ip_address, veth_host, app_name, created_at" ++
            " FROM containers WHERE app_name = ? AND hostname = ? ORDER BY created_at DESC LIMIT 1;",
        .{},
        .{ "myapp", "db" },
    ) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("f2", record.id);
    try std.testing.expectEqualStrings("db", record.hostname);
    try std.testing.expectEqualStrings("myapp", record.app_name.?);

    // look for nonexistent service
    const missing = db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT id, rootfs, command, hostname, status, pid, exit_code, ip_address, veth_host, app_name, created_at" ++
            " FROM containers WHERE app_name = ? AND hostname = ? ORDER BY created_at DESC LIMIT 1;",
        .{},
        .{ "myapp", "cache" },
    ) catch unreachable;
    try std.testing.expect(missing == null);
}

test "deployment record round-trip via sqlite" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, message, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep001", "web", "sha256:abc", "{\"image\":\"nginx:latest\"}", "completed", "initial deploy", @as(i64, 1000) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        DeploymentRow,
        alloc,
        "SELECT id, service_name, manifest_hash, config_snapshot, status, message, created_at" ++
            " FROM deployments WHERE id = ?;",
        .{},
        .{"dep001"},
    ) catch unreachable).?;
    const record = deploymentRowToRecord(row);
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
        "INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep002", "api", "sha256:def", "{}", "pending", @as(i64, 2000) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        DeploymentRow,
        alloc,
        "SELECT id, service_name, manifest_hash, config_snapshot, status, message, created_at" ++
            " FROM deployments WHERE id = ?;",
        .{},
        .{"dep002"},
    ) catch unreachable).?;
    const record = deploymentRowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expect(record.message == null);
}

test "deployment list ordered by timestamp desc" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    // insert two deployments for the same service
    db.exec(
        "INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep-old", "web", "sha256:old", "{}", "completed", @as(i64, 100) },
    ) catch unreachable;
    db.exec(
        "INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep-new", "web", "sha256:new", "{}", "completed", @as(i64, 200) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    var stmt = db.prepare(
        "SELECT id, service_name, manifest_hash, config_snapshot, status, message, created_at" ++
            " FROM deployments WHERE service_name = ? ORDER BY created_at DESC;",
    ) catch unreachable;
    defer stmt.deinit();

    var results: std.ArrayList(DeploymentRecord) = .empty;
    defer {
        for (results.items) |rec| rec.deinit(alloc);
        results.deinit(alloc);
    }

    var iter = stmt.iterator(DeploymentRow, .{"web"}) catch unreachable;
    while (iter.nextAlloc(alloc, .{}) catch unreachable) |row| {
        results.append(alloc, deploymentRowToRecord(row)) catch unreachable;
    }

    try std.testing.expectEqual(@as(usize, 2), results.items.len);
    try std.testing.expectEqualStrings("dep-new", results.items[0].id);
    try std.testing.expectEqualStrings("dep-old", results.items[1].id);
}

test "deployment status update" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep-upd", "web", "sha256:abc", "{}", "pending", @as(i64, 100) },
    ) catch unreachable;

    db.exec(
        "UPDATE deployments SET status = ?, message = ? WHERE id = ?;",
        .{},
        .{ "completed", "all containers healthy", "dep-upd" },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        DeploymentRow,
        alloc,
        "SELECT id, service_name, manifest_hash, config_snapshot, status, message, created_at" ++
            " FROM deployments WHERE id = ?;",
        .{},
        .{"dep-upd"},
    ) catch unreachable).?;
    const record = deploymentRowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("completed", record.status);
    try std.testing.expectEqualStrings("all containers healthy", record.message.?);
}

test "deployment latest returns most recent" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep-1", "web", "sha256:first", "{}", "completed", @as(i64, 100) },
    ) catch unreachable;
    db.exec(
        "INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep-2", "web", "sha256:second", "{}", "in_progress", @as(i64, 200) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        DeploymentRow,
        alloc,
        "SELECT id, service_name, manifest_hash, config_snapshot, status, message, created_at" ++
            " FROM deployments WHERE service_name = ? ORDER BY created_at DESC LIMIT 1;",
        .{},
        .{"web"},
    ) catch unreachable).?;
    const record = deploymentRowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("dep-2", record.id);
}

test "deployment not found returns null" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const alloc = std.testing.allocator;
    const row = db.oneAlloc(
        DeploymentRow,
        alloc,
        "SELECT id, service_name, manifest_hash, config_snapshot, status, message, created_at" ++
            " FROM deployments WHERE id = ?;",
        .{},
        .{"nonexistent"},
    ) catch unreachable;

    try std.testing.expect(row == null);
}
