// schema — database schema and initialization
//
// creates the tables yoq needs on first run. all schema changes
// go through this file so there's one place to look for the
// database structure.

const std = @import("std");
const sqlite = @import("sqlite");
const paths = @import("../lib/paths.zig");

pub const SchemaError = error{
    InitFailed,
    PathTooLong,
    HomeDirNotFound,
};

/// initialize the database schema. safe to call multiple times
/// (uses CREATE TABLE IF NOT EXISTS).
pub fn init(db: *sqlite.Db) SchemaError!void {
    db.exec(
        \\CREATE TABLE IF NOT EXISTS containers (
        \\    id TEXT PRIMARY KEY,
        \\    rootfs TEXT NOT NULL,
        \\    command TEXT NOT NULL,
        \\    hostname TEXT NOT NULL DEFAULT 'container',
        \\    status TEXT NOT NULL DEFAULT 'created',
        \\    pid INTEGER,
        \\    exit_code INTEGER,
        \\    ip_address TEXT,
        \\    veth_host TEXT,
        \\    app_name TEXT,
        \\    created_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return SchemaError.InitFailed;

    // migration for existing databases — add app_name column if missing
    db.exec("ALTER TABLE containers ADD COLUMN app_name TEXT;", .{}, .{}) catch {};

    db.exec(
        \\CREATE TABLE IF NOT EXISTS images (
        \\    id TEXT PRIMARY KEY,
        \\    repository TEXT NOT NULL,
        \\    tag TEXT NOT NULL DEFAULT 'latest',
        \\    manifest_digest TEXT NOT NULL,
        \\    config_digest TEXT NOT NULL,
        \\    total_size INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return SchemaError.InitFailed;

    db.exec(
        \\CREATE TABLE IF NOT EXISTS ip_allocations (
        \\    container_id TEXT PRIMARY KEY,
        \\    ip_address TEXT NOT NULL UNIQUE,
        \\    allocated_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return SchemaError.InitFailed;

    db.exec(
        \\CREATE TABLE IF NOT EXISTS build_cache (
        \\    cache_key TEXT PRIMARY KEY,
        \\    layer_digest TEXT NOT NULL,
        \\    diff_id TEXT NOT NULL,
        \\    layer_size INTEGER NOT NULL,
        \\    created_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return SchemaError.InitFailed;

    db.exec(
        \\CREATE TABLE IF NOT EXISTS service_names (
        \\    name TEXT NOT NULL,
        \\    container_id TEXT NOT NULL,
        \\    ip_address TEXT NOT NULL,
        \\    registered_at INTEGER NOT NULL,
        \\    PRIMARY KEY (name, container_id)
        \\);
    , .{}, .{}) catch return SchemaError.InitFailed;

    db.exec(
        \\CREATE TABLE IF NOT EXISTS agents (
        \\    id TEXT PRIMARY KEY,
        \\    address TEXT NOT NULL,
        \\    status TEXT NOT NULL DEFAULT 'active',
        \\    cpu_cores INTEGER NOT NULL DEFAULT 0,
        \\    memory_mb INTEGER NOT NULL DEFAULT 0,
        \\    cpu_used INTEGER NOT NULL DEFAULT 0,
        \\    memory_used_mb INTEGER NOT NULL DEFAULT 0,
        \\    containers INTEGER NOT NULL DEFAULT 0,
        \\    last_heartbeat INTEGER NOT NULL,
        \\    registered_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return SchemaError.InitFailed;

    db.exec(
        \\CREATE TABLE IF NOT EXISTS assignments (
        \\    id TEXT PRIMARY KEY,
        \\    agent_id TEXT NOT NULL,
        \\    image TEXT NOT NULL,
        \\    command TEXT NOT NULL DEFAULT '',
        \\    status TEXT NOT NULL DEFAULT 'pending',
        \\    cpu_limit INTEGER NOT NULL DEFAULT 1000,
        \\    memory_limit_mb INTEGER NOT NULL DEFAULT 256,
        \\    created_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return SchemaError.InitFailed;

    db.exec(
        \\CREATE TABLE IF NOT EXISTS deployments (
        \\    id TEXT PRIMARY KEY,
        \\    service_name TEXT NOT NULL,
        \\    manifest_hash TEXT NOT NULL,
        \\    config_snapshot TEXT NOT NULL DEFAULT '',
        \\    status TEXT NOT NULL DEFAULT 'pending',
        \\    message TEXT,
        \\    created_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return SchemaError.InitFailed;

    db.exec(
        \\CREATE INDEX IF NOT EXISTS idx_deployments_service
        \\    ON deployments (service_name, created_at DESC);
    , .{}, .{}) catch return SchemaError.InitFailed;

    db.exec(
        \\CREATE TABLE IF NOT EXISTS secrets (
        \\    name TEXT PRIMARY KEY,
        \\    encrypted_value BLOB NOT NULL,
        \\    nonce BLOB NOT NULL,
        \\    tag BLOB NOT NULL,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return SchemaError.InitFailed;

    // migration: add per-node subnet and wireguard columns to agents.
    // these support cluster networking — each agent gets a unique node_id
    // (for its /24 subnet), a wireguard public key, and an overlay IP.
    // ALTER TABLE ... ADD COLUMN is safe to call on existing databases;
    // it errors if the column already exists, which we silently ignore.
    db.exec("ALTER TABLE agents ADD COLUMN node_id INTEGER;", .{}, .{}) catch {};
    db.exec("ALTER TABLE agents ADD COLUMN wg_public_key TEXT;", .{}, .{}) catch {};
    db.exec("ALTER TABLE agents ADD COLUMN overlay_ip TEXT;", .{}, .{}) catch {};

    db.exec(
        \\CREATE TABLE IF NOT EXISTS wireguard_peers (
        \\    node_id INTEGER NOT NULL,
        \\    agent_id TEXT NOT NULL,
        \\    public_key TEXT NOT NULL,
        \\    endpoint TEXT NOT NULL,
        \\    overlay_ip TEXT NOT NULL,
        \\    container_subnet TEXT NOT NULL,
        \\    PRIMARY KEY (node_id)
        \\);
    , .{}, .{}) catch return SchemaError.InitFailed;
}

/// build the default database path: ~/.local/share/yoq/yoq.db
/// creates parent directories if needed.
pub fn defaultDbPath(buf: *[512]u8) SchemaError![:0]const u8 {
    // ensure the data directory exists
    paths.ensureDataDir("") catch return SchemaError.HomeDirNotFound;

    const path = paths.dataPath(buf, "yoq.db") catch |err| return switch (err) {
        error.HomeDirNotFound => SchemaError.HomeDirNotFound,
        error.PathTooLong => SchemaError.PathTooLong,
    };
    // null-terminate for sqlite
    if (path.len >= buf.len) return SchemaError.PathTooLong;
    buf[path.len] = 0;
    return buf[0..path.len :0];
}

// -- tests --

test "init creates containers table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    // verify table exists by inserting a row
    db.exec(
        "INSERT INTO containers (id, rootfs, command, created_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "test123", "/tmp/rootfs", "/bin/sh", @as(i64, 1234567890) },
    ) catch unreachable;
}

test "init creates images table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO images (id, repository, tag, manifest_digest, config_digest, total_size, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "sha256:abc", "library/nginx", "latest", "sha256:abc", "sha256:def", @as(i64, 1024), @as(i64, 1234567890) },
    ) catch unreachable;
}

test "init creates ip_allocations table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO ip_allocations (container_id, ip_address, allocated_at) VALUES (?, ?, ?);",
        .{},
        .{ "abc123", "10.42.0.2", @as(i64, 1234567890) },
    ) catch unreachable;
}

test "init creates build_cache table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO build_cache (cache_key, layer_digest, diff_id, layer_size, created_at)" ++
            " VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "sha256:cachekey", "sha256:layer", "sha256:diff", @as(i64, 4096), @as(i64, 1234567890) },
    ) catch unreachable;
}

test "init creates service_names table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO service_names (name, container_id, ip_address, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "web", "abc123", "10.42.0.2", @as(i64, 1234567890) },
    ) catch unreachable;
}

test "init creates agents table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO agents (id, address, last_heartbeat, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "agent001", "10.0.0.1:7701", @as(i64, 1000), @as(i64, 1000) },
    ) catch unreachable;
}

test "init creates assignments table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO assignments (id, agent_id, image, created_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "assign001", "agent001", "nginx:latest", @as(i64, 1000) },
    ) catch unreachable;
}

test "init creates deployments table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO deployments (id, service_name, manifest_hash, config_snapshot, status, created_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep001", "web", "sha256:abc", "{}", "completed", @as(i64, 1000) },
    ) catch unreachable;
}

test "init creates secrets table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO secrets (name, encrypted_value, nonce, tag, created_at, updated_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "db_password", "encrypted_bytes", "nonce_bytes", "tag_bytes", @as(i64, 1000), @as(i64, 1000) },
    ) catch unreachable;
}

test "agents table has wireguard and subnet columns" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    // insert an agent with the new columns populated
    db.exec(
        "INSERT INTO agents (id, address, node_id, wg_public_key, overlay_ip, last_heartbeat, registered_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "agent-wg", "10.0.0.5:7701", @as(i64, 3), "base64pubkey==", "10.40.0.3", @as(i64, 1000), @as(i64, 1000) },
    ) catch unreachable;

    // read them back to verify the columns work
    const alloc = std.testing.allocator;
    const Row = struct { node_id: ?i64, wg_public_key: ?sqlite.Text, overlay_ip: ?sqlite.Text };
    const row = (db.oneAlloc(
        Row,
        alloc,
        "SELECT node_id, wg_public_key, overlay_ip FROM agents WHERE id = ?;",
        .{},
        .{"agent-wg"},
    ) catch unreachable).?;
    defer {
        if (row.wg_public_key) |k| alloc.free(k.data);
        if (row.overlay_ip) |o| alloc.free(o.data);
    }

    try std.testing.expectEqual(@as(?i64, 3), row.node_id);
    try std.testing.expectEqualStrings("base64pubkey==", row.wg_public_key.?.data);
    try std.testing.expectEqualStrings("10.40.0.3", row.overlay_ip.?.data);
}

test "agents table new columns default to null" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    // insert without the new columns — they should be null
    db.exec(
        "INSERT INTO agents (id, address, last_heartbeat, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "agent-plain", "10.0.0.1:7701", @as(i64, 1000), @as(i64, 1000) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const Row = struct { node_id: ?i64, wg_public_key: ?sqlite.Text, overlay_ip: ?sqlite.Text };
    const row = (db.oneAlloc(
        Row,
        alloc,
        "SELECT node_id, wg_public_key, overlay_ip FROM agents WHERE id = ?;",
        .{},
        .{"agent-plain"},
    ) catch unreachable).?;
    defer {
        if (row.wg_public_key) |k| alloc.free(k.data);
        if (row.overlay_ip) |o| alloc.free(o.data);
    }

    try std.testing.expect(row.node_id == null);
    try std.testing.expect(row.wg_public_key == null);
    try std.testing.expect(row.overlay_ip == null);
}

test "init is idempotent" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);
    try init(&db);
}

test "default columns" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO containers (id, rootfs, command, created_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "abc", "/rootfs", "/bin/sh", @as(i64, 100) },
    ) catch unreachable;

    const Row = struct {
        hostname: sqlite.Text,
        status: sqlite.Text,
        pid: ?i64,
        exit_code: ?i64,
    };

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(Row, alloc, "SELECT hostname, status, pid, exit_code FROM containers WHERE id = ?;", .{}, .{"abc"}) catch unreachable).?;
    defer {
        alloc.free(row.hostname.data);
        alloc.free(row.status.data);
    }

    try std.testing.expectEqualStrings("container", row.hostname.data);
    try std.testing.expectEqualStrings("created", row.status.data);
    try std.testing.expect(row.pid == null);
    try std.testing.expect(row.exit_code == null);
}

test "init creates wireguard_peers table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO wireguard_peers (node_id, agent_id, public_key, endpoint, overlay_ip, container_subnet)" ++
            " VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ @as(i64, 1), "agent-001", "dGVzdHB1YmtleQ==", "10.0.0.2:51820", "10.40.0.2", "10.42.1.0/24" },
    ) catch unreachable;
}
