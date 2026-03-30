// schema — database schema and initialization
//
// creates the tables yoq needs on first run. all schema changes
// go through this file so there's one place to look for the
// database structure.

const std = @import("std");
const sqlite = @import("sqlite");
const paths = @import("../lib/paths.zig");
const tables = @import("schema/tables.zig");
const migrations = @import("schema/migrations.zig");
const indexes = @import("schema/indexes.zig");

pub const SchemaError = error{
    InitFailed,
    PathTooLong,
    HomeDirNotFound,
};

pub const secrets_create_table_sql = tables.secrets_create_table_sql;

/// initialize the database schema. safe to call multiple times
/// (uses CREATE TABLE IF NOT EXISTS).
pub fn init(db: *sqlite.Db) SchemaError!void {
    try tables.initCoreTables(db);
    try tables.initClusterTables(db);
    try tables.initSecurityTables(db);
    try tables.initStorageTables(db);
    try tables.initTrainingTables(db);
    try migrations.apply(db);
    try indexes.init(db);
    indexes.applyPragmas(db);
}

/// build the default database path: ~/.local/share/yoq/yoq.db
/// creates parent directories if needed.
pub fn defaultDbPath(buf: *[paths.max_path]u8) SchemaError![:0]const u8 {
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

test "init creates services table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO services (" ++
            "service_name, vip_address, lb_policy, http_proxy_host, http_proxy_path_prefix, http_proxy_rewrite_prefix, http_proxy_retries, http_proxy_connect_timeout_ms, http_proxy_request_timeout_ms, http_proxy_target_port, http_proxy_preserve_host, created_at, updated_at" ++
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "api", "10.43.0.10", "consistent_hash", "api.internal", "/v1", "/internal", @as(i64, 2), @as(i64, 1000), @as(i64, 5000), @as(i64, 8080), @as(i64, 1), @as(i64, 1000), @as(i64, 1000) },
    ) catch unreachable;
}

test "init creates service_endpoints table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO service_endpoints (" ++
            "service_name, endpoint_id, container_id, node_id, ip_address, port, weight, admin_state, generation, registered_at, last_seen_at" ++
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            "api",
            "ctr-1:8080",
            "ctr-1",
            @as(i64, 1),
            "10.42.0.10",
            @as(i64, 8080),
            @as(i64, 1),
            "active",
            @as(i64, 1),
            @as(i64, 1000),
            @as(i64, 1000),
        },
    ) catch unreachable;
}

test "init creates service_http_routes table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO service_http_routes (" ++
            "service_name, route_name, host, path_prefix, rewrite_prefix, retries, connect_timeout_ms, request_timeout_ms, target_port, preserve_host, route_order, created_at, updated_at" ++
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "api", "default", "api.internal", "/v1", "/internal", @as(i64, 2), @as(i64, 1000), @as(i64, 5000), @as(i64, 8080), @as(i64, 1), @as(i64, 0), @as(i64, 1000), @as(i64, 1000) },
    ) catch unreachable;
}

test "init creates service_http_route_headers table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO service_http_route_headers (" ++
            "service_name, route_name, header_name, header_value, match_order, created_at, updated_at" ++
            ") VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "api", "default", "x-env", "canary", @as(i64, 0), @as(i64, 1000), @as(i64, 1000) },
    ) catch unreachable;
}

test "init creates service_http_route_backends table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO service_http_route_backends (" ++
            "service_name, route_name, backend_service, weight, backend_order, created_at, updated_at" ++
            ") VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "api", "default", "api-canary", @as(i64, 10), @as(i64, 0), @as(i64, 1000), @as(i64, 1000) },
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

test "init creates network_policies table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO network_policies (source_service, target_service, action, created_at)" ++
            " VALUES (?, ?, ?, ?);",
        .{},
        .{ "web", "db", "deny", @as(i64, 1000) },
    ) catch unreachable;

    // verify unique index — same pair should replace
    db.exec(
        "INSERT OR REPLACE INTO network_policies (source_service, target_service, action, created_at)" ++
            " VALUES (?, ?, ?, ?);",
        .{},
        .{ "web", "db", "allow", @as(i64, 2000) },
    ) catch unreachable;
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

test "init creates certificates table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO certificates (domain, cert_pem, encrypted_key, key_nonce, key_tag, not_after, source, created_at, updated_at)" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "example.com", "cert-data", "enc-key", "nonce", "tag", @as(i64, 1735689600), "manual", @as(i64, 1000), @as(i64, 1000) },
    ) catch unreachable;
}

test "init creates volumes table" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    db.exec(
        "INSERT INTO volumes (name, app_name, driver, path, created_at)" ++
            " VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "data", "myapp", "local", "/home/user/.local/share/yoq/volumes/myapp/data", @as(i64, 1000) },
    ) catch unreachable;
}

test "init creates performance indexes" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    try init(&db);

    // verify indexes exist by querying sqlite_master
    const alloc = std.testing.allocator;
    const Row = struct { name: sqlite.Text };

    // check one representative index
    const row = (db.oneAlloc(
        Row,
        alloc,
        "SELECT name FROM sqlite_master WHERE type='index' AND name=?;",
        .{},
        .{"idx_containers_status"},
    ) catch unreachable);

    if (row) |r| {
        defer alloc.free(r.name.data);
        try std.testing.expectEqualStrings("idx_containers_status", r.name.data);
    } else {
        return error.TestUnexpectedResult;
    }
}
