const sqlite = @import("sqlite");
const std = @import("std");

pub const SchemaError = error{InitFailed};

pub fn apply(db: *sqlite.Db) SchemaError!void {
    // reserve the writer before reading the schema. a deferred transaction can
    // otherwise lose its wal snapshot to a concurrent supervisor update.
    // preserve an existing caller transaction with a nested savepoint.
    const owns_transaction = sqlite.c.sqlite3_get_autocommit(db.db) != 0;
    try exec(db, if (owns_transaction) "BEGIN IMMEDIATE;" else "SAVEPOINT yoq_migrations;");
    errdefer {
        const rollback = if (owns_transaction) "ROLLBACK;" else "ROLLBACK TO yoq_migrations; RELEASE yoq_migrations;";
        _ = sqlite.c.sqlite3_exec(db.db, rollback, null, null, null);
    }
    try migrateContainers(db);
    try migrateAgents(db);
    try migrateAssignments(db);
    try migrateServices(db);
    try migrateDeployments(db);
    try migrateCronSchedules(db);
    try migrateAuditLog(db);
    try migrateTokens(db);
    try migrateClusterCa(db);
    try exec(db, if (owns_transaction) "COMMIT;" else "RELEASE yoq_migrations;");
}

fn migrateContainers(db: *sqlite.Db) SchemaError!void {
    try addColumnIfMissing(db, "ALTER TABLE containers ADD COLUMN startup_outcome INTEGER NOT NULL DEFAULT 0;");
    try addColumnIfMissing(db, "ALTER TABLE containers ADD COLUMN app_name TEXT;");
}

fn migrateAgents(db: *sqlite.Db) SchemaError!void {
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN credential_hash TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN agent_api_port INTEGER;");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN node_id INTEGER;");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN wg_public_key TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN overlay_ip TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN role TEXT DEFAULT 'both';");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN region TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN labels TEXT DEFAULT '';");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN gpu_count INTEGER DEFAULT 0;");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN gpu_used INTEGER DEFAULT 0;");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN gpu_model TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN gpu_vram_mb INTEGER;");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN rdma_capable INTEGER DEFAULT 0;");
    try addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN gpu_health TEXT DEFAULT 'healthy';");
}

fn migrateServices(db: *sqlite.Db) SchemaError!void {
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_host TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_path_prefix TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_rewrite_prefix TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_retries INTEGER;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_connect_timeout_ms INTEGER;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_request_timeout_ms INTEGER;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_http2_idle_timeout_ms INTEGER;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_target_port INTEGER;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_preserve_host INTEGER;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_mirror_service TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_retry_on_5xx INTEGER;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_circuit_breaker_threshold INTEGER;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_circuit_breaker_timeout_ms INTEGER;");
    try addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN peer_mode TEXT DEFAULT 'off';");
    try createTableIfMissing(db,
        \\CREATE TABLE IF NOT EXISTS service_http_routes (
        \\    service_name TEXT NOT NULL,
        \\    route_name TEXT NOT NULL,
        \\    host TEXT NOT NULL,
        \\    path_prefix TEXT NOT NULL DEFAULT '/',
        \\    rewrite_prefix TEXT,
        \\    mirror_service TEXT,
        \\    retries INTEGER NOT NULL DEFAULT 0,
        \\    connect_timeout_ms INTEGER NOT NULL DEFAULT 1000,
        \\    request_timeout_ms INTEGER NOT NULL DEFAULT 5000,
        \\    http2_idle_timeout_ms INTEGER NOT NULL DEFAULT 30000,
        \\    target_port INTEGER,
        \\    preserve_host INTEGER NOT NULL DEFAULT 1,
        \\    route_order INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (service_name, route_name)
        \\);
    );
    try createTableIfMissing(db,
        \\CREATE TABLE IF NOT EXISTS service_http_route_headers (
        \\    service_name TEXT NOT NULL,
        \\    route_name TEXT NOT NULL,
        \\    header_name TEXT NOT NULL,
        \\    header_value TEXT NOT NULL,
        \\    match_order INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (service_name, route_name, match_order)
        \\);
    );
    try createTableIfMissing(db,
        \\CREATE TABLE IF NOT EXISTS service_http_route_methods (
        \\    service_name TEXT NOT NULL,
        \\    route_name TEXT NOT NULL,
        \\    method TEXT NOT NULL,
        \\    match_order INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (service_name, route_name, match_order)
        \\);
    );
    try createTableIfMissing(db,
        \\CREATE TABLE IF NOT EXISTS service_http_route_backends (
        \\    service_name TEXT NOT NULL,
        \\    route_name TEXT NOT NULL,
        \\    backend_service TEXT NOT NULL,
        \\    weight INTEGER NOT NULL,
        \\    backend_order INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (service_name, route_name, backend_order)
        \\);
    );
    try addColumnIfMissing(db, "ALTER TABLE service_http_routes ADD COLUMN rewrite_prefix TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE service_http_routes ADD COLUMN mirror_service TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE service_http_routes ADD COLUMN http2_idle_timeout_ms INTEGER NOT NULL DEFAULT 30000;");
    try addColumnIfMissing(db, "ALTER TABLE service_http_routes ADD COLUMN retry_on_5xx INTEGER NOT NULL DEFAULT 1;");
    try addColumnIfMissing(db, "ALTER TABLE service_http_routes ADD COLUMN circuit_breaker_threshold INTEGER NOT NULL DEFAULT 3;");
    try addColumnIfMissing(db, "ALTER TABLE service_http_routes ADD COLUMN circuit_breaker_timeout_ms INTEGER NOT NULL DEFAULT 30000;");
    exec(
        db,
        "INSERT INTO service_http_routes (" ++
            "service_name, route_name, host, path_prefix, rewrite_prefix, mirror_service, retries, connect_timeout_ms, request_timeout_ms, http2_idle_timeout_ms, target_port, preserve_host, route_order, created_at, updated_at" ++
            ") SELECT service_name, 'default', http_proxy_host, COALESCE(http_proxy_path_prefix, '/'), http_proxy_rewrite_prefix, http_proxy_mirror_service, COALESCE(http_proxy_retries, 0), COALESCE(http_proxy_connect_timeout_ms, 1000), COALESCE(http_proxy_request_timeout_ms, 5000), COALESCE(http_proxy_http2_idle_timeout_ms, 30000), http_proxy_target_port, COALESCE(http_proxy_preserve_host, 1), 0, created_at, updated_at" ++
            " FROM services WHERE http_proxy_host IS NOT NULL AND NOT EXISTS (" ++
            "SELECT 1 FROM service_http_routes routes WHERE routes.service_name = services.service_name AND routes.route_name = 'default'" ++
            ");",
    ) catch return SchemaError.InitFailed;
    exec(
        db,
        "INSERT INTO service_http_route_backends (" ++
            "service_name, route_name, backend_service, weight, backend_order, created_at, updated_at" ++
            ") SELECT service_name, 'default', service_name, 100, 0, created_at, updated_at" ++
            " FROM services WHERE http_proxy_host IS NOT NULL AND NOT EXISTS (" ++
            "SELECT 1 FROM service_http_route_backends backends WHERE backends.service_name = services.service_name AND backends.route_name = 'default'" ++
            ");",
    ) catch return SchemaError.InitFailed;
}

fn migrateDeployments(db: *sqlite.Db) SchemaError!void {
    try addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN app_name TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN trigger TEXT NOT NULL DEFAULT 'apply';");
    try addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN source_release_id TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN resumed_from_release_id TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN superseded_by_release_id TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN completed_targets INTEGER NOT NULL DEFAULT 0;");
    try addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN failed_targets INTEGER NOT NULL DEFAULT 0;");
    try addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN failure_details_json TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN rollout_targets_json TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN rollout_checkpoint_json TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN rollout_control_state TEXT DEFAULT 'active';");
    exec(db, "UPDATE deployments SET trigger = 'apply' WHERE trigger IS NULL OR trigger = '';") catch return SchemaError.InitFailed;
    exec(db, "UPDATE deployments SET rollout_control_state = 'active' WHERE rollout_control_state IS NULL OR rollout_control_state = '';") catch return SchemaError.InitFailed;
}

fn migrateCronSchedules(db: *sqlite.Db) SchemaError!void {
    try createTableIfMissing(db,
        \\CREATE TABLE IF NOT EXISTS cron_schedules (
        \\    app_name TEXT NOT NULL,
        \\    name TEXT NOT NULL,
        \\    every INTEGER NOT NULL,
        \\    spec_json TEXT NOT NULL,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (app_name, name)
        \\);
    );
}

fn migrateAuditLog(db: *sqlite.Db) SchemaError!void {
    try createTableIfMissing(db,
        \\CREATE TABLE IF NOT EXISTS audit_log (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    recorded_at INTEGER NOT NULL,
        \\    actor TEXT NOT NULL,
        \\    action TEXT NOT NULL,
        \\    target TEXT,
        \\    outcome TEXT NOT NULL
        \\);
    );
}

fn migrateClusterCa(db: *sqlite.Db) SchemaError!void {
    // single-row table (CHECK(id=1)) holding the cluster's mTLS CA cert and its
    // encrypted private key. the key is encrypted at rest with a join-token-
    // derived key so any node in the cluster can decrypt it and sign leaves;
    // the row is distributed via raft.
    try createTableIfMissing(db,
        \\CREATE TABLE IF NOT EXISTS cluster_ca (
        \\    id INTEGER PRIMARY KEY CHECK (id = 1),
        \\    cert_pem BLOB NOT NULL,
        \\    encrypted_key BLOB NOT NULL,
        \\    key_nonce BLOB NOT NULL,
        \\    key_tag BLOB NOT NULL,
        \\    created_at INTEGER NOT NULL,
        \\    not_after INTEGER NOT NULL
        \\);
    );
}

fn migrateTokens(db: *sqlite.Db) SchemaError!void {
    try createTableIfMissing(db,
        \\CREATE TABLE IF NOT EXISTS tokens (
        \\    name TEXT PRIMARY KEY,
        \\    secret_hash TEXT NOT NULL,
        \\    scopes TEXT NOT NULL,
        \\    created_at INTEGER NOT NULL,
        \\    expires_at INTEGER,
        \\    revoked_at INTEGER
        \\);
    );
}

fn migrateAssignments(db: *sqlite.Db) SchemaError!void {
    try addColumnIfMissing(db, "ALTER TABLE assignments ADD COLUMN status_reason TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE assignments ADD COLUMN app_name TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE assignments ADD COLUMN workload_kind TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE assignments ADD COLUMN workload_name TEXT;");
    try addColumnIfMissing(db, "ALTER TABLE assignments ADD COLUMN health_check_json TEXT;");
}

fn addColumnIfMissing(db: *sqlite.Db, sql: []const u8) SchemaError!void {
    exec(db, sql) catch {
        const err_msg = std.mem.span(sqlite.c.sqlite3_errmsg(db.db));
        if (std.mem.indexOf(u8, err_msg, "duplicate column name") != null) return;
        return SchemaError.InitFailed;
    };
}

fn createTableIfMissing(db: *sqlite.Db, sql: []const u8) SchemaError!void {
    try exec(db, sql);
}

fn exec(db: *sqlite.Db, sql: []const u8) SchemaError!void {
    var statement = db.prepareDynamic(sql) catch return error.InitFailed;
    defer statement.deinit();
    statement.exec(.{}, .{}) catch {
        _ = sqlite.c.sqlite3_reset(statement.stmt);
        return error.InitFailed;
    };
}

test "addColumnIfMissing ignores duplicate column errors" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    db.exec("CREATE TABLE t (id INTEGER, name TEXT);", .{}, .{}) catch unreachable;
    try addColumnIfMissing(&db, "ALTER TABLE t ADD COLUMN name TEXT;");
}

test "migrateServices adds http proxy columns" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    db.exec(
        "CREATE TABLE services (service_name TEXT PRIMARY KEY, vip_address TEXT NOT NULL UNIQUE, lb_policy TEXT NOT NULL DEFAULT 'consistent_hash', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);",
        .{},
        .{},
    ) catch unreachable;

    try migrateServices(&db);

    db.exec(
        "INSERT INTO services (" ++
            "service_name, vip_address, lb_policy, http_proxy_host, http_proxy_path_prefix, http_proxy_rewrite_prefix, http_proxy_retries, http_proxy_connect_timeout_ms, http_proxy_request_timeout_ms, http_proxy_http2_idle_timeout_ms, http_proxy_target_port, http_proxy_preserve_host, created_at, updated_at" ++
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "api", "10.43.0.2", "consistent_hash", "api.internal", "/v1", "/internal", @as(i64, 2), @as(i64, 1500), @as(i64, 5000), @as(i64, 30000), @as(i64, 8080), @as(i64, 1), @as(i64, 1000), @as(i64, 1000) },
    ) catch unreachable;

    db.exec(
        "SELECT service_name, route_name, host FROM service_http_routes WHERE service_name = ?;",
        .{},
        .{"api"},
    ) catch unreachable;
}

test "migrateDeployments adds release transition columns" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    db.exec(
        "CREATE TABLE deployments (" ++
            "id TEXT PRIMARY KEY, " ++
            "service_name TEXT NOT NULL, " ++
            "manifest_hash TEXT NOT NULL, " ++
            "config_snapshot TEXT NOT NULL DEFAULT '', " ++
            "status TEXT NOT NULL DEFAULT 'pending', " ++
            "message TEXT, " ++
            "created_at INTEGER NOT NULL" ++
            ");",
        .{},
        .{},
    ) catch unreachable;

    try migrateDeployments(&db);

    db.exec(
        "INSERT INTO deployments (id, app_name, service_name, trigger, source_release_id, manifest_hash, config_snapshot, status, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep-1", "demo-app", "demo-app", "rollback", "dep-0", "sha256:test", "{}", "completed", "rollback completed", @as(i64, 100) },
    ) catch unreachable;
}

test "schema migration failure rolls back added columns and retries cleanly" {
    const schema = @import("../schema.zig");
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);
    try db.exec("ALTER TABLE containers DROP COLUMN startup_outcome;", .{}, .{});
    try db.exec("ALTER TABLE agents DROP COLUMN credential_hash;", .{}, .{});

    const Failure = struct {
        fn authorize(_: ?*anyopaque, action: c_int, _: [*c]const u8, table: [*c]const u8, _: [*c]const u8, _: [*c]const u8) callconv(.c) c_int {
            if (action == sqlite.c.SQLITE_ALTER_TABLE and table != null and std.mem.eql(u8, std.mem.span(table), "agents")) return sqlite.c.SQLITE_DENY;
            return sqlite.c.SQLITE_OK;
        }
    };
    try std.testing.expectEqual(sqlite.c.SQLITE_OK, sqlite.c.sqlite3_set_authorizer(db.db, Failure.authorize, null));
    defer _ = sqlite.c.sqlite3_set_authorizer(db.db, null, null);
    try std.testing.expectError(error.InitFailed, schema.init(&db));
    const Row = struct { count: i64 };
    const columns = (try db.one(Row, "SELECT COUNT(*) AS count FROM pragma_table_info('containers') WHERE name = 'startup_outcome';", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 0), columns.count);
    try std.testing.expectEqual(@as(c_int, 1), sqlite.c.sqlite3_get_autocommit(db.db));

    try std.testing.expectEqual(sqlite.c.SQLITE_OK, sqlite.c.sqlite3_set_authorizer(db.db, null, null));
    try schema.init(&db);
    try schema.init(&db);
    const credentials = (try db.one(Row, "SELECT COUNT(*) AS count FROM pragma_table_info('agents') WHERE name = 'credential_hash';", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 1), credentials.count);
    const startup = (try db.one(Row, "SELECT COUNT(*) AS count FROM pragma_table_info('containers') WHERE name = 'startup_outcome';", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 1), startup.count);
}

test "schema migrations reserve the writer before reading an existing wal schema" {
    const schema = @import("../schema.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var directory_buf: [4096]u8 = undefined;
    const directory_len = try tmp.dir.realPathFile(std.testing.io, ".", &directory_buf);
    var path_buf: [4096]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "{s}/migration.db", .{directory_buf[0..directory_len]});
    var migrator = try sqlite.Db.init(.{ .mode = .{ .File = path }, .open_flags = .{ .write = true, .create = true } });
    defer migrator.deinit();
    try schema.init(&migrator);
    var supervisor = try sqlite.Db.init(.{ .mode = .{ .File = path }, .open_flags = .{ .write = true } });
    defer supervisor.deinit();
    // the competing write must report contention instead of waiting inside
    // the callback while the migration holds its reservation.
    _ = sqlite.c.sqlite3_busy_timeout(supervisor.db, 0);
    const Contention = struct {
        supervisor: *sqlite.Db,
        attempted: bool = false,
        result: c_int = -1,

        fn authorize(context: ?*anyopaque, action: c_int, table: [*c]const u8, _: [*c]const u8, _: [*c]const u8, _: [*c]const u8) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (!self.attempted and action == sqlite.c.SQLITE_INSERT and table != null and std.mem.eql(u8, std.mem.span(table), "service_http_routes")) {
                self.attempted = true;
                self.result = sqlite.c.sqlite3_exec(self.supervisor.db, "INSERT INTO containers (id, rootfs, command, created_at) VALUES ('fast-exit', '/', 'exit 0', 0);", null, null, null);
            }
            return sqlite.c.SQLITE_OK;
        }
    };
    var contention: Contention = .{ .supervisor = &supervisor };
    try std.testing.expectEqual(sqlite.c.SQLITE_OK, sqlite.c.sqlite3_set_authorizer(migrator.db, Contention.authorize, &contention));
    defer _ = sqlite.c.sqlite3_set_authorizer(migrator.db, null, null);
    try apply(&migrator);
    try std.testing.expect(contention.attempted);
    try std.testing.expectEqual(sqlite.c.SQLITE_BUSY, contention.result);
    try supervisor.exec("INSERT INTO containers (id, rootfs, command, created_at) VALUES ('after-migration', '/', 'exit 0', 0);", .{}, .{});
    try std.testing.expectEqual(@as(c_int, 1), sqlite.c.sqlite3_get_autocommit(migrator.db));
}

test "schema migrations preserve the caller transaction" {
    const schema = @import("../schema.zig");
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);
    try db.exec("BEGIN IMMEDIATE; INSERT INTO containers (id, rootfs, command, created_at) VALUES ('outer', '/', 'true', 0);", .{}, .{});
    try apply(&db);
    try std.testing.expectEqual(@as(c_int, 0), sqlite.c.sqlite3_get_autocommit(db.db));
    try db.exec("ROLLBACK;", .{}, .{});
    try std.testing.expectEqual(@as(i64, 0), (try db.one(i64, "SELECT COUNT(*) FROM containers WHERE id = 'outer';", .{}, .{})).?);
}
