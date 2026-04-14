const sqlite = @import("sqlite");
const std = @import("std");

pub const SchemaError = error{InitFailed};

pub fn apply(db: *sqlite.Db) SchemaError!void {
    migrateContainers(db);
    migrateAgents(db);
    migrateAssignments(db);
    migrateServices(db);
    migrateDeployments(db);
    migrateCronSchedules(db);
}

fn migrateContainers(db: *sqlite.Db) void {
    addColumnIfMissing(db, "ALTER TABLE containers ADD COLUMN app_name TEXT;") catch {};
}

fn migrateAgents(db: *sqlite.Db) void {
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN agent_api_port INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN node_id INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN wg_public_key TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN overlay_ip TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN role TEXT DEFAULT 'both';") catch {};
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN region TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN labels TEXT DEFAULT '';") catch {};
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN gpu_count INTEGER DEFAULT 0;") catch {};
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN gpu_used INTEGER DEFAULT 0;") catch {};
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN gpu_model TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN gpu_vram_mb INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN rdma_capable INTEGER DEFAULT 0;") catch {};
    addColumnIfMissing(db, "ALTER TABLE agents ADD COLUMN gpu_health TEXT DEFAULT 'healthy';") catch {};
}

fn migrateServices(db: *sqlite.Db) void {
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_host TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_path_prefix TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_rewrite_prefix TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_retries INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_connect_timeout_ms INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_request_timeout_ms INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_http2_idle_timeout_ms INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_target_port INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_preserve_host INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_mirror_service TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_retry_on_5xx INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_circuit_breaker_threshold INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_circuit_breaker_timeout_ms INTEGER;") catch {};
    createTableIfMissing(db,
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
    ) catch {};
    createTableIfMissing(db,
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
    ) catch {};
    createTableIfMissing(db,
        \\CREATE TABLE IF NOT EXISTS service_http_route_methods (
        \\    service_name TEXT NOT NULL,
        \\    route_name TEXT NOT NULL,
        \\    method TEXT NOT NULL,
        \\    match_order INTEGER NOT NULL DEFAULT 0,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (service_name, route_name, match_order)
        \\);
    ) catch {};
    createTableIfMissing(db,
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
    ) catch {};
    addColumnIfMissing(db, "ALTER TABLE service_http_routes ADD COLUMN rewrite_prefix TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE service_http_routes ADD COLUMN mirror_service TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE service_http_routes ADD COLUMN http2_idle_timeout_ms INTEGER NOT NULL DEFAULT 30000;") catch {};
    addColumnIfMissing(db, "ALTER TABLE service_http_routes ADD COLUMN retry_on_5xx INTEGER NOT NULL DEFAULT 1;") catch {};
    addColumnIfMissing(db, "ALTER TABLE service_http_routes ADD COLUMN circuit_breaker_threshold INTEGER NOT NULL DEFAULT 3;") catch {};
    addColumnIfMissing(db, "ALTER TABLE service_http_routes ADD COLUMN circuit_breaker_timeout_ms INTEGER NOT NULL DEFAULT 30000;") catch {};
    db.exec(
        "INSERT INTO service_http_routes (" ++
            "service_name, route_name, host, path_prefix, rewrite_prefix, mirror_service, retries, connect_timeout_ms, request_timeout_ms, http2_idle_timeout_ms, target_port, preserve_host, route_order, created_at, updated_at" ++
            ") SELECT service_name, 'default', http_proxy_host, COALESCE(http_proxy_path_prefix, '/'), http_proxy_rewrite_prefix, http_proxy_mirror_service, COALESCE(http_proxy_retries, 0), COALESCE(http_proxy_connect_timeout_ms, 1000), COALESCE(http_proxy_request_timeout_ms, 5000), COALESCE(http_proxy_http2_idle_timeout_ms, 30000), http_proxy_target_port, COALESCE(http_proxy_preserve_host, 1), 0, created_at, updated_at" ++
            " FROM services WHERE http_proxy_host IS NOT NULL AND NOT EXISTS (" ++
            "SELECT 1 FROM service_http_routes routes WHERE routes.service_name = services.service_name AND routes.route_name = 'default'" ++
            ");",
        .{},
        .{},
    ) catch {};
    db.exec(
        "INSERT INTO service_http_route_backends (" ++
            "service_name, route_name, backend_service, weight, backend_order, created_at, updated_at" ++
            ") SELECT service_name, 'default', service_name, 100, 0, created_at, updated_at" ++
            " FROM services WHERE http_proxy_host IS NOT NULL AND NOT EXISTS (" ++
            "SELECT 1 FROM service_http_route_backends backends WHERE backends.service_name = services.service_name AND backends.route_name = 'default'" ++
            ");",
        .{},
        .{},
    ) catch {};
}

fn migrateDeployments(db: *sqlite.Db) void {
    addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN app_name TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN trigger TEXT NOT NULL DEFAULT 'apply';") catch {};
    addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN source_release_id TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN resumed_from_release_id TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN completed_targets INTEGER NOT NULL DEFAULT 0;") catch {};
    addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN failed_targets INTEGER NOT NULL DEFAULT 0;") catch {};
    addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN failure_details_json TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN rollout_targets_json TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN rollout_checkpoint_json TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE deployments ADD COLUMN rollout_control_state TEXT DEFAULT 'active';") catch {};
    db.exec("UPDATE deployments SET trigger = 'apply' WHERE trigger IS NULL OR trigger = '';", .{}, .{}) catch {};
    db.exec("UPDATE deployments SET rollout_control_state = 'active' WHERE rollout_control_state IS NULL OR rollout_control_state = '';", .{}, .{}) catch {};
}

fn migrateCronSchedules(db: *sqlite.Db) void {
    createTableIfMissing(db,
        \\CREATE TABLE IF NOT EXISTS cron_schedules (
        \\    app_name TEXT NOT NULL,
        \\    name TEXT NOT NULL,
        \\    every INTEGER NOT NULL,
        \\    spec_json TEXT NOT NULL,
        \\    created_at INTEGER NOT NULL,
        \\    updated_at INTEGER NOT NULL,
        \\    PRIMARY KEY (app_name, name)
        \\);
    ) catch {};
}

fn migrateAssignments(db: *sqlite.Db) void {
    addColumnIfMissing(db, "ALTER TABLE assignments ADD COLUMN status_reason TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE assignments ADD COLUMN app_name TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE assignments ADD COLUMN workload_kind TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE assignments ADD COLUMN workload_name TEXT;") catch {};
    addColumnIfMissing(db, "ALTER TABLE assignments ADD COLUMN health_check_json TEXT;") catch {};
}

fn addColumnIfMissing(db: *sqlite.Db, sql: []const u8) SchemaError!void {
    db.execDynamic(sql, .{}, .{}) catch {
        const err_msg = std.mem.span(sqlite.c.sqlite3_errmsg(db.db));
        if (std.mem.indexOf(u8, err_msg, "duplicate column name") != null) return;
        return SchemaError.InitFailed;
    };
}

fn createTableIfMissing(db: *sqlite.Db, sql: []const u8) SchemaError!void {
    db.execDynamic(sql, .{}, .{}) catch return SchemaError.InitFailed;
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

    try apply(&db);

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

    try apply(&db);

    db.exec(
        "INSERT INTO deployments (id, app_name, service_name, trigger, source_release_id, manifest_hash, config_snapshot, status, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "dep-1", "demo-app", "demo-app", "rollback", "dep-0", "sha256:test", "{}", "completed", "rollback completed", @as(i64, 100) },
    ) catch unreachable;
}
