const sqlite = @import("sqlite");
const std = @import("std");

pub const SchemaError = error{InitFailed};

pub fn apply(db: *sqlite.Db) SchemaError!void {
    migrateContainers(db);
    migrateAgents(db);
    migrateServices(db);
}

fn migrateContainers(db: *sqlite.Db) void {
    addColumnIfMissing(db, "ALTER TABLE containers ADD COLUMN app_name TEXT;") catch {};
}

fn migrateAgents(db: *sqlite.Db) void {
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
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_retries INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_connect_timeout_ms INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_request_timeout_ms INTEGER;") catch {};
    addColumnIfMissing(db, "ALTER TABLE services ADD COLUMN http_proxy_preserve_host INTEGER;") catch {};
}

fn addColumnIfMissing(db: *sqlite.Db, sql: []const u8) SchemaError!void {
    db.execDynamic(sql, .{}, .{}) catch {
        const err_msg = std.mem.span(sqlite.c.sqlite3_errmsg(db.db));
        if (std.mem.indexOf(u8, err_msg, "duplicate column name") != null) return;
        return SchemaError.InitFailed;
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

    try apply(&db);

    db.exec(
        "INSERT INTO services (" ++
            "service_name, vip_address, lb_policy, http_proxy_host, http_proxy_path_prefix, http_proxy_retries, http_proxy_connect_timeout_ms, http_proxy_request_timeout_ms, http_proxy_preserve_host, created_at, updated_at" ++
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "api", "10.43.0.2", "consistent_hash", "api.internal", "/v1", @as(i64, 2), @as(i64, 1500), @as(i64, 5000), @as(i64, 1), @as(i64, 1000), @as(i64, 1000) },
    ) catch unreachable;
}
