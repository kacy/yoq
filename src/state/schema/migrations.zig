const sqlite = @import("sqlite");
const std = @import("std");

pub const SchemaError = error{InitFailed};

pub fn apply(db: *sqlite.Db) SchemaError!void {
    migrateContainers(db);
    migrateAgents(db);
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
