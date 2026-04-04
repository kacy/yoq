const std = @import("std");
const sqlite = @import("sqlite");
const schema = @import("../../state/schema.zig");
const log = @import("../../lib/log.zig");

pub const StateMachineError = error{
    DbOpenFailed,
};

pub const MetaError = error{
    ReadFailed,
    WriteFailed,
};

const meta_create_table_sql =
    \\CREATE TABLE IF NOT EXISTS state_machine_meta (
    \\    id INTEGER PRIMARY KEY CHECK (id = 1),
    \\    last_applied INTEGER NOT NULL DEFAULT 0
    \\);
;

pub fn init(path: [:0]const u8) StateMachineError!sqlite.Db {
    var db = sqlite.Db.init(.{
        .mode = .{ .File = path },
        .open_flags = .{ .write = true, .create = true },
    }) catch return StateMachineError.DbOpenFailed;

    schema.init(&db) catch |e| {
        log.err("state_machine: failed to initialize schema: {}. Database may be corrupted.", .{e});
        db.deinit();
        return StateMachineError.DbOpenFailed;
    };
    initMeta(&db) catch |e| {
        log.err("state_machine: failed to initialize metadata: {}", .{e});
        db.deinit();
        return StateMachineError.DbOpenFailed;
    };

    return db;
}

pub fn initMemory() StateMachineError!sqlite.Db {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return StateMachineError.DbOpenFailed;

    schema.init(&db) catch |e| {
        log.err("state_machine: failed to initialize schema: {}. Database may be corrupted.", .{e});
        db.deinit();
        return StateMachineError.DbOpenFailed;
    };
    initMeta(&db) catch |e| {
        log.err("state_machine: failed to initialize metadata: {}", .{e});
        db.deinit();
        return StateMachineError.DbOpenFailed;
    };

    return db;
}

pub fn initMeta(db: *sqlite.Db) MetaError!void {
    db.exec(meta_create_table_sql, .{}, .{}) catch return MetaError.WriteFailed;
    db.exec(
        "INSERT OR IGNORE INTO state_machine_meta (id, last_applied) VALUES (1, 0);",
        .{},
        .{},
    ) catch return MetaError.WriteFailed;
}

pub fn getLastApplied(db: *sqlite.Db) MetaError!u64 {
    const Row = struct { last_applied: i64 };
    const row = (db.one(
        Row,
        "SELECT last_applied FROM state_machine_meta WHERE id = 1;",
        .{},
        .{},
    ) catch return MetaError.ReadFailed) orelse return 0;
    return std.math.cast(u64, row.last_applied) orelse return MetaError.ReadFailed;
}

pub fn setLastApplied(db: *sqlite.Db, last_applied: u64) MetaError!void {
    try initMeta(db);
    db.exec(
        "UPDATE state_machine_meta SET last_applied = ? WHERE id = 1;",
        .{},
        .{@as(i64, @intCast(last_applied))},
    ) catch return MetaError.WriteFailed;
}
