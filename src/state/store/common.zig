const std = @import("std");
const sqlite = @import("sqlite");
const schema = @import("../schema.zig");
const paths = @import("../../lib/paths.zig");

pub const StoreError = error{
    WriteFailed,
    ReadFailed,
    NotFound,
    DbOpenFailed,
};

var global_db: ?sqlite.Db = null;
var db_mutex: std.Io.Mutex = .init;
var test_db_lifetime_mutex: std.Io.Mutex = .init;

pub fn initTestDb() StoreError!void {
    // The in-memory test DB is global process state. Hold an exclusive
    // lifetime lock until deinitTestDb() so concurrent tests can't reset the
    // database out from under each other.
    test_db_lifetime_mutex.lockUncancelable(std.Options.debug_io);
    errdefer test_db_lifetime_mutex.unlock(std.Options.debug_io);

    db_mutex.lockUncancelable(std.Options.debug_io);
    defer db_mutex.unlock(std.Options.debug_io);

    if (global_db) |*db| {
        db.deinit();
        global_db = null;
    }

    global_db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true, .create = true },
    }) catch return StoreError.DbOpenFailed;

    schema.init(&global_db.?) catch {
        global_db.?.deinit();
        global_db = null;
        return StoreError.DbOpenFailed;
    };
}

pub fn deinitTestDb() void {
    db_mutex.lockUncancelable(std.Options.debug_io);
    defer db_mutex.unlock(std.Options.debug_io);

    if (global_db) |*db| {
        db.deinit();
        global_db = null;
    }

    test_db_lifetime_mutex.unlock(std.Options.debug_io);
}

pub fn getDb() StoreError!*sqlite.Db {
    if (global_db != null) return &global_db.?;

    db_mutex.lockUncancelable(std.Options.debug_io);
    defer db_mutex.unlock(std.Options.debug_io);

    if (global_db != null) return &global_db.?;

    var path_buf: [paths.max_path]u8 = undefined;
    const path = schema.defaultDbPath(&path_buf) catch return StoreError.DbOpenFailed;
    global_db = sqlite.Db.init(.{
        .mode = .{ .File = path },
        .open_flags = .{ .write = true, .create = true },
    }) catch return StoreError.DbOpenFailed;

    schema.init(&global_db.?) catch {
        global_db.?.deinit();
        global_db = null;
        return StoreError.DbOpenFailed;
    };

    return &global_db.?;
}

pub fn closeDb() void {
    db_mutex.lockUncancelable(std.Options.debug_io);
    defer db_mutex.unlock(std.Options.debug_io);

    if (global_db) |*db| {
        db.deinit();
        global_db = null;
    }
}

pub fn openDb() StoreError!sqlite.Db {
    var path_buf: [paths.max_path]u8 = undefined;
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
