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

pub const DbLease = struct {
    db: *sqlite.Db,

    pub fn deinit(self: *DbLease) void {
        _ = self;
        db_mutex.unlock(std.Options.debug_io);
    }
};

pub fn leaseDb() StoreError!DbLease {
    db_mutex.lockUncancelable(std.Options.debug_io);
    errdefer db_mutex.unlock(std.Options.debug_io);

    return .{ .db = try getDbLocked() };
}

fn getDbLocked() StoreError!*sqlite.Db {
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

test "DbLease holds database lifetime until deinit" {
    try initTestDb();
    defer deinitTestDb();

    const State = struct {
        entered: std.atomic.Value(bool) = .init(false),
        release: std.atomic.Value(bool) = .init(false),
        close_returned: std.atomic.Value(bool) = .init(false),

        fn runHold(self: *@This()) void {
            var lease = leaseDb() catch unreachable;
            defer lease.deinit();

            _ = lease.db;
            self.entered.store(true, .release);
            while (!self.release.load(.acquire)) {
                std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(1), .awake) catch unreachable;
            }
        }

        fn runClose(self: *@This()) void {
            closeDb();
            self.close_returned.store(true, .release);
        }
    };

    var state: State = .{};
    const holder = try std.Thread.spawn(.{}, State.runHold, .{&state});

    while (!state.entered.load(.acquire)) {
        std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(1), .awake) catch unreachable;
    }

    const closer = try std.Thread.spawn(.{}, State.runClose, .{&state});
    std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(25), .awake) catch unreachable;
    try std.testing.expect(!state.close_returned.load(.acquire));

    state.release.store(true, .release);
    holder.join();
    closer.join();
    try std.testing.expect(state.close_returned.load(.acquire));
}
