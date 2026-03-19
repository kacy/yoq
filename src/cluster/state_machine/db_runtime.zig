const sqlite = @import("sqlite");
const schema = @import("../../state/schema.zig");
const log = @import("../../lib/log.zig");

pub const StateMachineError = error{
    DbOpenFailed,
};

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

    return db;
}
