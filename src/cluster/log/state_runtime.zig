const sqlite = @import("sqlite");

const common = @import("common.zig");
const schema_support = @import("schema_support.zig");

const Term = common.Term;
const NodeId = common.NodeId;
const LogError = common.LogError;

pub fn init(path: [:0]const u8) LogError!sqlite.Db {
    var db = sqlite.Db.init(.{
        .mode = .{ .File = path },
        .open_flags = .{ .write = true, .create = true },
    }) catch return LogError.DbOpenFailed;

    db.exec("PRAGMA synchronous = FULL;", .{}, .{}) catch {
        db.deinit();
        return LogError.DbOpenFailed;
    };

    schema_support.initSchema(&db) catch {
        db.deinit();
        return LogError.DbOpenFailed;
    };

    _ = readState(&db) catch |err| {
        db.deinit();
        return err;
    };
    return db;
}

pub fn initMemory() LogError!sqlite.Db {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return LogError.DbOpenFailed;

    schema_support.initSchema(&db) catch {
        db.deinit();
        return LogError.DbOpenFailed;
    };

    _ = readState(&db) catch |err| {
        db.deinit();
        return err;
    };
    return db;
}

pub const State = struct { current_term: Term, voted_for: ?NodeId };

pub fn readState(db: *sqlite.Db) LogError!State {
    const Row = struct { current_term: i64, voted_for: ?i64 };
    const row = (db.one(Row, "SELECT current_term, voted_for FROM raft_state WHERE id = 1;", .{}, .{}) catch return error.ReadFailed) orelse return error.CorruptedLog;
    return .{
        .current_term = try common.safeU64(row.current_term),
        .voted_for = if (row.voted_for) |id| try common.safeU64(id) else null,
    };
}

pub fn getCurrentTerm(db: *sqlite.Db) LogError!Term {
    return (try readState(db)).current_term;
}

pub fn setCurrentTerm(db: *sqlite.Db, term: Term) LogError!void {
    common.execStatement(
        db,
        "UPDATE raft_state SET current_term = ? WHERE id = 1;",
        .{@as(i64, @intCast(term))},
    ) catch return LogError.WriteFailed;
}

pub fn getVotedFor(db: *sqlite.Db) LogError!?NodeId {
    return (try readState(db)).voted_for;
}

pub fn setVotedFor(db: *sqlite.Db, id: ?NodeId) LogError!void {
    const val: ?i64 = if (id) |v| @intCast(v) else null;
    db.exec(
        "UPDATE raft_state SET voted_for = ? WHERE id = 1;",
        .{},
        .{val},
    ) catch return LogError.WriteFailed;
}
