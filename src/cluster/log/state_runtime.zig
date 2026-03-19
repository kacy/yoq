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

    schema_support.initSchema(&db) catch {
        db.deinit();
        return LogError.DbOpenFailed;
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

    return db;
}

pub fn getCurrentTerm(db: *sqlite.Db) Term {
    const Row = struct { current_term: i64 };
    const row = (db.one(
        Row,
        "SELECT current_term FROM raft_state WHERE id = 1;",
        .{},
        .{},
    ) catch return 0) orelse return 0;
    return common.safeU64(row.current_term) catch 0;
}

pub fn setCurrentTerm(db: *sqlite.Db, term: Term) LogError!void {
    db.exec(
        "UPDATE raft_state SET current_term = ? WHERE id = 1;",
        .{},
        .{@as(i64, @intCast(term))},
    ) catch return LogError.WriteFailed;
}

pub fn getVotedFor(db: *sqlite.Db) ?NodeId {
    const Row = struct { voted_for: ?i64 };
    const row = (db.one(
        Row,
        "SELECT voted_for FROM raft_state WHERE id = 1;",
        .{},
        .{},
    ) catch return null) orelse return null;
    return if (row.voted_for) |v| common.safeU64(v) catch null else null;
}

pub fn setVotedFor(db: *sqlite.Db, id: ?NodeId) LogError!void {
    const val: ?i64 = if (id) |v| @intCast(v) else null;
    db.exec(
        "UPDATE raft_state SET voted_for = ? WHERE id = 1;",
        .{},
        .{val},
    ) catch return LogError.WriteFailed;
}
