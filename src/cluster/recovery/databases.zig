const std = @import("std");
const sqlite = @import("sqlite");
const c = sqlite.c;
const files = @import("files.zig");
const schema = @import("../../state/schema.zig");
const backup_schema = @import("../../state/backup_schema.zig");
const io = std.Options.debug_io;

pub const Boundary = struct {
    node_id: u64,
    voters: []const u8,
    current_term: u64,
    last_applied: u64,
    last_log_index: u64,
    snapshot_index: u64,
    snapshot_term: u64,
    snapshot_size: u64,

    pub fn deinit(self: Boundary, alloc: std.mem.Allocator) void {
        alloc.free(self.voters);
    }
};

/// hold an exclusive lock after the transaction ends so sqlite's backup api
/// can open its own transaction without allowing another writer to intervene.
pub fn lock(db: *sqlite.Db) !void {
    _ = c.sqlite3_busy_timeout(db.db, 0);
    if (c.sqlite3_exec(db.db, "PRAGMA locking_mode=EXCLUSIVE;", null, null, null) != c.SQLITE_OK) return error.DatabaseLockFailed;
    const rc = c.sqlite3_exec(db.db, "BEGIN EXCLUSIVE;", null, null, null);
    if (rc == c.SQLITE_BUSY or rc == c.SQLITE_LOCKED) return error.ServerRunning;
    if (rc != c.SQLITE_OK) return error.DatabaseLockFailed;
    if (c.sqlite3_exec(db.db, "COMMIT;", null, null, null) != c.SQLITE_OK) return error.DatabaseLockFailed;
}

pub fn open(alloc: std.mem.Allocator, dir: std.Io.Dir, name: []const u8, write: bool) !sqlite.Db {
    var file = try files.openRegular(dir, name, false);
    defer file.close(io);
    for ([_][]const u8{ "-wal", "-shm", "-journal" }) |suffix| {
        var sidecar_buf: [256]u8 = undefined;
        const sidecar = try std.fmt.bufPrint(&sidecar_buf, "{s}{s}", .{ name, suffix });
        var existing = files.openRegular(dir, sidecar, false) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        existing.close(io);
    }
    // sqlite needs the real filename to find its wal and shared-memory files.
    // the caller holds the private directory and server ownership lock.
    const path = try dir.realPathFileAlloc(io, name, alloc);
    defer alloc.free(path);
    const terminated = try alloc.dupeZ(u8, path);
    defer alloc.free(terminated);
    return sqlite.Db.init(.{ .mode = .{ .File = terminated }, .open_flags = .{ .write = write } });
}

pub fn copy(alloc: std.mem.Allocator, source: *sqlite.Db, destination: std.Io.Dir, name: []const u8) !files.Digest {
    const pages = (try source.one(struct { count: i64 }, "PRAGMA page_count;", .{}, .{})).?.count;
    const page_size = (try source.one(struct { size: i64 }, "PRAGMA page_size;", .{}, .{})).?.size;
    if (pages < 0 or page_size <= 0 or @as(u64, @intCast(pages)) > files.max_database_size / @as(u64, @intCast(page_size))) return error.FileTooLarge;
    var file = try files.create(destination, name);
    file.close(io);
    errdefer destination.deleteFile(io, name) catch {};
    {
        var target = try open(alloc, destination, name, true);
        defer target.deinit();
        const handle = c.sqlite3_backup_init(target.db, "main", source.db, "main") orelse return error.DatabaseBackupFailed;
        const step = c.sqlite3_backup_step(handle, -1);
        const finish = c.sqlite3_backup_finish(handle);
        if (step != c.SQLITE_DONE or finish != c.SQLITE_OK) return error.DatabaseBackupFailed;
        // bundles contain self-contained databases, never wal sidecars.
        try target.exec("PRAGMA journal_mode=DELETE;", .{}, .{});
        try integrity(&target);
    }
    var output = try files.openRegular(destination, name, true);
    defer output.close(io);
    try output.sync(io);
    return files.digest(destination, name, files.max_database_size);
}

pub fn integrity(db: *sqlite.Db) !void {
    var result = try db.prepare("PRAGMA integrity_check;");
    defer result.deinit();
    if (c.sqlite3_step(result.stmt) != c.SQLITE_ROW) return error.CorruptDatabase;
    const value = c.sqlite3_column_text(result.stmt, 0) orelse return error.CorruptDatabase;
    if (!std.mem.eql(u8, std.mem.span(value), "ok") or c.sqlite3_step(result.stmt) != c.SQLITE_DONE) return error.CorruptDatabase;
    var foreign = try db.prepare("PRAGMA foreign_key_check;");
    defer foreign.deinit();
    if (c.sqlite3_step(foreign.stmt) != c.SQLITE_DONE) return error.CorruptDatabase;
}

/// migrate only a private staging copy, then compare it with the current schema.
pub fn validateState(db: *sqlite.Db) !void {
    try integrity(db);
    const identity = (try db.one(struct { count: i64 }, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('containers','images','secrets','agents','assignments');", .{}, .{})).?;
    if (identity.count != 5) return error.InvalidStateSchema;
    try backup_schema.validateExistingTriggers(db.db);
    try schema.init(db);
    try backup_schema.validate(db.db);
    try integrity(db);
}

pub fn validateVoters(voters: []const u8, node_id: u64) !void {
    if (node_id == 0 or node_id > std.math.maxInt(i64) or voters.len == 0 or voters.len > 4096 or voters[voters.len - 1] != ',') return error.InvalidMembership;
    var tokens = std.mem.splitScalar(u8, voters[0 .. voters.len - 1], ',');
    var previous: u64 = 0;
    var found = false;
    while (tokens.next()) |token| {
        const member = std.fmt.parseInt(u64, token, 10) catch return error.InvalidMembership;
        if (member <= previous or member > std.math.maxInt(i64)) return error.InvalidMembership;
        var canonical: [20]u8 = undefined;
        if (!std.mem.eql(u8, token, try std.fmt.bufPrint(&canonical, "{d}", .{member}))) return error.InvalidMembership;
        if (member == node_id) found = true;
        previous = member;
    }
    if (!found) return error.InvalidMembership;
}

pub fn readBoundary(alloc: std.mem.Allocator, raft: *sqlite.Db, state: *sqlite.Db) !Boundary {
    try integrity(raft);
    try validateRaftSchema(raft);
    const bad_schema = (try raft.one(struct { count: i64 }, "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view');", .{}, .{})).?;
    if (bad_schema.count != 0) return error.InvalidRaftSchema;
    const membership = (try raft.oneAlloc(struct { node_id: i64, voters: []const u8 }, alloc, "SELECT node_id,voters FROM static_membership WHERE id=1;", .{}, .{})) orelse return error.InvalidMembership;
    errdefer alloc.free(membership.voters);
    const node_id = std.math.cast(u64, membership.node_id) orelse return error.InvalidMembership;
    try validateVoters(membership.voters, node_id);
    const persistent = (try raft.one(struct { current_term: i64, voted_for: ?i64 }, "SELECT current_term,voted_for FROM raft_state WHERE id=1;", .{}, .{})) orelse return error.InvalidRaftState;
    const term = std.math.cast(u64, persistent.current_term) orelse return error.InvalidRaftState;
    if (persistent.voted_for) |vote| {
        var voter_buf: [24]u8 = undefined;
        const voter = try std.fmt.bufPrint(&voter_buf, "{d},", .{vote});
        var found = false;
        var tokens = std.mem.splitScalar(u8, membership.voters, ',');
        while (tokens.next()) |token| {
            if (std.mem.eql(u8, token, voter[0 .. voter.len - 1])) found = true;
        }
        if (!found) return error.InvalidRaftState;
    }
    const snapshot = (try raft.one(struct { index: i64, term: i64, size: i64 }, "SELECT last_included_index,last_included_term,data_len FROM snapshot_meta WHERE id=1;", .{}, .{})) orelse return error.InvalidRaftState;
    const snapshot_index = std.math.cast(u64, snapshot.index) orelse return error.InvalidRaftState;
    const snapshot_term = std.math.cast(u64, snapshot.term) orelse return error.InvalidRaftState;
    const snapshot_size = std.math.cast(u64, snapshot.size) orelse return error.InvalidRaftState;
    if (snapshot_term > term or (snapshot_index == 0 and (snapshot_term != 0 or snapshot_size != 0))) return error.InvalidRaftState;
    const state_rows = (try state.one(struct { count: i64 }, "SELECT COUNT(*) FROM state_machine_meta;", .{}, .{})).?;
    if (state_rows.count != 1) return error.InvalidStateBoundary;
    const applied = (try state.one(struct { index: i64 }, "SELECT last_applied FROM state_machine_meta WHERE id=1;", .{}, .{})) orelse return error.InvalidStateBoundary;
    const last_applied = std.math.cast(u64, applied.index) orelse return error.InvalidStateBoundary;
    const suffix = (try raft.one(struct { count: i64, min: ?i64, max: ?i64, invalid: i64 }, "SELECT COUNT(*),MIN(log_index),MAX(log_index),COALESCE(SUM(term < 0 OR term > ?),0) FROM raft_log;", .{}, .{persistent.current_term})).?;
    var last_log_index = snapshot_index;
    if (suffix.count > 0) {
        if (snapshot.index == std.math.maxInt(i64) or suffix.min.? != snapshot.index + 1 or suffix.max.? - suffix.min.? + 1 != suffix.count or suffix.invalid != 0) return error.InvalidLogBoundary;
        last_log_index = std.math.cast(u64, suffix.max.?) orelse return error.InvalidLogBoundary;
    }
    if (last_applied < snapshot_index or last_applied > last_log_index) return error.InvalidStateBoundary;
    return .{ .node_id = node_id, .voters = membership.voters, .current_term = term, .last_applied = last_applied, .last_log_index = last_log_index, .snapshot_index = snapshot_index, .snapshot_term = snapshot_term, .snapshot_size = snapshot_size };
}

fn validateRaftSchema(actual: *sqlite.Db) !void {
    var expected = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer expected.deinit();
    try @import("../log/schema_support.zig").initSchema(&expected);
    try expected.exec("CREATE TABLE static_membership (id INTEGER PRIMARY KEY CHECK (id = 1), node_id INTEGER NOT NULL, voters TEXT NOT NULL);", .{}, .{});
    const query = "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name;";
    var left = try expected.prepare(query);
    defer left.deinit();
    var right = try actual.prepare(query);
    defer right.deinit();
    while (true) {
        const a = c.sqlite3_step(left.stmt);
        const b = c.sqlite3_step(right.stmt);
        if (a != b) return error.InvalidRaftSchema;
        if (a == c.SQLITE_DONE) break;
        if (a != c.SQLITE_ROW) return error.InvalidRaftSchema;
        for (0..4) |column| {
            const x = c.sqlite3_column_text(left.stmt, @intCast(column)) orelse return error.InvalidRaftSchema;
            const y = c.sqlite3_column_text(right.stmt, @intCast(column)) orelse return error.InvalidRaftSchema;
            if (!sameDefinition(std.mem.span(x), std.mem.span(y))) return error.InvalidRaftSchema;
        }
    }
    const counts = (try actual.one(struct { state: i64, snapshot: i64, membership: i64 }, "SELECT (SELECT COUNT(*) FROM raft_state),(SELECT COUNT(*) FROM snapshot_meta),(SELECT COUNT(*) FROM static_membership);", .{}, .{})).?;
    if (counts.state != 1 or counts.snapshot != 1 or counts.membership != 1) return error.InvalidRaftState;
}

fn sameDefinition(left: []const u8, right: []const u8) bool {
    var a: usize = 0;
    var b: usize = 0;
    while (true) {
        while (a < left.len and std.ascii.isWhitespace(left[a])) : (a += 1) {}
        while (b < right.len and std.ascii.isWhitespace(right[b])) : (b += 1) {}
        if (a == left.len or b == right.len) return a == left.len and b == right.len;
        if (std.ascii.toLower(left[a]) != std.ascii.toLower(right[b])) return false;
        a += 1;
        b += 1;
    }
}
