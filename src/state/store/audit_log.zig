const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const schema = @import("../schema.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const AuditLogRecord = struct {
    id: i64,
    recorded_at: i64,
    actor: []const u8,
    action: []const u8,
    target: ?[]const u8,
    outcome: []const u8,

    pub fn deinit(self: AuditLogRecord, alloc: Allocator) void {
        alloc.free(self.actor);
        alloc.free(self.action);
        if (self.target) |t| alloc.free(t);
        alloc.free(self.outcome);
    }
};

const audit_columns = "id, recorded_at, actor, action, target, outcome";

const AuditLogRow = struct {
    id: i64,
    recorded_at: i64,
    actor: sqlite.Text,
    action: sqlite.Text,
    target: ?sqlite.Text,
    outcome: sqlite.Text,
};

fn rowToRecord(row: AuditLogRow) AuditLogRecord {
    return .{
        .id = row.id,
        .recorded_at = row.recorded_at,
        .actor = row.actor.data,
        .action = row.action.data,
        .target = if (row.target) |t| t.data else null,
        .outcome = row.outcome.data,
    };
}

/// append an audit entry. append-only — there is no update or delete path.
pub fn appendAuditEntry(
    actor: []const u8,
    action: []const u8,
    target: ?[]const u8,
    outcome: []const u8,
    recorded_at: i64,
) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();
    return appendAuditEntryInDb(lease.db, actor, action, target, outcome, recorded_at);
}

pub fn appendAuditEntryInDb(
    db: *sqlite.Db,
    actor: []const u8,
    action: []const u8,
    target: ?[]const u8,
    outcome: []const u8,
    recorded_at: i64,
) StoreError!void {
    db.exec(
        "INSERT INTO audit_log (recorded_at, actor, action, target, outcome) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ recorded_at, actor, action, target, outcome },
    ) catch return StoreError.WriteFailed;
}

/// list the most recent audit entries, newest first, capped at `limit`.
pub fn listAuditEntries(alloc: Allocator, limit: u32) StoreError!std.ArrayList(AuditLogRecord) {
    var lease = try common.leaseDb();
    defer lease.deinit();
    return listAuditEntriesInDb(lease.db, alloc, limit);
}

pub fn listAuditEntriesInDb(db: *sqlite.Db, alloc: Allocator, limit: u32) StoreError!std.ArrayList(AuditLogRecord) {
    var records: std.ArrayList(AuditLogRecord) = .empty;
    var stmt = db.prepare(
        "SELECT " ++ audit_columns ++ " FROM audit_log ORDER BY id DESC LIMIT ?;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(AuditLogRow, .{@as(i64, limit)}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        records.append(alloc, rowToRecord(row)) catch return StoreError.ReadFailed;
    }
    return records;
}

test "audit log append and list newest-first with limit" {
    const alloc = std.testing.allocator;
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try appendAuditEntryInDb(&db, "api-token", "secret_set", "db-password", "ok", 100);
    try appendAuditEntryInDb(&db, "local", "backup", null, "ok", 200);
    try appendAuditEntryInDb(&db, "api-token", "policy_add", "web->db", "ok", 300);

    var records = try listAuditEntriesInDb(&db, alloc, 2);
    defer {
        for (records.items) |r| r.deinit(alloc);
        records.deinit(alloc);
    }

    // limit respected, newest first
    try std.testing.expectEqual(@as(usize, 2), records.items.len);
    try std.testing.expectEqualStrings("policy_add", records.items[0].action);
    try std.testing.expectEqualStrings("backup", records.items[1].action);
    // null target round-trips
    try std.testing.expect(records.items[1].target == null);
    try std.testing.expectEqualStrings("web->db", records.items[0].target.?);
}
