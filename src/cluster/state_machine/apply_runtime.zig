const std = @import("std");
const sqlite = @import("sqlite");
const types = @import("../raft_types.zig");
const log = @import("../../lib/log.zig");
const raft_log_mod = @import("../log.zig");
const sql_guard = @import("sql_guard.zig");
const db_runtime = @import("db_runtime.zig");

const LogEntry = types.LogEntry;
const LogIndex = types.LogIndex;
const Log = raft_log_mod.Log;

pub fn apply(self: anytype, entry: LogEntry) void {
    if (entry.index <= self.last_applied) return;
    if (entry.index != self.last_applied + 1) {
        log.warn("state machine: refusing out-of-order entry {d} (last_applied={d})", .{ entry.index, self.last_applied });
        return;
    }

    if (!sql_guard.isAllowedStatement(entry.data)) {
        log.warn("state machine: rejected disallowed SQL at entry {d}", .{entry.index});
        return;
    }

    applyBatch(&self.db, entry) catch |err| {
        log.err("state machine: failed to apply entry {d}: {}", .{ entry.index, err });
        return;
    };
    self.last_applied = entry.index;
}

/// The entire entry has already passed the guard. Use the same iterator to
/// execute every statement, keeping the mutations and replay position in one
/// transaction. Neither a later statement failure nor a failed commit may
/// leave a partial batch or advance the in-memory position.
fn applyBatch(db: *sqlite.Db, entry: LogEntry) !void {
    try db_runtime.execStatement(db, "BEGIN IMMEDIATE;", .{});
    errdefer {
        // SQLite may already have rolled back on a storage/constraint error.
        if (sqlite.c.sqlite3_get_autocommit(db.db) == 0) {
            db_runtime.execStatement(db, "ROLLBACK;", .{}) catch |err| {
                log.err("state machine: failed to roll back entry {d}: {}", .{ entry.index, err });
            };
        }
    }

    var statements = sql_guard.StatementIterator{ .sql = entry.data };
    while (statements.next()) |sql| {
        try db_runtime.execStatement(db, sql, .{});
    }
    try db_runtime.setLastApplied(db, entry.index);
    try db_runtime.execStatement(db, "COMMIT;", .{});
}

pub fn applyUpTo(self: anytype, raft_log: *Log, alloc: std.mem.Allocator, up_to: LogIndex) void {
    var idx = self.last_applied + 1;
    while (idx <= up_to) : (idx += 1) {
        const entry = (raft_log.getEntry(alloc, idx) catch {
            log.warn("state_machine: failed to read log entry {d}, stopping apply", .{idx});
            break;
        }) orelse {
            log.warn("state_machine: missing log entry {d}, stopping apply", .{idx});
            break;
        };
        defer alloc.free(entry.data);
        apply(self, entry);
        if (self.last_applied != idx) break;
    }
}
