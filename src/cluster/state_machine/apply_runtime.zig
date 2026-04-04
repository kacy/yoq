const std = @import("std");
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

    self.db.execDynamic(entry.data, .{}, .{}) catch |err| {
        log.err("state machine: failed to apply entry {d}: {}", .{ entry.index, err });
        return;
    };
    db_runtime.setLastApplied(&self.db, entry.index) catch |err| {
        log.err("state machine: failed to persist last_applied {d}: {}", .{ entry.index, err });
        return;
    };
    self.last_applied = entry.index;
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
