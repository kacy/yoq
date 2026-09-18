//! durable assignment attempts and status reports. a terminal result fences
//! duplicate starts until an authoritative assignment snapshot retires it.
const std = @import("std");
const sqlite = @import("sqlite");
const cache = @import("../agent_store.zig");

pub const max_attempts = 8192;
pub const schema =
    \\CREATE TABLE IF NOT EXISTS assignment_results (
    \\    agent_id TEXT NOT NULL,
    \\    assignment_id TEXT NOT NULL,
    \\    generation INTEGER NOT NULL,
    \\    status TEXT NOT NULL,
    \\    reason TEXT,
    \\    container_id TEXT,
    \\    revision INTEGER NOT NULL DEFAULT 0,
    \\    delivered INTEGER NOT NULL DEFAULT 0,
    \\    attempts INTEGER NOT NULL DEFAULT 0,
    \\    PRIMARY KEY (agent_id, assignment_id, generation)
    \\);
;

pub const Result = struct {
    assignment_id: []const u8,
    generation: i64,
    status: []const u8,
    reason: ?[]const u8,
    container_id: ?[]const u8,
    revision: i64,
    delivered: i64,

    pub fn deinit(self: Result, alloc: std.mem.Allocator) void {
        alloc.free(self.assignment_id);
        alloc.free(self.status);
        if (self.reason) |value| alloc.free(value);
        if (self.container_id) |value| alloc.free(value);
    }

    pub fn terminal(self: Result) bool {
        return std.mem.eql(u8, self.status, "stopped") or std.mem.eql(u8, self.status, "failed");
    }
};

pub fn claim(agent: []const u8, id: []const u8, generation: i64) !bool {
    const db = try cache.lockDb();
    defer cache.unlockDb();
    const existing = try db.one(struct { present: i64 }, "SELECT 1 AS present FROM assignment_results WHERE agent_id = ? AND assignment_id = ? AND generation = ?;", .{}, .{ agent, id, generation });
    if (existing != null) return false;
    const count = (try db.one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignment_results;", .{}, .{})).?;
    // stop admitting work when results cannot drain; never evict an undelivered
    // terminal report to make room for a new workload.
    if (count.count >= max_attempts) return error.ResultQueueFull;
    try db.exec("INSERT INTO assignment_results (agent_id, assignment_id, generation, status) VALUES (?, ?, ?, 'starting');", .{}, .{ agent, id, generation });
    return true;
}

pub fn attachContainer(agent: []const u8, id: []const u8, generation: i64, container_id: []const u8) !void {
    const db = try cache.lockDb();
    defer cache.unlockDb();
    try db.exec("UPDATE assignment_results SET container_id = ? WHERE agent_id = ? AND assignment_id = ? AND generation = ? AND status = 'starting';", .{}, .{ container_id, agent, id, generation });
}

pub fn record(agent: []const u8, id: []const u8, generation: i64, status: []const u8, reason: ?[]const u8) !void {
    const db = try cache.lockDb();
    defer cache.unlockDb();
    // only the first terminal result wins. a delayed running report cannot
    // replace it, even if another thread is acknowledging an older revision.
    try db.exec("UPDATE assignment_results SET status = ?, reason = ?, revision = revision + 1, delivered = 0 WHERE agent_id = ? AND assignment_id = ? AND generation = ? AND status IN ('starting', 'running');", .{}, .{ status, reason, agent, id, generation });
}

pub fn acknowledge(agent: []const u8, result: Result) !void {
    const db = try cache.lockDb();
    defer cache.unlockDb();
    try db.exec("UPDATE assignment_results SET delivered = 1 WHERE agent_id = ? AND assignment_id = ? AND generation = ? AND revision = ?;", .{}, .{ agent, result.assignment_id, result.generation, result.revision });
}

pub fn attempted(agent: []const u8, result: Result) !void {
    const db = try cache.lockDb();
    defer cache.unlockDb();
    try db.exec("UPDATE assignment_results SET attempts = attempts + 1 WHERE agent_id = ? AND assignment_id = ? AND generation = ?;", .{}, .{ agent, result.assignment_id, result.generation });
}

pub fn retire(agent: []const u8, result: Result) !void {
    const db = try cache.lockDb();
    defer cache.unlockDb();
    try db.exec("DELETE FROM assignment_results WHERE agent_id = ? AND assignment_id = ? AND generation = ? AND revision = ? AND delivered = 1 AND status IN ('stopped', 'failed');", .{}, .{ agent, result.assignment_id, result.generation, result.revision });
}

pub fn list(alloc: std.mem.Allocator, agent: []const u8) ![]Result {
    const db = try cache.lockDb();
    defer cache.unlockDb();
    const Row = struct { assignment_id: sqlite.Text, generation: i64, status: sqlite.Text, reason: ?sqlite.Text, container_id: ?sqlite.Text, revision: i64, delivered: i64 };
    var stmt = try db.prepare("SELECT assignment_id, generation, status, reason, container_id, revision, delivered FROM assignment_results WHERE agent_id = ? ORDER BY attempts, assignment_id, generation;");
    defer stmt.deinit();
    var iter = try stmt.iterator(Row, .{agent});
    var results: std.ArrayList(Result) = .empty;
    errdefer {
        for (results.items) |result| result.deinit(alloc);
        results.deinit(alloc);
    }
    while (try iter.nextAlloc(alloc, .{})) |row| {
        const result: Result = .{ .assignment_id = row.assignment_id.data, .generation = row.generation, .status = row.status.data, .reason = if (row.reason) |value| value.data else null, .container_id = if (row.container_id) |value| value.data else null, .revision = row.revision, .delivered = row.delivered };
        results.append(alloc, result) catch |err| {
            result.deinit(alloc);
            return err;
        };
    }
    return results.toOwnedSlice(alloc);
}

test "agent recovery result outbox survives reopen and ignores stale acknowledgments" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(std.testing.io, ".", alloc);
    defer alloc.free(dir);
    try cache.init(dir);
    defer cache.closeDb();
    try std.testing.expect(try claim("agent", "assignment", 3));
    try record("agent", "assignment", 3, "running", null);
    const running = try list(alloc, "agent");
    defer {
        for (running) |result| result.deinit(alloc);
        alloc.free(running);
    }
    try record("agent", "assignment", 3, "failed", "process_failed");
    try acknowledge("agent", running[0]);
    try record("agent", "assignment", 3, "running", null);
    cache.closeDb();
    try cache.init(dir);
    const restored = try list(alloc, "agent");
    defer {
        for (restored) |result| result.deinit(alloc);
        alloc.free(restored);
    }
    try std.testing.expectEqual(@as(usize, 1), restored.len);
    try std.testing.expectEqualStrings("failed", restored[0].status);
    try std.testing.expectEqual(@as(i64, 0), restored[0].delivered);
    try std.testing.expect(!try claim("agent", "assignment", 3));
    try std.testing.expect(try claim("agent", "assignment", 4));
    try acknowledge("agent", restored[0]);
    try retire("agent", restored[0]);
    const other_agent = try list(alloc, "other-agent");
    defer alloc.free(other_agent);
    try std.testing.expectEqual(@as(usize, 0), other_agent.len);
}
