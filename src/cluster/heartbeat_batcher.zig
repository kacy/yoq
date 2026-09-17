// batch agent heartbeats into one raft proposal
//
// http threads call record() for each heartbeat. the buffer keeps the last
// recorded entry for each agent, regardless of its timestamp. the tick loop
// calls flush() to drain those entries into one sql string for raft.
//
// a separate mutex protects the buffer without taking the raft lock.

const std = @import("std");
const agent_types = @import("agent_types.zig");
const registry = @import("registry.zig");

const Allocator = std.mem.Allocator;
pub const AgentResources = agent_types.AgentResources;

pub const Entry = struct {
    id: [12]u8,
    resources: AgentResources,
    timestamp: i64,
};

pub const HeartbeatBatcher = struct {
    alloc: Allocator,
    mu: std.Io.Mutex,
    buffer: std.AutoArrayHashMapUnmanaged([12]u8, Entry),

    pub fn init(alloc: Allocator) HeartbeatBatcher {
        return .{
            .alloc = alloc,
            .mu = .init,
            .buffer = .empty,
        };
    }

    pub fn deinit(self: *HeartbeatBatcher) void {
        self.buffer.deinit(self.alloc);
    }

    /// replace this agent's buffered heartbeat, even if its timestamp is older.
    /// safe to call from any thread.
    pub fn record(self: *HeartbeatBatcher, id: []const u8, resources: AgentResources, now: i64) void {
        if (id.len != 12) return;

        var key: [12]u8 = undefined;
        @memcpy(&key, id[0..12]);

        self.mu.lockUncancelable(std.Options.debug_io);
        defer self.mu.unlock(std.Options.debug_io);

        self.buffer.put(self.alloc, key, .{
            .id = key,
            .resources = resources,
            .timestamp = now,
        }) catch return;
    }

    /// drain the buffer and build sql outside the lock. returns null if empty.
    /// caller must free the returned slice with alloc. if sql construction
    /// fails after the drain, the entries are not restored.
    pub fn flush(self: *HeartbeatBatcher, alloc: Allocator) !?[]const u8 {
        const entries = (try self.drainEntries(alloc)) orelse return null;
        defer alloc.free(entries);
        return formatEntries(alloc, entries);
    }

    fn drainEntries(self: *HeartbeatBatcher, alloc: Allocator) !?[]Entry {
        self.mu.lockUncancelable(std.Options.debug_io);
        defer self.mu.unlock(std.Options.debug_io);

        if (self.buffer.count() == 0) return null;

        // copy before clearing so allocation failure leaves the buffer intact.
        const entries = try alloc.dupe(Entry, self.buffer.values());
        self.buffer.clearRetainingCapacity();
        return entries;
    }

    fn formatEntries(alloc: Allocator, entries: []const Entry) !?[]const u8 {
        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(alloc);

        var sql_buf: [512]u8 = undefined;
        for (entries) |entry| {
            const sql = try registry.heartbeatSql(
                &sql_buf,
                &entry.id,
                entry.resources,
                entry.timestamp,
            );
            if (result.items.len > 0) {
                try result.append(alloc, ' ');
            }
            try result.appendSlice(alloc, sql);
        }

        if (result.items.len == 0) {
            result.deinit(alloc);
            return null;
        }

        return try result.toOwnedSlice(alloc);
    }
};

// -- tests --

test "record and flush single entry" {
    const alloc = std.testing.allocator;
    var batcher = HeartbeatBatcher.init(alloc);
    defer batcher.deinit();

    batcher.record("agent1234567", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 2,
        .memory_used_mb = 4096,
        .containers = 3,
    }, 1000);

    const sql = try batcher.flush(alloc);
    try std.testing.expect(sql != null);
    defer alloc.free(sql.?);

    try std.testing.expect(std.mem.indexOf(u8, sql.?, "agent1234567") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql.?, "UPDATE agents") != null);
}

test "flush returns null when empty" {
    const alloc = std.testing.allocator;
    var batcher = HeartbeatBatcher.init(alloc);
    defer batcher.deinit();

    const sql = try batcher.flush(alloc);
    try std.testing.expect(sql == null);
}

test "record replaces an agent heartbeat even with an older timestamp" {
    const alloc = std.testing.allocator;
    var batcher = HeartbeatBatcher.init(alloc);
    defer batcher.deinit();

    // the second record replaces the first entry.
    batcher.record("agent1234567", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 1,
        .memory_used_mb = 1000,
        .containers = 1,
    }, 2000);

    batcher.record("agent1234567", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 3,
        .memory_used_mb = 6000,
        .containers = 5,
    }, 1000);

    const sql = try batcher.flush(alloc);
    try std.testing.expect(sql != null);
    defer alloc.free(sql.?);

    try std.testing.expect(std.mem.indexOf(u8, sql.?, "cpu_used = 3") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql.?, "memory_used_mb = 6000") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql.?, "containers = 5") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql.?, "last_heartbeat = 1000") != null);

    // replacement produces one update for this agent.
    var count: usize = 0;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, sql.?, pos, "UPDATE agents")) |idx| {
        count += 1;
        pos = idx + 1;
    }
    try std.testing.expectEqual(@as(usize, 1), count);
}

test "batches multiple agents" {
    const alloc = std.testing.allocator;
    var batcher = HeartbeatBatcher.init(alloc);
    defer batcher.deinit();

    batcher.record("aaaa11112222", .{
        .cpu_cores = 2,
        .memory_mb = 4096,
    }, 1000);

    batcher.record("bbbb33334444", .{
        .cpu_cores = 8,
        .memory_mb = 16384,
        .cpu_used = 4,
        .memory_used_mb = 8000,
        .containers = 10,
    }, 1000);

    // replacing an entry keeps its original position in the batch.
    batcher.record("aaaa11112222", .{ .cpu_cores = 2, .memory_mb = 4096 }, 2000);

    const sql = try batcher.flush(alloc);
    try std.testing.expect(sql != null);
    defer alloc.free(sql.?);

    const first_agent = std.mem.indexOf(u8, sql.?, "aaaa11112222") orelse return error.TestUnexpectedResult;
    const second_agent = std.mem.indexOf(u8, sql.?, "bbbb33334444") orelse return error.TestUnexpectedResult;
    try std.testing.expect(first_agent < second_agent);

    var count: usize = 0;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, sql.?, pos, "UPDATE agents")) |idx| {
        count += 1;
        pos = idx + 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "flush clears buffer" {
    const alloc = std.testing.allocator;
    var batcher = HeartbeatBatcher.init(alloc);
    defer batcher.deinit();

    batcher.record("agent1234567", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
    }, 1000);

    const sql1 = try batcher.flush(alloc);
    try std.testing.expect(sql1 != null);
    alloc.free(sql1.?);

    const sql2 = try batcher.flush(alloc);
    try std.testing.expect(sql2 == null);
}

test "ignores invalid id length" {
    const alloc = std.testing.allocator;
    var batcher = HeartbeatBatcher.init(alloc);
    defer batcher.deinit();

    // too short
    batcher.record("short", .{ .cpu_cores = 1, .memory_mb = 512 }, 1000);
    // too long
    batcher.record("toolongagentid123", .{ .cpu_cores = 1, .memory_mb = 512 }, 1000);

    const sql = try batcher.flush(alloc);
    try std.testing.expect(sql == null);
}

test "flush preserves heartbeats when the snapshot allocation fails" {
    const alloc = std.testing.allocator;
    var batcher = HeartbeatBatcher.init(alloc);
    defer batcher.deinit();
    batcher.record("agent1234567", .{ .cpu_cores = 4, .memory_mb = 8192 }, 1000);

    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, batcher.flush(failing.allocator()));

    const sql = (try batcher.flush(alloc)) orelse return error.TestUnexpectedResult;
    defer alloc.free(sql);
    try std.testing.expect(std.mem.indexOf(u8, sql, "agent1234567") != null);
    try std.testing.expect((try batcher.flush(alloc)) == null);
}

test "flush leaves heartbeats drained when sql allocation fails" {
    const alloc = std.testing.allocator;
    var batcher = HeartbeatBatcher.init(alloc);
    defer batcher.deinit();
    batcher.record("agent1234567", .{ .cpu_cores = 4, .memory_mb = 8192 }, 1000);

    // allow the snapshot allocation, then fail the sql buffer allocation.
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 1 });
    try std.testing.expectError(error.OutOfMemory, batcher.flush(failing.allocator()));
    try std.testing.expect((try batcher.flush(alloc)) == null);

    batcher.record("agent1234567", .{ .cpu_cores = 4, .memory_mb = 8192 }, 2000);
    const sql = (try batcher.flush(alloc)) orelse return error.TestUnexpectedResult;
    defer alloc.free(sql);
    try std.testing.expect(std.mem.indexOf(u8, sql, "last_heartbeat = 2000") != null);
}
