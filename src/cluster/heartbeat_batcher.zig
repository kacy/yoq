// heartbeat_batcher — batches agent heartbeats for efficient raft proposals
//
// HTTP threads call record() on every heartbeat request, which deduplicates
// by agent ID and keeps the latest entry. the tick loop periodically calls
// flush() to drain the buffer into a single concatenated SQL string that
// gets proposed through raft as one entry instead of N individual proposals.
//
// uses its own mutex (not node.mu) so HTTP threads and the tick loop
// never contend on the raft lock for heartbeat writes.

const std = @import("std");
const platform = @import("platform");
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

    /// record a heartbeat from an agent. deduplicates by agent ID,
    /// keeping the latest entry. safe to call from any thread.
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

    /// drain the buffer and build concatenated SQL. returns null if empty.
    /// caller must free the returned slice.
    pub fn flush(self: *HeartbeatBatcher, alloc: Allocator) !?[]const u8 {
        // swap entries out under lock
        var entries: []Entry = &.{};
        {
            self.mu.lockUncancelable(std.Options.debug_io);
            defer self.mu.unlock(std.Options.debug_io);

            if (self.buffer.count() == 0) return null;

            const values = self.buffer.values();
            entries = try alloc.alloc(Entry, values.len);
            @memcpy(entries, values);
            self.buffer.clearRetainingCapacity();
        }
        defer alloc.free(entries);

        // build concatenated SQL outside the lock
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

    // should contain UPDATE statement with the agent ID
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

test "deduplicates by agent ID" {
    const alloc = std.testing.allocator;
    var batcher = HeartbeatBatcher.init(alloc);
    defer batcher.deinit();

    // record same agent twice — second should overwrite
    batcher.record("agent1234567", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 1,
        .memory_used_mb = 1000,
        .containers = 1,
    }, 1000);

    batcher.record("agent1234567", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 3,
        .memory_used_mb = 6000,
        .containers = 5,
    }, 2000);

    const sql = try batcher.flush(alloc);
    try std.testing.expect(sql != null);
    defer alloc.free(sql.?);

    // should only have one UPDATE (no separator space means single entry)
    // count occurrences of "UPDATE agents"
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

    const sql = try batcher.flush(alloc);
    try std.testing.expect(sql != null);
    defer alloc.free(sql.?);

    // should contain both agent IDs
    try std.testing.expect(std.mem.indexOf(u8, sql.?, "aaaa11112222") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql.?, "bbbb33334444") != null);

    // should have two UPDATE statements
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

    // second flush should return null
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
