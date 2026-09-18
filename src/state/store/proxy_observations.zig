const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");

pub const samples_per_writer = 256;
pub const writers_per_service = 8;
pub const max_rows = 4096;
pub const window_ns = 60 * std.time.ns_per_s;
pub const Sample = struct { at_ns: u64, duration_ns: u64, failed: bool };

pub const History = struct { service: []const u8, samples: []const Sample };

pub fn save(alloc: std.mem.Allocator, service: []const u8, producer: []const u8, boot: []const u8, samples: []const Sample, now_ns: u64) !void {
    return saveBatch(alloc, producer, boot, &.{.{ .service = service, .samples = samples }}, now_ns);
}

pub fn saveBatch(alloc: std.mem.Allocator, producer: []const u8, boot: []const u8, histories: []const History, now_ns: u64) !void {
    if (histories.len == 0) return;
    var lease = try common.leaseDb();
    defer lease.deinit();
    try lease.db.exec("BEGIN IMMEDIATE;", .{}, .{});
    errdefer lease.db.exec("ROLLBACK;", .{}, .{}) catch {};
    try lease.db.exec("DELETE FROM proxy_observations WHERE boot != ? OR updated_ns < ?;", .{}, .{ boot, @as(i64, @intCast(now_ns -| window_ns)) });
    for (histories) |history| {
        if (history.samples.len > samples_per_writer) return error.TooManySamples;
        const json = try std.json.Stringify.valueAlloc(alloc, history.samples, .{});
        defer alloc.free(json);
        try lease.db.exec(
            "INSERT INTO proxy_observations (service, producer, boot, updated_ns, history_json) VALUES (?, ?, ?, ?, ?) " ++
                "ON CONFLICT(service, producer) DO UPDATE SET boot = excluded.boot, updated_ns = excluded.updated_ns, history_json = excluded.history_json;",
            .{},
            .{ history.service, producer, boot, @as(i64, @intCast(now_ns)), json },
        );
        try lease.db.exec("DELETE FROM proxy_observations WHERE service = ? AND rowid NOT IN (SELECT rowid FROM proxy_observations WHERE service = ? ORDER BY updated_ns DESC, rowid DESC LIMIT 8);", .{}, .{ history.service, history.service });
    }
    try lease.db.exec("DELETE FROM proxy_observations WHERE rowid NOT IN (SELECT rowid FROM proxy_observations ORDER BY updated_ns DESC, rowid DESC LIMIT 4096);", .{}, .{});
    try lease.db.exec("COMMIT;", .{}, .{});
}

pub fn appendForeign(alloc: std.mem.Allocator, service: []const u8, producer: []const u8, boot: []const u8, now_ns: u64, output: []Sample) !usize {
    var lease = try common.leaseDb();
    defer lease.deinit();
    var statement = try lease.db.prepare("SELECT history_json FROM proxy_observations WHERE service = ? AND producer != ? AND boot = ? AND updated_ns >= ? ORDER BY updated_ns DESC LIMIT 8;");
    defer statement.deinit();
    var rows = try statement.iterator(struct { history_json: sqlite.Text }, .{ service, producer, boot, @as(i64, @intCast(now_ns -| window_ns)) });
    var count: usize = 0;
    while (try rows.nextAlloc(alloc, .{})) |row| {
        defer alloc.free(row.history_json.data);
        if (row.history_json.data.len > 64 * 1024) return error.InvalidHistory;
        const parsed = try std.json.parseFromSlice([]Sample, alloc, row.history_json.data, .{});
        defer parsed.deinit();
        if (parsed.value.len > samples_per_writer) return error.InvalidHistory;
        for (parsed.value) |sample| {
            if (sample.at_ns > now_ns or now_ns - sample.at_ns > window_ns) continue;
            if (count == output.len) return error.TooManySamples;
            output[count] = sample;
            count += 1;
        }
    }
    return count;
}

test "persisted proxy histories isolate boots expire samples and bound producer rows" {
    const store = @import("../store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    const sample = Sample{ .at_ns = 100, .duration_ns = 20, .failed = true };
    try save(alloc, "api", "writer", "boot", &.{sample}, 100);
    var output: [samples_per_writer * writers_per_service]Sample = undefined;
    try std.testing.expectEqual(@as(usize, 1), try appendForeign(alloc, "api", "reader", "boot", 101, &output));
    try std.testing.expectEqual(@as(usize, 0), try appendForeign(alloc, "api", "reader", "other-boot", 101, &output));
    try std.testing.expectEqual(@as(usize, 0), try appendForeign(alloc, "api", "reader", "boot", window_ns + 101, &output));
    for (0..writers_per_service + 3) |index| {
        var producer: [32]u8 = undefined;
        try save(alloc, "api", try std.fmt.bufPrint(&producer, "writer-{d}", .{index}), "boot", &.{sample}, 101 + index);
    }
    try std.testing.expectEqual(@as(usize, writers_per_service), try appendForeign(alloc, "api", "reader", "boot", 120, &output));
    try save(alloc, "api", "fresh-writer", "fresh-boot", &.{sample}, 100);
    try std.testing.expectEqual(@as(usize, 0), try appendForeign(alloc, "api", "reader", "boot", 120, &output));
}

test "proxy history batch rolls back earlier services when a later history is invalid" {
    const store = @import("../store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    const sample = Sample{ .at_ns = 100, .duration_ns = 20, .failed = false };
    const too_many = [_]Sample{sample} ** (samples_per_writer + 1);
    try std.testing.expectError(error.TooManySamples, saveBatch(std.testing.allocator, "writer", "boot", &.{
        .{ .service = "valid", .samples = &.{sample} },
        .{ .service = "invalid", .samples = &too_many },
    }, 101));
    var output: [samples_per_writer]Sample = undefined;
    try std.testing.expectEqual(@as(usize, 0), try appendForeign(std.testing.allocator, "valid", "reader", "boot", 102, &output));
}
