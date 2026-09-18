const std = @import("std");

const max_services = 1024;
const samples_per_service = 256;
const window_ns = 60 * std.time.ns_per_s;
const alloc = std.heap.page_allocator;
var mutex: std.Io.Mutex = .init;
var services: std.StringHashMapUnmanaged(History) = .{};

const Sample = struct { at_ns: u64, duration_ns: u64, failed: bool };
const History = struct {
    samples: [samples_per_service]Sample = undefined,
    count: usize = 0,
    next: usize = 0,
    last_seen_ns: u64 = 0,
};

pub const Snapshot = struct {
    samples: usize,
    latency_p99_ms: f64,
    error_rate_percent: f64,
};

pub fn nowNs() u64 {
    return @intCast(@max(0, std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds()));
}

// a completed logical request contributes once, including time spent retrying.
// the newest 256 observations expire after a minute; idle traffic is unknown.
pub fn record(service: []const u8, started_ns: u64, failed: bool) void {
    if (started_ns == 0) return;
    const now = nowNs();
    recordAt(service, now -| started_ns, failed, now);
}

fn recordAt(service: []const u8, duration_ns: u64, failed: bool, now_ns: u64) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    if (!services.contains(service)) {
        if (services.count() == max_services) {
            var entries = services.iterator();
            var expired: ?[]const u8 = null;
            while (entries.next()) |entry| {
                if (now_ns -| entry.value_ptr.last_seen_ns > window_ns) {
                    expired = entry.key_ptr.*;
                    break;
                }
            }
            const key = expired orelse return;
            _ = services.remove(key);
            alloc.free(key);
        }
        const key = alloc.dupe(u8, service) catch return;
        services.put(alloc, key, .{}) catch {
            alloc.free(key);
            return;
        };
    }
    const history = services.getPtr(service).?;
    history.samples[history.next] = .{ .at_ns = now_ns, .duration_ns = duration_ns, .failed = failed };
    history.next = (history.next + 1) % samples_per_service;
    history.count = @min(history.count + 1, samples_per_service);
    history.last_seen_ns = now_ns;
}

pub fn snapshot(service: []const u8) ?Snapshot {
    return snapshotAt(service, nowNs());
}

fn snapshotAt(service: []const u8, now_ns: u64) ?Snapshot {
    var durations: [samples_per_service]u64 = undefined;
    var count: usize = 0;
    var failures: usize = 0;
    {
        mutex.lockUncancelable(std.Options.debug_io);
        defer mutex.unlock(std.Options.debug_io);
        const history = services.getPtr(service) orelse return null;
        for (history.samples[0..history.count]) |sample| {
            if (now_ns -| sample.at_ns > window_ns) continue;
            durations[count] = sample.duration_ns;
            count += 1;
            failures += @intFromBool(sample.failed);
        }
    }
    if (count == 0) return null;
    std.mem.sort(u64, durations[0..count], {}, std.sort.asc(u64));
    const percentile_index = (count * 99 + 99) / 100 - 1;
    return .{
        .samples = count,
        .latency_p99_ms = @as(f64, @floatFromInt(durations[percentile_index])) / std.time.ns_per_ms,
        .error_rate_percent = @as(f64, @floatFromInt(failures)) / @as(f64, @floatFromInt(count)) * 100,
    };
}

pub fn reset() void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    var keys = services.keyIterator();
    while (keys.next()) |key| alloc.free(key.*);
    services.deinit(alloc);
    services = .{};
}

test "proxy observations expire idle services and compute p99 from the bounded recent window" {
    reset();
    defer reset();
    for (0..100) |index| recordAt("api", (index + 1) * std.time.ns_per_ms, index < 10, 100);
    const stats = snapshotAt("api", 101).?;
    try std.testing.expectEqual(@as(usize, 100), stats.samples);
    try std.testing.expectEqual(@as(f64, 99), stats.latency_p99_ms);
    try std.testing.expectEqual(@as(f64, 10), stats.error_rate_percent);
    try std.testing.expect(snapshotAt("api", window_ns + 101) == null);
    for (0..samples_per_service + 10) |_| recordAt("api", std.time.ns_per_ms, false, window_ns + 102);
    const replaced = snapshotAt("api", window_ns + 103).?;
    try std.testing.expectEqual(@as(usize, samples_per_service), replaced.samples);
    try std.testing.expectEqual(@as(f64, 1), replaced.latency_p99_ms);
    try std.testing.expectEqual(@as(f64, 0), replaced.error_rate_percent);
}
