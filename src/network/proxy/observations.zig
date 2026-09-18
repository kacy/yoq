const std = @import("std");
const history_store = @import("../../state/store/proxy_observations.zig");
const platform = @import("linux_platform");
const log = @import("../../lib/log.zig");

const max_services = 1024;
const samples_per_service = 256;
const window_ns = 60 * std.time.ns_per_s;
const alloc = std.heap.page_allocator;
var mutex: std.Io.Mutex = .init;
var services: std.StringHashMapUnmanaged(History) = .{};

const Sample = history_store.Sample;
const Identity = struct { boot: [36]u8, producer: [32]u8 };
var identity: ?Identity = null;
var last_published_ns: u64 = 0;
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

fn identityLocked() !Identity {
    if (identity) |value| return value;
    var boot_buffer: [64]u8 = undefined;
    const raw = try platform.cwd().readFile("/proc/sys/kernel/random/boot_id", &boot_buffer);
    const boot = std.mem.trim(u8, raw, "\r\n ");
    if (boot.len != 36) return error.InvalidBootIdentity;
    var random: [16]u8 = undefined;
    platform.randomBytes(&random);
    identity = .{ .boot = boot[0..36].*, .producer = std.fmt.bytesToHex(random, .lower) };
    return identity.?;
}

// publish off the request path. a fresh random producer id avoids treating a
// reused pid as the previous proxy, while boot ids scope monotonic timestamps.
pub fn flush() void {
    flushAt(nowNs()) catch |err| log.warn("proxy observations: cannot publish request history: {s}", .{@errorName(err)});
}

fn flushAt(now_ns: u64) !void {
    const Owned = struct { service: []u8, history: History };
    var copies: std.ArrayList(Owned) = .empty;
    defer {
        for (copies.items) |copy| alloc.free(copy.service);
        copies.deinit(alloc);
    }
    const source = blk: {
        mutex.lockUncancelable(std.Options.debug_io);
        defer mutex.unlock(std.Options.debug_io);
        if (services.count() == 0) return;
        if (last_published_ns != 0 and now_ns -| last_published_ns < 5 * std.time.ns_per_s) return;
        const source = try identityLocked();
        var iterator = services.iterator();
        while (iterator.next()) |entry| {
            if (now_ns -| entry.value_ptr.last_seen_ns > window_ns) continue;
            const name = try alloc.dupe(u8, entry.key_ptr.*);
            copies.append(alloc, .{ .service = name, .history = entry.value_ptr.* }) catch |err| {
                alloc.free(name);
                return err;
            };
        }
        last_published_ns = now_ns;
        break :blk source;
    };
    for (copies.items) |copy| try history_store.save(alloc, copy.service, &source.producer, &source.boot, copy.history.samples[0..copy.history.count], now_ns);
}

pub fn snapshotShared(service: []const u8) !?Snapshot {
    return snapshotSharedAt(service, nowNs());
}

fn snapshotSharedAt(service: []const u8, now_ns: u64) !?Snapshot {
    var samples: [samples_per_service * (history_store.writers_per_service + 1)]Sample = undefined;
    var count: usize = 0;
    const source = blk: {
        mutex.lockUncancelable(std.Options.debug_io);
        defer mutex.unlock(std.Options.debug_io);
        if (services.getPtr(service)) |history| {
            for (history.samples[0..history.count]) |sample| {
                if (sample.at_ns > now_ns or now_ns - sample.at_ns > window_ns) continue;
                samples[count] = sample;
                count += 1;
            }
        }
        break :blk try identityLocked();
    };
    count += try history_store.appendForeign(alloc, service, &source.producer, &source.boot, now_ns, samples[count..]);
    if (count == 0) return null;
    std.mem.sort(Sample, samples[0..count], {}, struct {
        fn lessThan(_: void, a: Sample, b: Sample) bool {
            return a.at_ns < b.at_ns;
        }
    }.lessThan);
    const recent = samples[count - @min(count, samples_per_service) .. count];
    var durations: [samples_per_service]u64 = undefined;
    var failures: usize = 0;
    for (recent, 0..) |sample, index| {
        durations[index] = sample.duration_ns;
        failures += @intFromBool(sample.failed);
    }
    std.mem.sort(u64, durations[0..recent.len], {}, std.sort.asc(u64));
    return .{
        .samples = recent.len,
        .latency_p99_ms = @as(f64, @floatFromInt(durations[(recent.len * 99 + 99) / 100 - 1])) / std.time.ns_per_ms,
        .error_rate_percent = @as(f64, @floatFromInt(failures)) / @as(f64, @floatFromInt(recent.len)) * 100,
    };
}

pub fn reset() void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    var keys = services.keyIterator();
    while (keys.next()) |key| alloc.free(key.*);
    services.deinit(alloc);
    services = .{};
    identity = null;
    last_published_ns = 0;
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

test "proxy observations cross a producer restart through the persisted bounded history" {
    const store = @import("../../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    reset();
    defer reset();
    recordAt("api", 20 * std.time.ns_per_ms, true, 100);
    try flushAt(101);
    reset();
    try std.testing.expect(snapshotAt("api", 102) == null);
    const shared = (try snapshotSharedAt("api", 102)).?;
    try std.testing.expectEqual(@as(f64, 20), shared.latency_p99_ms);
    try std.testing.expectEqual(@as(f64, 100), shared.error_rate_percent);
    try std.testing.expect((try snapshotSharedAt("api", window_ns + 102)) == null);
}
