const std = @import("std");
const cgroups = @import("../../runtime/cgroups.zig");
const store = @import("../../state/store.zig");
const observations = @import("../../network/proxy/observations.zig");

const alloc = std.heap.page_allocator;
const history_samples = 13;
const window_ms = 60_000;

pub const Values = struct {
    cpu_percent: ?f64 = null,
    memory_percent: ?f64 = null,
    restart_count: ?f64 = null,
    latency_p99_ms: ?f64 = null,
    error_rate_percent: ?f64 = null,
    resource_error: ?[]const u8 = null,
};

pub const Sampler = struct {
    previous_cpu: std.AutoHashMapUnmanaged([12]u8, u64) = .{},
    previous_ms: ?u64 = null,
    restart_history: [history_samples]struct { at_ms: u64, total: u64 } = undefined,
    restart_samples: usize = 0,
    restart_next: usize = 0,

    pub fn deinit(self: *Sampler) void {
        self.previous_cpu.deinit(alloc);
    }

    pub fn collect(self: *Sampler, app: []const u8, service: []const u8, now_ms: u64, restarts: ?u64) Values {
        var values: Values = .{};
        values.restart_count = if (restarts) |total| self.restartCount(now_ms, total) else null;
        if (observations.snapshot(service)) |traffic| {
            values.latency_p99_ms = traffic.latency_p99_ms;
            values.error_rate_percent = traffic.error_rate_percent;
        }
        var records = store.listAll(alloc) catch {
            values.resource_error = "container state unavailable";
            return values;
        };
        defer {
            for (records.items) |record| record.deinit(alloc);
            records.deinit(alloc);
        }
        var next_cpu: std.AutoHashMapUnmanaged([12]u8, u64) = .{};
        defer {
            self.previous_cpu.deinit(alloc);
            self.previous_cpu = next_cpu;
            self.previous_ms = now_ms;
        }
        var count: usize = 0;
        var cpu_count: usize = 0;
        var memory_count: usize = 0;
        var max_cpu: f64 = 0;
        var max_memory: f64 = 0;
        for (records.items) |record| {
            if (!std.mem.eql(u8, record.app_name orelse "", app) or !std.mem.eql(u8, record.hostname, service) or
                !std.mem.eql(u8, record.status, "running")) continue;
            count += 1;
            if (record.id.len != 12) continue;
            const cg = cgroups.Cgroup.open(record.id) catch continue;
            const metrics = cg.readAllMetrics();
            if (metrics.memory_bytes) |used| {
                if (metrics.memory_limit) |limit| {
                    if (limit > 0) {
                        max_memory = @max(max_memory, @as(f64, @floatFromInt(used)) * 100 / @as(f64, @floatFromInt(limit)));
                        memory_count += 1;
                    }
                }
            }
            const cpu = metrics.cpu_usec orelse continue;
            const key: [12]u8 = record.id[0..12].*;
            next_cpu.put(alloc, key, cpu) catch continue;
            const previous = self.previous_cpu.get(key) orelse continue;
            const previous_ms = self.previous_ms orelse continue;
            if (cpu < previous or now_ms <= previous_ms) continue;
            // without a quota, 100% means one fully occupied cpu core.
            const cores = if (metrics.cpu_max_usec) |quota|
                @as(f64, @floatFromInt(quota)) / @as(f64, @floatFromInt(metrics.cpu_max_period orelse 100_000))
            else
                1;
            if (cores <= 0) continue;
            max_cpu = @max(max_cpu, cpuPercent(cpu - previous, now_ms - previous_ms, cores));
            cpu_count += 1;
        }
        if (count == 0) {
            values.resource_error = "no running containers";
        } else {
            // incomplete replica measurements must not silently report recovery.
            if (cpu_count == count) values.cpu_percent = max_cpu;
            if (memory_count == count) values.memory_percent = max_memory;
            if (cpu_count != count or memory_count != count) values.resource_error = "cgroup sample or resource limit unavailable";
        }
        return values;
    }

    fn restartCount(self: *Sampler, now_ms: u64, total: u64) f64 {
        var baseline = total;
        var oldest = now_ms;
        for (self.restart_history[0..self.restart_samples]) |sample| {
            if (now_ms -| sample.at_ms <= window_ms and sample.at_ms <= oldest) {
                oldest = sample.at_ms;
                baseline = sample.total;
            }
        }
        self.restart_history[self.restart_next] = .{ .at_ms = now_ms, .total = total };
        self.restart_next = (self.restart_next + 1) % history_samples;
        self.restart_samples = @min(self.restart_samples + 1, history_samples);
        return @floatFromInt(total -| baseline);
    }
};

fn cpuPercent(delta_usec: u64, elapsed_ms: u64, cores: f64) f64 {
    return @as(f64, @floatFromInt(delta_usec)) * 100 / (@as(f64, @floatFromInt(elapsed_ms)) * 1000 * cores);
}

test "alert cpu uses elapsed deltas and configured quota" {
    try std.testing.expectEqual(@as(f64, 50), cpuPercent(5_000_000, 5000, 2));
    try std.testing.expectEqual(@as(f64, 100), cpuPercent(2_500_000, 5000, 0.5));
}

test "alert restarts expire from their observation window" {
    var sampler: Sampler = .{};
    defer sampler.deinit();
    try std.testing.expectEqual(@as(f64, 0), sampler.restartCount(0, 3));
    try std.testing.expectEqual(@as(f64, 2), sampler.restartCount(5000, 5));
    try std.testing.expectEqual(@as(f64, 2), sampler.restartCount(60_000, 5));
    try std.testing.expectEqual(@as(f64, 0), sampler.restartCount(65_001, 5));
}
