// monitor — point-in-time resource snapshots for `yoq status`
//
// collects per-service status by reading cgroup metrics, health state,
// and container records. designed for single-shot CLI queries — no
// background threads or time-series storage.
//
// wires together:
//   - cgroups.zig:  CPU usage, memory usage, PSI pressure
//   - health.zig:   health check status (healthy/unhealthy/starting)
//   - store.zig:    container records (status, timestamps, cgroup paths)

const std = @import("std");
const store = @import("../state/store.zig");
const health = @import("../manifest/health.zig");
const cgroups = @import("cgroups.zig");

/// point-in-time snapshot of a service's resource usage and health.
pub const ServiceSnapshot = struct {
    name: []const u8,
    status: ServiceStatus,
    health_status: ?health.HealthStatus,
    cpu_pct: f64,
    memory_bytes: u64,
    psi_cpu: ?cgroups.PsiMetrics,
    psi_memory: ?cgroups.PsiMetrics,
    io_read_bytes: u64 = 0,
    io_write_bytes: u64 = 0,
    running_count: u32,
    desired_count: u32,
    uptime_secs: i64,
    memory_limit: ?u64 = null, // configured memory.max (null = unlimited)
    cpu_quota_pct: ?f64 = null, // cpu quota as percentage (quota/period * 100)
};

pub const ServiceStatus = enum {
    running,
    stopped,
    mixed, // some containers running, some not
};

/// collect snapshots for all services.
/// groups containers by hostname (service name), reads cgroup metrics
/// for running containers, and merges health status.
///
/// caller owns the returned list. snapshot name slices point into
/// the container records and share their lifetime — the caller should
/// free container_records after it's done with the snapshots.
pub fn collectSnapshots(
    alloc: std.mem.Allocator,
    container_records: *std.ArrayList(store.ContainerRecord),
) !std.ArrayList(ServiceSnapshot) {
    var snapshots: std.ArrayList(ServiceSnapshot) = .empty;

    // group containers by service name (hostname).
    // we walk the records (already sorted by hostname, created_at DESC)
    // and collect runs of the same hostname.
    var i: usize = 0;
    while (i < container_records.items.len) {
        const service_name = container_records.items[i].hostname;

        // find the extent of this service group
        var j = i + 1;
        while (j < container_records.items.len) {
            if (!std.mem.eql(u8, container_records.items[j].hostname, service_name)) break;
            j += 1;
        }

        const group = container_records.items[i..j];
        const snapshot = collectServiceSnapshot(service_name, group);
        try snapshots.append(alloc, snapshot);

        i = j;
    }

    return snapshots;
}

/// build a snapshot for a single service from its container records.
fn collectServiceSnapshot(name: []const u8, containers: []const store.ContainerRecord) ServiceSnapshot {
    var running: u32 = 0;
    var total: u32 = 0;
    var total_cpu_usec: u64 = 0;
    var total_memory: u64 = 0;
    var earliest_start: i64 = std.math.maxInt(i64);
    var has_cpu = false;
    var total_io_read: u64 = 0;
    var total_io_write: u64 = 0;
    var psi_cpu: ?cgroups.PsiMetrics = null;
    var psi_memory: ?cgroups.PsiMetrics = null;
    var memory_limit: ?u64 = null;
    var cpu_quota_pct: ?f64 = null;

    for (containers) |rec| {
        total += 1;
        if (std.mem.eql(u8, rec.status, "running")) {
            running += 1;

            if (rec.created_at < earliest_start) {
                earliest_start = rec.created_at;
            }

            // open existing cgroup and read all metrics in one pass
            const cg = cgroups.Cgroup.open(rec.id) catch continue;
            const metrics = cg.readAllMetrics();

            if (metrics.memory_bytes) |mem| total_memory += mem;
            if (metrics.cpu_usec) |cpu_usec| {
                total_cpu_usec += cpu_usec;
                has_cpu = true;
            }

            if (metrics.io) |io| {
                total_io_read += io.read_bytes;
                total_io_write += io.write_bytes;
            }

            // use PSI and limits from the first running container (representative)
            if (psi_cpu == null) {
                psi_cpu = metrics.psi_cpu;
                psi_memory = metrics.psi_memory;
                memory_limit = metrics.memory_limit;
                if (metrics.cpu_max_usec) |quota| {
                    if (metrics.cpu_max_period) |period| {
                        if (period > 0) {
                            cpu_quota_pct = @as(f64, @floatFromInt(quota)) / @as(f64, @floatFromInt(period)) * 100.0;
                        }
                    }
                }
            }
        }
    }

    const now = std.time.timestamp();

    // compute CPU percentage from total usage since container start.
    // usage_usec / elapsed_usec * 100 gives approximate CPU%.
    const cpu_pct = if (has_cpu) blk: {
        const elapsed_secs = now - earliest_start;
        if (elapsed_secs <= 0) break :blk @as(f64, 0.0);
        const elapsed_usec: f64 = @floatFromInt(elapsed_secs * std.time.us_per_s);
        break :blk @as(f64, @floatFromInt(total_cpu_usec)) / elapsed_usec * 100.0;
    } else 0.0;

    // determine aggregate service status
    const status: ServiceStatus = if (running == total and running > 0)
        .running
    else if (running == 0)
        .stopped
    else
        .mixed;

    // uptime is seconds since earliest running container started
    const uptime: i64 = if (running > 0) now - earliest_start else 0;

    return .{
        .name = name,
        .status = status,
        .health_status = health.getStatus(name),
        .cpu_pct = cpu_pct,
        .memory_bytes = total_memory,
        .psi_cpu = psi_cpu,
        .psi_memory = psi_memory,
        .io_read_bytes = total_io_read,
        .io_write_bytes = total_io_write,
        .running_count = running,
        .desired_count = total,
        .uptime_secs = uptime,
        .memory_limit = memory_limit,
        .cpu_quota_pct = cpu_quota_pct,
    };
}

// -- formatting helpers --

/// format uptime seconds as a human-readable string like "2h 15m" or "45s".
/// writes into the provided buffer and returns the formatted slice.
pub fn formatUptime(buf: []u8, secs: i64) []const u8 {
    if (secs <= 0) return "-";

    const s: u64 = @intCast(secs);
    const days = s / 86400;
    const hours = (s % 86400) / 3600;
    const minutes = (s % 3600) / 60;
    const seconds = s % 60;

    if (days > 0) {
        return std.fmt.bufPrint(buf, "{d}d {d}h", .{ days, hours }) catch "-";
    } else if (hours > 0) {
        return std.fmt.bufPrint(buf, "{d}h {d}m", .{ hours, minutes }) catch "-";
    } else if (minutes > 0) {
        return std.fmt.bufPrint(buf, "{d}m {d}s", .{ minutes, seconds }) catch "-";
    } else {
        return std.fmt.bufPrint(buf, "{d}s", .{seconds}) catch "-";
    }
}

/// format bytes as a human-readable string like "84 MB" or "1.2 GB".
pub fn formatBytes(buf: []u8, bytes: u64) []const u8 {
    if (bytes == 0) return "-";

    const gb: f64 = @floatFromInt(bytes);
    if (bytes >= 1024 * 1024 * 1024) {
        return std.fmt.bufPrint(buf, "{d:.1} GB", .{gb / (1024.0 * 1024.0 * 1024.0)}) catch "-";
    } else if (bytes >= 1024 * 1024) {
        return std.fmt.bufPrint(buf, "{d:.0} MB", .{gb / (1024.0 * 1024.0)}) catch "-";
    } else if (bytes >= 1024) {
        return std.fmt.bufPrint(buf, "{d:.0} KB", .{gb / 1024.0}) catch "-";
    } else {
        return std.fmt.bufPrint(buf, "{d} B", .{bytes}) catch "-";
    }
}

/// format a health status as a display string.
pub fn formatHealth(status: ?health.HealthStatus) []const u8 {
    const health_status = status orelse return "\xe2\x80\x94"; // em dash
    return switch (health_status) {
        .healthy => "healthy",
        .unhealthy => "unhealthy",
        .starting => "starting",
    };
}

/// format service status as a display string.
pub fn formatStatus(status: ServiceStatus) []const u8 {
    return switch (status) {
        .running => "running",
        .stopped => "stopped",
        .mixed => "partial",
    };
}

// -- auto-tuning suggestions --

/// generate a concrete tuning suggestion based on resource usage vs limits.
/// writes into the provided buffer and returns the formatted message,
/// or null if no suggestion is warranted (low pressure, no limits set).
pub fn suggestTuning(buf: []u8, snap: ServiceSnapshot) ?[]const u8 {
    // memory suggestions take priority — OOM kills are worse than CPU throttling
    if (snap.memory_limit) |limit| {
        if (limit > 0 and snap.memory_bytes > 0) {
            const usage_pct = @as(f64, @floatFromInt(snap.memory_bytes)) / @as(f64, @floatFromInt(limit)) * 100.0;
            const psi = if (snap.psi_memory) |p| p.some_avg10 else 0.0;

            if (usage_pct > 80.0 and psi > 10.0) {
                // high usage + pressure → concrete suggestion with specific numbers
                const suggested = suggestedMemoryLimit(limit);
                var usage_buf: [16]u8 = undefined;
                var limit_buf: [16]u8 = undefined;
                var suggested_buf: [16]u8 = undefined;
                const usage_str = formatBytes(&usage_buf, snap.memory_bytes);
                const limit_str = formatBytes(&limit_buf, limit);
                const suggested_str = formatBytes(&suggested_buf, suggested);

                return std.fmt.bufPrint(buf, "\xe2\x9a\xa0 memory: using {s} of {s} ({d:.0}%), pressure {d:.0}% \xe2\x80\x94 suggest increasing to {s}", .{
                    usage_str, limit_str, usage_pct, psi, suggested_str,
                }) catch null;
            } else if (usage_pct > 80.0) {
                // high usage but no pressure yet — informational
                var usage_buf: [16]u8 = undefined;
                var limit_buf: [16]u8 = undefined;
                const usage_str = formatBytes(&usage_buf, snap.memory_bytes);
                const limit_str = formatBytes(&limit_buf, limit);

                return std.fmt.bufPrint(buf, "  memory: using {s} of {s} ({d:.0}%) \xe2\x80\x94 approaching limit", .{
                    usage_str, limit_str, usage_pct,
                }) catch null;
            }
        }
    } else {
        // no memory limit — check if host is memory-constrained
        if (snap.psi_memory) |psi| {
            if (psi.some_avg10 > 25.0) {
                return std.fmt.bufPrint(buf, "  memory: pressure {d:.0}% without limit set \xe2\x80\x94 host may be memory-constrained", .{
                    psi.some_avg10,
                }) catch null;
            }
        }
    }

    // cpu suggestions
    if (snap.cpu_quota_pct) |quota| {
        if (snap.psi_cpu) |psi| {
            if (psi.some_avg10 > 50.0) {
                return std.fmt.bufPrint(buf, "\xe2\x9a\xa0 cpu: significant pressure {d:.0}% \xe2\x80\x94 service is cpu-starved at {d:.0}% quota", .{
                    psi.some_avg10, quota,
                }) catch null;
            } else if (psi.some_avg10 > 25.0) {
                return std.fmt.bufPrint(buf, "\xe2\x9a\xa0 cpu: pressure {d:.0}% with {d:.0}% quota \xe2\x80\x94 consider increasing cpu allocation", .{
                    psi.some_avg10, quota,
                }) catch null;
            }
        }
    }

    return null;
}

/// suggest a reasonable next memory limit: double the current, rounded
/// to a friendly value. capped at 64 GB to avoid suggesting absurd limits.
fn suggestedMemoryLimit(current: u64) u64 {
    const doubled = current *| 2; // saturating multiply
    const max_suggestion: u64 = 64 * 1024 * 1024 * 1024; // 64 GB
    return @min(doubled, max_suggestion);
}

// -- tests --

test "formatUptime — seconds only" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("45s", formatUptime(&buf, 45));
}

test "formatUptime — minutes and seconds" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("2m 30s", formatUptime(&buf, 150));
}

test "formatUptime — hours and minutes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("2h 15m", formatUptime(&buf, 2 * 3600 + 15 * 60));
}

test "formatUptime — days and hours" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("3d 5h", formatUptime(&buf, 3 * 86400 + 5 * 3600));
}

test "formatUptime — zero" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("-", formatUptime(&buf, 0));
}

test "formatUptime — negative" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("-", formatUptime(&buf, -5));
}

test "formatBytes — zero" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("-", formatBytes(&buf, 0));
}

test "formatBytes — megabytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("84 MB", formatBytes(&buf, 84 * 1024 * 1024));
}

test "formatBytes — gigabytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("1.5 GB", formatBytes(&buf, 1536 * 1024 * 1024));
}

test "formatBytes — kilobytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("512 KB", formatBytes(&buf, 512 * 1024));
}

test "formatBytes — small bytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("100 B", formatBytes(&buf, 100));
}

test "formatHealth — no health check" {
    try std.testing.expectEqualStrings("\xe2\x80\x94", formatHealth(null));
}

test "formatHealth — healthy" {
    try std.testing.expectEqualStrings("healthy", formatHealth(.healthy));
}

test "formatHealth — unhealthy" {
    try std.testing.expectEqualStrings("unhealthy", formatHealth(.unhealthy));
}

test "formatHealth — starting" {
    try std.testing.expectEqualStrings("starting", formatHealth(.starting));
}

test "formatStatus values" {
    try std.testing.expectEqualStrings("running", formatStatus(.running));
    try std.testing.expectEqualStrings("stopped", formatStatus(.stopped));
    try std.testing.expectEqualStrings("partial", formatStatus(.mixed));
}

test "collectServiceSnapshot — all stopped" {
    const records = [_]store.ContainerRecord{
        testRecord("svc1", "stopped", 1000),
        testRecord("svc1", "stopped", 900),
    };
    const snap = collectServiceSnapshot("svc1", &records);
    try std.testing.expectEqual(ServiceStatus.stopped, snap.status);
    try std.testing.expectEqual(@as(u32, 0), snap.running_count);
    try std.testing.expectEqual(@as(u32, 2), snap.desired_count);
    try std.testing.expectEqual(@as(i64, 0), snap.uptime_secs);
}

test "collectServiceSnapshot — empty group" {
    const records = [_]store.ContainerRecord{};
    const snap = collectServiceSnapshot("empty", &records);
    try std.testing.expectEqual(ServiceStatus.stopped, snap.status);
    try std.testing.expectEqual(@as(u32, 0), snap.running_count);
    try std.testing.expectEqual(@as(u32, 0), snap.desired_count);
}

fn testRecord(hostname: []const u8, rec_status: []const u8, created_at: i64) store.ContainerRecord {
    return .{
        .id = "abc123",
        .rootfs = "/tmp",
        .command = "/bin/sh",
        .hostname = hostname,
        .status = rec_status,
        .pid = null,
        .exit_code = null,
        .created_at = created_at,
    };
}

fn testSnapshot() ServiceSnapshot {
    return .{
        .name = "web",
        .status = .running,
        .health_status = null,
        .cpu_pct = 0.0,
        .memory_bytes = 0,
        .psi_cpu = null,
        .psi_memory = null,
        .running_count = 1,
        .desired_count = 1,
        .uptime_secs = 100,
    };
}

test "suggestTuning — high memory usage with pressure" {
    var buf: [256]u8 = undefined;
    var snap = testSnapshot();
    snap.memory_limit = 512 * 1024 * 1024; // 512 MB
    snap.memory_bytes = 450 * 1024 * 1024; // 450 MB (88%)
    snap.psi_memory = .{ .some_avg10 = 32.0, .full_avg10 = 8.0 };

    const msg = suggestTuning(&buf, snap);
    try std.testing.expect(msg != null);
    // should contain concrete numbers and suggestion
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "450 MB") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "512 MB") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "1.0 GB") != null); // 512*2 = 1024 MB = 1.0 GB
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "suggest increasing") != null);
}

test "suggestTuning — high memory usage without pressure" {
    var buf: [256]u8 = undefined;
    var snap = testSnapshot();
    snap.memory_limit = 512 * 1024 * 1024;
    snap.memory_bytes = 450 * 1024 * 1024; // 88%
    snap.psi_memory = .{ .some_avg10 = 2.0, .full_avg10 = 0.0 };

    const msg = suggestTuning(&buf, snap);
    try std.testing.expect(msg != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "approaching limit") != null);
}

test "suggestTuning — low pressure, no suggestion" {
    var buf: [256]u8 = undefined;
    var snap = testSnapshot();
    snap.memory_limit = 512 * 1024 * 1024;
    snap.memory_bytes = 100 * 1024 * 1024; // 20%
    snap.psi_memory = .{ .some_avg10 = 1.0, .full_avg10 = 0.0 };
    snap.psi_cpu = .{ .some_avg10 = 5.0, .full_avg10 = 0.0 };

    const msg = suggestTuning(&buf, snap);
    try std.testing.expect(msg == null);
}

test "suggestTuning — unlimited memory with high pressure" {
    var buf: [256]u8 = undefined;
    var snap = testSnapshot();
    snap.memory_limit = null; // unlimited
    snap.psi_memory = .{ .some_avg10 = 40.0, .full_avg10 = 15.0 };

    const msg = suggestTuning(&buf, snap);
    try std.testing.expect(msg != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "host may be memory-constrained") != null);
}

test "suggestTuning — cpu-starved" {
    var buf: [256]u8 = undefined;
    var snap = testSnapshot();
    snap.cpu_quota_pct = 50.0;
    snap.psi_cpu = .{ .some_avg10 = 65.0, .full_avg10 = 30.0 };

    const msg = suggestTuning(&buf, snap);
    try std.testing.expect(msg != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "cpu-starved") != null);
}

test "suggestTuning — moderate cpu pressure" {
    var buf: [256]u8 = undefined;
    var snap = testSnapshot();
    snap.cpu_quota_pct = 25.0;
    snap.psi_cpu = .{ .some_avg10 = 35.0, .full_avg10 = 10.0 };

    const msg = suggestTuning(&buf, snap);
    try std.testing.expect(msg != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "consider increasing cpu allocation") != null);
}

test "suggestedMemoryLimit — doubles current" {
    try std.testing.expectEqual(@as(u64, 1024 * 1024 * 1024), suggestedMemoryLimit(512 * 1024 * 1024));
}

test "suggestedMemoryLimit — capped at 64 GB" {
    const large: u64 = 48 * 1024 * 1024 * 1024; // 48 GB
    const suggested = suggestedMemoryLimit(large);
    try std.testing.expectEqual(@as(u64, 64 * 1024 * 1024 * 1024), suggested);
}
