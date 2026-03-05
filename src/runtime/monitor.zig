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
    running_count: u32,
    desired_count: u32,
    uptime_secs: i64,
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
    var psi_cpu: ?cgroups.PsiMetrics = null;
    var psi_memory: ?cgroups.PsiMetrics = null;

    for (containers) |rec| {
        total += 1;
        if (std.mem.eql(u8, rec.status, "running")) {
            running += 1;

            if (rec.created_at < earliest_start) {
                earliest_start = rec.created_at;
            }

            // try to read cgroup metrics for this container
            var cg = cgroups.Cgroup.create(rec.id) catch continue;
            if (cg.memoryUsage()) |mem| {
                total_memory += mem;
            } else |_| {}

            if (cg.cpuUsage()) |cpu_usec| {
                total_cpu_usec += cpu_usec;
                has_cpu = true;
            } else |_| {}

            // read PSI from the first running container (representative)
            if (psi_cpu == null) {
                psi_cpu = cg.cpuPressure() catch null;
                psi_memory = cg.memoryPressure() catch null;
            }
        }
    }

    // compute CPU percentage from total usage since container start.
    // usage_usec / elapsed_usec * 100 gives approximate CPU%.
    const cpu_pct = if (has_cpu) blk: {
        const now = std.time.timestamp();
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
    const now = std.time.timestamp();
    const uptime: i64 = if (running > 0) now - earliest_start else 0;

    return .{
        .name = name,
        .status = status,
        .health_status = health.getStatus(name),
        .cpu_pct = cpu_pct,
        .memory_bytes = total_memory,
        .psi_cpu = psi_cpu,
        .psi_memory = psi_memory,
        .running_count = running,
        .desired_count = total,
        .uptime_secs = uptime,
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
    const s = status orelse return "\xe2\x80\x94"; // em dash
    return switch (s) {
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

fn testRecord(hostname: []const u8, status: []const u8, created_at: i64) store.ContainerRecord {
    return .{
        .id = "abc123",
        .rootfs = "/tmp",
        .command = "/bin/sh",
        .hostname = hostname,
        .status = status,
        .pid = null,
        .exit_code = null,
        .created_at = created_at,
    };
}
