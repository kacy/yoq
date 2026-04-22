const std = @import("std");
const store = @import("../../state/store.zig");
const health = @import("../../manifest/health.zig");
const cgroups = @import("../cgroups.zig");
const common = @import("common.zig");

pub const ServiceSnapshot = common.ServiceSnapshot;
pub const ServiceStatus = common.ServiceStatus;

pub fn collectSnapshots(
    alloc: std.mem.Allocator,
    container_records: *std.ArrayList(store.ContainerRecord),
) !std.ArrayList(ServiceSnapshot) {
    var snapshots: std.ArrayList(ServiceSnapshot) = .empty;

    var i: usize = 0;
    while (i < container_records.items.len) {
        const service_name = container_records.items[i].hostname;

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

    const now = @import("compat").timestamp();
    const cpu_pct = if (has_cpu) blk: {
        const elapsed_secs = now - earliest_start;
        if (elapsed_secs <= 0) break :blk @as(f64, 0.0);
        const elapsed_usec: f64 = @floatFromInt(elapsed_secs * std.time.us_per_s);
        break :blk @as(f64, @floatFromInt(total_cpu_usec)) / elapsed_usec * 100.0;
    } else 0.0;

    const status: ServiceStatus = if (running == total and running > 0)
        .running
    else if (running == 0)
        .stopped
    else
        .mixed;

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
