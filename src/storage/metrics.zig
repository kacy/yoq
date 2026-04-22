// storage/metrics — per-container block I/O metrics via eBPF
//
// loads the storage_metrics BPF program and reads per-cgroup I/O counters.
// the BPF program tracks read/write bytes and IOPS at the block layer,
// keyed by cgroup ID. this module provides the userspace interface for
// reading those metrics.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const is_linux = builtin.os.tag == .linux;
const ebpf = if (is_linux) @import("../network/ebpf.zig") else struct {};

pub const IoMetrics = extern struct {
    read_bytes: u64,
    write_bytes: u64,
    read_ops: u64,
    write_ops: u64,
};

pub const IoEntry = struct {
    cgroup_id: u64,
    metrics: IoMetrics,
};

pub const StorageMetricsCollector = struct {
    map_fd: posix.fd_t,

    /// read I/O metrics for a single cgroup.
    pub fn readContainerIoMetrics(self: *const StorageMetricsCollector, cgroup_id: u64) ?IoMetrics {
        if (!is_linux) return null;
        var value: IoMetrics = std.mem.zeroes(IoMetrics);
        const key = std.mem.asBytes(&cgroup_id);
        if (ebpf.mapLookup(self.map_fd, key, std.mem.asBytes(&value))) {
            return value;
        }
        return null;
    }

    /// read all I/O metrics entries from the map.
    pub fn listAllIoMetrics(self: *const StorageMetricsCollector, buf: []IoEntry) usize {
        if (!is_linux) return 0;
        var count: usize = 0;
        var key: u64 = 0;
        var next_key: u64 = 0;

        while (count < buf.len) {
            if (!ebpf.mapGetNextKey(self.map_fd, std.mem.asBytes(&key), std.mem.asBytes(&next_key))) break;

            var value: IoMetrics = std.mem.zeroes(IoMetrics);
            if (ebpf.mapLookup(self.map_fd, std.mem.asBytes(&next_key), std.mem.asBytes(&value))) {
                buf[count] = .{ .cgroup_id = next_key, .metrics = value };
                count += 1;
            }

            key = next_key;
        }

        return count;
    }

    pub fn deinit(self: *StorageMetricsCollector) void {
        if (is_linux and self.map_fd >= 0) {
            @import("compat").posix.close(self.map_fd);
        }
    }
};

/// global storage metrics collector instance.
var storage_collector: ?StorageMetricsCollector = null;

pub fn getStorageMetricsCollector() ?*const StorageMetricsCollector {
    if (storage_collector) |*c| return c;
    return null;
}

pub fn setStorageMetricsCollector(collector: StorageMetricsCollector) void {
    storage_collector = collector;
}

pub fn unloadStorageMetricsCollector() void {
    if (storage_collector) |*c| {
        c.deinit();
        storage_collector = null;
    }
}

// -- tests --

test "IoMetrics defaults" {
    const m = std.mem.zeroes(IoMetrics);
    try std.testing.expectEqual(@as(u64, 0), m.read_bytes);
    try std.testing.expectEqual(@as(u64, 0), m.write_bytes);
    try std.testing.expectEqual(@as(u64, 0), m.read_ops);
    try std.testing.expectEqual(@as(u64, 0), m.write_ops);
}

test "IoMetrics struct size" {
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(IoMetrics));
}

test "IoEntry struct layout" {
    const entry = IoEntry{
        .cgroup_id = 12345,
        .metrics = .{
            .read_bytes = 1024,
            .write_bytes = 2048,
            .read_ops = 10,
            .write_ops = 20,
        },
    };
    try std.testing.expectEqual(@as(u64, 12345), entry.cgroup_id);
    try std.testing.expectEqual(@as(u64, 1024), entry.metrics.read_bytes);
    try std.testing.expectEqual(@as(u64, 2048), entry.metrics.write_bytes);
    try std.testing.expectEqual(@as(u64, 10), entry.metrics.read_ops);
    try std.testing.expectEqual(@as(u64, 20), entry.metrics.write_ops);
}

test "StorageMetricsCollector singleton starts null" {
    try std.testing.expect(getStorageMetricsCollector() == null);
}

test "unloadStorageMetricsCollector is idempotent" {
    unloadStorageMetricsCollector();
    try std.testing.expect(getStorageMetricsCollector() == null);
}
