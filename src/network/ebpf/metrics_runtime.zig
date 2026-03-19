const std = @import("std");
const posix = std.posix;
const log = @import("../../lib/log.zig");
const attach_support = @import("attach_support.zig");
const common = @import("common.zig");
const map_support = @import("map_support.zig");
const program_support = @import("program_support.zig");
const resource_support = @import("resource_support.zig");

const metrics_prog = @import("../bpf/metrics.zig");

pub const IpMetrics = extern struct {
    packets: u64,
    bytes: u64,
};

pub const PairKey = extern struct {
    src_ip: u32,
    dst_ip: u32,
    dst_port: u16,
    pad: u16 = 0,
};

pub const PairMetrics = extern struct {
    packets: u64,
    bytes: u64,
    connections: u64,
    errors: u64,
};

pub const PairEntry = struct {
    key: PairKey,
    value: PairMetrics,
};

pub const MetricsCollector = struct {
    prog_fd: posix.fd_t,
    metrics_fd: posix.fd_t,
    pair_metrics_fd: posix.fd_t,
    if_index: u32,

    pub fn readMetrics(self: *const MetricsCollector, ip_net: u32) ?IpMetrics {
        var value: IpMetrics = std.mem.zeroes(IpMetrics);
        const key = std.mem.asBytes(&ip_net);
        if (map_support.mapLookup(self.metrics_fd, key, std.mem.asBytes(&value))) {
            return value;
        }
        return null;
    }

    pub fn readPairMetrics(self: *const MetricsCollector, buf: []PairEntry) usize {
        var count: usize = 0;
        var key: PairKey = std.mem.zeroes(PairKey);
        var next_key: PairKey = std.mem.zeroes(PairKey);
        var first = true;

        while (count < buf.len) {
            const found = if (first)
                map_support.mapGetNextKey(self.pair_metrics_fd, std.mem.asBytes(&key), std.mem.asBytes(&next_key))
            else
                map_support.mapGetNextKey(self.pair_metrics_fd, std.mem.asBytes(&key), std.mem.asBytes(&next_key));

            if (!found) break;
            first = false;

            var value: PairMetrics = std.mem.zeroes(PairMetrics);
            if (map_support.mapLookup(self.pair_metrics_fd, std.mem.asBytes(&next_key), std.mem.asBytes(&value))) {
                buf[count] = .{ .key = next_key, .value = value };
                count += 1;
            }

            key = next_key;
        }

        return count;
    }

    pub fn deinit(self: *MetricsCollector) void {
        attach_support.detachTC(self.if_index) catch |e| {
            log.debug("ebpf: failed to detach metrics collector: {}", .{e});
        };
        if (self.prog_fd >= 0) {
            posix.close(self.prog_fd);
            resource_support.releaseBpfFd();
        }
        if (self.metrics_fd >= 0) {
            posix.close(self.metrics_fd);
            resource_support.releaseBpfFd();
        }
        if (self.pair_metrics_fd >= 0) {
            posix.close(self.pair_metrics_fd);
            resource_support.releaseBpfFd();
        }
    }
};

pub fn load(bridge_if_index: u32) common.EbpfError!MetricsCollector {
    const map0_def = metrics_prog.maps[0];
    const map_fd = try map_support.createMap(
        @enumFromInt(map0_def.map_type),
        map0_def.key_size,
        map0_def.value_size,
        map0_def.max_entries,
    );
    errdefer {
        posix.close(map_fd);
        resource_support.releaseBpfFd();
    }

    const map1_def = metrics_prog.maps[1];
    const pair_fd = try map_support.createMap(
        @enumFromInt(map1_def.map_type),
        map1_def.key_size,
        map1_def.value_size,
        map1_def.max_entries,
    );
    errdefer {
        posix.close(pair_fd);
        resource_support.releaseBpfFd();
    }

    var map_fds = [_]posix.fd_t{ map_fd, pair_fd };
    const prog_fd = try program_support.loadProgram(metrics_prog, &map_fds);
    errdefer {
        posix.close(prog_fd);
        resource_support.releaseBpfFd();
    }

    try attach_support.attachTC(bridge_if_index, .ingress, prog_fd, 2);

    return .{
        .prog_fd = prog_fd,
        .metrics_fd = map_fd,
        .pair_metrics_fd = pair_fd,
        .if_index = bridge_if_index,
    };
}
