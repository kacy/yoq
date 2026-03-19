const std = @import("std");
const builtin = @import("builtin");
const http = @import("../../http.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const storage_metrics = @import("../../../storage/metrics.zig");
const gpu_health = @import("../../../gpu/health.zig");
const gpu_detect = @import("../../../gpu/detect.zig");
const ip_mod = @import("../../../network/ip.zig");

const Response = common.Response;
const ebpf = if (builtin.os.tag == .linux) @import("../../../network/ebpf.zig") else struct {
    pub const PairEntry = struct {
        key: struct {
            src_ip: u32,
            dst_ip: u32,
            dst_port: u16,
        },
        value: struct {
            connections: u64,
            packets: u64,
            bytes: u64,
            errors: u64,
        },
    };

    pub const Metrics = struct {
        packets: u64 = 0,
        bytes: u64 = 0,
    };

    pub const Collector = struct {
        pub fn readMetrics(_: *@This(), _: u32) ?Metrics {
            return null;
        }

        pub fn readPairMetrics(_: *@This(), _: []PairEntry) usize {
            return 0;
        }
    };

    pub fn getMetricsCollector() ?*Collector {
        return null;
    }

    pub fn ipToNetworkOrder(_: [4]u8) u32 {
        return 0;
    }
};

pub fn handleMetrics(alloc: std.mem.Allocator, request: http.Request) Response {
    const format = common.extractQueryParam(request.path, "format");
    if (format) |value| {
        if (std.mem.eql(u8, value, "prometheus")) return handleMetricsPrometheus(alloc);
    }

    const mode = common.extractQueryParam(request.path, "mode");
    if (mode) |value| {
        if (std.mem.eql(u8, value, "pairs")) return handleMetricsPairs(alloc);
        if (std.mem.eql(u8, value, "storage_io")) return handleStorageIoMetrics(alloc);
        if (std.mem.eql(u8, value, "gpu")) return handleGpuMetrics(alloc);
    }

    const service_filter = common.extractQueryParam(request.path, "service");

    var records = store.listAll(alloc) catch return common.internalError();
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
    }

    const collector = ebpf.getMetricsCollector();

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    var writer = json_buf.writer(alloc);
    writer.writeByte('[') catch return common.internalError();

    var first = true;
    for (records.items) |rec| {
        if (!std.mem.eql(u8, rec.status, "running")) continue;

        if (service_filter) |svc| {
            if (!std.mem.eql(u8, rec.hostname, svc)) continue;
        }

        const ip_str = rec.ip_address orelse continue;

        var packets: u64 = 0;
        var bytes: u64 = 0;
        if (collector) |mc| {
            if (ip_mod.parseIp(ip_str)) |addr| {
                const ip_net = ebpf.ipToNetworkOrder(addr);
                if (mc.readMetrics(ip_net)) |metrics| {
                    packets = metrics.packets;
                    bytes = metrics.bytes;
                }
            }
        }

        if (!first) writer.writeByte(',') catch return common.internalError();
        first = false;

        const short_id = if (rec.id.len >= 6) rec.id[0..6] else rec.id;
        writer.print(
            "{{\"service\":\"{s}\",\"container\":\"{s}\",\"ip\":\"{s}\",\"packets\":{d},\"bytes\":{d}}}",
            .{ rec.hostname, short_id, ip_str, packets, bytes },
        ) catch return common.internalError();
    }

    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleMetricsPairs(alloc: std.mem.Allocator) Response {
    const collector = ebpf.getMetricsCollector() orelse return common.jsonOkOwned(alloc, "[]");

    var entries: [1024]ebpf.PairEntry = undefined;
    const count = collector.readPairMetrics(&entries);

    var records = store.listAll(alloc) catch return common.internalError();
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    var writer = json_buf.writer(alloc);
    writer.writeByte('[') catch return common.internalError();

    var first = true;
    for (entries[0..count]) |entry| {
        if (!first) writer.writeByte(',') catch return common.internalError();
        first = false;

        const src_name = resolveIpToService(entry.key.src_ip, records.items);
        const dst_name = resolveIpToService(entry.key.dst_ip, records.items);
        const port = std.mem.nativeTo(u16, entry.key.dst_port, .big);

        writer.print(
            "{{\"from\":\"{s}\",\"to\":\"{s}\",\"port\":{d},\"connections\":{d},\"packets\":{d},\"bytes\":{d},\"errors\":{d}}}",
            .{ src_name, dst_name, port, entry.value.connections, entry.value.packets, entry.value.bytes, entry.value.errors },
        ) catch return common.internalError();
    }

    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleStorageIoMetrics(alloc: std.mem.Allocator) Response {
    const collector = storage_metrics.getStorageMetricsCollector() orelse return common.jsonOkOwned(alloc, "[]");

    var entries: [1024]storage_metrics.IoEntry = undefined;
    const count = collector.listAllIoMetrics(&entries);

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    var writer = json_buf.writer(alloc);
    writer.writeByte('[') catch return common.internalError();

    for (entries[0..count], 0..) |entry, idx| {
        if (idx > 0) writer.writeByte(',') catch return common.internalError();
        writer.print(
            "{{\"cgroup_id\":{d},\"read_bytes\":{d},\"write_bytes\":{d},\"read_ops\":{d},\"write_ops\":{d}}}",
            .{
                entry.cgroup_id,
                entry.metrics.read_bytes,
                entry.metrics.write_bytes,
                entry.metrics.read_ops,
                entry.metrics.write_ops,
            },
        ) catch return common.internalError();
    }

    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleMetricsPrometheus(alloc: std.mem.Allocator) Response {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    var writer = buf.writer(alloc);

    if (ebpf.getMetricsCollector()) |collector| {
        var entries: [1024]ebpf.PairEntry = undefined;
        const count = collector.readPairMetrics(&entries);

        writer.writeAll("# HELP yoq_network_bytes_total Network bytes transferred\n") catch return common.internalError();
        writer.writeAll("# TYPE yoq_network_bytes_total counter\n") catch return common.internalError();
        for (entries[0..count]) |entry| {
            const port = std.mem.nativeTo(u16, entry.key.dst_port, .big);
            writer.print("yoq_network_bytes_total{{port=\"{d}\"}} {d}\n", .{ port, entry.value.bytes }) catch return common.internalError();
        }

        writer.writeAll("# HELP yoq_network_packets_total Network packets transferred\n") catch return common.internalError();
        writer.writeAll("# TYPE yoq_network_packets_total counter\n") catch return common.internalError();
        for (entries[0..count]) |entry| {
            const port = std.mem.nativeTo(u16, entry.key.dst_port, .big);
            writer.print("yoq_network_packets_total{{port=\"{d}\"}} {d}\n", .{ port, entry.value.packets }) catch return common.internalError();
        }
    }

    if (storage_metrics.getStorageMetricsCollector()) |collector| {
        var entries: [1024]storage_metrics.IoEntry = undefined;
        const count = collector.listAllIoMetrics(&entries);

        writer.writeAll("# HELP yoq_storage_read_bytes_total Storage read bytes\n") catch return common.internalError();
        writer.writeAll("# TYPE yoq_storage_read_bytes_total counter\n") catch return common.internalError();
        for (entries[0..count]) |entry| {
            writer.print("yoq_storage_read_bytes_total{{cgroup_id=\"{d}\"}} {d}\n", .{ entry.cgroup_id, entry.metrics.read_bytes }) catch return common.internalError();
        }

        writer.writeAll("# HELP yoq_storage_write_bytes_total Storage write bytes\n") catch return common.internalError();
        writer.writeAll("# TYPE yoq_storage_write_bytes_total counter\n") catch return common.internalError();
        for (entries[0..count]) |entry| {
            writer.print("yoq_storage_write_bytes_total{{cgroup_id=\"{d}\"}} {d}\n", .{ entry.cgroup_id, entry.metrics.write_bytes }) catch return common.internalError();
        }
    }

    var gpu_result = gpu_detect.detect();
    defer gpu_result.deinit();
    if (gpu_result.nvml) |*nvml| {
        const gpu_metrics = gpu_health.pollAllMetrics(nvml, gpu_result.count);
        gpu_health.writePrometheus(writer, gpu_metrics, gpu_result.count) catch return common.internalError();
    }

    const body = buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{
        .status = .ok,
        .body = body,
        .allocated = true,
        .content_type = "text/plain; version=0.0.4; charset=utf-8",
    };
}

pub fn handleGpuMetrics(alloc: std.mem.Allocator) Response {
    var gpu_result = gpu_detect.detect();
    defer gpu_result.deinit();

    var nvml = gpu_result.nvml orelse return common.jsonOkOwned(alloc, "{\"gpu_metrics\":[]}");
    const metrics = gpu_health.pollAllMetrics(&nvml, gpu_result.count);

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    var writer = json_buf.writer(alloc);

    writer.writeByte('{') catch return common.internalError();
    gpu_health.writeMetricsJson(writer, metrics, gpu_result.count) catch return common.internalError();
    writer.writeByte('}') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn resolveIpToService(ip_net: u32, records: []const store.ContainerRecord) []const u8 {
    const ip_bytes = std.mem.asBytes(&ip_net);
    for (records) |rec| {
        if (!std.mem.eql(u8, rec.status, "running")) continue;
        const rec_ip_str = rec.ip_address orelse continue;
        if (ip_mod.parseIp(rec_ip_str)) |addr| {
            if (std.mem.eql(u8, &addr, ip_bytes[0..4])) return rec.hostname;
        }
    }
    return "unknown";
}
