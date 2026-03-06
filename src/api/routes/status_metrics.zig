const std = @import("std");
const http = @import("../http.zig");
const store = @import("../../state/store.zig");
const monitor = @import("../../runtime/monitor.zig");
const ebpf = @import("../../network/ebpf.zig");
const ip_mod = @import("../../network/ip.zig");
const common = @import("common.zig");

const Response = common.Response;

pub fn route(request: http.Request, alloc: std.mem.Allocator) ?Response {
    const path = request.path_only;

    if (request.method == .GET and std.mem.eql(u8, path, "/v1/status")) {
        return handleStatus(alloc);
    }

    if (request.method == .GET and std.mem.startsWith(u8, path, "/v1/metrics")) {
        return handleMetrics(alloc, request);
    }

    return null;
}

fn handleStatus(alloc: std.mem.Allocator) Response {
    var records = store.listAll(alloc) catch return common.internalError();

    var snapshots = monitor.collectSnapshots(alloc, &records) catch {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
        return common.internalError();
    };
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
        snapshots.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    var writer = json_buf.writer(alloc);
    writer.writeByte('[') catch return common.internalError();

    for (snapshots.items, 0..) |snap, idx| {
        if (idx > 0) writer.writeByte(',') catch return common.internalError();
        writeSnapshotJson(writer, snap) catch return common.internalError();
    }

    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn writeSnapshotJson(writer: anytype, snap: monitor.ServiceSnapshot) !void {
    try writer.print("{{\"name\":\"{s}\",\"status\":\"{s}\",", .{ snap.name, monitor.formatStatus(snap.status) });

    if (snap.health_status) |hs| {
        try writer.print("\"health\":\"{s}\",", .{monitor.formatHealth(hs)});
    } else {
        try writer.writeAll("\"health\":null,");
    }

    try writer.print(
        "\"cpu_pct\":{d:.1},\"memory_bytes\":{d},\"running\":{d},\"desired\":{d},\"uptime_secs\":{d}",
        .{ snap.cpu_pct, snap.memory_bytes, snap.running_count, snap.desired_count, snap.uptime_secs },
    );

    if (snap.psi_cpu) |psi| {
        try writer.print(",\"psi_cpu_some\":{d:.2},\"psi_cpu_full\":{d:.2}", .{ psi.some_avg10, psi.full_avg10 });
    }
    if (snap.psi_memory) |psi| {
        try writer.print(",\"psi_mem_some\":{d:.2},\"psi_mem_full\":{d:.2}", .{ psi.some_avg10, psi.full_avg10 });
    }

    try writer.writeByte('}');
}

fn handleMetrics(alloc: std.mem.Allocator, request: http.Request) Response {
    const mode = common.extractQueryParam(request.path, "mode");
    if (mode) |m| {
        if (std.mem.eql(u8, m, "pairs")) return handleMetricsPairs(alloc);
    }

    const service_filter = common.extractQueryParam(request.path, "service");

    var records = store.listAll(alloc) catch return common.internalError();
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
    }

    const mc = ebpf.getMetricsCollector();

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
        if (mc) |collector| {
            if (ip_mod.parseIp(ip_str)) |addr| {
                const ip_net = ebpf.ipToNetworkOrder(addr);
                if (collector.readMetrics(ip_net)) |m| {
                    packets = m.packets;
                    bytes = m.bytes;
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

fn handleMetricsPairs(alloc: std.mem.Allocator) Response {
    const mc = ebpf.getMetricsCollector() orelse return common.jsonOkOwned(alloc, "[]");

    var entries: [1024]ebpf.PairEntry = undefined;
    const count = mc.readPairMetrics(&entries);

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

fn resolveIpToService(ip_net: u32, records: []const store.ContainerRecord) []const u8 {
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
