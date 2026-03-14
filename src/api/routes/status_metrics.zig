const std = @import("std");
const builtin = @import("builtin");
const http = @import("../http.zig");
const store = @import("../../state/store.zig");
const monitor = @import("../../runtime/monitor.zig");
const cgroups = @import("../../runtime/cgroups.zig");
const ebpf = if (builtin.os.tag == .linux) @import("../../network/ebpf.zig") else struct {
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
const storage_metrics = @import("../../storage/metrics.zig");
const ip_mod = @import("../../network/ip.zig");
const common = @import("common.zig");
const testing = std.testing;

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

    if (snap.io_read_bytes > 0 or snap.io_write_bytes > 0) {
        try writer.print(",\"io_read_bytes\":{d},\"io_write_bytes\":{d}", .{ snap.io_read_bytes, snap.io_write_bytes });
    }

    try writer.writeByte('}');
}

fn handleMetrics(alloc: std.mem.Allocator, request: http.Request) Response {
    const mode = common.extractQueryParam(request.path, "mode");
    if (mode) |m| {
        if (std.mem.eql(u8, m, "pairs")) return handleMetricsPairs(alloc);
        if (std.mem.eql(u8, m, "storage_io")) return handleStorageIoMetrics(alloc);
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

fn handleStorageIoMetrics(alloc: std.mem.Allocator) Response {
    const sc = storage_metrics.getStorageMetricsCollector() orelse return common.jsonOkOwned(alloc, "[]");

    var entries: [1024]storage_metrics.IoEntry = undefined;
    const count = sc.listAllIoMetrics(&entries);

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

// ============================================================================
// Tests
// ============================================================================

test "route returns null for unknown path" {
    const req = http.Request{
        .method = .GET,
        .path = "/unknown",
        .path_only = "/unknown",
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator);
    try testing.expect(response == null);
}

test "route handles /v1/status GET" {
    if (true) return error.SkipZigTest; // Skip - requires store layer
    const req = http.Request{
        .method = .GET,
        .path = "/v1/status",
        .path_only = "/v1/status",
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator);
    _ = response; // May be null or a Response depending on store state
    // Should return a response (either empty array or error)
    // Don't check exact result as it depends on store state
}

test "route handles /v1/metrics GET" {
    if (true) return error.SkipZigTest; // Skip - requires store layer
    const req = http.Request{
        .method = .GET,
        .path = "/v1/metrics",
        .path_only = "/v1/metrics",
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator);
    _ = response; // May be null or a Response depending on store state and ebpf
    // Should return a response (either empty array or metrics)
    // Don't check exact result as it depends on store state and ebpf availability
}

test "route handles /v1/metrics?mode=pairs GET" {
    if (true) return error.SkipZigTest; // Skip - requires ebpf layer
    const req = http.Request{
        .method = .GET,
        .path = "/v1/metrics?mode=pairs",
        .path_only = "/v1/metrics",
        .query = "mode=pairs",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator);
    _ = response; // May be null or a Response depending on ebpf availability
    // Should handle the pairs mode query parameter
}

test "route returns null for POST to status" {
    const req = http.Request{
        .method = .POST,
        .path = "/v1/status",
        .path_only = "/v1/status",
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator);
    try testing.expect(response == null);
}

test "route returns null for DELETE to metrics" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/v1/metrics",
        .path_only = "/v1/metrics",
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator);
    try testing.expect(response == null);
}

test "resolveIpToService returns unknown for empty records" {
    const ip_net: u32 = 0x0A000001; // 10.0.0.1 in network order
    const records: []const store.ContainerRecord = &.{};
    const result = resolveIpToService(ip_net, records);
    try testing.expectEqualStrings("unknown", result);
}

test "writeSnapshotJson produces valid JSON" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const snap = monitor.ServiceSnapshot{
        .name = "test-service",
        .status = .running,
        .health_status = .healthy,
        .cpu_pct = 50.5,
        .memory_bytes = 1024 * 1024 * 100, // 100MB
        .running_count = 3,
        .desired_count = 3,
        .uptime_secs = 3600,
        .psi_cpu = null,
        .psi_memory = null,
    };

    writeSnapshotJson(writer, snap) catch unreachable;
    const json = stream.getWritten();

    // Verify JSON contains expected fields
    try testing.expect(std.mem.indexOf(u8, json, "test-service") != null);
    try testing.expect(std.mem.indexOf(u8, json, "running") != null);
    try testing.expect(std.mem.indexOf(u8, json, "healthy") != null);
    try testing.expect(std.mem.indexOf(u8, json, "50.5") != null);
}

test "writeSnapshotJson handles null health" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const snap = monitor.ServiceSnapshot{
        .name = "test-service",
        .status = .running,
        .health_status = null,
        .cpu_pct = 0.0,
        .memory_bytes = 0,
        .running_count = 1,
        .desired_count = 1,
        .uptime_secs = 0,
        .psi_cpu = null,
        .psi_memory = null,
    };

    writeSnapshotJson(writer, snap) catch unreachable;
    const json = stream.getWritten();

    try testing.expect(std.mem.indexOf(u8, json, "null") != null);
}

test "writeSnapshotJson includes PSI metrics when present" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const psi = cgroups.PsiMetrics{ .some_avg10 = 1.5, .full_avg10 = 0.5 };
    const snap = monitor.ServiceSnapshot{
        .name = "test-service",
        .status = .running,
        .health_status = .healthy,
        .cpu_pct = 25.0,
        .memory_bytes = 512 * 1024 * 1024,
        .running_count = 2,
        .desired_count = 2,
        .uptime_secs = 7200,
        .psi_cpu = psi,
        .psi_memory = psi,
    };

    writeSnapshotJson(writer, snap) catch unreachable;
    const json = stream.getWritten();

    try testing.expect(std.mem.indexOf(u8, json, "psi_cpu") != null);
    try testing.expect(std.mem.indexOf(u8, json, "psi_mem") != null);
}

test "route handles service filter in metrics" {
    if (true) return error.SkipZigTest; // Skip - requires store layer
    const req = http.Request{
        .method = .GET,
        .path = "/v1/metrics?service=myapp",
        .path_only = "/v1/metrics",
        .query = "service=myapp",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator);
    _ = response; // May be null or a Response depending on store state
    // Should handle the service filter query parameter
}

test "extractQueryParam from full path with multiple params" {
    try testing.expectEqualStrings("myapp", common.extractQueryParam("/v1/metrics?service=myapp&mode=details", "service").?);
    try testing.expectEqualStrings("details", common.extractQueryParam("/v1/metrics?service=myapp&mode=details", "mode").?);
}
