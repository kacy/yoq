const std = @import("std");
const builtin = @import("builtin");
const http = @import("../../http.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const storage_metrics = @import("../../../storage/metrics.zig");
const gpu_health = @import("../../../gpu/health.zig");
const gpu_detect = @import("../../../gpu/detect.zig");
const ip_mod = @import("../../../network/ip.zig");
const dns_registry = @import("../../../network/dns/registry_support.zig");
const dns_prog = @import("../../../network/bpf/dns_intercept.zig");
const ebpf_map_support = @import("../../../network/ebpf/map_support.zig");
const lb_prog = @import("../../../network/bpf/lb.zig");
const lb_runtime = @import("../../../network/ebpf/lb_runtime.zig");
const health = @import("../../../manifest/health.zig");
const service_registry_backfill = @import("../../../network/service_registry_backfill.zig");
const service_registry_bridge = @import("../../../network/service_registry_bridge.zig");
const service_cutover_readiness = @import("../../../network/service_cutover_readiness.zig");
const service_rollout = @import("../../../network/service_rollout.zig");
const service_reconciler = @import("../../../network/service_reconciler.zig");
const proxy_runtime = @import("../../../network/proxy/runtime.zig");
const listener_runtime = @import("../../../network/proxy/listener_runtime.zig");
const proxy_control_plane = @import("../../../network/proxy/control_plane.zig");
const steering_runtime = @import("../../../network/proxy/steering_runtime.zig");

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

    writeServiceRolloutPrometheus(writer) catch return common.internalError();

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

fn writeServiceRolloutPrometheus(writer: anytype) !void {
    const flags = service_rollout.current();
    const is_shadow = service_rollout.mode() == .shadow;
    var backfill = try service_registry_backfill.snapshot(std.heap.page_allocator);
    defer backfill.deinit(std.heap.page_allocator);
    var audit = try service_reconciler.snapshotAuditState(std.heap.page_allocator);
    defer audit.deinit(std.heap.page_allocator);
    var cutover = try service_cutover_readiness.snapshot(std.heap.page_allocator);
    defer cutover.deinit(std.heap.page_allocator);
    var l7_proxy = try proxy_runtime.snapshot(std.heap.page_allocator);
    defer l7_proxy.deinit(std.heap.page_allocator);
    var l7_listener = try listener_runtime.snapshot(std.heap.page_allocator);
    defer l7_listener.deinit(std.heap.page_allocator);
    const l7_control_plane = proxy_control_plane.snapshot();
    var l7_steering = try steering_runtime.snapshot(std.heap.page_allocator);
    defer l7_steering.deinit(std.heap.page_allocator);
    const node_signals = service_reconciler.snapshotNodeSignalState();
    const components = service_reconciler.snapshotComponentState();
    const checker = health.snapshotChecker();

    try writer.writeAll("# HELP yoq_service_rollout_shadow_mode Service rollout mode, 1 when shadow mode is active\n");
    try writer.writeAll("# TYPE yoq_service_rollout_shadow_mode gauge\n");
    try writer.print("yoq_service_rollout_shadow_mode {d}\n", .{@intFromBool(is_shadow)});

    try writer.writeAll("# HELP yoq_service_rollout_flag Service rollout feature flags\n");
    try writer.writeAll("# TYPE yoq_service_rollout_flag gauge\n");
    try writer.print("yoq_service_rollout_flag{{flag=\"service_registry_v2\"}} {d}\n", .{@intFromBool(flags.service_registry_v2)});
    try writer.print("yoq_service_rollout_flag{{flag=\"service_registry_reconciler\"}} {d}\n", .{@intFromBool(flags.service_registry_reconciler)});
    try writer.print("yoq_service_rollout_flag{{flag=\"dns_returns_vip\"}} {d}\n", .{@intFromBool(flags.dns_returns_vip)});
    try writer.print("yoq_service_rollout_flag{{flag=\"l7_proxy_http\"}} {d}\n", .{@intFromBool(flags.l7_proxy_http)});

    try writer.writeAll("# HELP yoq_service_rollout_limit Compile-time rollout and data-plane limits\n");
    try writer.writeAll("# TYPE yoq_service_rollout_limit gauge\n");
    try writer.print("yoq_service_rollout_limit{{limit=\"dns_registry_services\"}} {d}\n", .{dns_registry.max_services});
    try writer.print("yoq_service_rollout_limit{{limit=\"dns_name_length\"}} {d}\n", .{dns_registry.max_name_len});
    try writer.print("yoq_service_rollout_limit{{limit=\"dns_bpf_services\"}} {d}\n", .{dns_prog.maps[0].max_entries});
    try writer.print("yoq_service_rollout_limit{{limit=\"load_balancer_vips\"}} {d}\n", .{lb_prog.maps[0].max_entries});
    try writer.print("yoq_service_rollout_limit{{limit=\"load_balancer_backends_per_vip\"}} {d}\n", .{lb_runtime.max_backends});
    try writer.print("yoq_service_rollout_limit{{limit=\"conntrack_entries\"}} {d}\n", .{lb_prog.maps[1].max_entries});
    try writer.print("yoq_service_rollout_limit{{limit=\"recent_shadow_events\"}} {d}\n", .{service_reconciler.max_recent_events});
    try writer.print("yoq_service_rollout_limit{{limit=\"health_workers\"}} {d}\n", .{health.max_worker_threads});
    try writer.print("yoq_service_rollout_limit{{limit=\"health_queued_checks\"}} {d}\n", .{health.max_queued_checks});

    try writer.writeAll("# HELP yoq_service_l7_proxy_enabled Whether the L7 proxy control plane is enabled\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_enabled gauge\n");
    try writer.print("yoq_service_l7_proxy_enabled {d}\n", .{@intFromBool(l7_proxy.enabled)});

    try writer.writeAll("# HELP yoq_service_l7_proxy_running Whether the L7 proxy control plane has bootstrapped\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_running gauge\n");
    try writer.print("yoq_service_l7_proxy_running {d}\n", .{@intFromBool(l7_proxy.running)});

    try writer.writeAll("# HELP yoq_service_l7_proxy_configured_services Services with HTTP proxy policy configured\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_configured_services gauge\n");
    try writer.print("yoq_service_l7_proxy_configured_services {d}\n", .{l7_proxy.configured_services});

    try writer.writeAll("# HELP yoq_service_l7_proxy_routes Materialized HTTP proxy routes\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_routes gauge\n");
    try writer.print("yoq_service_l7_proxy_routes {d}\n", .{l7_proxy.routes});

    try writer.writeAll("# HELP yoq_service_l7_proxy_requests_total Total L7 proxy requests handled\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_requests_total counter\n");
    try writer.print("yoq_service_l7_proxy_requests_total {d}\n", .{l7_proxy.requests_total});

    try writer.writeAll("# HELP yoq_service_l7_proxy_responses_total L7 proxy responses by class\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_responses_total counter\n");
    try writer.print("yoq_service_l7_proxy_responses_total{{class=\"2xx\"}} {d}\n", .{l7_proxy.responses_2xx_total});
    try writer.print("yoq_service_l7_proxy_responses_total{{class=\"4xx\"}} {d}\n", .{l7_proxy.responses_4xx_total});
    try writer.print("yoq_service_l7_proxy_responses_total{{class=\"5xx\"}} {d}\n", .{l7_proxy.responses_5xx_total});

    try writer.writeAll("# HELP yoq_service_l7_proxy_retries_total L7 proxy retry attempts\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_retries_total counter\n");
    try writer.print("yoq_service_l7_proxy_retries_total {d}\n", .{l7_proxy.retries_total});

    try writer.writeAll("# HELP yoq_service_l7_proxy_loop_rejections_total L7 proxy requests rejected to prevent loops\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_loop_rejections_total counter\n");
    try writer.print("yoq_service_l7_proxy_loop_rejections_total {d}\n", .{l7_proxy.loop_rejections_total});

    try writer.writeAll("# HELP yoq_service_l7_proxy_upstream_failures_total L7 proxy upstream failures by stage\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_upstream_failures_total counter\n");
    try writer.print("yoq_service_l7_proxy_upstream_failures_total{{kind=\"connect\"}} {d}\n", .{l7_proxy.upstream_connect_failures_total});
    try writer.print("yoq_service_l7_proxy_upstream_failures_total{{kind=\"send\"}} {d}\n", .{l7_proxy.upstream_send_failures_total});
    try writer.print("yoq_service_l7_proxy_upstream_failures_total{{kind=\"receive\"}} {d}\n", .{l7_proxy.upstream_receive_failures_total});
    try writer.print("yoq_service_l7_proxy_upstream_failures_total{{kind=\"other\"}} {d}\n", .{l7_proxy.upstream_other_failures_total});

    try writer.writeAll("# HELP yoq_service_l7_proxy_circuit_trips_total L7 proxy endpoint circuit breaker trips\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_circuit_trips_total counter\n");
    try writer.print("yoq_service_l7_proxy_circuit_trips_total {d}\n", .{l7_proxy.circuit_trips_total});

    try writer.writeAll("# HELP yoq_service_l7_proxy_circuit_endpoints L7 proxy endpoints currently gated by circuit state\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_circuit_endpoints gauge\n");
    try writer.print("yoq_service_l7_proxy_circuit_endpoints{{state=\"open\"}} {d}\n", .{l7_proxy.circuit_open_endpoints});
    try writer.print("yoq_service_l7_proxy_circuit_endpoints{{state=\"half_open\"}} {d}\n", .{l7_proxy.circuit_half_open_endpoints});

    try writer.writeAll("# HELP yoq_service_l7_proxy_listener_enabled Whether the L7 proxy listener is enabled\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_listener_enabled gauge\n");
    try writer.print("yoq_service_l7_proxy_listener_enabled {d}\n", .{@intFromBool(l7_listener.enabled)});

    try writer.writeAll("# HELP yoq_service_l7_proxy_listener_running Whether the L7 proxy listener is accepting connections\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_listener_running gauge\n");
    try writer.print("yoq_service_l7_proxy_listener_running {d}\n", .{@intFromBool(l7_listener.running)});

    try writer.writeAll("# HELP yoq_service_l7_proxy_listener_port Loopback port bound by the L7 proxy listener\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_listener_port gauge\n");
    try writer.print("yoq_service_l7_proxy_listener_port {d}\n", .{l7_listener.port});

    try writer.writeAll("# HELP yoq_service_l7_proxy_listener_accepted_connections_total Total accepted L7 proxy listener connections\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_listener_accepted_connections_total counter\n");
    try writer.print("yoq_service_l7_proxy_listener_accepted_connections_total {d}\n", .{l7_listener.accepted_connections_total});

    try writer.writeAll("# HELP yoq_service_l7_proxy_listener_active_connections Active L7 proxy listener connections\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_listener_active_connections gauge\n");
    try writer.print("yoq_service_l7_proxy_listener_active_connections {d}\n", .{l7_listener.active_connections});

    try writer.writeAll("# HELP yoq_service_l7_proxy_control_plane_enabled Whether periodic L7 control-plane repair is enabled\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_control_plane_enabled gauge\n");
    try writer.print("yoq_service_l7_proxy_control_plane_enabled {d}\n", .{@intFromBool(l7_control_plane.enabled)});

    try writer.writeAll("# HELP yoq_service_l7_proxy_control_plane_steering_enabled Whether VIP steering repair is active within the L7 control plane\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_control_plane_steering_enabled gauge\n");
    try writer.print("yoq_service_l7_proxy_control_plane_steering_enabled {d}\n", .{@intFromBool(l7_control_plane.steering_enabled)});

    try writer.writeAll("# HELP yoq_service_l7_proxy_control_plane_running Whether the periodic L7 control-plane repair loop is running\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_control_plane_running gauge\n");
    try writer.print("yoq_service_l7_proxy_control_plane_running {d}\n", .{@intFromBool(l7_control_plane.running)});

    try writer.writeAll("# HELP yoq_service_l7_proxy_control_plane_interval_seconds Periodic L7 control-plane repair interval in seconds\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_control_plane_interval_seconds gauge\n");
    try writer.print("yoq_service_l7_proxy_control_plane_interval_seconds {d}\n", .{l7_control_plane.interval_secs});

    try writer.writeAll("# HELP yoq_service_l7_proxy_control_plane_passes_total Periodic L7 control-plane repair passes executed\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_control_plane_passes_total counter\n");
    try writer.print("yoq_service_l7_proxy_control_plane_passes_total {d}\n", .{l7_control_plane.passes_total});

    try writer.writeAll("# HELP yoq_service_l7_proxy_control_plane_passes_by_trigger_total L7 control-plane repair passes by trigger\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_control_plane_passes_by_trigger_total counter\n");
    try writer.print("yoq_service_l7_proxy_control_plane_passes_by_trigger_total{{trigger=\"event\"}} {d}\n", .{l7_control_plane.event_passes_total});
    try writer.print("yoq_service_l7_proxy_control_plane_passes_by_trigger_total{{trigger=\"periodic\"}} {d}\n", .{l7_control_plane.periodic_passes_total});

    try writer.writeAll("# HELP yoq_service_l7_proxy_control_plane_last_trigger Active label for the most recent control-plane sync trigger\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_control_plane_last_trigger gauge\n");
    inline for (comptime std.meta.fields(proxy_control_plane.SyncTrigger)) |field| {
        const trigger = @field(proxy_control_plane.SyncTrigger, field.name);
        try writer.print(
            "yoq_service_l7_proxy_control_plane_last_trigger{{trigger=\"{s}\"}} {d}\n",
            .{ trigger.label(), @intFromBool(l7_control_plane.last_trigger == trigger) },
        );
    }

    try writer.writeAll("# HELP yoq_service_l7_proxy_steering_enabled Whether VIP steering into the L7 listener is enabled\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_steering_enabled gauge\n");
    try writer.print("yoq_service_l7_proxy_steering_enabled {d}\n", .{@intFromBool(l7_steering.enabled)});

    try writer.writeAll("# HELP yoq_service_l7_proxy_steering_running Whether VIP steering currently has active applied mappings\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_steering_running gauge\n");
    try writer.print("yoq_service_l7_proxy_steering_running {d}\n", .{@intFromBool(l7_steering.running)});

    try writer.writeAll("# HELP yoq_service_l7_proxy_steering_blocked_reason Active VIP steering blocked reason by label\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_steering_blocked_reason gauge\n");
    inline for (comptime std.meta.fields(steering_runtime.BlockedReason)) |field| {
        const reason = @field(steering_runtime.BlockedReason, field.name);
        try writer.print(
            "yoq_service_l7_proxy_steering_blocked_reason{{reason=\"{s}\"}} {d}\n",
            .{ reason.label(), @intFromBool(l7_steering.blocked_reason == reason) },
        );
    }

    try writer.writeAll("# HELP yoq_service_l7_proxy_steering_configured_services Services eligible for VIP steering\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_steering_configured_services gauge\n");
    try writer.print("yoq_service_l7_proxy_steering_configured_services {d}\n", .{l7_steering.configured_services});

    try writer.writeAll("# HELP yoq_service_l7_proxy_steering_services Steering readiness summary by state\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_steering_services gauge\n");
    try writer.print("yoq_service_l7_proxy_steering_services{{state=\"not_ready\"}} {d}\n", .{l7_steering.not_ready_services});
    try writer.print("yoq_service_l7_proxy_steering_services{{state=\"blocked\"}} {d}\n", .{l7_steering.blocked_services});
    try writer.print("yoq_service_l7_proxy_steering_services{{state=\"drifted\"}} {d}\n", .{l7_steering.drifted_services});

    try writer.writeAll("# HELP yoq_service_l7_proxy_steering_mappings VIP steering mappings by state\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_steering_mappings gauge\n");
    try writer.print("yoq_service_l7_proxy_steering_mappings{{state=\"desired\"}} {d}\n", .{l7_steering.desired_mappings});
    try writer.print("yoq_service_l7_proxy_steering_mappings{{state=\"applied\"}} {d}\n", .{l7_steering.applied_mappings});

    try writer.writeAll("# HELP yoq_service_l7_proxy_steering_syncs_total Steering sync attempts by outcome\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_steering_syncs_total counter\n");
    try writer.print("yoq_service_l7_proxy_steering_syncs_total{{outcome=\"attempted\"}} {d}\n", .{l7_steering.sync_attempts_total});
    try writer.print("yoq_service_l7_proxy_steering_syncs_total{{outcome=\"failed\"}} {d}\n", .{l7_steering.sync_failures_total});

    try writer.writeAll("# HELP yoq_service_l7_proxy_steering_mapping_changes_total Steering mapping adds and removals\n");
    try writer.writeAll("# TYPE yoq_service_l7_proxy_steering_mapping_changes_total counter\n");
    try writer.print("yoq_service_l7_proxy_steering_mapping_changes_total{{action=\"applied\"}} {d}\n", .{l7_steering.mappings_applied_total});
    try writer.print("yoq_service_l7_proxy_steering_mapping_changes_total{{action=\"removed\"}} {d}\n", .{l7_steering.mappings_removed_total});

    try writer.writeAll("# HELP yoq_service_registry_bridge_fault_injections_total Injected bridge faults by operation\n");
    try writer.writeAll("# TYPE yoq_service_registry_bridge_fault_injections_total counter\n");
    try writer.print(
        "yoq_service_registry_bridge_fault_injections_total{{operation=\"container_register\"}} {d}\n",
        .{service_registry_bridge.faultInjectionCount(.container_register)},
    );
    try writer.print(
        "yoq_service_registry_bridge_fault_injections_total{{operation=\"container_unregister\"}} {d}\n",
        .{service_registry_bridge.faultInjectionCount(.container_unregister)},
    );
    try writer.print(
        "yoq_service_registry_bridge_fault_injections_total{{operation=\"endpoint_healthy\"}} {d}\n",
        .{service_registry_bridge.faultInjectionCount(.endpoint_healthy)},
    );
    try writer.print(
        "yoq_service_registry_bridge_fault_injections_total{{operation=\"endpoint_unhealthy\"}} {d}\n",
        .{service_registry_bridge.faultInjectionCount(.endpoint_unhealthy)},
    );

    try writer.writeAll("# HELP yoq_service_registry_bridge_fault_mode Active bridge fault mode by operation\n");
    try writer.writeAll("# TYPE yoq_service_registry_bridge_fault_mode gauge\n");
    try writeBridgeFaultMode(writer, .container_register);
    try writeBridgeFaultMode(writer, .container_unregister);
    try writeBridgeFaultMode(writer, .endpoint_healthy);
    try writeBridgeFaultMode(writer, .endpoint_unhealthy);

    try writer.writeAll("# HELP yoq_ebpf_map_update_fault_injections_total Injected eBPF map_update faults\n");
    try writer.writeAll("# TYPE yoq_ebpf_map_update_fault_injections_total counter\n");
    try writer.print("yoq_ebpf_map_update_fault_injections_total {d}\n", .{ebpf_map_support.mapUpdateFaultInjectionCount()});

    try writer.writeAll("# HELP yoq_ebpf_map_update_fault_mode Active eBPF map_update fault mode\n");
    try writer.writeAll("# TYPE yoq_ebpf_map_update_fault_mode gauge\n");
    try writeMapUpdateFaultMode(writer);

    try writer.writeAll("# HELP yoq_dns_cluster_lookup_fault_injections_total Injected cluster lookup faults\n");
    try writer.writeAll("# TYPE yoq_dns_cluster_lookup_fault_injections_total counter\n");
    try writer.print("yoq_dns_cluster_lookup_fault_injections_total {d}\n", .{dns_registry.clusterLookupFaultInjectionCount()});

    try writer.writeAll("# HELP yoq_dns_cluster_lookup_fault_mode Active cluster lookup fault mode\n");
    try writer.writeAll("# TYPE yoq_dns_cluster_lookup_fault_mode gauge\n");
    try writeClusterLookupFaultMode(writer);

    try writer.writeAll("# HELP yoq_dns_interceptor_fault_injections_total Injected DNS interceptor faults\n");
    try writer.writeAll("# TYPE yoq_dns_interceptor_fault_injections_total counter\n");
    try writer.print("yoq_dns_interceptor_fault_injections_total {d}\n", .{dns_registry.dnsInterceptorFaultInjectionCount()});

    try writer.writeAll("# HELP yoq_dns_interceptor_fault_mode Active DNS interceptor fault mode\n");
    try writer.writeAll("# TYPE yoq_dns_interceptor_fault_mode gauge\n");
    try writeDnsInterceptorFaultMode(writer);

    try writer.writeAll("# HELP yoq_load_balancer_fault_injections_total Injected load balancer faults\n");
    try writer.writeAll("# TYPE yoq_load_balancer_fault_injections_total counter\n");
    try writer.print("yoq_load_balancer_fault_injections_total {d}\n", .{dns_registry.loadBalancerFaultInjectionCount()});

    try writer.writeAll("# HELP yoq_load_balancer_fault_mode Active load balancer fault mode\n");
    try writer.writeAll("# TYPE yoq_load_balancer_fault_mode gauge\n");
    try writeLoadBalancerFaultMode(writer);
    try writer.writeAll("# HELP yoq_service_reconciler_shadow_events_total Shadow service reconciler events observed by kind\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_shadow_events_total counter\n");
    try writeShadowEventCounters(writer, .container_runtime);
    try writeShadowEventCounters(writer, .health_checker);
    try writeShadowEventCounters(writer, .unspecified);

    try writer.writeAll("# HELP yoq_service_registry_backfill_runs_total Legacy service_names backfill runs\n");
    try writer.writeAll("# TYPE yoq_service_registry_backfill_runs_total counter\n");
    try writer.print("yoq_service_registry_backfill_runs_total {d}\n", .{backfill.runs_total});

    try writer.writeAll("# HELP yoq_service_registry_backfill_created_total Canonical records created by legacy backfill\n");
    try writer.writeAll("# TYPE yoq_service_registry_backfill_created_total counter\n");
    try writer.print("yoq_service_registry_backfill_created_total{{kind=\"services\"}} {d}\n", .{backfill.services_created_total});
    try writer.print("yoq_service_registry_backfill_created_total{{kind=\"endpoints\"}} {d}\n", .{backfill.endpoints_created_total});

    try writer.writeAll("# HELP yoq_service_reconciler_audit_passes_total Service reconciler audit passes\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_audit_passes_total counter\n");
    try writer.print("yoq_service_reconciler_audit_passes_total {d}\n", .{audit.passes_total});

    try writer.writeAll("# HELP yoq_service_reconciler_audit_mismatch_services_total Service reconciler audit mismatches by service\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_audit_mismatch_services_total counter\n");
    try writer.print("yoq_service_reconciler_audit_mismatch_services_total {d}\n", .{audit.mismatch_services_total});

    try writer.writeAll("# HELP yoq_service_reconciler_audit_mismatches_by_kind_total Service reconciler audit mismatches by kind\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_audit_mismatches_by_kind_total counter\n");
    try writer.print("yoq_service_reconciler_audit_mismatches_by_kind_total{{kind=\"vip\"}} {d}\n", .{audit.vip_mismatches_total});
    try writer.print("yoq_service_reconciler_audit_mismatches_by_kind_total{{kind=\"endpoint_count\"}} {d}\n", .{audit.endpoint_count_mismatches_total});
    try writer.print("yoq_service_reconciler_audit_mismatches_by_kind_total{{kind=\"stale_endpoint\"}} {d}\n", .{audit.stale_endpoint_mismatches_total});
    try writer.print("yoq_service_reconciler_audit_mismatches_by_kind_total{{kind=\"eligibility\"}} {d}\n", .{audit.eligibility_mismatches_total});

    try writer.writeAll("# HELP yoq_service_reconciler_audit_repairs_total Service reconciler audit repairs\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_audit_repairs_total counter\n");
    try writer.print("yoq_service_reconciler_audit_repairs_total {d}\n", .{audit.repairs_total});

    try writer.writeAll("# HELP yoq_service_reconciler_stale_endpoint_quarantines_total Durable endpoints quarantined as stale\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_stale_endpoint_quarantines_total counter\n");
    try writer.print("yoq_service_reconciler_stale_endpoint_quarantines_total {d}\n", .{audit.stale_endpoint_quarantines_total});

    try writer.writeAll("# HELP yoq_service_reconciler_audit_running Whether the audit loop is running\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_audit_running gauge\n");
    try writer.print("yoq_service_reconciler_audit_running {d}\n", .{@intFromBool(audit.running)});

    try writer.writeAll("# HELP yoq_service_reconciler_degraded_services Current degraded services tracked by audits\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_degraded_services gauge\n");
    try writer.print("yoq_service_reconciler_degraded_services {d}\n", .{audit.degraded_services.items.len});

    try writer.writeAll("# HELP yoq_service_reconciler_node_signals_total Node loss and recovery signals processed by the reconciler\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_node_signals_total counter\n");
    try writer.print("yoq_service_reconciler_node_signals_total{{kind=\"lost\"}} {d}\n", .{node_signals.lost_total});
    try writer.print("yoq_service_reconciler_node_signals_total{{kind=\"recovered\"}} {d}\n", .{node_signals.recovered_total});

    try writer.writeAll("# HELP yoq_service_reconciler_node_signal_endpoints_changed_total Endpoint eligibility changes from node signals\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_node_signal_endpoints_changed_total counter\n");
    try writer.print("yoq_service_reconciler_node_signal_endpoints_changed_total {d}\n", .{node_signals.endpoints_changed_total});

    try writer.writeAll("# HELP yoq_service_reconciler_component_ready Whether a reconciler component is currently ready\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_component_ready gauge\n");
    try writer.print("yoq_service_reconciler_component_ready{{component=\"dns_resolver\"}} {d}\n", .{@intFromBool(components.state.dns_resolver_running)});
    try writer.print("yoq_service_reconciler_component_ready{{component=\"dns_interceptor\"}} {d}\n", .{@intFromBool(components.state.dns_interceptor_loaded)});
    try writer.print("yoq_service_reconciler_component_ready{{component=\"load_balancer\"}} {d}\n", .{@intFromBool(components.state.load_balancer_loaded)});

    try writer.writeAll("# HELP yoq_service_reconciler_component_state_changes_total Reconciler component state transitions\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_component_state_changes_total counter\n");
    try writer.print("yoq_service_reconciler_component_state_changes_total {d}\n", .{components.state_changes_total});

    try writer.writeAll("# HELP yoq_service_reconciler_component_full_resyncs_total Full resyncs triggered by component transitions\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_component_full_resyncs_total counter\n");
    try writer.print("yoq_service_reconciler_component_full_resyncs_total {d}\n", .{components.full_resyncs_total});

    try writer.writeAll("# HELP yoq_service_rollout_cutover_ready Cutover readiness checks and decisions\n");
    try writer.writeAll("# TYPE yoq_service_rollout_cutover_ready gauge\n");
    try writer.print("yoq_service_rollout_cutover_ready{{check=\"backfill_complete\"}} {d}\n", .{@intFromBool(cutover.backfill_complete)});
    try writer.print("yoq_service_rollout_cutover_ready{{check=\"audit_fresh\"}} {d}\n", .{@intFromBool(cutover.audit_fresh)});
    try writer.print("yoq_service_rollout_cutover_ready{{check=\"shadow_clean\"}} {d}\n", .{@intFromBool(cutover.shadow_clean)});
    try writer.print("yoq_service_rollout_cutover_ready{{check=\"components_ready\"}} {d}\n", .{@intFromBool(cutover.components_ready)});
    try writer.print("yoq_service_rollout_cutover_ready{{check=\"fault_modes_clear\"}} {d}\n", .{@intFromBool(cutover.fault_modes_clear)});
    try writer.print("yoq_service_rollout_cutover_ready{{check=\"downgrade_safe\"}} {d}\n", .{@intFromBool(cutover.downgrade_safe)});
    try writer.print("yoq_service_rollout_cutover_ready{{check=\"steering_ready\"}} {d}\n", .{@intFromBool(cutover.steering_ready)});
    try writer.print("yoq_service_rollout_cutover_ready{{check=\"reconciler_cutover\"}} {d}\n", .{@intFromBool(cutover.ready_for_reconciler_cutover)});
    try writer.print("yoq_service_rollout_cutover_ready{{check=\"vip_cutover\"}} {d}\n", .{@intFromBool(cutover.ready_for_vip_cutover)});

    try writer.writeAll("# HELP yoq_service_rollout_cutover_steering_services Steering preflight service counts for VIP cutover\n");
    try writer.writeAll("# TYPE yoq_service_rollout_cutover_steering_services gauge\n");
    try writer.print("yoq_service_rollout_cutover_steering_services{{state=\"blocked\"}} {d}\n", .{cutover.steering_blocked_services});
    try writer.print("yoq_service_rollout_cutover_steering_services{{state=\"missing_ports\"}} {d}\n", .{cutover.steering_no_port_services});

    try writer.writeAll("# HELP yoq_health_checker_running Whether the health checker scheduler is running\n");
    try writer.writeAll("# TYPE yoq_health_checker_running gauge\n");
    try writer.print("yoq_health_checker_running {d}\n", .{@intFromBool(checker.running)});

    try writer.writeAll("# HELP yoq_health_checker_tracked_endpoints Tracked health-checked endpoints\n");
    try writer.writeAll("# TYPE yoq_health_checker_tracked_endpoints gauge\n");
    try writer.print("yoq_health_checker_tracked_endpoints {d}\n", .{checker.tracked_endpoints});

    try writer.writeAll("# HELP yoq_health_checker_in_flight_checks In-flight health checks\n");
    try writer.writeAll("# TYPE yoq_health_checker_in_flight_checks gauge\n");
    try writer.print("yoq_health_checker_in_flight_checks {d}\n", .{checker.in_flight_checks});

    try writer.writeAll("# HELP yoq_health_checker_queued_checks Queued health checks\n");
    try writer.writeAll("# TYPE yoq_health_checker_queued_checks gauge\n");
    try writer.print("yoq_health_checker_queued_checks {d}\n", .{checker.queued_checks});

    try writer.writeAll("# HELP yoq_health_checker_worker_threads Worker threads for health checks\n");
    try writer.writeAll("# TYPE yoq_health_checker_worker_threads gauge\n");
    try writer.print("yoq_health_checker_worker_threads {d}\n", .{checker.worker_threads});

    try writer.writeAll("# HELP yoq_health_checker_checks_total Scheduled and completed health checks\n");
    try writer.writeAll("# TYPE yoq_health_checker_checks_total counter\n");
    try writer.print("yoq_health_checker_checks_total{{kind=\"scheduled\"}} {d}\n", .{checker.scheduled_total});
    try writer.print("yoq_health_checker_checks_total{{kind=\"completed\"}} {d}\n", .{checker.completed_total});

    try writer.writeAll("# HELP yoq_health_checker_stale_results_total Stale health check completions rejected by generation or registration epoch\n");
    try writer.writeAll("# TYPE yoq_health_checker_stale_results_total counter\n");
    try writer.print("yoq_health_checker_stale_results_total {d}\n", .{checker.stale_results_total});

    try writer.writeAll("# HELP yoq_health_checker_queue_drops_total Health checks dropped because the queue is full\n");
    try writer.writeAll("# TYPE yoq_health_checker_queue_drops_total counter\n");
    try writer.print("yoq_health_checker_queue_drops_total {d}\n", .{checker.dropped_queue_full_total});
}

fn writeBridgeFaultMode(writer: anytype, operation: service_registry_bridge.BridgeOperation) !void {
    const mode = service_registry_bridge.faultMode(operation);
    try writer.print(
        "yoq_service_registry_bridge_fault_mode{{operation=\"{s}\",mode=\"none\"}} {d}\n",
        .{ operation.label(), @intFromBool(mode == .none) },
    );
    try writer.print(
        "yoq_service_registry_bridge_fault_mode{{operation=\"{s}\",mode=\"skip_legacy_apply\"}} {d}\n",
        .{ operation.label(), @intFromBool(mode == .skip_legacy_apply) },
    );
    try writer.print(
        "yoq_service_registry_bridge_fault_mode{{operation=\"{s}\",mode=\"skip_shadow_record\"}} {d}\n",
        .{ operation.label(), @intFromBool(mode == .skip_shadow_record) },
    );
}

fn writeMapUpdateFaultMode(writer: anytype) !void {
    const mode = ebpf_map_support.mapUpdateFaultMode();
    try writer.print(
        "yoq_ebpf_map_update_fault_mode{{mode=\"none\"}} {d}\n",
        .{@intFromBool(mode == .none)},
    );
    try writer.print(
        "yoq_ebpf_map_update_fault_mode{{mode=\"fail_update\"}} {d}\n",
        .{@intFromBool(mode == .fail_update)},
    );
    try writer.print(
        "yoq_ebpf_map_update_fault_mode{{mode=\"map_full\"}} {d}\n",
        .{@intFromBool(mode == .map_full)},
    );
}

fn writeClusterLookupFaultMode(writer: anytype) !void {
    const mode = dns_registry.clusterLookupFaultMode();
    try writer.print(
        "yoq_dns_cluster_lookup_fault_mode{{mode=\"none\"}} {d}\n",
        .{@intFromBool(mode == .none)},
    );
    try writer.print(
        "yoq_dns_cluster_lookup_fault_mode{{mode=\"force_miss\"}} {d}\n",
        .{@intFromBool(mode == .force_miss)},
    );
    try writer.print(
        "yoq_dns_cluster_lookup_fault_mode{{mode=\"stale_override\"}} {d}\n",
        .{@intFromBool(mode == .stale_override)},
    );
}

fn writeDnsInterceptorFaultMode(writer: anytype) !void {
    const mode = dns_registry.dnsInterceptorFaultMode();
    try writer.print(
        "yoq_dns_interceptor_fault_mode{{mode=\"none\"}} {d}\n",
        .{@intFromBool(mode == .none)},
    );
    try writer.print(
        "yoq_dns_interceptor_fault_mode{{mode=\"unavailable\"}} {d}\n",
        .{@intFromBool(mode == .unavailable)},
    );
}

fn writeLoadBalancerFaultMode(writer: anytype) !void {
    const mode = dns_registry.loadBalancerFaultMode();
    try writer.print(
        "yoq_load_balancer_fault_mode{{mode=\"none\"}} {d}\n",
        .{@intFromBool(mode == .none)},
    );
    try writer.print(
        "yoq_load_balancer_fault_mode{{mode=\"endpoint_overflow\"}} {d}\n",
        .{@intFromBool(mode == .endpoint_overflow)},
    );
}
fn writeShadowEventCounters(writer: anytype, source: service_reconciler.EventSource) !void {
    try writer.print(
        "yoq_service_reconciler_shadow_events_total{{source=\"{s}\",kind=\"container_registered\"}} {d}\n",
        .{ source.label(), service_reconciler.eventCountBySource(source, .container_registered) },
    );
    try writer.print(
        "yoq_service_reconciler_shadow_events_total{{source=\"{s}\",kind=\"container_unregistered\"}} {d}\n",
        .{ source.label(), service_reconciler.eventCountBySource(source, .container_unregistered) },
    );
    try writer.print(
        "yoq_service_reconciler_shadow_events_total{{source=\"{s}\",kind=\"endpoint_healthy\"}} {d}\n",
        .{ source.label(), service_reconciler.eventCountBySource(source, .endpoint_healthy) },
    );
    try writer.print(
        "yoq_service_reconciler_shadow_events_total{{source=\"{s}\",kind=\"endpoint_unhealthy\"}} {d}\n",
        .{ source.label(), service_reconciler.eventCountBySource(source, .endpoint_unhealthy) },
    );
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
