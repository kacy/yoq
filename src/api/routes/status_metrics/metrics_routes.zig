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
const service_registry_bridge = @import("../../../network/service_registry_bridge.zig");
const service_rollout = @import("../../../network/service_rollout.zig");
const service_reconciler = @import("../../../network/service_reconciler.zig");

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
    var audit = try service_reconciler.snapshotAuditState(std.heap.page_allocator);
    defer audit.deinit(std.heap.page_allocator);

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

    try writer.writeAll("# HELP yoq_service_reconciler_audit_passes_total Service reconciler audit passes\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_audit_passes_total counter\n");
    try writer.print("yoq_service_reconciler_audit_passes_total {d}\n", .{audit.passes_total});

    try writer.writeAll("# HELP yoq_service_reconciler_audit_mismatch_services_total Service reconciler audit mismatches by service\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_audit_mismatch_services_total counter\n");
    try writer.print("yoq_service_reconciler_audit_mismatch_services_total {d}\n", .{audit.mismatch_services_total});

    try writer.writeAll("# HELP yoq_service_reconciler_audit_repairs_total Service reconciler audit repairs\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_audit_repairs_total counter\n");
    try writer.print("yoq_service_reconciler_audit_repairs_total {d}\n", .{audit.repairs_total});

    try writer.writeAll("# HELP yoq_service_reconciler_audit_running Whether the audit loop is running\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_audit_running gauge\n");
    try writer.print("yoq_service_reconciler_audit_running {d}\n", .{@intFromBool(audit.running)});

    try writer.writeAll("# HELP yoq_service_reconciler_degraded_services Current degraded services tracked by audits\n");
    try writer.writeAll("# TYPE yoq_service_reconciler_degraded_services gauge\n");
    try writer.print("yoq_service_reconciler_degraded_services {d}\n", .{audit.degraded_services.items.len});
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
