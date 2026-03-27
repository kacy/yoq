const std = @import("std");
const store = @import("../../../state/store.zig");
const monitor = @import("../../../runtime/monitor.zig");
const common = @import("../common.zig");
const writers = @import("writers.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const dns_registry = @import("../../../network/dns/registry_support.zig");
const dns_prog = @import("../../../network/bpf/dns_intercept.zig");
const ebpf_map_support = @import("../../../network/ebpf/map_support.zig");
const lb_prog = @import("../../../network/bpf/lb.zig");
const lb_runtime = @import("../../../network/ebpf/lb_runtime.zig");
const health = @import("../../../manifest/health.zig");
const service_registry_bridge = @import("../../../network/service_registry_bridge.zig");
const service_rollout = @import("../../../network/service_rollout.zig");
const service_reconciler = @import("../../../network/service_reconciler.zig");

const Response = common.Response;

pub fn handleStatus(alloc: std.mem.Allocator) Response {
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
        writers.writeSnapshotJson(writer, snap) catch return common.internalError();
    }

    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleServiceRolloutStatus(alloc: std.mem.Allocator) Response {
    const flags = service_rollout.current();
    var audit = service_reconciler.snapshotAuditState(alloc) catch return common.internalError();
    defer audit.deinit(alloc);
    const node_signals = service_reconciler.snapshotNodeSignalState();
    const components = service_reconciler.snapshotComponentState();
    const checker = health.snapshotChecker();

    var events: [service_reconciler.max_recent_events]service_reconciler.Event = undefined;
    const event_count = service_reconciler.snapshotRecentEvents(&events);

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    var writer = json_buf.writer(alloc);

    writer.writeAll("{\"mode\":\"") catch return common.internalError();
    writer.writeAll(switch (service_rollout.mode()) {
        .legacy => "legacy",
        .shadow => "shadow",
    }) catch return common.internalError();
    writer.writeAll("\",\"flags\":{") catch return common.internalError();
    writer.print(
        "\"service_registry_v2\":{},\"service_registry_reconciler\":{},\"dns_returns_vip\":{},\"l7_proxy_http\":{}",
        .{
            flags.service_registry_v2,
            flags.service_registry_reconciler,
            flags.dns_returns_vip,
            flags.l7_proxy_http,
        },
    ) catch return common.internalError();
    writer.writeAll("},\"limits\":{") catch return common.internalError();
    writer.print(
        "\"dns_registry_services\":{d},\"dns_name_length\":{d},\"dns_bpf_services\":{d},\"load_balancer_vips\":{d},\"load_balancer_backends_per_vip\":{d},\"conntrack_entries\":{d},\"recent_shadow_events\":{d},\"health_workers\":{d},\"health_queued_checks\":{d}",
        .{
            dns_registry.max_services,
            dns_registry.max_name_len,
            dns_prog.maps[0].max_entries,
            lb_prog.maps[0].max_entries,
            lb_runtime.max_backends,
            lb_prog.maps[1].max_entries,
            service_reconciler.max_recent_events,
            health.max_worker_threads,
            health.max_queued_checks,
        },
    ) catch return common.internalError();
    writer.writeAll("},\"bridge_fault_injections\":{") catch return common.internalError();
    writer.print(
        "\"container_register\":{d},\"container_unregister\":{d},\"endpoint_healthy\":{d},\"endpoint_unhealthy\":{d}",
        .{
            service_registry_bridge.faultInjectionCount(.container_register),
            service_registry_bridge.faultInjectionCount(.container_unregister),
            service_registry_bridge.faultInjectionCount(.endpoint_healthy),
            service_registry_bridge.faultInjectionCount(.endpoint_unhealthy),
        },
    ) catch return common.internalError();
    writer.writeAll("},\"bridge_fault_modes\":{") catch return common.internalError();
    writer.print(
        "\"container_register\":\"{s}\",\"container_unregister\":\"{s}\",\"endpoint_healthy\":\"{s}\",\"endpoint_unhealthy\":\"{s}\"",
        .{
            service_registry_bridge.faultMode(.container_register).label(),
            service_registry_bridge.faultMode(.container_unregister).label(),
            service_registry_bridge.faultMode(.endpoint_healthy).label(),
            service_registry_bridge.faultMode(.endpoint_unhealthy).label(),
        },
    ) catch return common.internalError();
    writer.writeAll("},\"ebpf_map_update_fault\":{") catch return common.internalError();
    writer.print(
        "\"mode\":\"{s}\",\"injections\":{d}",
        .{
            ebpf_map_support.mapUpdateFaultMode().label(),
            ebpf_map_support.mapUpdateFaultInjectionCount(),
        },
    ) catch return common.internalError();
    const cluster_fault_ip = dns_registry.clusterLookupFaultIp();
    writer.writeAll("},\"cluster_lookup_fault\":{") catch return common.internalError();
    writer.print(
        "\"mode\":\"{s}\",\"injections\":{d},\"stale_ip\":\"{d}.{d}.{d}.{d}\"",
        .{
            dns_registry.clusterLookupFaultMode().label(),
            dns_registry.clusterLookupFaultInjectionCount(),
            cluster_fault_ip[0],
            cluster_fault_ip[1],
            cluster_fault_ip[2],
            cluster_fault_ip[3],
        },
    ) catch return common.internalError();
    writer.writeAll("},\"dns_interceptor_fault\":{") catch return common.internalError();
    writer.print(
        "\"mode\":\"{s}\",\"injections\":{d}",
        .{
            dns_registry.dnsInterceptorFaultMode().label(),
            dns_registry.dnsInterceptorFaultInjectionCount(),
        },
    ) catch return common.internalError();
    writer.writeAll("},\"load_balancer_fault\":{") catch return common.internalError();
    writer.print(
        "\"mode\":\"{s}\",\"injections\":{d}",
        .{
            dns_registry.loadBalancerFaultMode().label(),
            dns_registry.loadBalancerFaultInjectionCount(),
        },
    ) catch return common.internalError();
    writer.writeAll("},\"components\":{") catch return common.internalError();
    writer.print(
        "\"dns_resolver_running\":{},\"dns_interceptor_loaded\":{},\"load_balancer_loaded\":{},\"state_changes_total\":{d},\"full_resyncs_total\":{d},\"last_change_at\":",
        .{
            components.state.dns_resolver_running,
            components.state.dns_interceptor_loaded,
            components.state.load_balancer_loaded,
            components.state_changes_total,
            components.full_resyncs_total,
        },
    ) catch return common.internalError();
    if (components.last_change_at) |timestamp| {
        writer.print("{d}", .{timestamp}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll("},\"health_checker\":{") catch return common.internalError();
    writer.print(
        "\"running\":{},\"tracked_endpoints\":{d},\"in_flight_checks\":{d},\"queued_checks\":{d},\"worker_threads\":{d},\"scheduled_total\":{d},\"completed_total\":{d},\"stale_results_total\":{d},\"dropped_queue_full_total\":{d},\"last_scheduled_at\":",
        .{
            checker.running,
            checker.tracked_endpoints,
            checker.in_flight_checks,
            checker.queued_checks,
            checker.worker_threads,
            checker.scheduled_total,
            checker.completed_total,
            checker.stale_results_total,
            checker.dropped_queue_full_total,
        },
    ) catch return common.internalError();
    if (checker.last_scheduled_at) |timestamp| {
        writer.print("{d}", .{timestamp}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll(",\"last_completed_at\":") catch return common.internalError();
    if (checker.last_completed_at) |timestamp| {
        writer.print("{d}", .{timestamp}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll("},\"audit\":{") catch return common.internalError();
    writer.print(
        "\"enabled\":{},\"running\":{},\"passes_total\":{d},\"mismatch_services_total\":{d},\"repairs_total\":{d},\"stale_endpoint_quarantines_total\":{d},\"last_audit_at\":",
        .{
            audit.enabled,
            audit.running,
            audit.passes_total,
            audit.mismatch_services_total,
            audit.repairs_total,
            audit.stale_endpoint_quarantines_total,
        },
    ) catch return common.internalError();
    if (audit.last_audit_at) |timestamp| {
        writer.print("{d}", .{timestamp}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll(",\"last_mismatch_at\":") catch return common.internalError();
    if (audit.last_mismatch_at) |timestamp| {
        writer.print("{d}", .{timestamp}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll(",\"last_stale_quarantine_at\":") catch return common.internalError();
    if (audit.last_stale_quarantine_at) |timestamp| {
        writer.print("{d}", .{timestamp}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll(",\"last_error\":") catch return common.internalError();
    if (audit.last_error) |message| {
        writer.writeByte('"') catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, message) catch return common.internalError();
        writer.writeByte('"') catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll(",\"degraded_services\":[") catch return common.internalError();
    for (audit.degraded_services.items, 0..) |service_name, idx| {
        if (idx > 0) writer.writeByte(',') catch return common.internalError();
        writer.writeByte('"') catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, service_name) catch return common.internalError();
        writer.writeByte('"') catch return common.internalError();
    }
    writer.writeAll("],\"node_signals\":{") catch return common.internalError();
    writer.print(
        "\"lost_total\":{d},\"recovered_total\":{d},\"endpoints_changed_total\":{d},\"last_lost_node_id\":",
        .{
            node_signals.lost_total,
            node_signals.recovered_total,
            node_signals.endpoints_changed_total,
        },
    ) catch return common.internalError();
    if (node_signals.last_lost_node_id) |node_id| {
        writer.print("{d}", .{node_id}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll(",\"last_recovered_node_id\":") catch return common.internalError();
    if (node_signals.last_recovered_node_id) |node_id| {
        writer.print("{d}", .{node_id}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll("},\"events\":{\"counts\":{") catch return common.internalError();
    writer.print(
        "\"container_registered\":{d},\"container_unregistered\":{d},\"endpoint_healthy\":{d},\"endpoint_unhealthy\":{d}",
        .{
            service_reconciler.eventCount(.container_registered),
            service_reconciler.eventCount(.container_unregistered),
            service_reconciler.eventCount(.endpoint_healthy),
            service_reconciler.eventCount(.endpoint_unhealthy),
        },
    ) catch return common.internalError();
    writer.writeAll("},\"by_source\":{") catch return common.internalError();
    writeSourceCounts(writer, .container_runtime) catch return common.internalError();
    writer.writeByte(',') catch return common.internalError();
    writeSourceCounts(writer, .health_checker) catch return common.internalError();
    writer.writeByte(',') catch return common.internalError();
    writeSourceCounts(writer, .unspecified) catch return common.internalError();
    writer.writeAll("},\"recent\":[") catch return common.internalError();

    for (events[0..event_count], 0..) |event, idx| {
        if (idx > 0) writer.writeByte(',') catch return common.internalError();

        writer.writeAll("{\"source\":\"") catch return common.internalError();
        writer.writeAll(event.source.label()) catch return common.internalError();
        writer.writeAll("\",\"kind\":\"") catch return common.internalError();
        writer.writeAll(event.kind.label()) catch return common.internalError();
        writer.writeAll("\",\"service\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, event.serviceName()) catch return common.internalError();
        writer.writeAll("\",\"container\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, event.containerId()) catch return common.internalError();
        writer.writeAll("\",\"recorded_at\":") catch return common.internalError();
        writer.print("{d}", .{event.recorded_at}) catch return common.internalError();
        if (event.ip) |ip| {
            writer.writeAll(",\"ip\":\"") catch return common.internalError();
            writer.print("{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch return common.internalError();
            writer.writeByte('"') catch return common.internalError();
        }
        writer.writeByte('}') catch return common.internalError();
    }

    writer.writeAll("]}}") catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn writeSourceCounts(writer: anytype, source: service_reconciler.EventSource) !void {
    try writer.print(
        "\"{s}\":{{\"container_registered\":{d},\"container_unregistered\":{d},\"endpoint_healthy\":{d},\"endpoint_unhealthy\":{d}}}",
        .{
            source.label(),
            service_reconciler.eventCountBySource(source, .container_registered),
            service_reconciler.eventCountBySource(source, .container_unregistered),
            service_reconciler.eventCountBySource(source, .endpoint_healthy),
            service_reconciler.eventCountBySource(source, .endpoint_unhealthy),
        },
    );
}
