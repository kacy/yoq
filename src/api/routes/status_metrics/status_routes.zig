const std = @import("std");
const store = @import("../../../state/store.zig");
const monitor = @import("../../../runtime/monitor.zig");
const common = @import("../common.zig");
const route_traffic_json = @import("../route_traffic_json.zig");
const writers = @import("writers.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
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
    const flags = service_rollout.canonicalFlags();
    var backfill = service_registry_backfill.snapshot(alloc) catch return common.internalError();
    defer backfill.deinit(alloc);
    var audit = service_reconciler.snapshotAuditState(alloc) catch return common.internalError();
    defer audit.deinit(alloc);
    var cutover = service_cutover_readiness.snapshot(alloc) catch return common.internalError();
    defer cutover.deinit(alloc);
    var l7_proxy = proxy_runtime.snapshot(alloc) catch return common.internalError();
    defer l7_proxy.deinit(alloc);
    var l7_listener = listener_runtime.snapshot(alloc) catch return common.internalError();
    defer l7_listener.deinit(alloc);
    const l7_control_plane = proxy_control_plane.snapshot();
    var l7_steering = steering_runtime.snapshot(alloc) catch return common.internalError();
    defer l7_steering.deinit(alloc);
    var l7_routes = proxy_runtime.snapshotRoutes(alloc) catch return common.internalError();
    defer {
        for (l7_routes.items) |route| route.deinit(alloc);
        l7_routes.deinit(alloc);
    }
    var l7_route_traffic = proxy_runtime.snapshotRouteTraffic(alloc) catch return common.internalError();
    defer {
        for (l7_route_traffic.items) |entry| entry.deinit(alloc);
        l7_route_traffic.deinit(alloc);
    }
    const node_signals = service_reconciler.snapshotNodeSignalState();
    const components = service_reconciler.snapshotComponentState();
    const checker = health.snapshotChecker();

    var events: [service_reconciler.max_recent_events]service_reconciler.Event = undefined;
    const event_count = service_reconciler.snapshotRecentEvents(&events);

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    var writer = json_buf.writer(alloc);

    writer.writeAll("{\"mode\":\"canonical") catch return common.internalError();
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
        "\"dns_registry_services\":{d},\"dns_name_length\":{d},\"dns_bpf_services\":{d},\"load_balancer_vips\":{d},\"load_balancer_backends_per_vip\":{d},\"conntrack_entries\":{d},\"recent_reconciler_events\":{d},\"recent_shadow_events\":{d},\"health_workers\":{d},\"health_queued_checks\":{d}",
        .{
            dns_registry.max_services,
            dns_registry.max_name_len,
            dns_prog.maps[0].max_entries,
            lb_prog.maps[0].max_entries,
            lb_runtime.max_backends,
            lb_prog.maps[1].max_entries,
            service_reconciler.max_recent_events,
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
    writer.writeAll("},\"backfill\":{") catch return common.internalError();
    writer.print(
        "\"enabled\":{},\"runs_total\":{d},\"services_created_total\":{d},\"endpoints_created_total\":{d},\"last_run_at\":",
        .{
            backfill.enabled,
            backfill.runs_total,
            backfill.services_created_total,
            backfill.endpoints_created_total,
        },
    ) catch return common.internalError();
    if (backfill.last_run_at) |timestamp| {
        writer.print("{d}", .{timestamp}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll(",\"last_error\":") catch return common.internalError();
    if (backfill.last_error) |message| {
        writer.writeByte('"') catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, message) catch return common.internalError();
        writer.writeByte('"') catch return common.internalError();
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
    writer.writeAll("},\"l7_proxy\":{") catch return common.internalError();
    writer.print(
        "\"enabled\":{},\"running\":{},\"configured_services\":{d},\"routes\":{d},\"requests_total\":{d},\"responses_2xx_total\":{d},\"responses_4xx_total\":{d},\"responses_5xx_total\":{d},\"retries_total\":{d},\"loop_rejections_total\":{d},\"upstream_connect_failures_total\":{d},\"upstream_send_failures_total\":{d},\"upstream_receive_failures_total\":{d},\"upstream_other_failures_total\":{d},\"circuit_trips_total\":{d},\"circuit_open_endpoints\":{d},\"circuit_half_open_endpoints\":{d},\"last_sync_at\":",
        .{
            l7_proxy.enabled,
            l7_proxy.running,
            l7_proxy.configured_services,
            l7_proxy.routes,
            l7_proxy.requests_total,
            l7_proxy.responses_2xx_total,
            l7_proxy.responses_4xx_total,
            l7_proxy.responses_5xx_total,
            l7_proxy.retries_total,
            l7_proxy.loop_rejections_total,
            l7_proxy.upstream_connect_failures_total,
            l7_proxy.upstream_send_failures_total,
            l7_proxy.upstream_receive_failures_total,
            l7_proxy.upstream_other_failures_total,
            l7_proxy.circuit_trips_total,
            l7_proxy.circuit_open_endpoints,
            l7_proxy.circuit_half_open_endpoints,
        },
    ) catch return common.internalError();
    if (l7_proxy.last_sync_at) |timestamp| {
        writer.print("{d}", .{timestamp}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll(",\"last_error\":") catch return common.internalError();
    if (l7_proxy.last_error) |message| {
        writer.writeByte('"') catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, message) catch return common.internalError();
        writer.writeByte('"') catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll(",\"sample_routes\":[") catch return common.internalError();
    for (l7_routes.items[0..@min(l7_routes.items.len, proxy_runtime.max_routes_in_status)], 0..) |route, idx| {
        if (idx > 0) writer.writeByte(',') catch return common.internalError();
        writer.writeAll("{\"name\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, route.name) catch return common.internalError();
        writer.writeAll("\",\"service\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, route.service) catch return common.internalError();
        writer.writeAll("\",\"vip_address\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, route.vip_address) catch return common.internalError();
        writer.writeAll("\",\"host\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, route.host) catch return common.internalError();
        writer.writeAll("\",\"path_prefix\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, route.path_prefix) catch return common.internalError();
        if (route.rewrite_prefix) |rewrite_prefix| {
            writer.writeAll("\",\"rewrite_prefix\":\"") catch return common.internalError();
            json_helpers.writeJsonEscaped(writer, rewrite_prefix) catch return common.internalError();
        }
        writer.print(
            "\",\"eligible_endpoints\":{d},\"healthy_endpoints\":{d},\"degraded\":{},\"degraded_reason\":\"{s}\",\"retries\":{d},\"connect_timeout_ms\":{d},\"request_timeout_ms\":{d},\"http2_idle_timeout_ms\":{d},\"preserve_host\":{},\"vip_traffic_mode\":\"{s}\",\"steering_desired_ports\":{d},\"steering_applied_ports\":{d},\"steering_ready\":{},\"steering_blocked\":{},\"steering_drifted\":{},\"steering_blocked_reason\":\"{s}\",\"last_failure_kind\":",
            .{
                route.eligible_endpoints,
                route.healthy_endpoints,
                route.degraded,
                route.degraded_reason.label(),
                route.retries,
                route.connect_timeout_ms,
                route.request_timeout_ms,
                route.http2_idle_timeout_ms,
                route.preserve_host,
                route.vip_traffic_mode.label(),
                route.steering_desired_ports,
                route.steering_applied_ports,
                route.steering_ready,
                route.steering_blocked,
                route.steering_drifted,
                route.steering_blocked_reason.label(),
            },
        ) catch return common.internalError();
        if (route.last_failure_kind) |kind| {
            writer.print("\"{s}\"", .{kind.label()}) catch return common.internalError();
        } else {
            writer.writeAll("null") catch return common.internalError();
        }
        if (route.method_matches.len > 0) {
            writer.writeAll(",\"match_methods\":") catch return common.internalError();
            writeMethodMatchesJson(writer, route.method_matches) catch return common.internalError();
        }
        if (route.header_matches.len > 0) {
            writer.writeAll(",\"match_headers\":") catch return common.internalError();
            writeHeaderMatchesJson(writer, route.header_matches) catch return common.internalError();
        }
        if (route.backend_services.len > 0) {
            writer.writeAll(",\"backend_services\":") catch return common.internalError();
            writeBackendServicesJson(writer, route.backend_services) catch return common.internalError();
        }
        if (route.mirror_service) |mirror_service| {
            writer.writeAll(",\"mirror_service\":\"") catch return common.internalError();
            json_helpers.writeJsonEscaped(writer, mirror_service) catch return common.internalError();
            writer.writeByte('"') catch return common.internalError();
        }
        writer.writeAll(",\"last_failure_at\":") catch return common.internalError();
        if (route.last_failure_at) |timestamp| {
            writer.print("{d}", .{timestamp}) catch return common.internalError();
        } else {
            writer.writeAll("null") catch return common.internalError();
        }
        writer.writeAll(",\"traffic\":") catch return common.internalError();
        route_traffic_json.writeRouteTrafficSummaryJson(writer, .primary, route.name, l7_route_traffic.items) catch return common.internalError();
        writer.writeAll(",\"backend_traffic\":") catch return common.internalError();
        route_traffic_json.writeRouteBackendTrafficJson(writer, .primary, route.name, l7_route_traffic.items) catch return common.internalError();
        writer.writeAll(",\"mirror_traffic\":") catch return common.internalError();
        route_traffic_json.writeRouteTrafficSummaryJson(writer, .mirror, route.name, l7_route_traffic.items) catch return common.internalError();
        writer.writeAll(",\"mirror_backend_traffic\":") catch return common.internalError();
        route_traffic_json.writeRouteBackendTrafficJson(writer, .mirror, route.name, l7_route_traffic.items) catch return common.internalError();
        writer.writeByte('}') catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();
    writer.writeAll(",\"sample_route_traffic\":") catch return common.internalError();
    writeRouteTrafficJson(writer, l7_route_traffic.items) catch return common.internalError();
    writer.writeAll("},\"listener\":{") catch return common.internalError();
    writer.print(
        "\"enabled\":{},\"running\":{},\"bind_addr\":\"{d}.{d}.{d}.{d}\",\"port\":{d},\"accepted_connections_total\":{d},\"active_connections\":{d},\"last_error\":",
        .{
            l7_listener.enabled,
            l7_listener.running,
            l7_listener.bind_addr[0],
            l7_listener.bind_addr[1],
            l7_listener.bind_addr[2],
            l7_listener.bind_addr[3],
            l7_listener.port,
            l7_listener.accepted_connections_total,
            l7_listener.active_connections,
        },
    ) catch return common.internalError();
    if (l7_listener.last_error) |message| {
        writer.writeByte('"') catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, message) catch return common.internalError();
        writer.writeByte('"') catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll("},\"control_plane\":{") catch return common.internalError();
    writer.print(
        "\"enabled\":{},\"steering_enabled\":{},\"running\":{},\"interval_secs\":{d},\"passes_total\":{d},\"event_passes_total\":{d},\"periodic_passes_total\":{d},\"last_trigger\":",
        .{
            l7_control_plane.enabled,
            l7_control_plane.steering_enabled,
            l7_control_plane.running,
            l7_control_plane.interval_secs,
            l7_control_plane.passes_total,
            l7_control_plane.event_passes_total,
            l7_control_plane.periodic_passes_total,
        },
    ) catch return common.internalError();
    if (l7_control_plane.last_trigger) |trigger| {
        writer.print("\"{s}\"", .{trigger.label()}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll(",\"last_pass_at\":") catch return common.internalError();
    if (l7_control_plane.last_pass_at) |timestamp| {
        writer.print("{d}", .{timestamp}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll("},\"steering\":{") catch return common.internalError();
    writer.print(
        "\"enabled\":{},\"running\":{},\"configured_services\":{d},\"not_ready_services\":{d},\"blocked_services\":{d},\"drifted_services\":{d},\"desired_mappings\":{d},\"applied_mappings\":{d},\"blocked_reason\":\"{s}\",\"sync_attempts_total\":{d},\"sync_failures_total\":{d},\"mappings_applied_total\":{d},\"mappings_removed_total\":{d},\"last_sync_at\":",
        .{
            l7_steering.enabled,
            l7_steering.running,
            l7_steering.configured_services,
            l7_steering.not_ready_services,
            l7_steering.blocked_services,
            l7_steering.drifted_services,
            l7_steering.desired_mappings,
            l7_steering.applied_mappings,
            l7_steering.blocked_reason.label(),
            l7_steering.sync_attempts_total,
            l7_steering.sync_failures_total,
            l7_steering.mappings_applied_total,
            l7_steering.mappings_removed_total,
        },
    ) catch return common.internalError();
    if (l7_steering.last_sync_at) |timestamp| {
        writer.print("{d}", .{timestamp}) catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll(",\"last_error\":") catch return common.internalError();
    if (l7_steering.last_error) |message| {
        writer.writeByte('"') catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, message) catch return common.internalError();
        writer.writeByte('"') catch return common.internalError();
    } else {
        writer.writeAll("null") catch return common.internalError();
    }
    writer.writeAll("},\"audit\":{") catch return common.internalError();
    writer.print(
        "\"enabled\":{},\"running\":{},\"passes_total\":{d},\"mismatch_services_total\":{d},\"vip_mismatches_total\":{d},\"endpoint_count_mismatches_total\":{d},\"stale_endpoint_mismatches_total\":{d},\"eligibility_mismatches_total\":{d},\"repairs_total\":{d},\"stale_endpoint_quarantines_total\":{d},\"last_audit_at\":",
        .{
            audit.enabled,
            audit.running,
            audit.passes_total,
            audit.mismatch_services_total,
            audit.vip_mismatches_total,
            audit.endpoint_count_mismatches_total,
            audit.stale_endpoint_mismatches_total,
            audit.eligibility_mismatches_total,
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
    writer.writeAll("],\"discovery_readiness\":{") catch return common.internalError();
    writeDiscoveryReadinessSnapshot(writer, cutover) catch return common.internalError();
    writer.writeAll("},\"cutover_readiness\":{") catch return common.internalError();
    writeCutoverReadinessSnapshot(writer, cutover) catch return common.internalError();
    writer.writeAll("},\"node_signals\":{") catch return common.internalError();
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

fn writeHeaderMatchesJson(writer: anytype, header_matches: anytype) !void {
    try writer.writeByte('[');
    for (header_matches, 0..) |header_match, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":\"");
        try json_helpers.writeJsonEscaped(writer, header_match.name);
        try writer.writeAll("\",\"value\":\"");
        try json_helpers.writeJsonEscaped(writer, header_match.value);
        try writer.writeAll("\"}");
    }
    try writer.writeByte(']');
}

fn writeBackendServicesJson(writer: anytype, backend_services: anytype) !void {
    try writer.writeByte('[');
    for (backend_services, 0..) |backend, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll("{\"service\":\"");
        try json_helpers.writeJsonEscaped(writer, backend.service_name);
        try writer.print("\",\"weight\":{d}}}", .{backend.weight});
    }
    try writer.writeByte(']');
}

fn writeMethodMatchesJson(writer: anytype, method_matches: anytype) !void {
    try writer.writeByte('[');
    for (method_matches, 0..) |method_match, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeByte('"');
        try json_helpers.writeJsonEscaped(writer, method_match.method);
        try writer.writeByte('"');
    }
    try writer.writeByte(']');
}

fn writeRouteTrafficJson(writer: anytype, route_traffic: anytype) !void {
    try writer.writeByte('[');
    for (route_traffic[0..@min(route_traffic.len, proxy_runtime.max_routes_in_status)], 0..) |entry, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll("{\"route\":\"");
        try json_helpers.writeJsonEscaped(writer, entry.route_name);
        try writer.writeAll("\",\"service\":\"");
        try json_helpers.writeJsonEscaped(writer, entry.service_name);
        try writer.writeAll("\",\"backend_service\":\"");
        try json_helpers.writeJsonEscaped(writer, entry.backend_service);
        try writer.writeAll("\",\"traffic_role\":\"");
        try json_helpers.writeJsonEscaped(writer, entry.traffic_role.label());
        try writer.print(
            "\",\"requests_total\":{d},\"responses_2xx_total\":{d},\"responses_4xx_total\":{d},\"responses_5xx_total\":{d},\"retries_total\":{d},\"upstream_failures_total\":{d}}}",
            .{
                entry.requests_total,
                entry.responses_2xx_total,
                entry.responses_4xx_total,
                entry.responses_5xx_total,
                entry.retries_total,
                entry.upstream_failures_total,
            },
        );
    }
    try writer.writeByte(']');
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

fn writeDiscoveryReadinessSnapshot(writer: anytype, readiness: service_cutover_readiness.Snapshot) !void {
    try writer.print(
        "\"backfill_complete\":{},\"audit_fresh\":{},\"audit_clean\":{},\"components_ready\":{},\"fault_modes_clear\":{},\"downgrade_safe\":{},\"steering_ready\":{},\"steering_blocked_services\":{d},\"steering_no_port_services\":{d},\"reconciler_ready\":{},\"vip_ready\":{},\"blockers\":[",
        .{
            readiness.backfill_complete,
            readiness.audit_fresh,
            readiness.shadow_clean,
            readiness.components_ready,
            readiness.fault_modes_clear,
            readiness.downgrade_safe,
            readiness.steering_ready,
            readiness.steering_blocked_services,
            readiness.steering_no_port_services,
            readiness.ready_for_reconciler_cutover,
            readiness.ready_for_vip_cutover,
        },
    );
    for (readiness.blockers.items, 0..) |blocker, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeByte('"');
        try json_helpers.writeJsonEscaped(writer, blocker);
        try writer.writeByte('"');
    }
    try writer.writeByte(']');
}

fn writeCutoverReadinessSnapshot(writer: anytype, readiness: service_cutover_readiness.Snapshot) !void {
    try writer.print(
        "\"backfill_complete\":{},\"audit_fresh\":{},\"shadow_clean\":{},\"components_ready\":{},\"fault_modes_clear\":{},\"downgrade_safe\":{},\"steering_ready\":{},\"steering_blocked_services\":{d},\"steering_no_port_services\":{d},\"ready_for_reconciler_cutover\":{},\"ready_for_vip_cutover\":{},\"blockers\":[",
        .{
            readiness.backfill_complete,
            readiness.audit_fresh,
            readiness.shadow_clean,
            readiness.components_ready,
            readiness.fault_modes_clear,
            readiness.downgrade_safe,
            readiness.steering_ready,
            readiness.steering_blocked_services,
            readiness.steering_no_port_services,
            readiness.ready_for_reconciler_cutover,
            readiness.ready_for_vip_cutover,
        },
    );
    for (readiness.blockers.items, 0..) |blocker, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeByte('"');
        try json_helpers.writeJsonEscaped(writer, blocker);
        try writer.writeByte('"');
    }
    try writer.writeByte(']');
}
