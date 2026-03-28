const std = @import("std");
const http = @import("../http.zig");
const store = @import("../../state/store.zig");
const monitor = @import("../../runtime/monitor.zig");
const cgroups = @import("../../runtime/cgroups.zig");
const common = @import("common.zig");
const status_routes = @import("status_metrics/status_routes.zig");
const metrics_routes = @import("status_metrics/metrics_routes.zig");
const writers = @import("status_metrics/writers.zig");
const testing = std.testing;

const Response = common.Response;
const writeSnapshotJson = writers.writeSnapshotJson;
const resolveIpToService = metrics_routes.resolveIpToService;
const handleMetricsPrometheus = metrics_routes.handleMetricsPrometheus;
const handleGpuMetrics = metrics_routes.handleGpuMetrics;

pub fn route(request: http.Request, alloc: std.mem.Allocator) ?Response {
    const path = request.path_only;

    if (request.method == .GET and std.mem.eql(u8, path, "/v1/status")) {
        const mode = common.extractQueryParam(request.path, "mode");
        if (mode) |value| {
            if (std.mem.eql(u8, value, "service_rollout")) {
                return status_routes.handleServiceRolloutStatus(alloc);
            }
        }
        return status_routes.handleStatus(alloc);
    }

    if (request.method == .GET and std.mem.startsWith(u8, path, "/v1/metrics")) {
        return metrics_routes.handleMetrics(alloc, request);
    }

    return null;
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

test "route handles /v1/status?mode=service_rollout GET" {
    const ebpf_map_support = @import("../../network/ebpf/map_support.zig");
    const service_registry_backfill = @import("../../network/service_registry_backfill.zig");
    const service_rollout = @import("../../network/service_rollout.zig");
    const service_registry_bridge = @import("../../network/service_registry_bridge.zig");
    const dns_registry = @import("../../network/dns/registry_support.zig");
    const service_reconciler = @import("../../network/service_reconciler.zig");
    const service_registry_runtime = @import("../../network/service_registry_runtime.zig");
    const proxy_control_plane = @import("../../network/proxy/control_plane.zig");
    const proxy_runtime = @import("../../network/proxy/runtime.zig");
    const listener_runtime = @import("../../network/proxy/listener_runtime.zig");
    const steering_runtime = @import("../../network/proxy/steering_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_control_plane.resetForTest();
    defer proxy_control_plane.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    service_rollout.setForTest(.{ .service_registry_v2 = true, .service_registry_reconciler = true });
    defer service_rollout.resetForTest();
    ebpf_map_support.resetFaultInjectionForTest();
    defer ebpf_map_support.resetFaultInjectionForTest();
    dns_registry.resetClusterLookupFaultsForTest();
    defer dns_registry.resetClusterLookupFaultsForTest();
    dns_registry.resetDnsInterceptorFaultsForTest();
    defer dns_registry.resetDnsInterceptorFaultsForTest();
    dns_registry.resetLoadBalancerFaultsForTest();
    defer dns_registry.resetLoadBalancerFaultsForTest();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    service_registry_backfill.resetForTest();
    defer service_registry_backfill.resetForTest();
    service_registry_bridge.resetFaultsForTest();
    defer service_registry_bridge.resetFaultsForTest();
    service_reconciler.resetForTest();
    service_reconciler.setComponentStateOverrideForTest(.{
        .dns_resolver_running = true,
        .dns_interceptor_loaded = false,
        .load_balancer_loaded = false,
    });

    ebpf_map_support.setMapUpdateFaultModeForTest(.map_full);
    dns_registry.setClusterLookupFaultForTest(.stale_override, .{ 10, 42, 9, 9 });
    dns_registry.setDnsInterceptorFaultModeForTest(.unavailable);
    dns_registry.setLoadBalancerFaultModeForTest(.endpoint_overflow);
    service_registry_bridge.setFaultModeForTest(.container_register, .skip_legacy_apply);
    service_registry_bridge.registerContainerService("api", "abc123", .{ 10, 42, 0, 9 }, null);

    const req = http.Request{
        .method = .GET,
        .path = "/v1/status?mode=service_rollout",
        .path_only = "/v1/status",
        .query = "mode=service_rollout",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator).?;
    defer if (response.allocated) testing.allocator.free(response.body);

    try testing.expectEqual(http.StatusCode.ok, response.status);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"mode\":\"shadow\"") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"service_registry_v2\":true") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"dns_registry_services\":1024") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"dns_bpf_services\":1024") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"load_balancer_backends_per_vip\":64") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"recent_shadow_events\":32") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"health_workers\":4") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"health_queued_checks\":64") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"bridge_fault_injections\":{\"container_register\":1") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"bridge_fault_modes\":{\"container_register\":\"skip_legacy_apply\"") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"ebpf_map_update_fault\":{\"mode\":\"map_full\",\"injections\":0}") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"cluster_lookup_fault\":{\"mode\":\"stale_override\",\"injections\":0,\"stale_ip\":\"10.42.9.9\"}") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"dns_interceptor_fault\":{\"mode\":\"unavailable\",\"injections\":0}") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"load_balancer_fault\":{\"mode\":\"endpoint_overflow\",\"injections\":0}") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"components\":{\"dns_resolver_running\":true,\"dns_interceptor_loaded\":false,\"load_balancer_loaded\":false") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"backfill\":{\"enabled\":true,\"runs_total\":0,\"services_created_total\":0,\"endpoints_created_total\":0") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"health_checker\":{\"running\":false,\"tracked_endpoints\":0,\"in_flight_checks\":0,\"queued_checks\":0,\"worker_threads\":0") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"l7_proxy\":{\"enabled\":false,\"running\":false,\"configured_services\":0,\"routes\":0,\"requests_total\":0,\"responses_2xx_total\":0,\"responses_4xx_total\":0,\"responses_5xx_total\":0,\"retries_total\":0,\"loop_rejections_total\":0,\"upstream_connect_failures_total\":0,\"upstream_send_failures_total\":0,\"upstream_receive_failures_total\":0,\"upstream_other_failures_total\":0,\"circuit_trips_total\":0,\"circuit_open_endpoints\":0,\"circuit_half_open_endpoints\":0,\"last_sync_at\":null,\"last_error\":null,\"sample_routes\":[]}") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"listener\":{\"enabled\":false,\"running\":false,\"port\":17080,\"accepted_connections_total\":0,\"active_connections\":0,\"last_error\":null}") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"control_plane\":{\"enabled\":false,\"steering_enabled\":false,\"running\":false,\"interval_secs\":15,\"passes_total\":0,\"event_passes_total\":0,\"periodic_passes_total\":0,\"last_trigger\":null,\"last_pass_at\":null}") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"steering\":{\"enabled\":false,\"running\":false,\"configured_services\":0,\"not_ready_services\":0,\"blocked_services\":0,\"drifted_services\":0,\"desired_mappings\":0,\"applied_mappings\":0,\"blocked_reason\":\"rollout_disabled\",\"sync_attempts_total\":0,\"sync_failures_total\":0,\"mappings_applied_total\":0,\"mappings_removed_total\":0,\"last_sync_at\":null,\"last_error\":null}") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"audit\":{\"enabled\":true") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"passes_total\":0") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"vip_mismatches_total\":0") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"endpoint_count_mismatches_total\":0") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"stale_endpoint_mismatches_total\":0") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"eligibility_mismatches_total\":0") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"cutover_readiness\":{\"backfill_complete\":false,\"audit_fresh\":false,\"shadow_clean\":true,\"components_ready\":false,\"fault_modes_clear\":false,\"downgrade_safe\":false,\"steering_ready\":true,\"steering_blocked_services\":0,\"steering_no_port_services\":0,\"ready_for_reconciler_cutover\":false,\"ready_for_vip_cutover\":false") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"blockers\":[\"backfill_incomplete\",\"audit_never_ran\",\"fault_mode_active\",\"components_not_ready\"]") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"stale_endpoint_quarantines_total\":0") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"node_signals\":{\"lost_total\":0,\"recovered_total\":0,\"endpoints_changed_total\":0") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"container_registered\":1") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"container_runtime\":{\"container_registered\":1") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"source\":\"container_runtime\"") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"kind\":\"container_registered\"") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"service\":\"api\"") != null);
}

test "route rollout status reports reconciler cutover ready after clean backfill and audit" {
    const service_registry_backfill = @import("../../network/service_registry_backfill.zig");
    const service_rollout = @import("../../network/service_rollout.zig");
    const dns_registry = @import("../../network/dns/registry_support.zig");
    const service_reconciler = @import("../../network/service_reconciler.zig");
    const service_registry_runtime = @import("../../network/service_registry_runtime.zig");
    const proxy_control_plane = @import("../../network/proxy/control_plane.zig");
    const proxy_runtime = @import("../../network/proxy/runtime.zig");
    const listener_runtime = @import("../../network/proxy/listener_runtime.zig");
    const steering_runtime = @import("../../network/proxy/steering_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_control_plane.resetForTest();
    defer proxy_control_plane.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    service_registry_backfill.resetForTest();
    defer service_registry_backfill.resetForTest();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    dns_registry.resetClusterLookupFaultsForTest();
    defer dns_registry.resetClusterLookupFaultsForTest();
    dns_registry.resetDnsInterceptorFaultsForTest();
    defer dns_registry.resetDnsInterceptorFaultsForTest();
    dns_registry.resetLoadBalancerFaultsForTest();
    defer dns_registry.resetLoadBalancerFaultsForTest();
    service_reconciler.resetForTest();
    defer service_reconciler.resetForTest();
    service_rollout.setForTest(.{ .service_registry_v2 = true, .service_registry_reconciler = true });
    defer service_rollout.resetForTest();

    try store.registerServiceName("api", "abc123", "10.42.0.9");
    try store.save(.{
        .id = "abc123",
        .rootfs = "/tmp/rootfs",
        .command = "sleep infinity",
        .hostname = "api",
        .status = "running",
        .pid = null,
        .exit_code = null,
        .ip_address = "10.42.0.9",
        .veth_host = null,
        .app_name = null,
        .created_at = 1000,
    });

    service_registry_backfill.runIfEnabled();
    service_reconciler.bootstrapIfEnabled();
    service_reconciler.runAuditPassIfEnabled();

    const req = http.Request{
        .method = .GET,
        .path = "/v1/status?mode=service_rollout",
        .path_only = "/v1/status",
        .query = "mode=service_rollout",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator).?;
    defer if (response.allocated) testing.allocator.free(response.body);

    try testing.expect(std.mem.indexOf(u8, response.body, "\"cutover_readiness\":{\"backfill_complete\":true,\"audit_fresh\":true,\"shadow_clean\":true,\"components_ready\":false,\"fault_modes_clear\":true,\"downgrade_safe\":true,\"steering_ready\":true,\"steering_blocked_services\":0,\"steering_no_port_services\":0,\"ready_for_reconciler_cutover\":true,\"ready_for_vip_cutover\":false") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"blockers\":[\"components_not_ready\"]") != null);
}

test "route rollout status reports steering blocker for VIP cutover readiness" {
    const service_registry_backfill = @import("../../network/service_registry_backfill.zig");
    const service_rollout = @import("../../network/service_rollout.zig");
    const dns_registry = @import("../../network/dns/registry_support.zig");
    const service_reconciler = @import("../../network/service_reconciler.zig");
    const service_registry_runtime = @import("../../network/service_registry_runtime.zig");
    const proxy_control_plane = @import("../../network/proxy/control_plane.zig");
    const proxy_runtime = @import("../../network/proxy/runtime.zig");
    const listener_runtime = @import("../../network/proxy/listener_runtime.zig");
    const steering_runtime = @import("../../network/proxy/steering_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_control_plane.resetForTest();
    defer proxy_control_plane.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    service_registry_backfill.resetForTest();
    defer service_registry_backfill.resetForTest();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    dns_registry.resetClusterLookupFaultsForTest();
    defer dns_registry.resetClusterLookupFaultsForTest();
    dns_registry.resetDnsInterceptorFaultsForTest();
    defer dns_registry.resetDnsInterceptorFaultsForTest();
    dns_registry.resetLoadBalancerFaultsForTest();
    defer dns_registry.resetLoadBalancerFaultsForTest();
    service_reconciler.resetForTest();
    defer service_reconciler.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .service_registry_reconciler = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();

    try store.registerServiceName("api", "abc123", "10.42.0.9");
    try store.save(.{
        .id = "abc123",
        .rootfs = "/tmp/rootfs",
        .command = "sleep infinity",
        .hostname = "api",
        .status = "running",
        .pid = null,
        .exit_code = null,
        .ip_address = "10.42.0.9",
        .veth_host = null,
        .app_name = null,
        .created_at = 1000,
    });

    service_registry_backfill.runIfEnabled();
    service_reconciler.bootstrapIfEnabled();
    service_reconciler.runAuditPassIfEnabled();

    const req = http.Request{
        .method = .GET,
        .path = "/v1/status?mode=service_rollout",
        .path_only = "/v1/status",
        .query = "mode=service_rollout",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator).?;
    defer if (response.allocated) testing.allocator.free(response.body);

    try testing.expect(std.mem.indexOf(u8, response.body, "\"cutover_readiness\":{\"backfill_complete\":true,\"audit_fresh\":true,\"shadow_clean\":true,\"components_ready\":false,\"fault_modes_clear\":true,\"downgrade_safe\":true,\"steering_ready\":false,\"steering_blocked_services\":1,\"steering_no_port_services\":1,\"ready_for_reconciler_cutover\":true,\"ready_for_vip_cutover\":false") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"blockers\":[\"components_not_ready\",\"steering_not_ready\"]") != null);
}

test "route rollout status sample routes expose steering drift details" {
    const service_rollout = @import("../../network/service_rollout.zig");
    const service_registry_runtime = @import("../../network/service_registry_runtime.zig");
    const proxy_control_plane = @import("../../network/proxy/control_plane.zig");
    const proxy_runtime = @import("../../network/proxy/runtime.zig");
    const listener_runtime = @import("../../network/proxy/listener_runtime.zig");
    const steering_runtime = @import("../../network/proxy/steering_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_control_plane.resetForTest();
    defer proxy_control_plane.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .dns_returns_vip = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "ctr-1:8080",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "10.42.0.9",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });

    service_registry_runtime.syncServiceFromStore("api");
    proxy_runtime.bootstrapIfEnabled();
    steering_runtime.setPortMapperAvailableForTest(true);
    steering_runtime.setBridgeIpForTest(.{ 10, 42, 0, 1 });
    listener_runtime.startForTest(testing.allocator, 0);
    try steering_runtime.setActualMappingsForTest(&.{});

    const req = http.Request{
        .method = .GET,
        .path = "/v1/status?mode=service_rollout",
        .path_only = "/v1/status",
        .query = "mode=service_rollout",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator).?;
    defer if (response.allocated) testing.allocator.free(response.body);

    try testing.expect(std.mem.indexOf(u8, response.body, "\"sample_routes\":[{\"name\":\"api:/v1\"") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"vip_traffic_mode\":\"l4_fallback\"") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"steering_blocked\":false") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"steering_drifted\":true") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"steering_blocked_reason\":\"none\"") != null);
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

test "handleMetricsPrometheus returns text content type" {
    const resp = handleMetricsPrometheus(testing.allocator);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqual(http.StatusCode.ok, resp.status);
    try testing.expect(resp.content_type != null);
    try testing.expectEqualStrings("text/plain; version=0.0.4; charset=utf-8", resp.content_type.?);
}

test "handleMetricsPrometheus exposes service rollout metrics" {
    const ebpf_map_support = @import("../../network/ebpf/map_support.zig");
    const health = @import("../../manifest/health.zig");
    const health_registry = @import("../../manifest/health/registry_support.zig");
    const service_rollout = @import("../../network/service_rollout.zig");
    const service_observability = @import("../../network/service_observability.zig");
    const service_registry_bridge = @import("../../network/service_registry_bridge.zig");
    const dns_registry = @import("../../network/dns/registry_support.zig");
    const service_reconciler = @import("../../network/service_reconciler.zig");
    const service_registry_runtime = @import("../../network/service_registry_runtime.zig");
    const proxy_control_plane = @import("../../network/proxy/control_plane.zig");
    const proxy_runtime = @import("../../network/proxy/runtime.zig");
    const listener_runtime = @import("../../network/proxy/listener_runtime.zig");
    const steering_runtime = @import("../../network/proxy/steering_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    health_registry.resetForTest();
    defer health_registry.resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_control_plane.resetForTest();
    defer proxy_control_plane.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .service_registry_reconciler = true,
        .dns_returns_vip = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    ebpf_map_support.resetFaultInjectionForTest();
    defer ebpf_map_support.resetFaultInjectionForTest();
    dns_registry.resetClusterLookupFaultsForTest();
    defer dns_registry.resetClusterLookupFaultsForTest();
    dns_registry.resetDnsInterceptorFaultsForTest();
    defer dns_registry.resetDnsInterceptorFaultsForTest();
    dns_registry.resetLoadBalancerFaultsForTest();
    defer dns_registry.resetLoadBalancerFaultsForTest();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    service_registry_bridge.resetFaultsForTest();
    defer service_registry_bridge.resetFaultsForTest();
    service_reconciler.resetForTest();
    service_reconciler.setComponentStateOverrideForTest(.{
        .dns_resolver_running = true,
        .dns_interceptor_loaded = true,
        .load_balancer_loaded = true,
    });

    ebpf_map_support.setMapUpdateFaultModeForTest(.fail_update);
    dns_registry.setClusterLookupFaultForTest(.force_miss, null);
    dns_registry.setDnsInterceptorFaultModeForTest(.unavailable);
    dns_registry.setLoadBalancerFaultModeForTest(.endpoint_overflow);
    service_registry_bridge.setFaultModeForTest(.container_register, .skip_legacy_apply);
    service_registry_bridge.registerContainerService("api", "abc123", .{ 10, 42, 0, 9 }, null);
    service_registry_bridge.markEndpointHealthy("api", "abc123", .{ 10, 42, 0, 9 });
    try service_registry_runtime.requestReconcile("api");
    try service_registry_runtime.markReconcileFailed("api", "sync failed");
    try service_registry_runtime.markReconcileSucceeded("api");
    try health.registerService("api", "abcdef123456".*, .{ 10, 42, 0, 9 }, .{
        .check_type = .{ .tcp = .{ .port = 8080 } },
    });
    service_observability.noteHealthCheckScheduled("api");
    service_observability.noteHealthCheckCompleted("api", false, 0.125);
    service_observability.noteHealthCheckCompleted("api", true, 0.25);
    service_observability.noteEndpointFlap("api");
    service_observability.noteVipAllocFailure();
    try store.createService(.{
        .service_name = "edge",
        .vip_address = "10.43.0.9",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "edge.internal",
        .http_proxy_path_prefix = "/",
        .created_at = 1000,
        .updated_at = 1000,
    });
    proxy_runtime.bootstrapIfEnabled();
    proxy_runtime.recordRequestStart();
    proxy_runtime.recordResponse(.ok);
    proxy_runtime.recordRetry();
    proxy_runtime.recordLoopRejection();
    proxy_runtime.recordUpstreamFailure(.connect);
    proxy_runtime.recordEndpointFailure("edge-1");
    proxy_runtime.recordEndpointFailure("edge-1");
    proxy_runtime.recordEndpointFailure("edge-1");

    const resp = handleMetricsPrometheus(testing.allocator);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_shadow_mode 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_flag{flag=\"service_registry_v2\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_flag{flag=\"dns_returns_vip\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_flag{flag=\"l7_proxy_http\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_limit{limit=\"load_balancer_backends_per_vip\"} 64") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_limit{limit=\"health_workers\"} 4") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_limit{limit=\"health_queued_checks\"} 64") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_endpoints_total{service=\"api\",state=\"total\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_eligible_endpoints{service=\"api\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_endpoints_total{service=\"api\",state=\"healthy\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_zero_backends_total{service=\"edge\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_degraded{service=\"edge\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconcile_runs_total{service=\"api\",result=\"requested\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconcile_runs_total{service=\"api\",result=\"succeeded\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconcile_runs_total{service=\"api\",result=\"failed\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconcile_duration_seconds{service=\"api\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_bpf_sync_failures_total{service=\"api\",component=\"dns_interceptor\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_bpf_sync_failures_total{service=\"api\",component=\"load_balancer\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_health_status{service=\"api\",status=\"starting\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_health_status{service=\"edge\",status=\"untracked\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_health_checks_total{service=\"api\",result=\"scheduled\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_health_checks_total{service=\"api\",result=\"completed\"} 2") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_health_checks_total{service=\"api\",result=\"stale\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_health_check_latency_seconds{service=\"api\"} 0.250000") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_endpoint_flaps_total{service=\"api\",endpoint=\"abcdef123456:0\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_vip_alloc_failures_total 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_enabled 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_running 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_configured_services 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_routes 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_requests_total 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_responses_total{class=\"2xx\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_retries_total 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_loop_rejections_total 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_upstream_failures_total{kind=\"connect\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_circuit_trips_total 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_circuit_endpoints{state=\"open\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_listener_enabled 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_listener_running 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_listener_port 17080") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_listener_accepted_connections_total 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_listener_active_connections 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_control_plane_enabled 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_control_plane_steering_enabled 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_control_plane_running 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_control_plane_interval_seconds 15") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_control_plane_passes_total 2") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_control_plane_passes_by_trigger_total{trigger=\"event\"} 2") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_control_plane_passes_by_trigger_total{trigger=\"periodic\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_control_plane_last_trigger{trigger=\"event\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_control_plane_last_trigger{trigger=\"periodic\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_enabled 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_running 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_blocked_reason{reason=\"listener_not_running\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_configured_services 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_services{state=\"not_ready\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_services{state=\"blocked\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_services{state=\"drifted\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_mappings{state=\"desired\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_mappings{state=\"applied\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_syncs_total{outcome=\"attempted\"} 2") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_syncs_total{outcome=\"failed\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_mapping_changes_total{action=\"applied\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_l7_proxy_steering_mapping_changes_total{action=\"removed\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_registry_bridge_fault_injections_total{operation=\"container_register\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_registry_bridge_fault_mode{operation=\"container_register\",mode=\"skip_legacy_apply\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_registry_bridge_fault_mode{operation=\"endpoint_healthy\",mode=\"none\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_registry_backfill_runs_total 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_registry_backfill_created_total{kind=\"services\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_ebpf_map_update_fault_injections_total 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_ebpf_map_update_fault_mode{mode=\"fail_update\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_dns_cluster_lookup_fault_injections_total 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_dns_cluster_lookup_fault_mode{mode=\"force_miss\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_dns_interceptor_fault_injections_total 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_dns_interceptor_fault_mode{mode=\"unavailable\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_load_balancer_fault_injections_total 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_load_balancer_fault_mode{mode=\"endpoint_overflow\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_shadow_events_total{source=\"container_runtime\",kind=\"container_registered\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_shadow_events_total{source=\"health_checker\",kind=\"endpoint_healthy\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_audit_passes_total 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_audit_mismatches_by_kind_total{kind=\"vip\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_audit_mismatches_by_kind_total{kind=\"eligibility\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_audit_running 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_degraded_services 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_stale_endpoint_quarantines_total 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_node_signals_total{kind=\"lost\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_node_signal_endpoints_changed_total 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_component_ready{component=\"dns_resolver\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_component_ready{component=\"dns_interceptor\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_reconciler_component_full_resyncs_total 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_cutover_ready{check=\"backfill_complete\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_cutover_ready{check=\"shadow_clean\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_cutover_ready{check=\"steering_ready\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_cutover_ready{check=\"reconciler_cutover\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_cutover_ready{check=\"vip_cutover\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_cutover_steering_services{state=\"blocked\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_rollout_cutover_steering_services{state=\"missing_ports\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_health_checker_running 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_health_checker_tracked_endpoints 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_health_checker_queued_checks 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_health_checker_checks_total{kind=\"scheduled\"} 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_health_checker_stale_results_total 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_checker_queue_depth 0") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "yoq_service_checker_workers_busy 0") != null);
}

test "handleGpuMetrics returns valid JSON" {
    const resp = handleGpuMetrics(testing.allocator);
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqual(http.StatusCode.ok, resp.status);
    // without NVML available, should return empty gpu_metrics
    try testing.expect(std.mem.indexOf(u8, resp.body, "gpu_metrics") != null);
}

test "route dispatches format=prometheus" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/metrics?format=prometheus",
        .path_only = "/v1/metrics",
        .query = "format=prometheus",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    const resp = response.?;
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqual(http.StatusCode.ok, resp.status);
    try testing.expect(resp.content_type != null);
}

test "route dispatches mode=gpu" {
    const req = http.Request{
        .method = .GET,
        .path = "/v1/metrics?mode=gpu",
        .path_only = "/v1/metrics",
        .query = "mode=gpu",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    const resp = response.?;
    defer if (resp.allocated) testing.allocator.free(resp.body);

    try testing.expectEqual(http.StatusCode.ok, resp.status);
    try testing.expect(std.mem.indexOf(u8, resp.body, "gpu_metrics") != null);
}
