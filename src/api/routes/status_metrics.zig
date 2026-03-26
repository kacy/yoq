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
    const service_rollout = @import("../../network/service_rollout.zig");
    const service_reconciler = @import("../../network/service_reconciler.zig");

    service_rollout.setForTest(.{ .service_registry_v2 = true, .service_registry_reconciler = true });
    defer service_rollout.resetForTest();
    service_reconciler.resetForTest();

    service_reconciler.noteContainerRegistered("api", "abc123", .{ 10, 42, 0, 9 });

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
    try testing.expect(std.mem.indexOf(u8, response.body, "\"container_registered\":1") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"kind\":\"container_registered\"") != null);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"service\":\"api\"") != null);
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
