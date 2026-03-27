// health — health check engine for services
//
// periodically probes services with configured health checks (http, tcp,
// or exec) and tracks their health status. the orchestrator spawns a
// single checker thread that polls all services at their configured
// intervals.
//
// state machine:
//   starting → healthy   (after start_period + first success)
//   starting → unhealthy (after start_period + retries consecutive failures)
//   healthy  → unhealthy (after retries consecutive failures)
//   unhealthy → healthy  (after one success)
//
// thread model: single checker thread, sleeps between polls.
// mutex protects the health state array so the orchestrator and
// DNS integration can read it safely.

const std = @import("std");
const types = @import("health/types.zig");
const registry_support = @import("health/registry_support.zig");
const checker_runtime = @import("health/checker_runtime.zig");
const check_runtime = @import("health/check_runtime.zig");

pub const HealthStatus = types.HealthStatus;
pub const ServiceHealth = types.ServiceHealth;
pub const HealthError = types.HealthError;
pub const CheckerSnapshot = types.CheckerSnapshot;
pub const max_worker_threads = types.max_worker_threads;
pub const max_queued_checks = types.max_queued_checks;

pub fn registerService(
    service_name: []const u8,
    container_id: [12]u8,
    container_ip: [4]u8,
    config: @import("spec.zig").HealthCheck,
) HealthError!void {
    return registry_support.registerService(service_name, container_id, container_ip, config);
}

/// unregister a service from health checking.
/// called when a service is stopped or removed.
pub fn unregisterService(service_name: []const u8) void {
    registry_support.unregisterService(service_name);
}

/// get the current health status for a service.
/// returns null if the service is not being health-checked.
pub fn getStatus(service_name: []const u8) ?HealthStatus {
    return registry_support.getStatus(service_name);
}

/// get the full health state for a service (for API responses).
/// returns null if the service is not being health-checked.
pub fn getServiceHealth(service_name: []const u8) ?ServiceHealth {
    return registry_support.getServiceHealth(service_name);
}

pub fn snapshotChecker() CheckerSnapshot {
    return registry_support.snapshotChecker();
}

/// start the health checker thread. idempotent.
pub fn startChecker() void {
    checker_runtime.startChecker();
}

/// stop the health checker thread.
pub fn stopChecker() void {
    checker_runtime.stopChecker();
}

// -- tests --

test "state machine — starting to healthy on first success" {
    var entry = testEntry(.starting);
    _ = checker_runtime.updateState(&entry, true);
    try std.testing.expectEqual(HealthStatus.healthy, entry.status);
    try std.testing.expectEqual(@as(u32, 1), entry.consecutive_successes);
    try std.testing.expectEqual(@as(u32, 0), entry.consecutive_failures);
}

test "state machine — starting stays starting on single failure" {
    var entry = testEntry(.starting);
    entry.config.retries = 3;
    _ = checker_runtime.updateState(&entry, false);
    try std.testing.expectEqual(HealthStatus.starting, entry.status);
    try std.testing.expectEqual(@as(u32, 1), entry.consecutive_failures);
}

test "state machine — starting to unhealthy after retries exhausted" {
    var entry = testEntry(.starting);
    entry.config.retries = 3;

    _ = checker_runtime.updateState(&entry, false);
    _ = checker_runtime.updateState(&entry, false);
    try std.testing.expectEqual(HealthStatus.starting, entry.status);

    _ = checker_runtime.updateState(&entry, false);
    try std.testing.expectEqual(HealthStatus.unhealthy, entry.status);
    try std.testing.expectEqual(@as(u32, 3), entry.consecutive_failures);
}

test "state machine — healthy to unhealthy after retries" {
    var entry = testEntry(.healthy);
    entry.config.retries = 2;

    _ = checker_runtime.updateState(&entry, false);
    try std.testing.expectEqual(HealthStatus.healthy, entry.status);

    _ = checker_runtime.updateState(&entry, false);
    try std.testing.expectEqual(HealthStatus.unhealthy, entry.status);
}

test "state machine — unhealthy to healthy on single success" {
    var entry = testEntry(.unhealthy);
    entry.consecutive_failures = 5;

    _ = checker_runtime.updateState(&entry, true);
    try std.testing.expectEqual(HealthStatus.healthy, entry.status);
    try std.testing.expectEqual(@as(u32, 0), entry.consecutive_failures);
    try std.testing.expectEqual(@as(u32, 1), entry.consecutive_successes);
}

test "state machine — healthy stays healthy on success" {
    var entry = testEntry(.healthy);
    entry.consecutive_successes = 10;

    _ = checker_runtime.updateState(&entry, true);
    try std.testing.expectEqual(HealthStatus.healthy, entry.status);
    try std.testing.expectEqual(@as(u32, 11), entry.consecutive_successes);
}

test "state machine — failure resets consecutive successes" {
    var entry = testEntry(.healthy);
    entry.consecutive_successes = 5;
    entry.config.retries = 10; // won't flip to unhealthy

    _ = checker_runtime.updateState(&entry, false);
    try std.testing.expectEqual(@as(u32, 0), entry.consecutive_successes);
    try std.testing.expectEqual(@as(u32, 1), entry.consecutive_failures);
}

test "state machine — success resets consecutive failures" {
    var entry = testEntry(.unhealthy);
    entry.consecutive_failures = 5;

    _ = checker_runtime.updateState(&entry, true);
    try std.testing.expectEqual(@as(u32, 0), entry.consecutive_failures);
    try std.testing.expectEqual(@as(u32, 1), entry.consecutive_successes);
}

test "state machine — intermittent failures don't trigger unhealthy" {
    var entry = testEntry(.healthy);
    entry.config.retries = 3;

    _ = checker_runtime.updateState(&entry, false);
    _ = checker_runtime.updateState(&entry, false);
    _ = checker_runtime.updateState(&entry, true);
    _ = checker_runtime.updateState(&entry, false);
    _ = checker_runtime.updateState(&entry, false);

    try std.testing.expectEqual(HealthStatus.healthy, entry.status);
}

test "isHttp2xx — valid 2xx responses" {
    try std.testing.expect(check_runtime.isHttp2xx("HTTP/1.0 200 OK\r\n"));
    try std.testing.expect(check_runtime.isHttp2xx("HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(check_runtime.isHttp2xx("HTTP/1.1 201 Created\r\n"));
    try std.testing.expect(check_runtime.isHttp2xx("HTTP/1.0 204 No Content\r\n"));
}

test "isHttp2xx — non-2xx responses" {
    try std.testing.expect(!check_runtime.isHttp2xx("HTTP/1.1 301 Moved\r\n"));
    try std.testing.expect(!check_runtime.isHttp2xx("HTTP/1.1 404 Not Found\r\n"));
    try std.testing.expect(!check_runtime.isHttp2xx("HTTP/1.1 500 Internal\r\n"));
    try std.testing.expect(!check_runtime.isHttp2xx("HTTP/1.1 100 Continue\r\n"));
}

test "isHttp2xx — malformed responses" {
    try std.testing.expect(!check_runtime.isHttp2xx(""));
    try std.testing.expect(!check_runtime.isHttp2xx("short"));
    try std.testing.expect(!check_runtime.isHttp2xx("not http at all"));
}

test "register and get status" {
    registry_support.resetForTest();

    try registerService("web", "abcdef123456".*, .{ 10, 42, 0, 5 }, .{
        .check_type = .{ .tcp = .{ .port = 8080 } },
    });

    const status = getStatus("web");
    try std.testing.expect(status != null);
    try std.testing.expectEqual(HealthStatus.starting, status.?);
}

test "unregister removes service" {
    registry_support.resetForTest();

    try registerService("web", "abcdef123456".*, .{ 10, 42, 0, 5 }, .{
        .check_type = .{ .tcp = .{ .port = 8080 } },
    });
    unregisterService("web");

    try std.testing.expect(getStatus("web") == null);
}

test "get status returns null for unknown service" {
    registry_support.resetForTest();
    try std.testing.expect(getStatus("nonexistent") == null);
}

test "getServiceHealth returns full state" {
    registry_support.resetForTest();

    try registerService("api", "abcdef123456".*, .{ 10, 42, 0, 10 }, .{
        .check_type = .{ .http = .{
            .path = "/health",
            .port = 3000,
        } },
        .interval = 15,
    });

    const sh = getServiceHealth("api");
    try std.testing.expect(sh != null);
    try std.testing.expectEqual(HealthStatus.starting, sh.?.status);
    try std.testing.expectEqual(@as(u32, 15), sh.?.config.interval);
    try std.testing.expect(sh.?.started_at != null);
}

// -- test helpers --

fn testEntry(status: HealthStatus) ServiceHealth {
    var entry = ServiceHealth{
        .status = status,
        .consecutive_failures = 0,
        .consecutive_successes = 0,
        .last_check = null,
        .last_error = null,
        .started_at = null,
        .container_id = "abcdef123456".*,
        .container_ip = .{ 10, 42, 0, 1 },
        .config = .{
            .check_type = .{ .tcp = .{ .port = 8080 } },
            .retries = 3,
        },
        .generation = 1,
        .name_len = 8,
        .endpoint_id_len = 14,
    };
    @memcpy(entry.name_buf[0..8], "test-svc");
    @memcpy(entry.endpoint_id_buf[0..14], "abcdef123456:0");
    return entry;
}
