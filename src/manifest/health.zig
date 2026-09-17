// health — health check engine for services
//
// periodically probes services with configured health checks (http, tcp,
// grpc, or exec) and tracks their health status. the orchestrator spawns a
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

comptime {
    _ = @import("health/check_runtime.zig");
    _ = @import("health/checker_runtime.zig");
}

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

/// Get an owned health snapshot. The caller frees snapshot.config with alloc.
/// returns null if the service is not being health-checked.
pub fn getServiceHealth(alloc: std.mem.Allocator, service_name: []const u8) !?ServiceHealth {
    return registry_support.getServiceHealth(alloc, service_name);
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

test "state machine reports the first failure when retries are zero" {
    for ([_]HealthStatus{ .starting, .healthy }) |status| {
        var entry = testEntry(status);
        entry.config.retries = 0;

        try std.testing.expect(checker_runtime.updateState(&entry, false) == .became_unhealthy);
        try std.testing.expectEqual(HealthStatus.unhealthy, entry.status);
        try std.testing.expectEqual(@as(u32, 1), entry.consecutive_failures);
        try std.testing.expectEqual(@as(u32, 1), entry.flap_count);
    }
}

test "state machine counts flaps only when health changes" {
    var entry = testEntry(.healthy);
    entry.config.retries = 2;
    entry.last_error = "connection refused";

    try std.testing.expect(checker_runtime.updateState(&entry, false) == .none);
    try std.testing.expectEqual(@as(u32, 0), entry.flap_count);
    try std.testing.expect(checker_runtime.updateState(&entry, false) == .became_unhealthy);
    try std.testing.expectEqual(@as(u32, 1), entry.flap_count);

    // further failures count toward backoff without another status transition.
    try std.testing.expect(checker_runtime.updateState(&entry, false) == .none);
    try std.testing.expectEqual(HealthStatus.unhealthy, entry.status);
    try std.testing.expectEqual(@as(u32, 3), entry.consecutive_failures);
    try std.testing.expectEqual(@as(u32, 1), entry.flap_count);
    try std.testing.expectEqualStrings("connection refused", entry.last_error.?);

    try std.testing.expect(checker_runtime.updateState(&entry, true) == .became_healthy);
    try std.testing.expectEqual(HealthStatus.healthy, entry.status);
    try std.testing.expectEqual(@as(u32, 0), entry.consecutive_failures);
    try std.testing.expectEqual(@as(u32, 1), entry.consecutive_successes);
    try std.testing.expectEqual(@as(u32, 2), entry.flap_count);
    try std.testing.expect(entry.last_error == null);

    try std.testing.expect(checker_runtime.updateState(&entry, true) == .none);
    try std.testing.expectEqual(@as(u32, 2), entry.consecutive_successes);
    try std.testing.expectEqual(@as(u32, 2), entry.flap_count);
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

test "register resets existing health state and owns the replacement config" {
    registry_support.resetForTest();
    defer registry_support.resetForTest();

    try registerService("api", "abcdef123456".*, .{ 10, 42, 0, 10 }, .{
        .check_type = .{ .http = .{ .path = "/health", .port = 3000 } },
    });
    const old_snapshot = (try getServiceHealth(std.testing.allocator, "api")).?;
    defer old_snapshot.config.deinit(std.testing.allocator);

    {
        registry_support.health_mutex.lockUncancelable(std.Options.debug_io);
        defer registry_support.health_mutex.unlock(std.Options.debug_io);
        const entry = &registry_support.health_states.items[0];
        entry.status = .unhealthy;
        entry.consecutive_failures = 3;
        entry.consecutive_successes = 2;
        entry.last_check = 42;
        entry.last_error = "connection refused";
        entry.started_at = 1;
        entry.registration_epoch = 7;
        entry.next_check_at = 99;
        entry.in_flight = true;
        entry.flap_count = 4;
    }

    var path = "/ready".*;
    try registerService("api", "123456abcdef".*, .{ 10, 42, 0, 11 }, .{
        .check_type = .{ .http = .{ .path = &path, .port = 8080 } },
        .interval = 30,
    });
    // the registered config must not borrow the caller's path buffer.
    @memset(&path, 'x');

    const snapshot = (try getServiceHealth(std.testing.allocator, "api")).?;
    defer snapshot.config.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), snapshotChecker().tracked_endpoints);
    try std.testing.expectEqual(HealthStatus.starting, snapshot.status);
    try std.testing.expectEqual(@as(u32, 0), snapshot.consecutive_failures);
    try std.testing.expectEqual(@as(u32, 0), snapshot.consecutive_successes);
    try std.testing.expectEqual(@as(?i64, null), snapshot.last_check);
    try std.testing.expect(snapshot.last_error == null);
    try std.testing.expect(snapshot.started_at.? > 1);
    try std.testing.expectEqual(snapshot.started_at.?, snapshot.next_check_at);
    try std.testing.expectEqual(@as(u64, 8), snapshot.registration_epoch);
    try std.testing.expect(!snapshot.in_flight);
    try std.testing.expectEqual(@as(u32, 0), snapshot.flap_count);
    try std.testing.expectEqualStrings("api", snapshot.serviceName());
    try std.testing.expectEqualStrings("123456abcdef", &snapshot.container_id);
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 11 }, snapshot.container_ip);
    try std.testing.expectEqualStrings("123456abcdef:0", snapshot.endpointId());
    try std.testing.expectEqualStrings("/ready", snapshot.config.check_type.http.path);
    try std.testing.expectEqual(@as(u16, 8080), snapshot.config.check_type.http.port);
    try std.testing.expectEqual(@as(u32, 30), snapshot.config.interval);

    // replacing the registry entry must leave earlier owned snapshots usable.
    try std.testing.expectEqualStrings("/health", old_snapshot.config.check_type.http.path);
    try std.testing.expectEqualStrings("abcdef123456", &old_snapshot.container_id);
    try std.testing.expectEqual(@as(u64, 1), old_snapshot.registration_epoch);
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

test "getServiceHealth returns owned state after unregister" {
    registry_support.resetForTest();
    defer registry_support.resetForTest();

    try registerService("api", "abcdef123456".*, .{ 10, 42, 0, 10 }, .{
        .check_type = .{ .http = .{
            .path = "/health",
            .port = 3000,
        } },
        .interval = 15,
    });

    const sh = try getServiceHealth(std.testing.allocator, "api");
    defer if (sh) |snapshot| snapshot.config.deinit(std.testing.allocator);
    unregisterService("api");
    try std.testing.expect(sh != null);
    try std.testing.expectEqualStrings("/health", sh.?.config.check_type.http.path);
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
