const std = @import("std");

pub const RequestPolicy = struct {
    retries: u8 = 0,
    retry_on_5xx: bool = true,
    preserve_host: bool = true,
};

pub const CircuitBreakerPolicy = struct {
    failure_threshold: u8 = 3,
    open_timeout_ms: u32 = 30_000,
};

pub const CircuitState = enum {
    closed,
    open,
    half_open,
};

pub fn methodIsRetryable(method: []const u8) bool {
    return std.ascii.eqlIgnoreCase(method, "GET") or
        std.ascii.eqlIgnoreCase(method, "HEAD") or
        std.ascii.eqlIgnoreCase(method, "OPTIONS");
}

pub fn shouldRetry(policy: RequestPolicy, method: []const u8, attempt: u8, status_code: ?u16, had_transport_error: bool) bool {
    if (attempt >= policy.retries) return false;
    if (!methodIsRetryable(method)) return false;
    if (had_transport_error) return true;
    if (!policy.retry_on_5xx) return false;

    const status = status_code orelse return false;
    return status >= 500 and status <= 599;
}

pub fn shouldTripCircuit(policy: CircuitBreakerPolicy, consecutive_failures: u8) bool {
    return consecutive_failures >= policy.failure_threshold;
}

pub fn shouldAllowHalfOpen(policy: CircuitBreakerPolicy, opened_at_ms: i64, now_ms: i64) bool {
    return now_ms - opened_at_ms >= @as(i64, @intCast(policy.open_timeout_ms));
}

test "methodIsRetryable recognizes safe methods" {
    try std.testing.expect(methodIsRetryable("GET"));
    try std.testing.expect(methodIsRetryable("head"));
    try std.testing.expect(methodIsRetryable("OPTIONS"));
    try std.testing.expect(!methodIsRetryable("POST"));
}

test "shouldRetry uses retry budget" {
    const policy = RequestPolicy{ .retries = 2 };

    try std.testing.expect(shouldRetry(policy, "GET", 0, 503, false));
    try std.testing.expect(shouldRetry(policy, "GET", 1, null, true));
    try std.testing.expect(!shouldRetry(policy, "GET", 2, 503, false));
}

test "shouldRetry rejects unsafe methods" {
    const policy = RequestPolicy{ .retries = 3 };

    try std.testing.expect(!shouldRetry(policy, "POST", 0, 503, false));
}

test "shouldTripCircuit opens after reaching threshold" {
    const policy = CircuitBreakerPolicy{ .failure_threshold = 3 };

    try std.testing.expect(!shouldTripCircuit(policy, 2));
    try std.testing.expect(shouldTripCircuit(policy, 3));
}

test "shouldAllowHalfOpen waits for timeout window" {
    const policy = CircuitBreakerPolicy{ .open_timeout_ms = 5000 };

    try std.testing.expect(!shouldAllowHalfOpen(policy, 1000, 5999));
    try std.testing.expect(shouldAllowHalfOpen(policy, 1000, 6000));
}
