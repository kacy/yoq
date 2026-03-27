const std = @import("std");

pub const RequestPolicy = struct {
    retries: u8 = 0,
    retry_on_5xx: bool = true,
    preserve_host: bool = true,
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
