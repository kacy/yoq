//! startup retries preserve the enrollment identity while waiting for a usable voter.
const std = @import("std");
const http = @import("../http_client.zig");
const json = @import("../../lib/json_helpers.zig");
const wait = @import("../../lib/runtime_wait.zig");

pub const Policy = struct {
    timeout_ms: u32 = 120_000,
    initial_delay_ms: u32 = 250,
    max_delay_ms: u32 = 2_000,
};

pub fn checkStatus(status: u16, body: []const u8) error{ EnrollmentUnavailable, RegistrationRejected }!void {
    if (status == 200) return;
    if (status == 408 or status == 429 or status == 502 or status == 503 or status == 504) return error.EnrollmentUnavailable;
    if (status == 400) {
        if (json.extractJsonString(body, "error")) |message| {
            if (std.mem.eql(u8, message, "not leader")) return error.EnrollmentUnavailable;
        }
    }
    return error.RegistrationRejected;
}

pub fn run(agent: anytype, canceled: *const std.atomic.Value(bool), policy: Policy) !void {
    const deadline = now() + policy.timeout_ms;
    const options: http.RequestOptions = .{ .deadline_ms = deadline, .canceled = canceled };
    var delay = policy.initial_delay_ms;
    var announced = false;
    while (true) {
        if (canceled.load(.acquire)) return error.Canceled;
        if (now() >= deadline) return error.EnrollmentTimeout;
        agent.registerWithOptions(options) catch |err| switch (err) {
            error.EnrollmentUnavailable => {
                if (!announced) {
                    @import("../../lib/log.zig").warn("cluster enrollment unavailable; retrying for up to {d} seconds", .{policy.timeout_ms / 1000});
                    announced = true;
                }
                try pause(canceled, @min(deadline, now() + delay));
                delay = @intCast(@min(@as(u64, delay) * 2, policy.max_delay_ms));
                continue;
            },
            else => return err,
        };
        if (canceled.load(.acquire)) return error.Canceled;
        return;
    }
}

fn now() i64 {
    return std.Io.Clock.awake.now(std.Options.debug_io).toMilliseconds();
}

fn pause(canceled: *const std.atomic.Value(bool), deadline: i64) !void {
    while (true) {
        if (canceled.load(.acquire)) return error.Canceled;
        const remaining = deadline - now();
        if (remaining <= 0) return;
        if (!wait.sleep(.fromMilliseconds(@intCast(@min(remaining, 100))), "agent enrollment retry")) return error.Canceled;
    }
}

test "agent enrollment retries only temporary status responses" {
    try checkStatus(200, "{}");
    for ([_]u16{ 408, 429, 502, 503, 504 }) |status|
        try std.testing.expectError(error.EnrollmentUnavailable, checkStatus(status, "{}"));
    try std.testing.expectError(error.EnrollmentUnavailable, checkStatus(400, "{\"error\":\"not leader\"}"));
    for ([_]u16{ 400, 401, 403, 409, 422, 500 }) |status|
        try std.testing.expectError(error.RegistrationRejected, checkStatus(status, "{\"error\":\"invalid identity\"}"));
}

const AttemptFixture = struct {
    calls: usize = 0,
    failures: usize = 0,
    failure: anyerror = error.EnrollmentUnavailable,
    cancel_on_attempt: ?*std.atomic.Value(bool) = null,

    pub fn registerWithOptions(self: *@This(), options: http.RequestOptions) !void {
        try options.check();
        self.calls += 1;
        if (self.cancel_on_attempt) |flag| flag.store(true, .release);
        if (self.calls <= self.failures) return self.failure;
    }
};

test "agent enrollment recovers after temporary failures but stops on permanent failures" {
    const canceled: std.atomic.Value(bool) = .init(false);
    var temporary: AttemptFixture = .{ .failures = 2 };
    try run(&temporary, &canceled, .{ .timeout_ms = 1000, .initial_delay_ms = 1, .max_delay_ms = 2 });
    try std.testing.expectEqual(@as(usize, 3), temporary.calls);
    for ([_]anyerror{ error.RegisterFailed, error.RegistrationRejected, error.InvalidResponse }) |failure| {
        var permanent: AttemptFixture = .{ .failures = 5, .failure = failure };
        try std.testing.expectError(failure, run(&permanent, &canceled, .{}));
        try std.testing.expectEqual(@as(usize, 1), permanent.calls);
    }
}

test "agent enrollment startup deadline and cancellation bound retry waits" {
    var canceled: std.atomic.Value(bool) = .init(false);
    var unavailable: AttemptFixture = .{ .failures = std.math.maxInt(usize) };
    try std.testing.expectError(error.EnrollmentTimeout, run(&unavailable, &canceled, .{ .timeout_ms = 20, .initial_delay_ms = 5, .max_delay_ms = 10 }));
    try std.testing.expect(unavailable.calls > 0);
    var interrupted: AttemptFixture = .{ .failures = 5, .cancel_on_attempt = &canceled };
    try std.testing.expectError(error.Canceled, run(&interrupted, &canceled, .{}));
    try std.testing.expectEqual(@as(usize, 1), interrupted.calls);
    var already_canceled: AttemptFixture = .{};
    try std.testing.expectError(error.Canceled, run(&already_canceled, &canceled, .{}));
    try std.testing.expectEqual(@as(usize, 0), already_canceled.calls);
}

test "agent enrollment cancellation prevents a real registration from touching local identity" {
    const Agent = @import("../agent.zig").Agent;
    var agent = Agent.init(std.testing.allocator, .{ 127, 0, 0, 1 }, 7700, "cluster-token");
    defer agent.deinit();
    const canceled: std.atomic.Value(bool) = .init(true);
    try std.testing.expectError(error.Canceled, agent.registerWithOptions(.{ .canceled = &canceled }));
    try std.testing.expect(agent.enrollment_target == null);
    try std.testing.expect(agent.worker_credential == null);
    try std.testing.expectError(error.Canceled, run(&agent, &canceled, .{}));
}
