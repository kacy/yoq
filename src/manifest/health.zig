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
const posix = std.posix;
const spec = @import("spec.zig");
const dns = @import("../network/dns.zig");
const log = @import("../lib/log.zig");

// -- public types --

pub const HealthStatus = enum {
    /// service registered but hasn't passed its first health check yet
    starting,
    /// service is passing health checks consistently
    healthy,
    /// service has failed enough consecutive health checks to be marked down
    unhealthy,
};

pub const ServiceHealth = struct {
    status: HealthStatus,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_check: ?i64, // unix timestamp
    last_error: ?[]const u8,
    started_at: ?i64, // when the service was first registered

    /// the service name, container ID, and container IP, used for checks
    /// and DNS registration/unregistration.
    /// name is copied into a fixed buffer to avoid lifetime dependency
    /// on the manifest memory — if the manifest is freed/reloaded while
    /// health checks run, a borrowed pointer would become use-after-free.
    name_buf: [64]u8 = undefined,
    name_len: u8 = 0,
    container_id: [12]u8,
    container_ip: [4]u8,
    config: spec.HealthCheck,

    pub fn serviceName(self: *const ServiceHealth) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

// -- health state registry --
//
// fixed-size array of per-service health state, protected by a mutex.
// mirrors the pattern from dns.zig — simple, no heap allocation for
// the registry itself.

const max_services = 64;

var health_states: [max_services]?ServiceHealth = [_]?ServiceHealth{null} ** max_services;
var health_mutex: std.Thread.Mutex = .{};

/// register a service for health checking.
/// called when a service starts and has a health_check configured.
/// the service starts in "starting" status.
pub const HealthError = error{
    /// the health check registry is full (max 64 services)
    RegistryFull,
};

pub fn registerService(
    service_name: []const u8,
    container_id: [12]u8,
    container_ip: [4]u8,
    config: spec.HealthCheck,
) HealthError!void {
    health_mutex.lock();
    defer health_mutex.unlock();

    // copy service name into the fixed buffer
    const len = @min(service_name.len, 64);

    // find an empty slot
    for (&health_states) |*slot| {
        if (slot.* == null) {
            var entry = ServiceHealth{
                .status = .starting,
                .consecutive_failures = 0,
                .consecutive_successes = 0,
                .last_check = null,
                .last_error = null,
                .started_at = std.time.timestamp(),
                .container_id = container_id,
                .container_ip = container_ip,
                .config = config,
                .name_len = @intCast(len),
            };
            @memcpy(entry.name_buf[0..len], service_name[0..len]);
            slot.* = entry;
            return;
        }
    }

    log.err("health: registry full (max {d}), cannot track {s}", .{ max_services, service_name });
    return HealthError.RegistryFull;
}

/// unregister a service from health checking.
/// called when a service is stopped or removed.
pub fn unregisterService(service_name: []const u8) void {
    health_mutex.lock();
    defer health_mutex.unlock();

    for (&health_states) |*slot| {
        if (slot.*) |entry| {
            if (std.mem.eql(u8, entry.serviceName(), service_name)) {
                slot.* = null;
                return;
            }
        }
    }
}

/// get the current health status for a service.
/// returns null if the service is not being health-checked.
pub fn getStatus(service_name: []const u8) ?HealthStatus {
    health_mutex.lock();
    defer health_mutex.unlock();

    for (health_states) |slot| {
        if (slot) |entry| {
            if (std.mem.eql(u8, entry.serviceName(), service_name)) {
                return entry.status;
            }
        }
    }
    return null;
}

/// get the full health state for a service (for API responses).
/// returns null if the service is not being health-checked.
pub fn getServiceHealth(service_name: []const u8) ?ServiceHealth {
    health_mutex.lock();
    defer health_mutex.unlock();

    for (health_states) |slot| {
        if (slot) |entry| {
            if (std.mem.eql(u8, entry.serviceName(), service_name)) {
                return entry;
            }
        }
    }
    return null;
}

// -- checker thread --

var checker_thread: ?std.Thread = null;
var checker_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

/// start the health checker thread. idempotent.
pub fn startChecker() void {
    if (checker_running.load(.acquire)) return;

    checker_running.store(true, .release);
    checker_thread = std.Thread.spawn(.{}, checkerLoop, .{}) catch |e| {
        log.warn("health: failed to spawn checker thread: {}", .{e});
        checker_running.store(false, .release);
        return;
    };

    log.info("health checker started", .{});
}

/// stop the health checker thread.
pub fn stopChecker() void {
    if (!checker_running.load(.acquire)) return;

    checker_running.store(false, .release);

    if (checker_thread) |t| {
        t.join();
        checker_thread = null;
    }
}

/// main loop for the checker thread.
/// iterates over all registered services each second, running checks
/// for any service whose interval has elapsed.
fn checkerLoop() void {
    while (checker_running.load(.acquire)) {
        const now = std.time.timestamp();

        // snapshot the services that need checking this tick.
        // we copy the data we need under the lock, then run the actual
        // checks outside the lock so we don't hold it during I/O.
        var to_check: [max_services]?CheckItem = [_]?CheckItem{null} ** max_services;
        var check_count: usize = 0;

        {
            health_mutex.lock();
            defer health_mutex.unlock();

            for (health_states, 0..) |slot, i| {
                const entry = slot orelse continue;

                // during start_period, don't run checks yet
                if (entry.started_at) |started| {
                    if (now - started < entry.config.start_period) continue;
                }

                // check if interval has elapsed since last check
                if (entry.last_check) |last| {
                    if (now - last < entry.config.interval) continue;
                }

                to_check[check_count] = .{
                    .index = i,
                    .container_ip = entry.container_ip,
                    .container_id = entry.container_id,
                    .config = entry.config,
                    .service_name = entry.serviceName(),
                };
                check_count += 1;
            }
        }

        // run checks outside the lock
        for (to_check[0..check_count]) |maybe_item| {
            const item = maybe_item orelse continue;
            const success = runCheck(item.container_ip, item.config);

            health_mutex.lock();
            defer health_mutex.unlock();

            if (health_states[item.index]) |*entry| {
                // verify the slot still belongs to the same container.
                // between snapshot and update, the service could have been
                // unregistered and the slot reused for a different service.
                if (!std.mem.eql(u8, &entry.container_id, &item.container_id)) continue;

                entry.last_check = now;
                updateState(entry, success);
            }
        }

        // sleep 1 second between polling cycles
        std.Thread.sleep(1 * std.time.ns_per_s);
    }
}

/// data needed to run a check outside the lock
const CheckItem = struct {
    index: usize,
    container_ip: [4]u8,
    container_id: [12]u8,
    config: spec.HealthCheck,
    service_name: []const u8,
};

// -- state machine --

/// update a service's health state based on a check result.
/// implements the state machine transitions described at the top of this file.
///
/// when a service transitions to healthy, it is registered with DNS for
/// service discovery (readiness gating). when it transitions to unhealthy,
/// it is unregistered so traffic stops flowing to it.
///
/// must be called with health_mutex held.
fn updateState(entry: *ServiceHealth, success: bool) void {
    if (success) {
        entry.consecutive_successes += 1;
        entry.consecutive_failures = 0;
        entry.last_error = null;

        switch (entry.status) {
            .starting => {
                entry.status = .healthy;
                log.info("health: {s} is now healthy", .{entry.serviceName()});
                dnsRegister(entry);
            },
            .unhealthy => {
                entry.status = .healthy;
                log.info("health: {s} recovered, now healthy", .{entry.serviceName()});
                dnsRegister(entry);
            },
            .healthy => {},
        }
    } else {
        entry.consecutive_failures += 1;
        entry.consecutive_successes = 0;

        switch (entry.status) {
            .starting => {
                if (entry.consecutive_failures >= entry.config.retries) {
                    entry.status = .unhealthy;
                    log.warn("health: {s} failed to start (after {d} retries)", .{
                        entry.serviceName(), entry.config.retries,
                    });
                }
            },
            .healthy => {
                if (entry.consecutive_failures >= entry.config.retries) {
                    entry.status = .unhealthy;
                    log.warn("health: {s} is now unhealthy (after {d} consecutive failures)", .{
                        entry.serviceName(), entry.config.retries,
                    });
                    dnsUnregister(entry);
                }
            },
            .unhealthy => {},
        }
    }
}

/// register a healthy service with DNS for service discovery.
/// called when a service transitions to healthy status.
fn dnsRegister(entry: *const ServiceHealth) void {
    dns.registerService(entry.serviceName(), &entry.container_id, entry.container_ip);
    log.info("health: registered {s} in DNS", .{entry.serviceName()});
}

/// unregister an unhealthy service from DNS.
/// called when a service transitions to unhealthy status.
fn dnsUnregister(entry: *const ServiceHealth) void {
    dns.unregisterService(&entry.container_id);
    log.info("health: unregistered {s} from DNS", .{entry.serviceName()});
}

// -- check implementations --

/// run a single health check based on its type.
/// returns true if the check passed, false otherwise.
fn runCheck(container_ip: [4]u8, config: spec.HealthCheck) bool {
    return switch (config.check_type) {
        .http => |h| runHttpCheck(container_ip, h.port, h.path, config.timeout),
        .tcp => |t| runTcpCheck(container_ip, t.port, config.timeout),
        .exec => {
            // exec checks require the container runtime and are wired up
            // in the orchestrator integration (PR 3). for now, we return
            // false so the state machine treats it as a failure until
            // the full integration is in place.
            return false;
        },
    };
}

/// HTTP health check: connect to container_ip:port, send GET request,
/// check for HTTP 2xx response.
fn runHttpCheck(container_ip: [4]u8, port: u16, path: []const u8, timeout: u32) bool {
    const sock = tcpConnect(container_ip, port, timeout) orelse return false;
    defer posix.close(sock);

    // send GET request
    var request_buf: [512]u8 = undefined;
    const request = std.fmt.bufPrint(&request_buf, "GET {s} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n", .{path}) catch return false;

    _ = posix.write(sock, request) catch return false;

    // read response — we only need the status line
    var response_buf: [256]u8 = undefined;
    const n = posix.read(sock, &response_buf) catch return false;
    if (n < 12) return false; // "HTTP/1.x 200" is 12 chars minimum

    const response = response_buf[0..n];

    // check for "HTTP/1.x 2xx" pattern
    return isHttp2xx(response);
}

/// check if a response starts with an HTTP 2xx status.
/// matches "HTTP/1.0 2xx" or "HTTP/1.1 2xx".
fn isHttp2xx(response: []const u8) bool {
    // minimum: "HTTP/1.0 200"
    if (response.len < 12) return false;

    // check "HTTP/1." prefix
    if (!std.mem.startsWith(u8, response, "HTTP/1.")) return false;

    // status code starts at position 9
    if (response[9] != '2') return false;

    return true;
}

/// TCP health check: just connect and disconnect.
/// success means the port is accepting connections.
fn runTcpCheck(container_ip: [4]u8, port: u16, timeout: u32) bool {
    const sock = tcpConnect(container_ip, port, timeout) orelse return false;
    posix.close(sock);
    return true;
}

/// create a TCP connection to a container IP with a timeout.
/// returns the socket on success, null on failure.
fn tcpConnect(container_ip: [4]u8, port: u16, timeout: u32) ?posix.socket_t {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch return null;
    errdefer posix.close(sock);

    // set send/receive timeouts
    const tv = posix.timeval{
        .sec = @intCast(timeout),
        .usec = 0,
    };
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};

    const addr = posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(container_ip),
    };

    posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch return null;

    return sock;
}

// -- tests --

test "state machine — starting to healthy on first success" {
    var entry = testEntry(.starting);
    updateState(&entry, true);
    try std.testing.expectEqual(HealthStatus.healthy, entry.status);
    try std.testing.expectEqual(@as(u32, 1), entry.consecutive_successes);
    try std.testing.expectEqual(@as(u32, 0), entry.consecutive_failures);
}

test "state machine — starting stays starting on single failure" {
    var entry = testEntry(.starting);
    entry.config.retries = 3;
    updateState(&entry, false);
    try std.testing.expectEqual(HealthStatus.starting, entry.status);
    try std.testing.expectEqual(@as(u32, 1), entry.consecutive_failures);
}

test "state machine — starting to unhealthy after retries exhausted" {
    var entry = testEntry(.starting);
    entry.config.retries = 3;

    updateState(&entry, false); // 1
    updateState(&entry, false); // 2
    try std.testing.expectEqual(HealthStatus.starting, entry.status);

    updateState(&entry, false); // 3 — should flip
    try std.testing.expectEqual(HealthStatus.unhealthy, entry.status);
    try std.testing.expectEqual(@as(u32, 3), entry.consecutive_failures);
}

test "state machine — healthy to unhealthy after retries" {
    var entry = testEntry(.healthy);
    entry.config.retries = 2;

    updateState(&entry, false); // 1
    try std.testing.expectEqual(HealthStatus.healthy, entry.status);

    updateState(&entry, false); // 2 — should flip
    try std.testing.expectEqual(HealthStatus.unhealthy, entry.status);
}

test "state machine — unhealthy to healthy on single success" {
    var entry = testEntry(.unhealthy);
    entry.consecutive_failures = 5;

    updateState(&entry, true);
    try std.testing.expectEqual(HealthStatus.healthy, entry.status);
    try std.testing.expectEqual(@as(u32, 0), entry.consecutive_failures);
    try std.testing.expectEqual(@as(u32, 1), entry.consecutive_successes);
}

test "state machine — healthy stays healthy on success" {
    var entry = testEntry(.healthy);
    entry.consecutive_successes = 10;

    updateState(&entry, true);
    try std.testing.expectEqual(HealthStatus.healthy, entry.status);
    try std.testing.expectEqual(@as(u32, 11), entry.consecutive_successes);
}

test "state machine — failure resets consecutive successes" {
    var entry = testEntry(.healthy);
    entry.consecutive_successes = 5;
    entry.config.retries = 10; // won't flip to unhealthy

    updateState(&entry, false);
    try std.testing.expectEqual(@as(u32, 0), entry.consecutive_successes);
    try std.testing.expectEqual(@as(u32, 1), entry.consecutive_failures);
}

test "state machine — success resets consecutive failures" {
    var entry = testEntry(.unhealthy);
    entry.consecutive_failures = 5;

    updateState(&entry, true);
    try std.testing.expectEqual(@as(u32, 0), entry.consecutive_failures);
    try std.testing.expectEqual(@as(u32, 1), entry.consecutive_successes);
}

test "state machine — intermittent failures don't trigger unhealthy" {
    var entry = testEntry(.healthy);
    entry.config.retries = 3;

    updateState(&entry, false); // 1 failure
    updateState(&entry, false); // 2 failures
    updateState(&entry, true); // success — resets count
    updateState(&entry, false); // 1 failure again
    updateState(&entry, false); // 2 failures

    try std.testing.expectEqual(HealthStatus.healthy, entry.status);
}

test "isHttp2xx — valid 2xx responses" {
    try std.testing.expect(isHttp2xx("HTTP/1.0 200 OK\r\n"));
    try std.testing.expect(isHttp2xx("HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(isHttp2xx("HTTP/1.1 201 Created\r\n"));
    try std.testing.expect(isHttp2xx("HTTP/1.0 204 No Content\r\n"));
}

test "isHttp2xx — non-2xx responses" {
    try std.testing.expect(!isHttp2xx("HTTP/1.1 301 Moved\r\n"));
    try std.testing.expect(!isHttp2xx("HTTP/1.1 404 Not Found\r\n"));
    try std.testing.expect(!isHttp2xx("HTTP/1.1 500 Internal\r\n"));
    try std.testing.expect(!isHttp2xx("HTTP/1.1 100 Continue\r\n"));
}

test "isHttp2xx — malformed responses" {
    try std.testing.expect(!isHttp2xx(""));
    try std.testing.expect(!isHttp2xx("short"));
    try std.testing.expect(!isHttp2xx("not http at all"));
}

test "register and get status" {
    resetForTest();

    try registerService("web", "abcdef123456".*, .{ 10, 42, 0, 5 }, .{
        .check_type = .{ .tcp = .{ .port = 8080 } },
    });

    const status = getStatus("web");
    try std.testing.expect(status != null);
    try std.testing.expectEqual(HealthStatus.starting, status.?);
}

test "unregister removes service" {
    resetForTest();

    try registerService("web", "abcdef123456".*, .{ 10, 42, 0, 5 }, .{
        .check_type = .{ .tcp = .{ .port = 8080 } },
    });
    unregisterService("web");

    try std.testing.expect(getStatus("web") == null);
}

test "get status returns null for unknown service" {
    resetForTest();
    try std.testing.expect(getStatus("nonexistent") == null);
}

test "getServiceHealth returns full state" {
    resetForTest();

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
        .name_len = 8,
    };
    @memcpy(entry.name_buf[0..8], "test-svc");
    return entry;
}

/// reset health state for test isolation.
fn resetForTest() void {
    health_mutex.lock();
    defer health_mutex.unlock();
    for (&health_states) |*slot| {
        slot.* = null;
    }
}
