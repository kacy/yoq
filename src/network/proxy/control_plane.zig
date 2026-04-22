const std = @import("std");
const service_rollout = @import("../service_rollout.zig");
const proxy_runtime = @import("runtime.zig");
const service_registry_runtime_mod = @import("../service_registry_runtime.zig");
const listener_runtime_mod = @import("listener_runtime.zig");
const steering_runtime = @import("steering_runtime.zig");
const posix = std.posix;
const socket_helpers = @import("socket_helpers.zig");

pub const sync_interval_secs: u64 = 15;

pub const SyncTrigger = enum {
    event,
    periodic,

    pub fn label(self: SyncTrigger) []const u8 {
        return switch (self) {
            .event => "event",
            .periodic => "periodic",
        };
    }
};

pub const Snapshot = struct {
    enabled: bool,
    steering_enabled: bool,
    running: bool,
    interval_secs: u64,
    passes_total: u64,
    event_passes_total: u64,
    periodic_passes_total: u64,
    last_trigger: ?SyncTrigger,
    last_pass_at: ?i64,
};

var sync_running = std.atomic.Value(bool).init(false);
var sync_thread: ?std.Thread = null;
var sync_interval_override_ms: ?u64 = null;
var mutex: @import("compat").Mutex = .{};
var sync_passes_total: u64 = 0;
var event_sync_passes_total: u64 = 0;
var periodic_sync_passes_total: u64 = 0;
var last_sync_trigger: ?SyncTrigger = null;
var last_sync_pass_at: ?i64 = null;

pub fn refreshIfEnabled() void {
    runSyncPass(.event);
}

pub fn startSyncLoopIfEnabled() void {
    if (sync_running.load(.acquire)) return;

    sync_running.store(true, .release);
    sync_thread = std.Thread.spawn(.{}, syncLoop, .{}) catch {
        sync_running.store(false, .release);
        return;
    };
}

pub fn stopSyncLoop() void {
    sync_running.store(false, .release);
    if (sync_thread) |thread| {
        sync_thread = null;
        thread.join();
    }
}

pub fn snapshot() Snapshot {
    mutex.lock();
    defer mutex.unlock();

    return .{
        .enabled = controlPlaneEnabled(),
        .steering_enabled = vipSteeringEnabled(),
        .running = sync_running.load(.acquire),
        .interval_secs = if (sync_interval_override_ms) |ms| @max(@divTrunc(ms, 1000), 1) else sync_interval_secs,
        .passes_total = sync_passes_total,
        .event_passes_total = event_sync_passes_total,
        .periodic_passes_total = periodic_sync_passes_total,
        .last_trigger = last_sync_trigger,
        .last_pass_at = last_sync_pass_at,
    };
}

pub fn resetForTest() void {
    stopSyncLoop();
    mutex.lock();
    defer mutex.unlock();
    sync_interval_override_ms = null;
    sync_passes_total = 0;
    event_sync_passes_total = 0;
    periodic_sync_passes_total = 0;
    last_sync_trigger = null;
    last_sync_pass_at = null;
}

pub fn setSyncIntervalMsForTest(interval_ms: ?u64) void {
    mutex.lock();
    defer mutex.unlock();
    sync_interval_override_ms = interval_ms;
}

fn controlPlaneEnabled() bool {
    return service_registry_runtime_mod.hasProxyConfiguredServices();
}

fn vipSteeringEnabled() bool {
    return controlPlaneEnabled();
}

fn runSyncPass(trigger: SyncTrigger) void {
    listener_runtime_mod.startIfEnabled(std.heap.page_allocator);
    steering_runtime.syncIfEnabled();
    mutex.lock();
    defer mutex.unlock();
    sync_passes_total += 1;
    switch (trigger) {
        .event => event_sync_passes_total += 1,
        .periodic => periodic_sync_passes_total += 1,
    }
    last_sync_trigger = trigger;
    last_sync_pass_at = @import("compat").timestamp();
}

fn syncLoop() void {
    runSyncPass(.periodic);

    while (sync_running.load(.acquire)) {
        const interval_ms = blk: {
            mutex.lock();
            defer mutex.unlock();
            break :blk sync_interval_override_ms orelse (sync_interval_secs * std.time.ms_per_s);
        };
        @import("compat").sleep(interval_ms * std.time.ns_per_ms);
        if (!sync_running.load(.acquire)) break;
        runSyncPass(.periodic);
    }
}

test "periodic steering sync loop repairs drifted mappings" {
    const store = @import("../../state/store.zig");
    const listener_runtime = @import("listener_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
    resetForTest();
    defer resetForTest();
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
        .http_proxy_path_prefix = "/",
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

    @import("../service_registry_runtime.zig").syncServiceFromStore("api");
    steering_runtime.setPortMapperAvailableForTest(true);
    steering_runtime.setBridgeIpForTest(.{ 10, 42, 0, 1 });
    try listener_runtime.startOrSkipForTest(std.testing.allocator, 0);
    try steering_runtime.setActualMappingsForTest(&.{});
    setSyncIntervalMsForTest(10);

    startSyncLoopIfEnabled();
    defer stopSyncLoop();

    @import("compat").sleep(40 * std.time.ns_per_ms);

    const state = try steering_runtime.snapshotServiceStatus(std.testing.allocator, "api");
    try std.testing.expect(state.ready);
    try std.testing.expect(!state.blocked);
    try std.testing.expect(!state.drifted);

    const loop_state = snapshot();
    try std.testing.expect(loop_state.running);
    try std.testing.expect(loop_state.passes_total > 0);
    try std.testing.expectEqual(@as(u64, 0), loop_state.event_passes_total);
    try std.testing.expect(loop_state.periodic_passes_total > 0);
    try std.testing.expectEqual(SyncTrigger.periodic, loop_state.last_trigger.?);
    try std.testing.expect(loop_state.last_pass_at != null);
}

test "refreshIfEnabled records event-triggered sync pass" {
    resetForTest();
    defer resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .dns_returns_vip = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();

    refreshIfEnabled();

    const state = snapshot();
    try std.testing.expectEqual(@as(u64, 1), state.passes_total);
    try std.testing.expectEqual(@as(u64, 1), state.event_passes_total);
    try std.testing.expectEqual(@as(u64, 0), state.periodic_passes_total);
    try std.testing.expectEqual(SyncTrigger.event, state.last_trigger.?);
    try std.testing.expect(state.last_pass_at != null);
}

test "periodic control plane repairs routes while steering waits on prerequisites" {
    const store = @import("../../state/store.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    resetForTest();
    defer resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-1",
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
    setSyncIntervalMsForTest(10);

    startSyncLoopIfEnabled();
    defer stopSyncLoop();

    @import("compat").sleep(40 * std.time.ns_per_ms);

    const proxy_state = try proxy_runtime.snapshot(std.testing.allocator);
    defer proxy_state.deinit(std.testing.allocator);
    try std.testing.expect(proxy_state.running);
    try std.testing.expectEqual(@as(u32, 1), proxy_state.configured_services);
    try std.testing.expectEqual(@as(u32, 1), proxy_state.routes);

    const loop_state = snapshot();
    try std.testing.expect(loop_state.enabled);
    try std.testing.expect(loop_state.steering_enabled);
    try std.testing.expect(loop_state.running);
    try std.testing.expect(loop_state.passes_total > 0);
    try std.testing.expectEqual(@as(u64, 0), loop_state.event_passes_total);
    try std.testing.expect(loop_state.periodic_passes_total > 0);
    try std.testing.expectEqual(SyncTrigger.periodic, loop_state.last_trigger.?);
}

test "listener state changes trigger event-driven steering repair" {
    const store = @import("../../state/store.zig");
    const listener_runtime = @import("listener_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
    resetForTest();
    defer resetForTest();
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
        .http_proxy_path_prefix = "/",
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

    @import("../service_registry_runtime.zig").syncServiceFromStore("api");
    steering_runtime.setPortMapperAvailableForTest(true);
    steering_runtime.setBridgeIpForTest(.{ 10, 42, 0, 1 });
    try steering_runtime.setActualMappingsForTest(&.{});
    listener_runtime.setStateChangeHook(refreshIfEnabled);
    defer listener_runtime.setStateChangeHook(null);

    try listener_runtime.startOrSkipForTest(std.testing.allocator, 0);

    var service_state = try steering_runtime.snapshotServiceStatus(std.testing.allocator, "api");
    try std.testing.expect(service_state.ready);
    try std.testing.expectEqual(@as(u32, 1), service_state.applied_ports);

    var loop_state = snapshot();
    try std.testing.expect(loop_state.steering_enabled);
    try std.testing.expectEqual(@as(u64, 1), loop_state.passes_total);
    try std.testing.expectEqual(@as(u64, 1), loop_state.event_passes_total);
    try std.testing.expectEqual(@as(u64, 0), loop_state.periodic_passes_total);
    try std.testing.expectEqual(SyncTrigger.event, loop_state.last_trigger.?);

    listener_runtime.stop();

    service_state = try steering_runtime.snapshotServiceStatus(std.testing.allocator, "api");
    try std.testing.expect(!service_state.ready);
    try std.testing.expect(service_state.blocked);
    try std.testing.expectEqual(steering_runtime.BlockedReason.listener_not_running, service_state.blocked_reason);

    loop_state = snapshot();
    try std.testing.expectEqual(@as(u64, 2), loop_state.passes_total);
    try std.testing.expectEqual(@as(u64, 2), loop_state.event_passes_total);
    try std.testing.expectEqual(@as(u64, 0), loop_state.periodic_passes_total);
    try std.testing.expectEqual(SyncTrigger.event, loop_state.last_trigger.?);
}

const TestUpstreamServer = struct {
    listen_fd: @import("compat").posix.socket_t,
    port: u16,
    thread: ?std.Thread = null,
    request_buf: [2048]u8 = undefined,
    request_len: usize = 0,
    response: []const u8,

    fn init(response: []const u8) !TestUpstreamServer {
        const listen_fd = try @import("compat").posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
        errdefer @import("compat").posix.close(listen_fd);

        const reuseaddr: i32 = 1;
        posix.setsockopt(listen_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuseaddr)) catch {};

        const addr = @import("compat").net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
        try @import("compat").posix.bind(listen_fd, &addr.any, addr.getOsSockLen());
        try @import("compat").posix.listen(listen_fd, 1);

        var bound_addr: posix.sockaddr.in = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        try @import("compat").posix.getsockname(listen_fd, @ptrCast(&bound_addr), &bound_len);

        return .{
            .listen_fd = listen_fd,
            .port = std.mem.bigToNative(u16, bound_addr.port),
            .response = response,
        };
    }

    fn deinit(self: *TestUpstreamServer) void {
        if (self.thread) |thread| thread.join();
        @import("compat").posix.close(self.listen_fd);
    }

    fn start(self: *TestUpstreamServer) !void {
        self.thread = try std.Thread.spawn(.{}, acceptOne, .{self});
    }

    fn request(self: *const TestUpstreamServer) []const u8 {
        return self.request_buf[0..self.request_len];
    }

    fn acceptOne(self: *TestUpstreamServer) void {
        const client_fd = @import("compat").posix.accept(self.listen_fd, null, null, posix.SOCK.CLOEXEC) catch return;
        defer @import("compat").posix.close(client_fd);
        self.request_len = posix.read(client_fd, &self.request_buf) catch 0;
        _ = socket_helpers.writeAll(client_fd, self.response) catch {};
    }
};

var recorded_target_port: u16 = 0;

fn recordMappedTarget(_: ?[4]u8, _: u16, _: u8, target_ip: [4]u8, target_port: u16) void {
    std.debug.assert(std.mem.eql(u8, target_ip[0..], &[_]u8{ 127, 0, 0, 1 }));
    recorded_target_port = target_port;
}

test "mapped listener target serves proxied HTTP after event-driven repair" {
    const store = @import("../../state/store.zig");
    const listener_runtime = @import("listener_runtime.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");
    if (@import("compat").getenv("YOQ_SKIP_SLOW_TESTS")) |_| return error.SkipZigTest;

    var upstream = try TestUpstreamServer.init("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
    defer upstream.deinit();
    try upstream.start();

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
    resetForTest();
    defer resetForTest();
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
        .http_proxy_path_prefix = "/",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-1",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "127.0.0.1",
        .port = upstream.port,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });

    service_registry_runtime.syncServiceFromStore("api");
    steering_runtime.setPortMapperAvailableForTest(true);
    steering_runtime.setBridgeIpForTest(.{ 127, 0, 0, 1 });
    try steering_runtime.setActualMappingsForTest(&.{});
    steering_runtime.setMappingHooksForTest(recordMappedTarget, null);
    defer steering_runtime.setMappingHooksForTest(null, null);
    listener_runtime.setStateChangeHook(refreshIfEnabled);
    defer listener_runtime.setStateChangeHook(null);
    recorded_target_port = 0;

    try listener_runtime.startOrSkipForTest(std.testing.allocator, 0);
    defer listener_runtime.stop();

    try std.testing.expect(recorded_target_port != 0);

    const client_fd = try @import("compat").posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer @import("compat").posix.close(client_fd);
    const listener_addr = @import("compat").net.Address.initIp4(.{ 127, 0, 0, 1 }, recorded_target_port);
    try @import("compat").posix.connect(client_fd, &listener_addr.any, listener_addr.getOsSockLen());
    try socket_helpers.writeAll(client_fd, "GET / HTTP/1.1\r\nHost: api.internal\r\n\r\n");

    var response_buf: [1024]u8 = undefined;
    const bytes_read = try posix.read(client_fd, &response_buf);
    try std.testing.expect(bytes_read > 0);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "HTTP/1.1 200 OK\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "\r\n\r\nhello") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(), "GET / HTTP/1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(), "Host: api.internal\r\n") != null);
}

test "periodic repair restores mapped listener target and serves proxied HTTP" {
    const store = @import("../../state/store.zig");
    const listener_runtime = @import("listener_runtime.zig");
    const service_registry_runtime = @import("../service_registry_runtime.zig");
    if (@import("compat").getenv("YOQ_SKIP_SLOW_TESTS")) |_| return error.SkipZigTest;

    var upstream = try TestUpstreamServer.init("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
    defer upstream.deinit();
    try upstream.start();

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
    resetForTest();
    defer resetForTest();
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
        .http_proxy_path_prefix = "/",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-1",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "127.0.0.1",
        .port = upstream.port,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });

    service_registry_runtime.syncServiceFromStore("api");
    steering_runtime.setPortMapperAvailableForTest(true);
    steering_runtime.setBridgeIpForTest(.{ 127, 0, 0, 1 });
    try steering_runtime.setActualMappingsForTest(&.{});
    steering_runtime.setMappingHooksForTest(recordMappedTarget, null);
    defer steering_runtime.setMappingHooksForTest(null, null);
    recorded_target_port = 0;
    setSyncIntervalMsForTest(10);

    try listener_runtime.startOrSkipForTest(std.testing.allocator, 0);
    defer listener_runtime.stop();

    startSyncLoopIfEnabled();
    defer stopSyncLoop();

    @import("compat").sleep(40 * std.time.ns_per_ms);
    try std.testing.expect(recorded_target_port != 0);

    const client_fd = try @import("compat").posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    defer @import("compat").posix.close(client_fd);
    const listener_addr = @import("compat").net.Address.initIp4(.{ 127, 0, 0, 1 }, recorded_target_port);
    try @import("compat").posix.connect(client_fd, &listener_addr.any, listener_addr.getOsSockLen());
    try socket_helpers.writeAll(client_fd, "GET / HTTP/1.1\r\nHost: api.internal\r\n\r\n");

    var response_buf: [1024]u8 = undefined;
    const bytes_read = try posix.read(client_fd, &response_buf);
    try std.testing.expect(bytes_read > 0);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "HTTP/1.1 200 OK\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response_buf[0..bytes_read], "\r\n\r\nhello") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(), "GET / HTTP/1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, upstream.request(), "Host: api.internal\r\n") != null);
}
