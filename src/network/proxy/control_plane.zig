const std = @import("std");
const service_rollout = @import("../service_rollout.zig");
const proxy_runtime = @import("runtime.zig");
const steering_runtime = @import("steering_runtime.zig");

pub const sync_interval_secs: u64 = 15;

pub const Snapshot = struct {
    enabled: bool,
    running: bool,
    interval_secs: u64,
    passes_total: u64,
    last_pass_at: ?i64,
};

var sync_running = std.atomic.Value(bool).init(false);
var sync_thread: ?std.Thread = null;
var sync_interval_override_ms: ?u64 = null;
var mutex: std.Thread.Mutex = .{};
var sync_passes_total: u64 = 0;
var last_sync_pass_at: ?i64 = null;

pub fn refreshIfEnabled() void {
    proxy_runtime.bootstrapIfEnabled();
    steering_runtime.syncIfEnabled();
}

pub fn startSyncLoopIfEnabled() void {
    if (!syncEnabled()) return;
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
        .enabled = syncEnabled(),
        .running = sync_running.load(.acquire),
        .interval_secs = if (sync_interval_override_ms) |ms| @max(@divTrunc(ms, 1000), 1) else sync_interval_secs,
        .passes_total = sync_passes_total,
        .last_pass_at = last_sync_pass_at,
    };
}

pub fn resetForTest() void {
    stopSyncLoop();
    mutex.lock();
    defer mutex.unlock();
    sync_interval_override_ms = null;
    sync_passes_total = 0;
    last_sync_pass_at = null;
}

pub fn setSyncIntervalMsForTest(interval_ms: ?u64) void {
    mutex.lock();
    defer mutex.unlock();
    sync_interval_override_ms = interval_ms;
}

fn syncEnabled() bool {
    const flags = service_rollout.current();
    return flags.l7_proxy_http and flags.dns_returns_vip;
}

fn runSyncPass() void {
    steering_runtime.syncIfEnabled();
    mutex.lock();
    defer mutex.unlock();
    sync_passes_total += 1;
    last_sync_pass_at = std.time.timestamp();
}

fn syncLoop() void {
    while (sync_running.load(.acquire)) {
        const interval_ms = blk: {
            mutex.lock();
            defer mutex.unlock();
            break :blk sync_interval_override_ms orelse (sync_interval_secs * std.time.ms_per_s);
        };
        std.Thread.sleep(interval_ms * std.time.ns_per_ms);
        if (!sync_running.load(.acquire)) break;
        if (!syncEnabled()) continue;
        runSyncPass();
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
    listener_runtime.startForTest(std.testing.allocator, 0);
    try steering_runtime.setActualMappingsForTest(&.{});
    setSyncIntervalMsForTest(10);

    startSyncLoopIfEnabled();
    defer stopSyncLoop();

    std.Thread.sleep(40 * std.time.ns_per_ms);

    const state = try steering_runtime.snapshotServiceStatus(std.testing.allocator, "api");
    try std.testing.expect(state.ready);
    try std.testing.expect(!state.blocked);
    try std.testing.expect(!state.drifted);

    const loop_state = snapshot();
    try std.testing.expect(loop_state.running);
    try std.testing.expect(loop_state.passes_total > 0);
    try std.testing.expect(loop_state.last_pass_at != null);
}
