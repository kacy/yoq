const std = @import("std");
const log = @import("../../lib/log.zig");
const bridge = @import("../bridge.zig");
const ip = @import("../ip.zig");
const service_registry_runtime = @import("../service_registry_runtime.zig");
const service_rollout = @import("../service_rollout.zig");
const listener_runtime = @import("listener_runtime.zig");
const ebpf = @import("../setup/ebpf_module.zig").ebpf;

const tcp_protocol: u8 = 6;

pub const Snapshot = struct {
    enabled: bool,
    running: bool,
    configured_services: u32,
    desired_mappings: u32,
    applied_mappings: u32,
    last_sync_at: ?i64,
    last_error: ?[]const u8,

    pub fn deinit(self: Snapshot, alloc: std.mem.Allocator) void {
        if (self.last_error) |message| alloc.free(message);
    }
};

pub const DesiredMapping = struct {
    vip: [4]u8,
    port: u16,
    listener_ip: [4]u8,
    listener_port: u16,
};

const AppliedMapping = struct {
    vip: [4]u8,
    port: u16,
};

var mutex: std.Thread.Mutex = .{};
var applied_mappings: std.ArrayList(AppliedMapping) = .empty;
var running: bool = false;
var configured_services: u32 = 0;
var desired_mappings: u32 = 0;
var last_sync_at: ?i64 = null;
var last_error: ?[]u8 = null;
var test_bridge_ip: ?[4]u8 = null;

pub fn resetForTest() void {
    mutex.lock();
    defer mutex.unlock();

    clearAppliedMappingsLocked();
    running = false;
    configured_services = 0;
    desired_mappings = 0;
    last_sync_at = null;
    clearLastErrorLocked();
    test_bridge_ip = null;
}

pub fn setBridgeIpForTest(address: [4]u8) void {
    mutex.lock();
    defer mutex.unlock();
    test_bridge_ip = address;
}

pub fn snapshot(alloc: std.mem.Allocator) !Snapshot {
    mutex.lock();
    defer mutex.unlock();

    return .{
        .enabled = service_rollout.current().l7_proxy_http and service_rollout.current().dns_returns_vip,
        .running = running,
        .configured_services = configured_services,
        .desired_mappings = desired_mappings,
        .applied_mappings = @intCast(applied_mappings.items.len),
        .last_sync_at = last_sync_at,
        .last_error = if (last_error) |message| try alloc.dupe(u8, message) else null,
    };
}

pub fn previewDesiredMappings(alloc: std.mem.Allocator) !std.ArrayList(DesiredMapping) {
    mutex.lock();
    defer mutex.unlock();

    return buildDesiredMappingsLocked(alloc);
}

pub fn syncIfEnabled() void {
    mutex.lock();
    defer mutex.unlock();

    syncLocked() catch |err| {
        setLastErrorLocked(err);
        running = false;
        log.warn("l7 proxy steering: sync failed: {}", .{err});
    };
}

fn syncLocked() !void {
    clearLastErrorLocked();

    if (!isEnabled()) {
        if (ebpf.getPortMapper()) |mapper| removeAppliedMappingsLocked(mapper);
        clearAppliedMappingsLocked();
        configured_services = 0;
        desired_mappings = 0;
        running = false;
        last_sync_at = null;
        return;
    }

    if (listener_runtime.portIfRunning() == null) {
        if (ebpf.getPortMapper()) |mapper| removeAppliedMappingsLocked(mapper);
        clearAppliedMappingsLocked();
        desired_mappings = 0;
        running = false;
        return;
    }

    const mapper = ebpf.getPortMapper() orelse return error.PortMapperUnavailable;

    var desired = try buildDesiredMappingsLocked(std.heap.page_allocator);
    defer desired.deinit(std.heap.page_allocator);

    for (applied_mappings.items) |mapping| {
        if (containsDesiredMapping(desired.items, mapping.vip, mapping.port)) continue;
        mapper.removeMappingForDestination(mapping.vip, mapping.port, tcp_protocol);
    }

    for (desired.items) |mapping| {
        if (containsAppliedMapping(mapping.vip, mapping.port)) continue;
        mapper.addMappingForDestination(mapping.vip, mapping.port, tcp_protocol, mapping.listener_ip, mapping.listener_port);
    }

    clearAppliedMappingsLocked();
    try applied_mappings.ensureTotalCapacity(std.heap.page_allocator, desired.items.len);
    for (desired.items) |mapping| {
        applied_mappings.appendAssumeCapacity(.{
            .vip = mapping.vip,
            .port = mapping.port,
        });
    }

    desired_mappings = @intCast(desired.items.len);
    running = true;
    last_sync_at = std.time.timestamp();
}

fn buildDesiredMappingsLocked(alloc: std.mem.Allocator) !std.ArrayList(DesiredMapping) {
    var mappings: std.ArrayList(DesiredMapping) = .empty;
    errdefer mappings.deinit(alloc);

    configured_services = 0;
    desired_mappings = 0;

    if (!isEnabled()) return mappings;

    const listener_port = listener_runtime.portIfRunning() orelse return error.ListenerNotRunning;
    const listener_ip = try currentBridgeIpLocked();
    var services = try service_registry_runtime.snapshotServices(alloc);
    defer {
        for (services.items) |service| service.deinit(alloc);
        services.deinit(alloc);
    }

    for (services.items) |service| {
        if (service.http_proxy_host == null) continue;
        configured_services += 1;

        const vip = ip.parseIp(service.vip_address) orelse continue;
        var endpoints = try service_registry_runtime.snapshotServiceEndpoints(alloc, service.service_name);
        defer {
            for (endpoints.items) |endpoint| endpoint.deinit(alloc);
            endpoints.deinit(alloc);
        }

        for (endpoints.items) |endpoint| {
            if (endpoint.port <= 0 or endpoint.port > std.math.maxInt(u16)) continue;
            const endpoint_port: u16 = @intCast(endpoint.port);
            if (containsDesiredMapping(mappings.items, vip, endpoint_port)) continue;
            try mappings.append(alloc, .{
                .vip = vip,
                .port = endpoint_port,
                .listener_ip = listener_ip,
                .listener_port = listener_port,
            });
        }
    }

    desired_mappings = @intCast(mappings.items.len);
    return mappings;
}

fn currentBridgeIpLocked() ![4]u8 {
    if (test_bridge_ip) |address| return address;
    return bridge.currentGatewayIp(bridge.default_bridge);
}

fn isEnabled() bool {
    const flags = service_rollout.current();
    return flags.l7_proxy_http and flags.dns_returns_vip;
}

fn containsDesiredMapping(mappings: []const DesiredMapping, vip: [4]u8, port: u16) bool {
    for (mappings) |mapping| {
        if (std.mem.eql(u8, mapping.vip[0..], vip[0..]) and mapping.port == port) return true;
    }
    return false;
}

fn containsAppliedMapping(vip: [4]u8, port: u16) bool {
    for (applied_mappings.items) |mapping| {
        if (std.mem.eql(u8, mapping.vip[0..], vip[0..]) and mapping.port == port) return true;
    }
    return false;
}

fn removeAppliedMappingsLocked(mapper: anytype) void {
    for (applied_mappings.items) |mapping| {
        mapper.removeMappingForDestination(mapping.vip, mapping.port, tcp_protocol);
    }
}

fn clearAppliedMappingsLocked() void {
    applied_mappings.clearAndFree(std.heap.page_allocator);
}

fn clearLastErrorLocked() void {
    if (last_error) |message| std.heap.page_allocator.free(message);
    last_error = null;
}

fn setLastErrorLocked(err: anyerror) void {
    clearLastErrorLocked();
    last_error = std.fmt.allocPrint(std.heap.page_allocator, "{}", .{err}) catch null;
}

test "previewDesiredMappings materializes unique vip port mappings" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .dns_returns_vip = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
    resetForTest();
    defer resetForTest();

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
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-2",
        .container_id = "ctr-2",
        .node_id = null,
        .ip_address = "10.42.0.10",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1001,
        .last_seen_at = 1001,
    });
    try store.createService(.{
        .service_name = "worker",
        .vip_address = "10.43.0.3",
        .lb_policy = "consistent_hash",
        .created_at = 1002,
        .updated_at = 1002,
    });

    service_registry_runtime.syncServiceFromStore("api");
    service_registry_runtime.syncServiceFromStore("worker");
    listener_runtime.startForTest(std.testing.allocator, 0);
    setBridgeIpForTest(.{ 10, 42, 0, 1 });

    var mappings = try previewDesiredMappings(std.testing.allocator);
    defer mappings.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), mappings.items.len);
    try std.testing.expectEqual([4]u8{ 10, 43, 0, 2 }, mappings.items[0].vip);
    try std.testing.expectEqual(@as(u16, 8080), mappings.items[0].port);
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 1 }, mappings.items[0].listener_ip);
    try std.testing.expect(mappings.items[0].listener_port != 0);

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);
    try std.testing.expect(state.enabled);
    try std.testing.expect(!state.running);
    try std.testing.expectEqual(@as(u32, 1), state.configured_services);
    try std.testing.expectEqual(@as(u32, 1), state.desired_mappings);
}
