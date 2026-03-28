const std = @import("std");
const log = @import("../../lib/log.zig");
const bridge = @import("../bridge.zig");
const ip = @import("../ip.zig");
const service_registry_runtime = @import("../service_registry_runtime.zig");
const service_rollout = @import("../service_rollout.zig");
const listener_runtime = @import("listener_runtime.zig");
const ebpf = @import("../setup/ebpf_module.zig").ebpf;

const tcp_protocol: u8 = 6;

pub const BlockedReason = enum {
    none,
    rollout_disabled,
    listener_not_running,
    port_mapper_unavailable,
    bridge_address_unavailable,
    no_service_ports,

    pub fn label(self: BlockedReason) []const u8 {
        return switch (self) {
            .none => "none",
            .rollout_disabled => "rollout_disabled",
            .listener_not_running => "listener_not_running",
            .port_mapper_unavailable => "port_mapper_unavailable",
            .bridge_address_unavailable => "bridge_address_unavailable",
            .no_service_ports => "no_service_ports",
        };
    }
};

pub const Snapshot = struct {
    enabled: bool,
    running: bool,
    configured_services: u32,
    desired_mappings: u32,
    applied_mappings: u32,
    blocked_reason: BlockedReason,
    sync_attempts_total: u64,
    sync_failures_total: u64,
    mappings_applied_total: u64,
    mappings_removed_total: u64,
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

pub const ServiceStatus = struct {
    desired_ports: u32,
    applied_ports: u32,
    ready: bool,
    blocked_reason: BlockedReason,
};

pub const MappingApplyHook = *const fn (destination_ip: ?[4]u8, host_port: u16, protocol: u8, target_ip: [4]u8, target_port: u16) void;
pub const MappingRemoveHook = *const fn (destination_ip: ?[4]u8, host_port: u16, protocol: u8) void;

const AppliedMapping = struct {
    vip: [4]u8,
    port: u16,
};

var mutex: std.Thread.Mutex = .{};
var applied_mappings: std.ArrayList(AppliedMapping) = .empty;
var running: bool = false;
var configured_services: u32 = 0;
var desired_mappings: u32 = 0;
var blocked_reason: BlockedReason = .none;
var sync_attempts_total: u64 = 0;
var sync_failures_total: u64 = 0;
var mappings_applied_total: u64 = 0;
var mappings_removed_total: u64 = 0;
var last_sync_at: ?i64 = null;
var last_error: ?[]u8 = null;
var test_bridge_ip: ?[4]u8 = null;
var test_port_mapper_available: ?bool = null;
var test_mapping_apply_hook: ?MappingApplyHook = null;
var test_mapping_remove_hook: ?MappingRemoveHook = null;

pub fn resetForTest() void {
    mutex.lock();
    defer mutex.unlock();

    clearAppliedMappingsLocked();
    running = false;
    configured_services = 0;
    desired_mappings = 0;
    blocked_reason = .none;
    sync_attempts_total = 0;
    sync_failures_total = 0;
    mappings_applied_total = 0;
    mappings_removed_total = 0;
    last_sync_at = null;
    clearLastErrorLocked();
    test_bridge_ip = null;
    test_port_mapper_available = null;
    test_mapping_apply_hook = null;
    test_mapping_remove_hook = null;
}

pub fn setBridgeIpForTest(address: [4]u8) void {
    mutex.lock();
    defer mutex.unlock();
    test_bridge_ip = address;
}

pub fn setPortMapperAvailableForTest(available: ?bool) void {
    mutex.lock();
    defer mutex.unlock();
    test_port_mapper_available = available;
}

pub fn setMappingHooksForTest(apply_hook: ?MappingApplyHook, remove_hook: ?MappingRemoveHook) void {
    mutex.lock();
    defer mutex.unlock();
    test_mapping_apply_hook = apply_hook;
    test_mapping_remove_hook = remove_hook;
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
        .blocked_reason = blocked_reason,
        .sync_attempts_total = sync_attempts_total,
        .sync_failures_total = sync_failures_total,
        .mappings_applied_total = mappings_applied_total,
        .mappings_removed_total = mappings_removed_total,
        .last_sync_at = last_sync_at,
        .last_error = if (last_error) |message| try alloc.dupe(u8, message) else null,
    };
}

pub fn previewDesiredMappings(alloc: std.mem.Allocator) !std.ArrayList(DesiredMapping) {
    mutex.lock();
    defer mutex.unlock();

    return buildDesiredMappingsLocked(alloc);
}

pub fn snapshotServiceStatus(alloc: std.mem.Allocator, service_name: []const u8) !ServiceStatus {
    mutex.lock();
    defer mutex.unlock();

    return buildServiceStatusLocked(alloc, service_name);
}

pub fn syncIfEnabled() void {
    mutex.lock();
    defer mutex.unlock();

    sync_attempts_total += 1;
    syncLocked() catch |err| {
        sync_failures_total += 1;
        setLastErrorLocked(err);
        running = false;
        log.warn("l7 proxy steering: sync failed: {}", .{err});
    };
}

fn syncLocked() !void {
    clearLastErrorLocked();

    if (!isEnabled()) {
        blocked_reason = .rollout_disabled;
        if (hasPortMapperLocked()) mappings_removed_total += removeAppliedMappingsLocked();
        clearAppliedMappingsLocked();
        configured_services = 0;
        desired_mappings = 0;
        running = false;
        last_sync_at = null;
        return;
    }

    if (listener_runtime.portIfRunning() == null) {
        blocked_reason = .listener_not_running;
        if (hasPortMapperLocked()) mappings_removed_total += removeAppliedMappingsLocked();
        clearAppliedMappingsLocked();
        desired_mappings = 0;
        running = false;
        return;
    }

    if (!hasPortMapperLocked()) {
        blocked_reason = .port_mapper_unavailable;
        return error.PortMapperUnavailable;
    }

    var desired = try buildDesiredMappingsLocked(std.heap.page_allocator);
    defer desired.deinit(std.heap.page_allocator);

    blocked_reason = if (desired.items.len == 0) .no_service_ports else .none;

    for (applied_mappings.items) |mapping| {
        if (containsDesiredMapping(desired.items, mapping.vip, mapping.port)) continue;
        removeMappingLocked(mapping.vip, mapping.port, tcp_protocol);
        mappings_removed_total += 1;
    }

    for (desired.items) |mapping| {
        if (containsAppliedMapping(mapping.vip, mapping.port)) continue;
        addMappingLocked(mapping.vip, mapping.port, tcp_protocol, mapping.listener_ip, mapping.listener_port);
        mappings_applied_total += 1;
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
    const listener_ip = currentBridgeIpLocked() catch |err| {
        blocked_reason = .bridge_address_unavailable;
        return err;
    };
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

fn buildServiceStatusLocked(alloc: std.mem.Allocator, service_name: []const u8) !ServiceStatus {
    const service = try service_registry_runtime.snapshotService(alloc, service_name);
    defer service.deinit(alloc);

    if (!isEnabled()) {
        return .{
            .desired_ports = 0,
            .applied_ports = 0,
            .ready = false,
            .blocked_reason = .rollout_disabled,
        };
    }

    var endpoints = try service_registry_runtime.snapshotServiceEndpoints(alloc, service_name);
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(alloc);
        endpoints.deinit(alloc);
    }

    var ports: std.ArrayList(u16) = .empty;
    defer ports.deinit(alloc);

    for (endpoints.items) |endpoint| {
        if (endpoint.port <= 0 or endpoint.port > std.math.maxInt(u16)) continue;
        const port: u16 = @intCast(endpoint.port);
        if (containsPort(ports.items, port)) continue;
        try ports.append(alloc, port);
    }

    if (ports.items.len == 0) {
        return .{
            .desired_ports = 0,
            .applied_ports = 0,
            .ready = false,
            .blocked_reason = .no_service_ports,
        };
    }

    const vip = ip.parseIp(service.vip_address) orelse [4]u8{ 0, 0, 0, 0 };
    var applied_ports: u32 = 0;
    for (ports.items) |port| {
        if (containsAppliedMapping(vip, port)) applied_ports += 1;
    }

    var reason = blocked_reason;
    if (applied_ports == ports.items.len) {
        reason = .none;
    } else if (reason == .none) {
        if (listener_runtime.portIfRunning() == null) {
            reason = .listener_not_running;
        } else if (!hasPortMapperLocked()) {
            reason = .port_mapper_unavailable;
        } else if (currentBridgeIpLocked()) |_| {
            reason = .none;
        } else |_| {
            reason = .bridge_address_unavailable;
        }
    }

    return .{
        .desired_ports = @intCast(ports.items.len),
        .applied_ports = applied_ports,
        .ready = applied_ports == ports.items.len,
        .blocked_reason = reason,
    };
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

fn containsPort(ports: []const u16, port: u16) bool {
    for (ports) |existing| {
        if (existing == port) return true;
    }
    return false;
}

fn hasPortMapperLocked() bool {
    if (test_port_mapper_available) |available| return available;
    return ebpf.getPortMapper() != null;
}

fn addMappingLocked(destination_ip: [4]u8, host_port: u16, protocol: u8, target_ip: [4]u8, target_port: u16) void {
    if (test_mapping_apply_hook) |hook| hook(destination_ip, host_port, protocol, target_ip, target_port);
    if (test_port_mapper_available != null) return;
    if (ebpf.getPortMapper()) |mapper| {
        mapper.addMappingForDestination(destination_ip, host_port, protocol, target_ip, target_port);
    }
}

fn removeMappingLocked(destination_ip: [4]u8, host_port: u16, protocol: u8) void {
    if (test_mapping_remove_hook) |hook| hook(destination_ip, host_port, protocol);
    if (test_port_mapper_available != null) return;
    if (ebpf.getPortMapper()) |mapper| {
        mapper.removeMappingForDestination(destination_ip, host_port, protocol);
    }
}

fn removeAppliedMappingsLocked() u64 {
    var removed: u64 = 0;
    for (applied_mappings.items) |mapping| {
        removeMappingLocked(mapping.vip, mapping.port, tcp_protocol);
        removed += 1;
    }
    return removed;
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

const RecordedApply = struct {
    destination_ip: ?[4]u8,
    host_port: u16,
    protocol: u8,
    target_ip: [4]u8,
    target_port: u16,
};

const RecordedRemove = struct {
    destination_ip: ?[4]u8,
    host_port: u16,
    protocol: u8,
};

var recorded_applies: [8]RecordedApply = undefined;
var recorded_apply_count: usize = 0;
var recorded_removes: [8]RecordedRemove = undefined;
var recorded_remove_count: usize = 0;

fn resetRecordedMappings() void {
    recorded_apply_count = 0;
    recorded_remove_count = 0;
}

fn recordAppliedMapping(destination_ip: ?[4]u8, host_port: u16, protocol: u8, target_ip: [4]u8, target_port: u16) void {
    std.debug.assert(recorded_apply_count < recorded_applies.len);
    recorded_applies[recorded_apply_count] = .{
        .destination_ip = destination_ip,
        .host_port = host_port,
        .protocol = protocol,
        .target_ip = target_ip,
        .target_port = target_port,
    };
    recorded_apply_count += 1;
}

fn recordRemovedMapping(destination_ip: ?[4]u8, host_port: u16, protocol: u8) void {
    std.debug.assert(recorded_remove_count < recorded_removes.len);
    recorded_removes[recorded_remove_count] = .{
        .destination_ip = destination_ip,
        .host_port = host_port,
        .protocol = protocol,
    };
    recorded_remove_count += 1;
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
    try std.testing.expectEqual(@as(u64, 0), state.sync_attempts_total);
    try std.testing.expectEqual(@as(u64, 0), state.sync_failures_total);
    try std.testing.expectEqual(@as(u64, 0), state.mappings_applied_total);
    try std.testing.expectEqual(@as(u64, 0), state.mappings_removed_total);
}

test "syncIfEnabled programs desired VIP mappings" {
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
    resetRecordedMappings();
    setPortMapperAvailableForTest(true);
    setMappingHooksForTest(recordAppliedMapping, recordRemovedMapping);
    defer setMappingHooksForTest(null, null);

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
    setBridgeIpForTest(.{ 10, 42, 0, 1 });
    listener_runtime.startForTest(std.testing.allocator, 0);

    syncIfEnabled();

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);
    try std.testing.expect(state.running);
    try std.testing.expectEqual(@as(u32, 1), state.applied_mappings);
    try std.testing.expectEqual(@as(usize, 1), recorded_apply_count);
    try std.testing.expectEqual(@as(usize, 0), recorded_remove_count);
    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), recorded_applies[0].destination_ip);
    try std.testing.expectEqual(@as(u16, 8080), recorded_applies[0].host_port);
    try std.testing.expectEqual(@as(u8, tcp_protocol), recorded_applies[0].protocol);
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 1 }, recorded_applies[0].target_ip);
    try std.testing.expect(recorded_applies[0].target_port != 0);
}

test "listener state changes resync steering" {
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
    resetRecordedMappings();
    setPortMapperAvailableForTest(true);
    setMappingHooksForTest(recordAppliedMapping, recordRemovedMapping);
    defer setMappingHooksForTest(null, null);

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
    setBridgeIpForTest(.{ 10, 42, 0, 1 });
    listener_runtime.setStateChangeHook(syncIfEnabled);
    defer listener_runtime.setStateChangeHook(null);

    listener_runtime.startForTest(std.testing.allocator, 0);

    {
        const state = try snapshot(std.testing.allocator);
        defer state.deinit(std.testing.allocator);
        try std.testing.expect(state.running);
        try std.testing.expectEqual(@as(u32, 1), state.desired_mappings);
        try std.testing.expectEqual(@as(u32, 1), state.applied_mappings);
        try std.testing.expectEqual(BlockedReason.none, state.blocked_reason);
        try std.testing.expectEqual(@as(u64, 1), state.sync_attempts_total);
        try std.testing.expectEqual(@as(u64, 1), state.mappings_applied_total);
        try std.testing.expectEqual(@as(usize, 1), recorded_apply_count);
        try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), recorded_applies[0].destination_ip);
        try std.testing.expectEqual(@as(u16, 8080), recorded_applies[0].host_port);
    }

    listener_runtime.stop();

    {
        const state = try snapshot(std.testing.allocator);
        defer state.deinit(std.testing.allocator);
        try std.testing.expect(!state.running);
        try std.testing.expectEqual(@as(u32, 0), state.applied_mappings);
        try std.testing.expectEqual(BlockedReason.listener_not_running, state.blocked_reason);
        try std.testing.expectEqual(@as(u64, 2), state.sync_attempts_total);
        try std.testing.expectEqual(@as(u64, 1), state.mappings_removed_total);
        try std.testing.expectEqual(@as(usize, 1), recorded_remove_count);
        try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), recorded_removes[0].destination_ip);
        try std.testing.expectEqual(@as(u16, 8080), recorded_removes[0].host_port);
    }
}
