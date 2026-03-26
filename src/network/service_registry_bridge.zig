const std = @import("std");
const dns = @import("dns.zig");
const dns_registry = @import("dns/registry_support.zig");
const log = @import("../lib/log.zig");
const rollout = @import("service_rollout.zig");
const service_reconciler = @import("service_reconciler.zig");

// Phase 0 bridge: preserve the current legacy DNS writes while routing all
// service discovery side effects through one module. Later phases can swap the
// legacy apply step for reconciler intents without touching every caller again.

pub const BridgeOperation = enum {
    container_register,
    container_unregister,
    endpoint_healthy,
    endpoint_unhealthy,

    pub fn label(self: BridgeOperation) []const u8 {
        return switch (self) {
            .container_register => "container_register",
            .container_unregister => "container_unregister",
            .endpoint_healthy => "endpoint_healthy",
            .endpoint_unhealthy => "endpoint_unhealthy",
        };
    }
};

pub const FaultMode = enum {
    none,
    skip_legacy_apply,
    skip_shadow_record,

    pub fn label(self: FaultMode) []const u8 {
        return switch (self) {
            .none => "none",
            .skip_legacy_apply => "skip_legacy_apply",
            .skip_shadow_record => "skip_shadow_record",
        };
    }
};

var fault_mutex: std.Thread.Mutex = .{};
var fault_modes: [@typeInfo(BridgeOperation).@"enum".fields.len]FaultMode = [_]FaultMode{.none} ** @typeInfo(BridgeOperation).@"enum".fields.len;
var fault_counts: [@typeInfo(BridgeOperation).@"enum".fields.len]u64 = [_]u64{0} ** @typeInfo(BridgeOperation).@"enum".fields.len;

pub fn registerContainerService(service_name: []const u8, container_id: []const u8, container_ip: [4]u8) void {
    const operation: BridgeOperation = .container_register;
    const mode = activeFaultMode(operation);
    switch (mode) {
        .none, .skip_shadow_record => dns.registerService(service_name, container_id, container_ip),
        .skip_legacy_apply => noteFaultInjection(operation),
    }
    switch (mode) {
        .none, .skip_legacy_apply => service_reconciler.noteContainerRegisteredFrom(.container_runtime, service_name, container_id, container_ip),
        .skip_shadow_record => noteFaultInjection(operation),
    }
}

pub fn unregisterContainerService(container_id: []const u8) void {
    const operation: BridgeOperation = .container_unregister;
    const mode = activeFaultMode(operation);
    switch (mode) {
        .none, .skip_shadow_record => dns.unregisterService(container_id),
        .skip_legacy_apply => noteFaultInjection(operation),
    }
    switch (mode) {
        .none, .skip_legacy_apply => service_reconciler.noteContainerUnregisteredFrom(.container_runtime, container_id),
        .skip_shadow_record => noteFaultInjection(operation),
    }
}

pub fn markEndpointHealthy(service_name: []const u8, container_id: []const u8, container_ip: [4]u8) void {
    const operation: BridgeOperation = .endpoint_healthy;
    const mode = activeFaultMode(operation);
    switch (mode) {
        .none, .skip_shadow_record => dns.registerService(service_name, container_id, container_ip),
        .skip_legacy_apply => noteFaultInjection(operation),
    }
    switch (mode) {
        .none, .skip_legacy_apply => service_reconciler.noteEndpointHealthyFrom(.health_checker, service_name, container_id, container_ip),
        .skip_shadow_record => noteFaultInjection(operation),
    }
}

pub fn markEndpointUnhealthy(service_name: []const u8, container_id: []const u8, container_ip: [4]u8) void {
    const operation: BridgeOperation = .endpoint_unhealthy;
    const mode = activeFaultMode(operation);
    switch (mode) {
        .none, .skip_shadow_record => dns.unregisterService(container_id),
        .skip_legacy_apply => noteFaultInjection(operation),
    }
    switch (mode) {
        .none, .skip_legacy_apply => service_reconciler.noteEndpointUnhealthyFrom(.health_checker, service_name, container_id, container_ip),
        .skip_shadow_record => noteFaultInjection(operation),
    }
}

pub fn faultInjectionCount(operation: BridgeOperation) u64 {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    return fault_counts[@intFromEnum(operation)];
}

pub fn faultMode(operation: BridgeOperation) FaultMode {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    return fault_modes[@intFromEnum(operation)];
}

pub fn setFaultModeForTest(operation: BridgeOperation, mode: FaultMode) void {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    fault_modes[@intFromEnum(operation)] = mode;
}

pub fn resetFaultsForTest() void {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    fault_modes = [_]FaultMode{.none} ** fault_modes.len;
    fault_counts = [_]u64{0} ** fault_counts.len;
}

fn activeFaultMode(operation: BridgeOperation) FaultMode {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    return fault_modes[@intFromEnum(operation)];
}

fn noteFaultInjection(operation: BridgeOperation) void {
    fault_mutex.lock();
    defer fault_mutex.unlock();
    fault_counts[@intFromEnum(operation)] += 1;
    log.warn("service registry bridge: injected fault mode={s} operation={s}", .{
        fault_modes[@intFromEnum(operation)].label(),
        operation.label(),
    });
}

test "container bridge preserves legacy DNS and shadow events" {
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetFaultsForTest();
    defer resetFaultsForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    service_reconciler.resetForTest();

    registerContainerService("api", "abc123", .{ 10, 42, 0, 9 });

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 42, 0, 9 }), dns.lookupService("api"));
    try std.testing.expectEqual(@as(u64, 1), service_reconciler.eventCount(.container_registered));
    try std.testing.expectEqual(@as(u64, 1), service_reconciler.eventCountBySource(.container_runtime, .container_registered));

    unregisterContainerService("abc123");

    try std.testing.expectEqual(@as(?[4]u8, null), dns.lookupService("api"));
    try std.testing.expectEqual(@as(u64, 1), service_reconciler.eventCount(.container_unregistered));
    try std.testing.expectEqual(@as(u64, 1), service_reconciler.eventCountBySource(.container_runtime, .container_unregistered));
}

test "endpoint bridge keeps legacy DNS in legacy rollout mode" {
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetFaultsForTest();
    defer resetFaultsForTest();
    rollout.setForTest(.{});
    defer rollout.resetForTest();
    service_reconciler.resetForTest();

    markEndpointHealthy("web", "def456", .{ 10, 42, 0, 10 });

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 42, 0, 10 }), dns.lookupService("web"));
    try std.testing.expectEqual(@as(u64, 0), service_reconciler.eventCount(.endpoint_healthy));

    markEndpointUnhealthy("web", "def456", .{ 10, 42, 0, 10 });

    try std.testing.expectEqual(@as(?[4]u8, null), dns.lookupService("web"));
    try std.testing.expectEqual(@as(u64, 0), service_reconciler.eventCount(.endpoint_unhealthy));
}

test "bridge can skip legacy apply while preserving shadow event" {
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetFaultsForTest();
    defer resetFaultsForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    service_reconciler.resetForTest();

    setFaultModeForTest(.container_register, .skip_legacy_apply);
    registerContainerService("api", "abc123", .{ 10, 42, 0, 9 });

    try std.testing.expectEqual(@as(?[4]u8, null), dns.lookupService("api"));
    try std.testing.expectEqual(@as(u64, 1), service_reconciler.eventCountBySource(.container_runtime, .container_registered));
    try std.testing.expectEqual(@as(u64, 1), faultInjectionCount(.container_register));
}

test "bridge can skip shadow record while preserving legacy apply" {
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetFaultsForTest();
    defer resetFaultsForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    service_reconciler.resetForTest();

    setFaultModeForTest(.endpoint_healthy, .skip_shadow_record);
    markEndpointHealthy("web", "def456", .{ 10, 42, 0, 10 });

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 42, 0, 10 }), dns.lookupService("web"));
    try std.testing.expectEqual(@as(u64, 0), service_reconciler.eventCountBySource(.health_checker, .endpoint_healthy));
    try std.testing.expectEqual(@as(u64, 1), faultInjectionCount(.endpoint_healthy));
}

test "fault mode accessor returns configured mode" {
    resetFaultsForTest();
    defer resetFaultsForTest();

    try std.testing.expectEqual(FaultMode.none, faultMode(.container_register));
    setFaultModeForTest(.container_register, .skip_legacy_apply);
    try std.testing.expectEqual(FaultMode.skip_legacy_apply, faultMode(.container_register));
}
