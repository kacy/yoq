const std = @import("std");
const dns = @import("dns.zig");
const dns_registry = @import("dns/registry_support.zig");
const rollout = @import("service_rollout.zig");
const service_reconciler = @import("service_reconciler.zig");

// Phase 0 bridge: preserve the current legacy DNS writes while routing all
// service discovery side effects through one module. Later phases can swap the
// legacy apply step for reconciler intents without touching every caller again.

pub fn registerContainerService(service_name: []const u8, container_id: []const u8, container_ip: [4]u8) void {
    dns.registerService(service_name, container_id, container_ip);
    service_reconciler.noteContainerRegistered(service_name, container_id, container_ip);
}

pub fn unregisterContainerService(container_id: []const u8) void {
    dns.unregisterService(container_id);
    service_reconciler.noteContainerUnregistered(container_id);
}

pub fn markEndpointHealthy(service_name: []const u8, container_id: []const u8, container_ip: [4]u8) void {
    dns.registerService(service_name, container_id, container_ip);
    service_reconciler.noteEndpointHealthy(service_name, container_id, container_ip);
}

pub fn markEndpointUnhealthy(service_name: []const u8, container_id: []const u8, container_ip: [4]u8) void {
    dns.unregisterService(container_id);
    service_reconciler.noteEndpointUnhealthy(service_name, container_id, container_ip);
}

test "container bridge preserves legacy DNS and shadow events" {
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    service_reconciler.resetForTest();

    registerContainerService("api", "abc123", .{ 10, 42, 0, 9 });

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 42, 0, 9 }), dns.lookupService("api"));
    try std.testing.expectEqual(@as(u64, 1), service_reconciler.eventCount(.container_registered));

    unregisterContainerService("abc123");

    try std.testing.expectEqual(@as(?[4]u8, null), dns.lookupService("api"));
    try std.testing.expectEqual(@as(u64, 1), service_reconciler.eventCount(.container_unregistered));
}

test "endpoint bridge keeps legacy DNS in legacy rollout mode" {
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
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
