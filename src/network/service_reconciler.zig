const std = @import("std");
const dns = @import("dns.zig");
const ip_mod = @import("ip.zig");
const log = @import("../lib/log.zig");
const policy = @import("policy.zig");
const rollout = @import("service_rollout.zig");
const service_registry_runtime = @import("service_registry_runtime.zig");
const store = @import("../state/store.zig");

pub const EventKind = enum {
    container_registered,
    container_unregistered,
    endpoint_healthy,
    endpoint_unhealthy,

    pub fn label(self: EventKind) []const u8 {
        return switch (self) {
            .container_registered => "container_registered",
            .container_unregistered => "container_unregistered",
            .endpoint_healthy => "endpoint_healthy",
            .endpoint_unhealthy => "endpoint_unhealthy",
        };
    }
};

pub const EventSource = enum {
    container_runtime,
    health_checker,
    unspecified,

    pub fn label(self: EventSource) []const u8 {
        return switch (self) {
            .container_runtime => "container_runtime",
            .health_checker => "health_checker",
            .unspecified => "unspecified",
        };
    }
};

pub const Event = struct {
    kind: EventKind,
    source: EventSource,
    service_name_buf: [64]u8 = [_]u8{0} ** 64,
    service_name_len: u8 = 0,
    container_id_buf: [64]u8 = [_]u8{0} ** 64,
    container_id_len: u8 = 0,
    ip: ?[4]u8 = null,
    recorded_at: i64,

    pub fn serviceName(self: *const Event) []const u8 {
        return self.service_name_buf[0..self.service_name_len];
    }

    pub fn containerId(self: *const Event) []const u8 {
        return self.container_id_buf[0..self.container_id_len];
    }
};

pub const max_recent_events = 32;

const AppliedEndpoint = struct {
    container_id: []const u8,
    ip: [4]u8,

    fn deinit(self: AppliedEndpoint, alloc: std.mem.Allocator) void {
        alloc.free(self.container_id);
    }
};

const AppliedService = struct {
    service_name: []const u8,
    endpoints: std.ArrayList(AppliedEndpoint) = .empty,

    fn deinit(self: *AppliedService, alloc: std.mem.Allocator) void {
        alloc.free(self.service_name);
        for (self.endpoints.items) |endpoint| endpoint.deinit(alloc);
        self.endpoints.deinit(alloc);
    }
};

var mutex: std.Thread.Mutex = .{};
var recent_events: [max_recent_events]Event = undefined;
var recent_start: usize = 0;
var recent_len: usize = 0;
var event_counts: [@typeInfo(EventKind).@"enum".fields.len]u64 = [_]u64{0} ** @typeInfo(EventKind).@"enum".fields.len;
var event_counts_by_source: [@typeInfo(EventSource).@"enum".fields.len][@typeInfo(EventKind).@"enum".fields.len]u64 = [_][@typeInfo(EventKind).@"enum".fields.len]u64{
    [_]u64{0} ** @typeInfo(EventKind).@"enum".fields.len,
} ** @typeInfo(EventSource).@"enum".fields.len;
var logged_authoritative_flag_notice: bool = false;
var authoritative_bootstrapped: bool = false;
var applied_services: std.ArrayList(AppliedService) = .empty;

pub fn noteContainerRegistered(service_name: []const u8, container_id: []const u8, endpoint_ip: [4]u8) void {
    noteContainerRegisteredFrom(.unspecified, service_name, container_id, endpoint_ip);
}

pub fn noteContainerRegisteredFrom(source: EventSource, service_name: []const u8, container_id: []const u8, endpoint_ip: [4]u8) void {
    noteEvent(buildEvent(.container_registered, source, service_name, container_id, endpoint_ip));
}

pub fn noteContainerUnregistered(container_id: []const u8) void {
    noteContainerUnregisteredFrom(.unspecified, container_id);
}

pub fn noteContainerUnregisteredFrom(source: EventSource, container_id: []const u8) void {
    noteEvent(buildEvent(.container_unregistered, source, "", container_id, null));
}

pub fn noteEndpointHealthy(service_name: []const u8, container_id: []const u8, endpoint_ip: [4]u8) void {
    noteEndpointHealthyFrom(.unspecified, service_name, container_id, endpoint_ip);
}

pub fn noteEndpointHealthyFrom(source: EventSource, service_name: []const u8, container_id: []const u8, endpoint_ip: [4]u8) void {
    noteEvent(buildEvent(.endpoint_healthy, source, service_name, container_id, endpoint_ip));
}

pub fn noteEndpointUnhealthy(service_name: []const u8, container_id: []const u8, endpoint_ip: [4]u8) void {
    noteEndpointUnhealthyFrom(.unspecified, service_name, container_id, endpoint_ip);
}

pub fn noteEndpointUnhealthyFrom(source: EventSource, service_name: []const u8, container_id: []const u8, endpoint_ip: [4]u8) void {
    noteEvent(buildEvent(.endpoint_unhealthy, source, service_name, container_id, endpoint_ip));
}

pub fn eventCount(kind: EventKind) u64 {
    mutex.lock();
    defer mutex.unlock();
    return event_counts[@intFromEnum(kind)];
}

pub fn eventCountBySource(source: EventSource, kind: EventKind) u64 {
    mutex.lock();
    defer mutex.unlock();
    return event_counts_by_source[@intFromEnum(source)][@intFromEnum(kind)];
}

pub fn snapshotRecentEvents(out: []Event) usize {
    mutex.lock();
    defer mutex.unlock();

    const count = @min(out.len, recent_len);
    const start = recent_len - count;
    for (0..count) |i| {
        const idx = (recent_start + start + i) % max_recent_events;
        out[i] = recent_events[idx];
    }
    return count;
}

pub fn resetForTest() void {
    mutex.lock();
    defer mutex.unlock();
    recent_start = 0;
    recent_len = 0;
    event_counts = [_]u64{0} ** event_counts.len;
    event_counts_by_source = [_][@typeInfo(EventKind).@"enum".fields.len]u64{
        [_]u64{0} ** @typeInfo(EventKind).@"enum".fields.len,
    } ** @typeInfo(EventSource).@"enum".fields.len;
    logged_authoritative_flag_notice = false;
    authoritative_bootstrapped = false;
    deinitAppliedServicesLocked();
}

pub fn bootstrapIfEnabled() void {
    if (!rollout.current().service_registry_reconciler) return;

    mutex.lock();
    defer mutex.unlock();

    bootstrapAuthoritativeLocked();
}

fn noteEvent(event: Event) void {
    if (rollout.mode() == .legacy) return;

    const current_flags = rollout.current();

    mutex.lock();
    defer mutex.unlock();

    if (current_flags.service_registry_reconciler and !logged_authoritative_flag_notice) {
        logged_authoritative_flag_notice = true;
        log.info("service reconciler flag enabled; authoritative reconciler owns legacy DNS and compatibility mirror writes", .{});
    }

    const write_idx = (recent_start + recent_len) % max_recent_events;
    recent_events[write_idx] = event;
    if (recent_len < max_recent_events) {
        recent_len += 1;
    } else {
        recent_start = (recent_start + 1) % max_recent_events;
    }

    event_counts[@intFromEnum(event.kind)] += 1;
    event_counts_by_source[@intFromEnum(event.source)][@intFromEnum(event.kind)] += 1;

    log.debug(
        "service reconciler: shadow event source={s} kind={s} service={s} container={s}",
        .{ event.source.label(), event.kind.label(), event.serviceName(), event.containerId() },
    );

    if (!current_flags.service_registry_reconciler) return;

    if (!authoritative_bootstrapped) {
        bootstrapAuthoritativeLocked();
        return;
    }

    if (event.serviceName().len > 0) {
        reconcileServiceLocked(event.serviceName()) catch |err| {
            log.warn("service reconciler: failed to reconcile service {s}: {}", .{ event.serviceName(), err });
        };
        return;
    }

    reconcileAllLocked() catch |err| {
        log.warn("service reconciler: failed to reconcile all services: {}", .{err});
    };
}

fn buildEvent(kind: EventKind, source: EventSource, service_name: []const u8, container_id: []const u8, endpoint_ip: ?[4]u8) Event {
    var event = Event{
        .kind = kind,
        .source = source,
        .recorded_at = std.time.timestamp(),
        .ip = endpoint_ip,
    };

    const service_len = @min(service_name.len, event.service_name_buf.len);
    event.service_name_len = @intCast(service_len);
    @memcpy(event.service_name_buf[0..service_len], service_name[0..service_len]);

    const container_len = @min(container_id.len, event.container_id_buf.len);
    event.container_id_len = @intCast(container_len);
    @memcpy(event.container_id_buf[0..container_len], container_id[0..container_len]);

    return event;
}

fn bootstrapAuthoritativeLocked() void {
    reconcileAllLocked() catch |err| {
        log.warn("service reconciler: authoritative bootstrap failed: {}", .{err});
        return;
    };
    authoritative_bootstrapped = true;
}

fn reconcileAllLocked() !void {
    const alloc = std.heap.page_allocator;

    var services = try service_registry_runtime.snapshotServices(alloc);
    defer {
        for (services.items) |service| service.deinit(alloc);
        services.deinit(alloc);
    }

    var service_names: std.ArrayList([]const u8) = .empty;
    defer {
        for (service_names.items) |name| alloc.free(name);
        service_names.deinit(alloc);
    }

    for (services.items) |service| {
        try service_names.append(alloc, try alloc.dupe(u8, service.service_name));
        try reconcileServiceLocked(service.service_name);
    }

    var idx: usize = 0;
    while (idx < applied_services.items.len) {
        const name = applied_services.items[idx].service_name;
        if (containsServiceName(service_names.items, name)) {
            idx += 1;
            continue;
        }

        try applyDesiredStateLocked(name, &.{});
    }
}

fn reconcileServiceLocked(service_name: []const u8) !void {
    const alloc = std.heap.page_allocator;

    var endpoint_snapshots = service_registry_runtime.snapshotServiceEndpoints(alloc, service_name) catch |err| switch (err) {
        error.ServiceNotFound => return try applyDesiredStateLocked(service_name, &[_]AppliedEndpoint{}),
        else => return err,
    };
    defer {
        for (endpoint_snapshots.items) |endpoint| endpoint.deinit(alloc);
        endpoint_snapshots.deinit(alloc);
    }

    var desired: std.ArrayList(AppliedEndpoint) = .empty;
    defer {
        for (desired.items) |endpoint| endpoint.deinit(alloc);
        desired.deinit(alloc);
    }

    for (endpoint_snapshots.items) |endpoint| {
        if (!endpoint.eligible) continue;
        const endpoint_ip = ip_mod.parseIp(endpoint.ip_address) orelse continue;
        try desired.append(alloc, .{
            .container_id = try alloc.dupe(u8, endpoint.container_id),
            .ip = endpoint_ip,
        });
    }

    try applyDesiredStateLocked(service_name, desired.items);
}

fn applyDesiredStateLocked(service_name: []const u8, desired: []const AppliedEndpoint) !void {
    const alloc = std.heap.page_allocator;
    const current = currentAppliedEndpoints(service_name);

    for (current) |applied| {
        if (!containsAppliedEndpoint(desired, applied.container_id, applied.ip)) {
            dns.unregisterServiceEndpoint(service_name, applied.container_id);
        }
    }

    for (desired) |endpoint| {
        if (!containsAppliedEndpoint(current, endpoint.container_id, endpoint.ip)) {
            dns.registerService(service_name, endpoint.container_id, endpoint.ip);
        }
    }

    store.removeServiceNamesByName(service_name) catch return error.StoreWriteFailed;
    for (desired) |endpoint| {
        var ip_buf: [16]u8 = undefined;
        store.registerServiceName(service_name, endpoint.container_id, ip_mod.formatIp(endpoint.ip, &ip_buf)) catch return error.StoreWriteFailed;
    }
    policy.syncPolicies(alloc);

    try replaceAppliedServiceLocked(service_name, desired);
}

fn currentAppliedEndpoints(service_name: []const u8) []const AppliedEndpoint {
    const idx = findAppliedServiceIndex(service_name) orelse return &[_]AppliedEndpoint{};
    return applied_services.items[idx].endpoints.items;
}

fn replaceAppliedServiceLocked(service_name: []const u8, desired: []const AppliedEndpoint) !void {
    const alloc = std.heap.page_allocator;
    if (desired.len == 0) {
        if (findAppliedServiceIndex(service_name)) |idx| {
            var service = applied_services.orderedRemove(idx);
            service.deinit(alloc);
        }
        return;
    }

    var next = try cloneAppliedEndpoints(alloc, desired);
    errdefer {
        for (next.items) |endpoint| endpoint.deinit(alloc);
        next.deinit(alloc);
    }

    if (findAppliedServiceIndex(service_name)) |idx| {
        var service = &applied_services.items[idx];
        for (service.endpoints.items) |endpoint| endpoint.deinit(alloc);
        service.endpoints.deinit(alloc);
        service.endpoints = next;
        return;
    }

    try applied_services.append(alloc, .{
        .service_name = try alloc.dupe(u8, service_name),
        .endpoints = next,
    });
}

fn cloneAppliedEndpoints(alloc: std.mem.Allocator, endpoints: []const AppliedEndpoint) !std.ArrayList(AppliedEndpoint) {
    var cloned: std.ArrayList(AppliedEndpoint) = .empty;
    errdefer {
        for (cloned.items) |endpoint| endpoint.deinit(alloc);
        cloned.deinit(alloc);
    }

    for (endpoints) |endpoint| {
        try cloned.append(alloc, .{
            .container_id = try alloc.dupe(u8, endpoint.container_id),
            .ip = endpoint.ip,
        });
    }
    return cloned;
}

fn findAppliedServiceIndex(service_name: []const u8) ?usize {
    for (applied_services.items, 0..) |service, idx| {
        if (std.mem.eql(u8, service.service_name, service_name)) return idx;
    }
    return null;
}

fn containsAppliedEndpoint(endpoints: []const AppliedEndpoint, container_id: []const u8, endpoint_ip: [4]u8) bool {
    for (endpoints) |endpoint| {
        if (std.mem.eql(u8, endpoint.container_id, container_id) and std.mem.eql(u8, endpoint.ip[0..], endpoint_ip[0..])) {
            return true;
        }
    }
    return false;
}

fn containsServiceName(service_names: []const []const u8, name: []const u8) bool {
    for (service_names) |candidate| {
        if (std.mem.eql(u8, candidate, name)) return true;
    }
    return false;
}

fn deinitAppliedServicesLocked() void {
    const alloc = std.heap.page_allocator;
    for (applied_services.items) |*service| service.deinit(alloc);
    applied_services.deinit(alloc);
    applied_services = .empty;
}

test "legacy mode does not record events" {
    rollout.setForTest(.{});
    defer rollout.resetForTest();
    resetForTest();

    noteContainerRegistered("api", "abc123", .{ 10, 42, 0, 9 });

    try std.testing.expectEqual(@as(u64, 0), eventCount(.container_registered));
}

test "shadow mode records container and health events" {
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    resetForTest();

    noteContainerRegisteredFrom(.container_runtime, "api", "abc123", .{ 10, 42, 0, 9 });
    noteEndpointHealthyFrom(.health_checker, "api", "abc123", .{ 10, 42, 0, 9 });

    try std.testing.expectEqual(@as(u64, 1), eventCount(.container_registered));
    try std.testing.expectEqual(@as(u64, 1), eventCount(.endpoint_healthy));
    try std.testing.expectEqual(@as(u64, 1), eventCountBySource(.container_runtime, .container_registered));
    try std.testing.expectEqual(@as(u64, 1), eventCountBySource(.health_checker, .endpoint_healthy));

    var events: [4]Event = undefined;
    const count = snapshotRecentEvents(&events);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("api", events[0].serviceName());
    try std.testing.expectEqualStrings("abc123", events[0].containerId());
    try std.testing.expectEqual(EventKind.container_registered, events[0].kind);
    try std.testing.expectEqual(EventSource.container_runtime, events[0].source);
    try std.testing.expectEqual(EventKind.endpoint_healthy, events[1].kind);
    try std.testing.expectEqual(EventSource.health_checker, events[1].source);
}

test "recent event buffer keeps only the newest events" {
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    resetForTest();

    var idx: usize = 0;
    while (idx < max_recent_events + 4) : (idx += 1) {
        var name_buf: [16]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "svc{d}", .{idx}) catch unreachable;
        noteContainerRegistered(name, "abc123", .{ 10, 42, 0, 9 });
    }

    try std.testing.expectEqual(@as(u64, max_recent_events + 4), eventCount(.container_registered));

    var events: [max_recent_events]Event = undefined;
    const count = snapshotRecentEvents(&events);
    try std.testing.expectEqual(@as(usize, max_recent_events), count);
    try std.testing.expectEqualStrings("svc4", events[0].serviceName());
}

test "authoritative bootstrap populates DNS and compatibility mirror" {
    const dns_registry = @import("dns/registry_support.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true, .service_registry_reconciler = true });
    defer rollout.resetForTest();
    defer resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "ctr-1:0",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "10.42.0.9",
        .port = 0,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();

    bootstrapIfEnabled();

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 42, 0, 9 }), dns.lookupService("api"));
    var mirrored = try store.lookupServiceNames(std.testing.allocator, "api");
    defer {
        for (mirrored.items) |ip_text| std.testing.allocator.free(ip_text);
        mirrored.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), mirrored.items.len);
    try std.testing.expectEqualStrings("10.42.0.9", mirrored.items[0]);
}
