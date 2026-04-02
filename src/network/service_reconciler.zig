const std = @import("std");
const cluster_registry = @import("../cluster/registry.zig");
const dns = @import("dns.zig");
const dns_registry_support = @import("dns/registry_support.zig");
const ip_mod = @import("ip.zig");
const log = @import("../lib/log.zig");
const bridge = @import("bridge.zig");
const policy = @import("policy.zig");
const proxy_control_plane = @import("proxy/control_plane.zig");
const rollout = @import("service_rollout.zig");
const service_registry_runtime = @import("service_registry_runtime.zig");
const ebpf = @import("setup/ebpf_module.zig").ebpf;
const ebpf_support = @import("setup/ebpf_support.zig");
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
pub const audit_interval_secs: u64 = 30;
const max_retry_backoff_secs: i64 = 300;

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

const RetryState = struct {
    service_name: []const u8,
    failures: u32,
    next_retry_at: i64,

    fn deinit(self: RetryState, alloc: std.mem.Allocator) void {
        alloc.free(self.service_name);
    }
};

pub const AuditSnapshot = struct {
    enabled: bool,
    running: bool,
    passes_total: u64,
    mismatch_services_total: u64,
    vip_mismatches_total: u64,
    endpoint_count_mismatches_total: u64,
    stale_endpoint_mismatches_total: u64,
    eligibility_mismatches_total: u64,
    repairs_total: u64,
    stale_endpoint_quarantines_total: u64,
    degraded_services: std.ArrayList([]const u8),
    last_audit_at: ?i64,
    last_mismatch_at: ?i64,
    last_stale_quarantine_at: ?i64,
    last_error: ?[]const u8,

    pub fn deinit(self: *AuditSnapshot, alloc: std.mem.Allocator) void {
        for (self.degraded_services.items) |name| alloc.free(name);
        self.degraded_services.deinit(alloc);
        if (self.last_error) |message| alloc.free(message);
    }
};

const AuditMismatchKind = enum {
    vip,
    endpoint_count,
    stale_endpoint,
    eligibility,
};

const AuditMismatch = struct {
    kind: AuditMismatchKind,
    reason: []const u8,
};

pub const NodeSignalSnapshot = struct {
    lost_total: u64,
    recovered_total: u64,
    endpoints_changed_total: u64,
    last_lost_node_id: ?i64,
    last_recovered_node_id: ?i64,
};

pub const ComponentState = struct {
    dns_resolver_running: bool,
    dns_interceptor_loaded: bool,
    load_balancer_loaded: bool,
};

pub const ComponentSnapshot = struct {
    state: ComponentState,
    state_changes_total: u64,
    full_resyncs_total: u64,
    last_change_at: ?i64,
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
var degraded_services: std.ArrayList([]const u8) = .empty;
var retry_states: std.ArrayList(RetryState) = .empty;
var audit_passes_total: u64 = 0;
var audit_mismatch_services_total: u64 = 0;
var audit_vip_mismatches_total: u64 = 0;
var audit_endpoint_count_mismatches_total: u64 = 0;
var audit_stale_endpoint_mismatches_total: u64 = 0;
var audit_eligibility_mismatches_total: u64 = 0;
var audit_repairs_total: u64 = 0;
var stale_endpoint_quarantines_total: u64 = 0;
var last_audit_at: ?i64 = null;
var last_mismatch_at: ?i64 = null;
var last_stale_quarantine_at: ?i64 = null;
var last_audit_error: ?[]const u8 = null;
var audit_thread: ?std.Thread = null;
var audit_running = std.atomic.Value(bool).init(false);
var node_lost_signals_total: u64 = 0;
var node_recovered_signals_total: u64 = 0;
var node_signal_endpoints_changed_total: u64 = 0;
var last_lost_node_id: ?i64 = null;
var last_recovered_node_id: ?i64 = null;
var component_state: ComponentState = .{
    .dns_resolver_running = false,
    .dns_interceptor_loaded = false,
    .load_balancer_loaded = false,
};
var component_state_changes_total: u64 = 0;
var component_full_resyncs_total: u64 = 0;
var component_last_change_at: ?i64 = null;
var component_state_override: ?ComponentState = null;

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
    audit_running.store(false, .release);
    if (audit_thread) |thread| {
        thread.join();
        audit_thread = null;
    }

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
    deinitDegradedServicesLocked();
    deinitRetryStatesLocked();
    audit_passes_total = 0;
    audit_mismatch_services_total = 0;
    audit_vip_mismatches_total = 0;
    audit_endpoint_count_mismatches_total = 0;
    audit_stale_endpoint_mismatches_total = 0;
    audit_eligibility_mismatches_total = 0;
    audit_repairs_total = 0;
    stale_endpoint_quarantines_total = 0;
    last_audit_at = null;
    last_mismatch_at = null;
    last_stale_quarantine_at = null;
    node_lost_signals_total = 0;
    node_recovered_signals_total = 0;
    node_signal_endpoints_changed_total = 0;
    last_lost_node_id = null;
    last_recovered_node_id = null;
    component_state = .{
        .dns_resolver_running = false,
        .dns_interceptor_loaded = false,
        .load_balancer_loaded = false,
    };
    component_state_changes_total = 0;
    component_full_resyncs_total = 0;
    component_last_change_at = null;
    component_state_override = null;
    clearLastAuditErrorLocked();
}

pub fn ensureDataPlaneReadyIfEnabled() void {
    if (!auditEnabled(rollout.current())) return;

    bridge.ensureBridge(bridge.default_bridge) catch |err| {
        log.warn("service reconciler: failed to ensure bridge before data-plane bootstrap: {}", .{err});
    };
    dns.startResolver();
    ebpf_support.loadDnsInterceptorOnBridge();
    refreshComponentStateIfEnabled();
}

pub fn bootstrapIfEnabled() void {
    const flags = rollout.current();
    if (!auditEnabled(flags)) return;

    mutex.lock();
    defer mutex.unlock();

    quarantineStaleEndpointsLocked();
    bootstrapAuthoritativeLocked();
    refreshComponentStateLocked();
}

pub fn startAuditLoopIfEnabled() void {
    const flags = rollout.current();
    if (!auditEnabled(flags)) return;
    if (audit_running.load(.acquire)) return;

    audit_running.store(true, .release);
    audit_thread = std.Thread.spawn(.{}, auditLoop, .{}) catch |err| {
        audit_running.store(false, .release);
        log.warn("service reconciler: failed to spawn audit loop: {}", .{err});
        return;
    };
}

pub fn runAuditPassIfEnabled() void {
    const flags = rollout.current();
    if (!auditEnabled(flags)) return;

    mutex.lock();
    defer mutex.unlock();
    runAuditPassLocked();
}

pub fn snapshotAuditState(alloc: std.mem.Allocator) !AuditSnapshot {
    mutex.lock();
    defer mutex.unlock();

    var degraded: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (degraded.items) |name| alloc.free(name);
        degraded.deinit(alloc);
    }
    for (degraded_services.items) |name| {
        try degraded.append(alloc, try alloc.dupe(u8, name));
    }

    return .{
        .enabled = auditEnabled(rollout.current()),
        .running = audit_running.load(.acquire),
        .passes_total = audit_passes_total,
        .mismatch_services_total = audit_mismatch_services_total,
        .vip_mismatches_total = audit_vip_mismatches_total,
        .endpoint_count_mismatches_total = audit_endpoint_count_mismatches_total,
        .stale_endpoint_mismatches_total = audit_stale_endpoint_mismatches_total,
        .eligibility_mismatches_total = audit_eligibility_mismatches_total,
        .repairs_total = audit_repairs_total,
        .stale_endpoint_quarantines_total = stale_endpoint_quarantines_total,
        .degraded_services = degraded,
        .last_audit_at = last_audit_at,
        .last_mismatch_at = last_mismatch_at,
        .last_stale_quarantine_at = last_stale_quarantine_at,
        .last_error = if (last_audit_error) |message| try alloc.dupe(u8, message) else null,
    };
}

pub fn snapshotNodeSignalState() NodeSignalSnapshot {
    mutex.lock();
    defer mutex.unlock();

    return .{
        .lost_total = node_lost_signals_total,
        .recovered_total = node_recovered_signals_total,
        .endpoints_changed_total = node_signal_endpoints_changed_total,
        .last_lost_node_id = last_lost_node_id,
        .last_recovered_node_id = last_recovered_node_id,
    };
}

pub fn snapshotComponentState() ComponentSnapshot {
    mutex.lock();
    defer mutex.unlock();

    return .{
        .state = detectComponentStateLocked(),
        .state_changes_total = component_state_changes_total,
        .full_resyncs_total = component_full_resyncs_total,
        .last_change_at = component_last_change_at,
    };
}

pub fn noteNodeLost(node_id: i64) void {
    noteNodeSignal(node_id, true);
}

pub fn noteNodeRecovered(node_id: i64) void {
    noteNodeSignal(node_id, false);
}

pub fn refreshComponentStateIfEnabled() void {
    if (rollout.mode() == .legacy) return;

    mutex.lock();
    defer mutex.unlock();
    refreshComponentStateLocked();
}

pub fn setComponentStateOverrideForTest(state: ComponentState) void {
    mutex.lock();
    defer mutex.unlock();
    component_state_override = state;
}

fn noteEvent(event: Event) void {
    if (rollout.mode() == .legacy) return;

    mutex.lock();
    defer mutex.unlock();

    if (!logged_authoritative_flag_notice) {
        logged_authoritative_flag_notice = true;
        log.info("service reconciler owns canonical DNS state", .{});
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
        "service reconciler: event source={s} kind={s} service={s} container={s}",
        .{ event.source.label(), event.kind.label(), event.serviceName(), event.containerId() },
    );

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

fn noteNodeSignal(node_id: i64, is_loss: bool) void {
    if (rollout.mode() == .legacy) return;

    mutex.lock();
    defer mutex.unlock();

    const alloc = std.heap.page_allocator;
    var service_names = collectServicesForNodeLocked(alloc, node_id) catch |err| {
        log.warn("service reconciler: failed to enumerate services for node {}: {}", .{ node_id, err });
        return;
    };
    defer {
        for (service_names.items) |service_name| alloc.free(service_name);
        service_names.deinit(alloc);
    }

    const changed_count = if (is_loss)
        service_registry_runtime.noteNodeLost(node_id) catch |err| {
            log.warn("service reconciler: failed to apply node signal node={} loss={}: {}", .{ node_id, is_loss, err });
            return;
        }
    else
        service_registry_runtime.noteNodeRecovered(node_id) catch |err| {
            log.warn("service reconciler: failed to apply node signal node={} loss={}: {}", .{ node_id, is_loss, err });
            return;
        };

    if (is_loss) {
        node_lost_signals_total += 1;
        last_lost_node_id = node_id;
    } else {
        node_recovered_signals_total += 1;
        last_recovered_node_id = node_id;
    }
    node_signal_endpoints_changed_total += changed_count;

    if (changed_count == 0) return;

    if (!authoritative_bootstrapped) {
        bootstrapAuthoritativeLocked();
        proxy_control_plane.refreshIfEnabled();
        return;
    }

    for (service_names.items) |service_name| {
        reconcileServiceLocked(service_name) catch |err| {
            log.warn("service reconciler: failed to reconcile service {s} after node signal for {}: {}", .{ service_name, node_id, err });
        };
    }
    proxy_control_plane.refreshIfEnabled();
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

fn auditLoop() void {
    while (audit_running.load(.acquire)) {
        std.Thread.sleep(audit_interval_secs * std.time.ns_per_s);
        if (!audit_running.load(.acquire)) break;
        runAuditPassIfEnabled();
    }
}

fn runAuditPassLocked() void {
    refreshComponentStateLocked();
    quarantineStaleEndpointsLocked();
    audit_passes_total += 1;
    last_audit_at = std.time.timestamp();
    clearLastAuditErrorLocked();
    deinitDegradedServicesLocked();

    auditOnceLocked() catch |err| {
        setLastAuditErrorLocked(@errorName(err));
        log.warn("service reconciler: audit pass failed: {}", .{err});
    };
}

fn auditOnceLocked() !void {
    const alloc = std.heap.page_allocator;

    var runtime_services = try service_registry_runtime.snapshotServices(alloc);
    defer {
        for (runtime_services.items) |service| service.deinit(alloc);
        runtime_services.deinit(alloc);
    }

    var db_services = store.listServices(alloc) catch return error.StoreReadFailed;
    defer {
        for (db_services.items) |service| service.deinit(alloc);
        db_services.deinit(alloc);
    }

    var audit_names: std.ArrayList([]const u8) = .empty;
    defer {
        for (audit_names.items) |name| alloc.free(name);
        audit_names.deinit(alloc);
    }

    for (db_services.items) |service| {
        try audit_names.append(alloc, try alloc.dupe(u8, service.service_name));
        try auditServiceLocked(service.service_name, &runtime_services);
    }

    for (runtime_services.items) |service| {
        if (containsServiceName(audit_names.items, service.service_name)) continue;
        try audit_names.append(alloc, try alloc.dupe(u8, service.service_name));
        try auditServiceLocked(service.service_name, &runtime_services);
    }
}

fn auditServiceLocked(service_name: []const u8, runtime_services: *const std.ArrayList(service_registry_runtime.ServiceSnapshot)) !void {
    const alloc = std.heap.page_allocator;
    const now = std.time.timestamp();
    const authoritative = auditEnabled(rollout.current());

    const runtime_service = findRuntimeService(runtime_services.items, service_name);
    const db_service = store.getService(alloc, service_name) catch |err| switch (err) {
        store.StoreError.NotFound => null,
        else => return error.StoreReadFailed,
    };
    defer if (db_service) |service| service.deinit(alloc);

    const mismatch = try computeAuditMismatch(alloc, service_name, runtime_service, db_service);
    defer if (mismatch) |value| alloc.free(value.reason);

    if (mismatch) |value| {
        audit_mismatch_services_total += 1;
        noteAuditMismatchKind(value.kind);
        last_mismatch_at = now;
        log.warn("service reconciler: audit mismatch service={s} kind={s} reason={s}", .{ service_name, auditMismatchKindLabel(value.kind), value.reason });
        try ensureDegradedServiceLocked(service_name);
        if (!authoritative) return;

        service_registry_runtime.markReconcileFailed(service_name, value.reason) catch |e| {
            log.warn("service reconciler: failed to mark {s} as failed: {}", .{ service_name, e });
        };

        if (!retryDueLocked(service_name, now)) return;

        service_registry_runtime.syncServiceFromStore(service_name);
        try reconcileServiceLocked(service_name);
        proxy_control_plane.refreshIfEnabled();

        const refreshed_runtime = service_registry_runtime.snapshotService(alloc, service_name) catch |err| switch (err) {
            error.ServiceNotFound => null,
            else => return err,
        };
        defer if (refreshed_runtime) |service| service.deinit(alloc);

        const repaired_mismatch = try computeAuditMismatch(alloc, service_name, refreshed_runtime, db_service);
        defer if (repaired_mismatch) |value_inner| alloc.free(value_inner.reason);

        if (repaired_mismatch == null) {
            audit_repairs_total += 1;
            removeDegradedServiceLocked(service_name);
            clearRetryStateLocked(service_name);
            service_registry_runtime.markReconcileSucceeded(service_name) catch |e| {
                log.warn("service reconciler: failed to mark {s} as succeeded: {}", .{ service_name, e });
            };
        } else {
            noteRetryFailureLocked(service_name, now) catch |err| {
                log.warn("service reconciler: failed to track retry backoff for {s}: {}", .{ service_name, err });
            };
        }
        return;
    }

    removeDegradedServiceLocked(service_name);
    clearRetryStateLocked(service_name);
    if (authoritative) service_registry_runtime.markReconcileSucceeded(service_name) catch |e| {
        log.warn("service reconciler: failed to mark {s} as succeeded: {}", .{ service_name, e });
    };
}

fn quarantineStaleEndpointsLocked() void {
    const alloc = std.heap.page_allocator;

    const agents = blk: {
        const cluster_db = dns.currentClusterDb() orelse break :blk null;
        break :blk cluster_registry.listAgents(alloc, cluster_db) catch |err| {
            log.warn("service reconciler: failed to load cluster agents for stale endpoint scan: {}", .{err});
            break :blk null;
        };
    };
    defer {
        if (agents) |records| {
            for (records) |agent| agent.deinit(alloc);
            alloc.free(records);
        }
    }

    var containers = store.listAll(alloc) catch |err| {
        log.warn("service reconciler: failed to list local containers for stale endpoint scan: {}", .{err});
        return;
    };
    defer {
        for (containers.items) |container| container.deinit(alloc);
        containers.deinit(alloc);
    }

    var services = store.listServices(alloc) catch |err| {
        log.warn("service reconciler: failed to list services for stale endpoint scan: {}", .{err});
        return;
    };
    defer {
        for (services.items) |service| service.deinit(alloc);
        services.deinit(alloc);
    }

    var changed_services: std.ArrayList([]const u8) = .empty;
    defer {
        for (changed_services.items) |service_name| alloc.free(service_name);
        changed_services.deinit(alloc);
    }

    var quarantined: u64 = 0;
    for (services.items) |service| {
        var endpoints = store.listServiceEndpoints(alloc, service.service_name) catch |err| {
            log.warn("service reconciler: failed to list endpoints for stale endpoint scan service={s}: {}", .{ service.service_name, err });
            continue;
        };
        defer {
            for (endpoints.items) |endpoint| endpoint.deinit(alloc);
            endpoints.deinit(alloc);
        }

        for (endpoints.items) |endpoint| {
            if (std.mem.eql(u8, endpoint.admin_state, "draining")) continue;

            var should_quarantine = false;
            if (endpoint.node_id) |node_id| {
                if (agents) |records| {
                    if (!agentExistsForNodeId(records, node_id)) {
                        log.warn(
                            "service reconciler: quarantining stale endpoint service={s} endpoint={s} node_id={}",
                            .{ service.service_name, endpoint.endpoint_id, node_id },
                        );
                        should_quarantine = true;
                    }
                }
            } else if (!containerExistsForId(containers.items, endpoint.container_id)) {
                log.warn(
                    "service reconciler: quarantining stale endpoint service={s} endpoint={s} missing local container={s}",
                    .{ service.service_name, endpoint.endpoint_id, endpoint.container_id },
                );
                should_quarantine = true;
            }

            if (!should_quarantine) continue;

            store.markServiceEndpointAdminState(service.service_name, endpoint.endpoint_id, "draining") catch |err| {
                log.warn(
                    "service reconciler: failed to quarantine stale endpoint service={s} endpoint={s}: {}",
                    .{ service.service_name, endpoint.endpoint_id, err },
                );
                continue;
            };
            quarantined += 1;

            if (!containsServiceName(changed_services.items, service.service_name)) {
                const duped = alloc.dupe(u8, service.service_name) catch {
                    log.warn("service reconciler: failed to duplicate service name for stale endpoint sync {s}", .{service.service_name});
                    continue;
                };
                changed_services.append(alloc, duped) catch |err| {
                    alloc.free(duped);
                    log.warn("service reconciler: failed to track stale endpoint service sync for {s}: {}", .{ service.service_name, err });
                    continue;
                };
            }
        }
    }

    if (quarantined == 0) return;

    stale_endpoint_quarantines_total += quarantined;
    last_stale_quarantine_at = std.time.timestamp();

    for (changed_services.items) |service_name| {
        service_registry_runtime.syncServiceFromStore(service_name);
    }
    proxy_control_plane.refreshIfEnabled();
}

fn computeAuditMismatch(
    alloc: std.mem.Allocator,
    service_name: []const u8,
    runtime_service: ?service_registry_runtime.ServiceSnapshot,
    db_service: ?store.ServiceRecord,
) !?AuditMismatch {
    if (db_service == null and runtime_service == null) return null;
    if (db_service == null) return .{ .kind = .stale_endpoint, .reason = try alloc.dupe(u8, "runtime service missing from durable store") };
    if (runtime_service == null) return .{ .kind = .stale_endpoint, .reason = try alloc.dupe(u8, "runtime service missing from in-memory registry") };

    if (!std.mem.eql(u8, runtime_service.?.vip_address, db_service.?.vip_address)) {
        return .{
            .kind = .vip,
            .reason = try std.fmt.allocPrint(alloc, "service vip drift runtime={s} db={s}", .{ runtime_service.?.vip_address, db_service.?.vip_address }),
        };
    }

    var db_endpoints = store.listServiceEndpoints(alloc, service_name) catch return error.StoreReadFailed;
    defer {
        for (db_endpoints.items) |endpoint| endpoint.deinit(alloc);
        db_endpoints.deinit(alloc);
    }
    if (runtime_service.?.total_endpoints != db_endpoints.items.len) {
        return .{
            .kind = .endpoint_count,
            .reason = try std.fmt.allocPrint(alloc, "endpoint count drift runtime={d} db={d}", .{ runtime_service.?.total_endpoints, db_endpoints.items.len }),
        };
    }

    var runtime_endpoints = service_registry_runtime.snapshotServiceEndpoints(alloc, service_name) catch |err| switch (err) {
        error.ServiceNotFound => return .{
            .kind = .stale_endpoint,
            .reason = try alloc.dupe(u8, "runtime endpoints missing"),
        },
        else => return err,
    };
    defer {
        for (runtime_endpoints.items) |endpoint| endpoint.deinit(alloc);
        runtime_endpoints.deinit(alloc);
    }

    const actual_dns_ip = dns_registry_support.lookupLocalService(service_name);

    var desired_ips: std.ArrayList([4]u8) = .empty;
    defer desired_ips.deinit(alloc);
    var desired_endpoints: std.ArrayList(AppliedEndpoint) = .empty;
    defer {
        for (desired_endpoints.items) |endpoint| endpoint.deinit(alloc);
        desired_endpoints.deinit(alloc);
    }
    for (runtime_endpoints.items) |endpoint| {
        if (!endpoint.eligible) continue;
        const endpoint_ip = ip_mod.parseIp(endpoint.ip_address) orelse continue;
        if (!containsIp(desired_ips.items, endpoint_ip)) try desired_ips.append(alloc, endpoint_ip);
        try desired_endpoints.append(alloc, .{
            .container_id = try alloc.dupe(u8, endpoint.container_id),
            .ip = endpoint_ip,
        });
    }

    const expected_vip = ip_mod.parseIp(runtime_service.?.vip_address) orelse return error.StoreReadFailed;
    if (desired_ips.items.len == 0) {
        if (actual_dns_ip != null) {
            return .{ .kind = .vip, .reason = try alloc.dupe(u8, "dns registry should be empty when no eligible endpoints remain") };
        }
    } else if (!optionalIpEqual(actual_dns_ip, expected_vip)) {
        return .{
            .kind = .vip,
            .reason = try std.fmt.allocPrint(
                alloc,
                "dns vip mismatch expected={d}.{d}.{d}.{d}",
                .{ expected_vip[0], expected_vip[1], expected_vip[2], expected_vip[3] },
            ),
        };
    }

    var registry_endpoints = dns_registry_support.snapshotServiceEntries(alloc, service_name) catch return error.StoreReadFailed;
    defer {
        for (registry_endpoints.items) |endpoint| endpoint.deinit(alloc);
        registry_endpoints.deinit(alloc);
    }
    if (registry_endpoints.items.len != desired_endpoints.items.len) {
        return .{
            .kind = .endpoint_count,
            .reason = try std.fmt.allocPrint(alloc, "dns registry endpoint count drift registry={d} desired={d}", .{
                registry_endpoints.items.len,
                desired_endpoints.items.len,
            }),
        };
    }
    for (registry_endpoints.items) |endpoint| {
        if (!containsAppliedEndpoint(desired_endpoints.items, endpoint.container_id, endpoint.ip)) {
            return .{ .kind = .eligibility, .reason = try alloc.dupe(u8, "dns registry endpoints differ from eligible set") };
        }
    }

    if (component_state.dns_interceptor_loaded) {
        const expected_dns_ip = dns_registry_support.lookupLocalService(service_name);
        const actual_interceptor_ip = dns_registry_support.lookupDnsInterceptorService(service_name);
        if (!optionalIpEqual(expected_dns_ip, actual_interceptor_ip)) {
            return .{ .kind = .eligibility, .reason = try alloc.dupe(u8, "dns interceptor map differs from registry") };
        }
    }

    if (component_state.load_balancer_loaded) {
        const maybe_lb_backends = dns_registry_support.snapshotLoadBalancerBackends(alloc, service_name) catch return error.StoreReadFailed;
        if (maybe_lb_backends) |backends_value| {
            var backends = backends_value;
            defer backends.deinit(alloc);

            if (backends.items.len != desired_ips.items.len) {
                return .{
                    .kind = .endpoint_count,
                    .reason = try std.fmt.allocPrint(alloc, "load balancer backend count drift backends={d} desired={d}", .{
                        backends.items.len,
                        desired_ips.items.len,
                    }),
                };
            }
            for (backends.items) |backend_ip| {
                if (!containsIp(desired_ips.items, backend_ip)) {
                    return .{ .kind = .eligibility, .reason = try alloc.dupe(u8, "load balancer backends differ from eligible set") };
                }
            }
        }
    }

    return null;
}

fn auditEnabled(flags: rollout.Flags) bool {
    return flags.service_registry_v2 or flags.service_registry_reconciler;
}

fn noteAuditMismatchKind(kind: AuditMismatchKind) void {
    switch (kind) {
        .vip => audit_vip_mismatches_total += 1,
        .endpoint_count => audit_endpoint_count_mismatches_total += 1,
        .stale_endpoint => audit_stale_endpoint_mismatches_total += 1,
        .eligibility => audit_eligibility_mismatches_total += 1,
    }
}

fn auditMismatchKindLabel(kind: AuditMismatchKind) []const u8 {
    return switch (kind) {
        .vip => "vip",
        .endpoint_count => "endpoint_count",
        .stale_endpoint => "stale_endpoint",
        .eligibility => "eligibility",
    };
}

fn refreshComponentStateLocked() void {
    const next_state = detectComponentStateLocked();
    if (std.meta.eql(component_state, next_state)) return;

    component_state = next_state;
    component_state_changes_total += 1;
    component_last_change_at = std.time.timestamp();

    log.info(
        "service reconciler: component state changed resolver={} dns_interceptor={} load_balancer={}",
        .{
            component_state.dns_resolver_running,
            component_state.dns_interceptor_loaded,
            component_state.load_balancer_loaded,
        },
    );

    component_full_resyncs_total += 1;
    if (!authoritative_bootstrapped) {
        bootstrapAuthoritativeLocked();
        return;
    }

    reconcileAllLocked() catch |err| {
        log.warn("service reconciler: failed full resync after component state change: {}", .{err});
    };
}

fn detectComponentStateLocked() ComponentState {
    if (component_state_override) |state| return state;

    return .{
        .dns_resolver_running = dns.resolverRunning(),
        .dns_interceptor_loaded = ebpf.getDnsInterceptor() != null,
        .load_balancer_loaded = ebpf.getLoadBalancer() != null,
    };
}

fn collectServicesForNodeLocked(alloc: std.mem.Allocator, node_id: i64) !std.ArrayList([]const u8) {
    var service_names: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (service_names.items) |name| alloc.free(name);
        service_names.deinit(alloc);
    }

    var endpoints = store.listServiceEndpointsByNode(alloc, node_id) catch return error.StoreReadFailed;
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(alloc);
        endpoints.deinit(alloc);
    }

    for (endpoints.items) |endpoint| {
        if (containsServiceName(service_names.items, endpoint.service_name)) continue;
        try service_names.append(alloc, try alloc.dupe(u8, endpoint.service_name));
    }
    return service_names;
}

fn agentExistsForNodeId(agents: []const cluster_registry.AgentRecord, node_id: i64) bool {
    for (agents) |agent| {
        const candidate = agent.node_id orelse continue;
        if (candidate == node_id) return true;
    }
    return false;
}

fn containerExistsForId(containers: []const store.ContainerRecord, container_id: []const u8) bool {
    for (containers) |container| {
        if (std.mem.eql(u8, container.id, container_id)) return true;
    }
    return false;
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

        try applyDesiredStateLocked(name, null, &.{});
    }
}

fn reconcileServiceLocked(service_name: []const u8) !void {
    const alloc = std.heap.page_allocator;

    const service_snapshot = service_registry_runtime.snapshotService(alloc, service_name) catch |err| switch (err) {
        error.ServiceNotFound => return try applyDesiredStateLocked(service_name, null, &[_]AppliedEndpoint{}),
        else => return err,
    };
    defer service_snapshot.deinit(alloc);

    var endpoint_snapshots = service_registry_runtime.snapshotServiceEndpoints(alloc, service_name) catch |err| switch (err) {
        error.ServiceNotFound => return try applyDesiredStateLocked(service_name, null, &[_]AppliedEndpoint{}),
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

    if (desired.items.len > dns_registry_support.max_backends_per_service) {
        service_registry_runtime.markReconcileFailed(service_name, "eligible backends exceed load balancer capacity") catch |e| {
            log.warn("service reconciler: failed to mark {s} as failed: {}", .{ service_name, e });
        };
    }

    const vip = ip_mod.parseIp(service_snapshot.vip_address) orelse return error.StoreReadFailed;
    try applyDesiredStateLocked(service_name, vip, desired.items);
}

fn applyDesiredStateLocked(service_name: []const u8, vip: ?[4]u8, desired: []const AppliedEndpoint) !void {
    const alloc = std.heap.page_allocator;

    if (vip) |service_vip| {
        var backends: std.ArrayList(dns_registry_support.BackendBinding) = .empty;
        defer backends.deinit(alloc);
        for (desired) |endpoint| {
            try backends.append(alloc, .{
                .container_id = endpoint.container_id,
                .ip = endpoint.ip,
            });
        }
        dns_registry_support.replaceServiceState(service_name, service_vip, backends.items);
    } else {
        dns_registry_support.removeServiceState(service_name);
    }

    policy.syncPolicies(alloc);

    try replaceAppliedServiceLocked(service_name, desired);
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

fn containsIp(ips: []const [4]u8, candidate: [4]u8) bool {
    for (ips) |ip_addr| {
        if (std.mem.eql(u8, ip_addr[0..], candidate[0..])) return true;
    }
    return false;
}

fn optionalIpEqual(lhs: ?[4]u8, rhs: ?[4]u8) bool {
    if (lhs == null and rhs == null) return true;
    if (lhs == null or rhs == null) return false;
    return std.mem.eql(u8, lhs.?[0..], rhs.?[0..]);
}

fn findRuntimeService(services: []const service_registry_runtime.ServiceSnapshot, service_name: []const u8) ?service_registry_runtime.ServiceSnapshot {
    for (services) |service| {
        if (std.mem.eql(u8, service.service_name, service_name)) return service;
    }
    return null;
}

fn deinitAppliedServicesLocked() void {
    const alloc = std.heap.page_allocator;
    for (applied_services.items) |*service| service.deinit(alloc);
    applied_services.deinit(alloc);
    applied_services = .empty;
}

fn deinitDegradedServicesLocked() void {
    const alloc = std.heap.page_allocator;
    for (degraded_services.items) |name| alloc.free(name);
    degraded_services.deinit(alloc);
    degraded_services = .empty;
}

fn deinitRetryStatesLocked() void {
    const alloc = std.heap.page_allocator;
    for (retry_states.items) |state| state.deinit(alloc);
    retry_states.deinit(alloc);
    retry_states = .empty;
}

fn ensureDegradedServiceLocked(service_name: []const u8) !void {
    if (containsServiceName(degraded_services.items, service_name)) return;
    try degraded_services.append(std.heap.page_allocator, try std.heap.page_allocator.dupe(u8, service_name));
}

fn removeDegradedServiceLocked(service_name: []const u8) void {
    var idx: usize = 0;
    while (idx < degraded_services.items.len) {
        if (std.mem.eql(u8, degraded_services.items[idx], service_name)) {
            const name = degraded_services.orderedRemove(idx);
            std.heap.page_allocator.free(name);
            return;
        }
        idx += 1;
    }
}

fn retryDueLocked(service_name: []const u8, now: i64) bool {
    const idx = findRetryStateIndex(service_name) orelse return true;
    return retry_states.items[idx].next_retry_at <= now;
}

fn noteRetryFailureLocked(service_name: []const u8, now: i64) !void {
    const idx = findRetryStateIndex(service_name) orelse {
        const service_name_copy = try std.heap.page_allocator.dupe(u8, service_name);
        errdefer std.heap.page_allocator.free(service_name_copy);
        try retry_states.append(std.heap.page_allocator, .{
            .service_name = service_name_copy,
            .failures = 1,
            .next_retry_at = nextRetryAt(now, 1),
        });
        return;
    };

    retry_states.items[idx].failures +|= 1;
    retry_states.items[idx].next_retry_at = nextRetryAt(now, retry_states.items[idx].failures);
}

fn clearRetryStateLocked(service_name: []const u8) void {
    const idx = findRetryStateIndex(service_name) orelse return;
    const state = retry_states.orderedRemove(idx);
    state.deinit(std.heap.page_allocator);
}

fn findRetryStateIndex(service_name: []const u8) ?usize {
    for (retry_states.items, 0..) |state, idx| {
        if (std.mem.eql(u8, state.service_name, service_name)) return idx;
    }
    return null;
}

fn nextRetryAt(now: i64, failures: u32) i64 {
    const shifts = @min(failures -| 1, 4);
    const interval = @as(i64, @intCast(audit_interval_secs)) << @as(u6, @intCast(shifts));
    return now + @min(interval, max_retry_backoff_secs);
}

fn clearLastAuditErrorLocked() void {
    if (last_audit_error) |message| std.heap.page_allocator.free(message);
    last_audit_error = null;
}

fn setLastAuditErrorLocked(message: []const u8) void {
    clearLastAuditErrorLocked();
    last_audit_error = std.heap.page_allocator.dupe(u8, message) catch null;
}

test "retry backoff grows and clears" {
    resetForTest();
    defer resetForTest();

    mutex.lock();
    defer mutex.unlock();

    try noteRetryFailureLocked("api", 100);
    try std.testing.expect(!retryDueLocked("api", 100));
    try std.testing.expectEqual(@as(i64, 130), retry_states.items[0].next_retry_at);

    try noteRetryFailureLocked("api", 130);
    try std.testing.expectEqual(@as(i64, 190), retry_states.items[0].next_retry_at);

    clearRetryStateLocked("api");
    try std.testing.expect(findRetryStateIndex("api") == null);
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

test "authoritative bootstrap publishes service VIPs" {
    const dns_registry = @import("dns/registry_support.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true, .service_registry_reconciler = true });
    defer rollout.resetForTest();
    defer resetForTest();
    try saveLocalContainerFixture("ctr-1", "api", "10.42.0.9");

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

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));
}

test "deprecated dns_returns_vip flag does not change authoritative bootstrap" {
    const dns_registry = @import("dns/registry_support.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{
        .service_registry_v2 = true,
        .service_registry_reconciler = true,
        .dns_returns_vip = true,
    });
    defer rollout.resetForTest();
    defer resetForTest();
    try saveLocalContainerFixture("ctr-1", "api", "10.42.0.9");

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

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));
}

test "audit stays clean after canonical bridge registration" {
    const dns_registry = @import("dns/registry_support.zig");
    const service_registry_bridge = @import("service_registry_bridge.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    defer resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    try saveLocalContainerFixture("abc123", "api", "10.42.0.9");

    service_registry_bridge.registerContainerService("api", "abc123", .{ 10, 42, 0, 9 }, null);

    runAuditPassIfEnabled();

    const audit = try snapshotAuditState(std.testing.allocator);
    defer {
        var mutable = audit;
        mutable.deinit(std.testing.allocator);
    }

    try std.testing.expect(audit.enabled);
    try std.testing.expectEqual(@as(u64, 1), audit.passes_total);
    try std.testing.expectEqual(@as(u64, 0), audit.mismatch_services_total);
    try std.testing.expectEqual(@as(u64, 0), audit.vip_mismatches_total);
    try std.testing.expectEqual(@as(u64, 0), audit.repairs_total);
    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));
}

test "audit pass ignores legacy service_names drift" {
    const dns_registry = @import("dns/registry_support.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true, .service_registry_reconciler = true });
    defer rollout.resetForTest();
    defer resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    try saveLocalContainerFixture("ctr-1", "api", "10.42.0.9");

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

    bootstrapIfEnabled();
    try store.removeServiceNamesByName("api");

    runAuditPassIfEnabled();

    var audit = try snapshotAuditState(std.testing.allocator);
    defer audit.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 1), audit.passes_total);
    try std.testing.expectEqual(@as(u64, 0), audit.mismatch_services_total);
    try std.testing.expectEqual(@as(u64, 0), audit.repairs_total);
    try std.testing.expectEqual(@as(usize, 0), audit.degraded_services.items.len);
}

test "audit ignores legacy service_names drift in canonical vip mode" {
    const dns_registry = @import("dns/registry_support.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{
        .service_registry_v2 = true,
        .service_registry_reconciler = true,
        .dns_returns_vip = true,
    });
    defer rollout.resetForTest();
    defer resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    try saveLocalContainerFixture("ctr-1", "api", "10.42.0.9");

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

    bootstrapIfEnabled();
    try store.removeServiceNamesByName("api");

    runAuditPassIfEnabled();

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));
}

test "audit pass repairs live dns registry drift" {
    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry_support.resetRegistryForTest();
    defer dns_registry_support.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true, .service_registry_reconciler = true });
    defer rollout.resetForTest();
    defer resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    try saveLocalContainerFixture("ctr-1", "api", "10.42.0.9");

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

    bootstrapIfEnabled();
    dns_registry_support.resetRegistryForTest();
    try std.testing.expectEqual(@as(?[4]u8, null), dns.lookupService("api"));

    runAuditPassIfEnabled();

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));
    var audit = try snapshotAuditState(std.testing.allocator);
    defer audit.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 1), audit.passes_total);
    try std.testing.expectEqual(@as(u64, 1), audit.mismatch_services_total);
    try std.testing.expectEqual(@as(u64, 1), audit.repairs_total);
    try std.testing.expectEqual(@as(usize, 0), audit.degraded_services.items.len);
}

test "node loss and recovery reconcile authoritative DNS immediately" {
    const dns_registry = @import("dns/registry_support.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true, .service_registry_reconciler = true });
    defer rollout.resetForTest();
    defer resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();

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
        .node_id = 7,
        .ip_address = "10.42.7.9",
        .port = 0,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });

    bootstrapIfEnabled();
    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));

    noteNodeLost(7);

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));

    var endpoints_after_loss = try service_registry_runtime.snapshotServiceEndpoints(std.testing.allocator, "api");
    defer {
        for (endpoints_after_loss.items) |endpoint| endpoint.deinit(std.testing.allocator);
        endpoints_after_loss.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), endpoints_after_loss.items.len);
    try std.testing.expect(!endpoints_after_loss.items[0].eligible);

    const after_loss = snapshotNodeSignalState();
    try std.testing.expectEqual(@as(u64, 1), after_loss.lost_total);
    try std.testing.expectEqual(@as(u64, 0), after_loss.recovered_total);
    try std.testing.expectEqual(@as(u64, 1), after_loss.endpoints_changed_total);
    try std.testing.expectEqual(@as(?i64, 7), after_loss.last_lost_node_id);

    noteNodeRecovered(7);

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));

    const after_recovery = snapshotNodeSignalState();
    try std.testing.expectEqual(@as(u64, 1), after_recovery.lost_total);
    try std.testing.expectEqual(@as(u64, 1), after_recovery.recovered_total);
    try std.testing.expectEqual(@as(u64, 2), after_recovery.endpoints_changed_total);
    try std.testing.expectEqual(@as(?i64, 7), after_recovery.last_recovered_node_id);
}

test "node loss refreshes l7 proxy route counts" {
    const proxy_runtime = @import("proxy/runtime.zig");
    const steering_runtime = @import("proxy/steering_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    resetForTest();
    rollout.setForTest(.{
        .service_registry_v2 = true,
        .service_registry_reconciler = true,
        .l7_proxy_http = true,
    });
    defer rollout.resetForTest();
    defer resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();

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
        .endpoint_id = "ctr-1:0",
        .container_id = "ctr-1",
        .node_id = 7,
        .ip_address = "10.42.7.9",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });

    bootstrapIfEnabled();
    proxy_runtime.bootstrapIfEnabled();

    {
        var routes_before = try proxy_runtime.snapshotServiceRoutes(std.testing.allocator, "api");
        defer {
            for (routes_before.items) |route_snapshot| route_snapshot.deinit(std.testing.allocator);
            routes_before.deinit(std.testing.allocator);
        }
        try std.testing.expectEqual(@as(usize, 1), routes_before.items.len);
        try std.testing.expectEqual(@as(u32, 1), routes_before.items[0].eligible_endpoints);
    }

    noteNodeLost(7);

    {
        var routes_after_loss = try proxy_runtime.snapshotServiceRoutes(std.testing.allocator, "api");
        defer {
            for (routes_after_loss.items) |route_snapshot| route_snapshot.deinit(std.testing.allocator);
            routes_after_loss.deinit(std.testing.allocator);
        }
        try std.testing.expectEqual(@as(usize, 1), routes_after_loss.items.len);
        try std.testing.expectEqual(@as(u32, 0), routes_after_loss.items[0].eligible_endpoints);
    }

    noteNodeRecovered(7);

    {
        var routes_after_recovery = try proxy_runtime.snapshotServiceRoutes(std.testing.allocator, "api");
        defer {
            for (routes_after_recovery.items) |route_snapshot| route_snapshot.deinit(std.testing.allocator);
            routes_after_recovery.deinit(std.testing.allocator);
        }
        try std.testing.expectEqual(@as(usize, 1), routes_after_recovery.items.len);
        try std.testing.expectEqual(@as(u32, 1), routes_after_recovery.items[0].eligible_endpoints);
    }
}

test "component state change triggers full resync" {
    const dns_registry = @import("dns/registry_support.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true, .service_registry_reconciler = true });
    defer rollout.resetForTest();
    defer resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    try saveLocalContainerFixture("ctr-1", "api", "10.42.0.9");

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

    setComponentStateOverrideForTest(.{
        .dns_resolver_running = false,
        .dns_interceptor_loaded = false,
        .load_balancer_loaded = false,
    });
    bootstrapIfEnabled();

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));

    dns_registry.resetRegistryForTest();
    setComponentStateOverrideForTest(.{
        .dns_resolver_running = true,
        .dns_interceptor_loaded = true,
        .load_balancer_loaded = true,
    });

    refreshComponentStateIfEnabled();

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));

    const snapshot = snapshotComponentState();
    try std.testing.expect(snapshot.state.dns_resolver_running);
    try std.testing.expect(snapshot.state.dns_interceptor_loaded);
    try std.testing.expect(snapshot.state.load_balancer_loaded);
    try std.testing.expectEqual(@as(u64, 1), snapshot.state_changes_total);
    try std.testing.expectEqual(@as(u64, 1), snapshot.full_resyncs_total);
    try std.testing.expect(snapshot.last_change_at != null);
}

test "bootstrap quarantines stale endpoint rows for missing nodes" {
    const sqlite = @import("sqlite");
    const cluster_registry_test_support = @import("../cluster/registry/test_support.zig");
    const dns_registry = @import("dns/registry_support.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true, .service_registry_reconciler = true });
    defer rollout.resetForTest();
    defer resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();

    var cluster_db = try sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    });
    defer cluster_db.deinit();
    try cluster_db.exec(cluster_registry_test_support.agents_schema, .{}, .{});
    const prev_cluster_db = dns.currentClusterDb();
    dns.setClusterDb(&cluster_db);
    defer dns.setClusterDb(prev_cluster_db);

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
        .node_id = 7,
        .ip_address = "10.42.7.9",
        .port = 0,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });

    bootstrapIfEnabled();

    var endpoints = try store.listServiceEndpoints(std.testing.allocator, "api");
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(std.testing.allocator);
        endpoints.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), endpoints.items.len);
    try std.testing.expectEqualStrings("draining", endpoints.items[0].admin_state);
    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));

    var audit = try snapshotAuditState(std.testing.allocator);
    defer audit.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 1), audit.stale_endpoint_quarantines_total);
    try std.testing.expect(audit.last_stale_quarantine_at != null);
}

test "bootstrap quarantines stale endpoint rows for missing local containers" {
    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry_support.resetRegistryForTest();
    defer dns_registry_support.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true, .service_registry_reconciler = true });
    defer rollout.resetForTest();
    defer resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();

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

    bootstrapIfEnabled();

    var endpoints = try store.listServiceEndpoints(std.testing.allocator, "api");
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(std.testing.allocator);
        endpoints.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), endpoints.items.len);
    try std.testing.expectEqualStrings("draining", endpoints.items[0].admin_state);
    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));

    var audit = try snapshotAuditState(std.testing.allocator);
    defer audit.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 1), audit.stale_endpoint_quarantines_total);
    try std.testing.expect(audit.last_stale_quarantine_at != null);
}

test "vip dns keeps service visible with zero eligible backends" {
    const dns_registry = @import("dns/registry_support.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{
        .service_registry_v2 = true,
        .service_registry_reconciler = true,
        .dns_returns_vip = true,
    });
    defer rollout.resetForTest();
    defer resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();

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
        .admin_state = "draining",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });

    bootstrapIfEnabled();

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));
}

test "vip dns marks services degraded when eligible backends exceed capacity" {
    const dns_registry = @import("dns/registry_support.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    dns_registry.resetRegistryForTest();
    defer dns_registry.resetRegistryForTest();
    resetForTest();
    rollout.setForTest(.{
        .service_registry_v2 = true,
        .service_registry_reconciler = true,
        .dns_returns_vip = true,
    });
    defer rollout.resetForTest();
    defer resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });

    for (0..dns_registry.max_backends_per_service + 1) |idx| {
        var endpoint_id_buf: [32]u8 = undefined;
        const endpoint_id = try std.fmt.bufPrint(&endpoint_id_buf, "ctr-{d}:0", .{idx});
        var container_id_buf: [16]u8 = undefined;
        const container_id = try std.fmt.bufPrint(&container_id_buf, "ctr-{d}", .{idx});
        var ip_buf: [16]u8 = undefined;
        const ip_text = try std.fmt.bufPrint(&ip_buf, "10.42.0.{d}", .{idx + 1});
        try saveLocalContainerFixture(container_id, "api", ip_text);
        try store.upsertServiceEndpoint(.{
            .service_name = "api",
            .endpoint_id = endpoint_id,
            .container_id = container_id,
            .node_id = null,
            .ip_address = ip_text,
            .port = 0,
            .weight = 1,
            .admin_state = "active",
            .generation = 1,
            .registered_at = 1000 + @as(i64, @intCast(idx)),
            .last_seen_at = 1000 + @as(i64, @intCast(idx)),
        });
    }

    bootstrapIfEnabled();

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), dns.lookupService("api"));
    const snapshot = try service_registry_runtime.snapshotService(std.testing.allocator, "api");
    defer snapshot.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("failed", snapshot.last_reconcile_status);
    try std.testing.expect(snapshot.degraded);
}

fn saveLocalContainerFixture(container_id: []const u8, hostname: []const u8, ip_address: []const u8) !void {
    try store.save(.{
        .id = container_id,
        .rootfs = "/tmp/rootfs",
        .command = "sleep infinity",
        .hostname = hostname,
        .status = "running",
        .pid = null,
        .exit_code = null,
        .ip_address = ip_address,
        .veth_host = null,
        .app_name = null,
        .created_at = 1000,
    });
}
