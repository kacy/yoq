const std = @import("std");
const dns_registry = @import("dns/registry_support.zig");
const ebpf_map_support = @import("ebpf/map_support.zig");
const service_registry_backfill = @import("service_registry_backfill.zig");
const service_registry_bridge = @import("service_registry_bridge.zig");
const steering_runtime = @import("proxy/steering_runtime.zig");
const service_reconciler = @import("service_reconciler.zig");

pub const Snapshot = struct {
    backfill_complete: bool,
    audit_fresh: bool,
    shadow_clean: bool,
    components_ready: bool,
    fault_modes_clear: bool,
    downgrade_safe: bool,
    steering_ready: bool,
    steering_blocked_services: u32,
    steering_no_port_services: u32,
    ready_for_reconciler_cutover: bool,
    ready_for_vip_cutover: bool,
    blockers: std.ArrayList([]const u8),

    pub fn deinit(self: *Snapshot, alloc: std.mem.Allocator) void {
        for (self.blockers.items) |blocker| alloc.free(blocker);
        self.blockers.deinit(alloc);
    }
};

pub fn snapshot(alloc: std.mem.Allocator) !Snapshot {
    var backfill = try service_registry_backfill.snapshot(alloc);
    defer backfill.deinit(alloc);
    var audit = try service_reconciler.snapshotAuditState(alloc);
    defer audit.deinit(alloc);
    const steering = try steering_runtime.snapshotVipCutoverReadiness(alloc);
    const components = service_reconciler.snapshotComponentState();
    const now = @import("compat").timestamp();

    const backfill_complete = !backfill.enabled or (backfill.runs_total > 0 and backfill.last_error == null);
    const audit_fresh = blk: {
        const last_audit_at = audit.last_audit_at orelse break :blk false;
        break :blk (now - last_audit_at) <= @as(i64, @intCast(service_reconciler.audit_interval_secs * 2));
    };
    const shadow_clean = audit.last_error == null and audit.degraded_services.items.len == 0;
    const components_ready =
        components.state.dns_resolver_running and
        components.state.dns_interceptor_loaded and
        components.state.load_balancer_loaded;
    const fault_modes_clear =
        service_registry_bridge.faultMode(.container_register) == .none and
        service_registry_bridge.faultMode(.container_unregister) == .none and
        service_registry_bridge.faultMode(.endpoint_healthy) == .none and
        service_registry_bridge.faultMode(.endpoint_unhealthy) == .none and
        ebpf_map_support.mapUpdateFaultMode() == .none and
        dns_registry.clusterLookupFaultMode() == .none and
        dns_registry.dnsInterceptorFaultMode() == .none and
        dns_registry.loadBalancerFaultMode() == .none;
    const downgrade_safe = audit_fresh and shadow_clean;
    const ready_for_reconciler_cutover = backfill_complete and audit_fresh and shadow_clean and fault_modes_clear;
    const steering_ready = !steering.enabled or steering.ready;
    const ready_for_vip_cutover =
        ready_for_reconciler_cutover and
        components_ready and
        steering_ready;

    var blockers: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (blockers.items) |blocker| alloc.free(blocker);
        blockers.deinit(alloc);
    }

    if (!backfill_complete) try appendBlocker(alloc, &blockers, if (backfill.last_error == null) "backfill_incomplete" else "backfill_error");
    if (!audit_fresh) try appendBlocker(alloc, &blockers, if (audit.last_audit_at == null) "audit_never_ran" else "audit_stale");
    if (audit.last_error != null) try appendBlocker(alloc, &blockers, "audit_error");
    if (!shadow_clean) try appendBlocker(alloc, &blockers, "shadow_mismatch_present");
    if (!fault_modes_clear) try appendBlocker(alloc, &blockers, "fault_mode_active");
    if (!components_ready) try appendBlocker(alloc, &blockers, "components_not_ready");
    if (!steering_ready) try appendBlocker(alloc, &blockers, "steering_not_ready");

    return .{
        .backfill_complete = backfill_complete,
        .audit_fresh = audit_fresh,
        .shadow_clean = shadow_clean,
        .components_ready = components_ready,
        .fault_modes_clear = fault_modes_clear,
        .downgrade_safe = downgrade_safe,
        .steering_ready = steering_ready,
        .steering_blocked_services = steering.blocked_services,
        .steering_no_port_services = steering.no_port_services,
        .ready_for_reconciler_cutover = ready_for_reconciler_cutover,
        .ready_for_vip_cutover = ready_for_vip_cutover,
        .blockers = blockers,
    };
}

fn appendBlocker(alloc: std.mem.Allocator, blockers: *std.ArrayList([]const u8), label: []const u8) !void {
    for (blockers.items) |existing| {
        if (std.mem.eql(u8, existing, label)) return;
    }
    try blockers.append(alloc, try alloc.dupe(u8, label));
}
