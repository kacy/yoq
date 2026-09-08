const std = @import("std");
const platform = @import("linux_platform");
const nl = @import("network/netlink.zig");
const ebpf = @import("network/ebpf.zig");
const runtime = @import("network/ebpf/policy_runtime.zig");
const maps = @import("network/ebpf/map_support.zig");
const rules = @import("network/policy_rules.zig");

pub fn main(_: std.process.Init) !void {
    const socket = try nl.openSocket();
    defer platform.posix.close(socket);
    const index = try nl.getIfIndex(socket, "yoq0");
    var entries = [_]rules.Rule{.{
        .key = .{ .src_ip = @bitCast([4]u8{ 10, 42, 0, 3 }), .dst_ip = @bitCast([4]u8{ 10, 43, 0, 2 }) },
        .action = .deny,
    }};
    const desired: rules.Snapshot = .{ .rules = &entries, .isolated = &.{} };
    try ebpf.installPolicyRules(index, desired);
    defer ebpf.unloadPolicyEnforcer();
    const original_id = try currentDeny(entries[0].key);
    try ebpf.replacePolicyRules(desired);
    if (original_id != try currentDeny(entries[0].key)) return error.UnchangedPolicyReplaced;

    // A failed update to private replacement maps must leave the attached
    // program and its existing deny unchanged.
    var allow_entries = entries;
    allow_entries[0].action = .allow;
    maps.setMapUpdateFaultModeForTest(.fail_update);
    if (ebpf.replacePolicyRules(.{ .rules = &allow_entries, .isolated = &.{} })) |_| {
        return error.MapFailureNotPropagated;
    } else |err| {
        if (err != error.MapUpdateFailed) return err;
    }
    maps.resetFaultInjectionForTest();
    if (original_id != try currentDeny(entries[0].key)) return error.FailedPreparationReplacedPolicy;

    // A different process may replace the owned slot. The unchanged desired
    // snapshot must be reinstalled, and the stale owner's detach must be inert.
    var external = try runtime.loadWithRules(index, desired);
    try ebpf.replacePolicyRules(desired);
    const restored_id = try currentDeny(entries[0].key);
    if (restored_id == original_id or restored_id == external.attachment.program_id) return error.OwnerNotRefreshed;
    external.deinit();
    _ = try currentDeny(entries[0].key);

    // Incremental edits invalidate the cached generation so the next full
    // refresh repairs the live maps even if desired definitions are unchanged.
    {
        var update = ebpf.leasePolicyUpdate() orelse return error.NoPolicy;
        defer update.deinit();
        update.enforcer.removeDeny(entries[0].key.src_ip, entries[0].key.dst_ip);
    }
    try ebpf.replacePolicyRules(desired);
    _ = try currentDeny(entries[0].key);
    try ebpf.replacePolicyRules(.{ .rules = &.{}, .isolated = &.{} });
    const current = ebpf.getPolicyEnforcer() orelse return error.NoPolicy;
    var action: u8 = 255;
    if (maps.mapLookup(current.policy_fd, std.mem.asBytes(&entries[0].key), std.mem.asBytes(&action))) return error.RemovedPolicyRetained;
    if (!try current.attachment.isCurrent()) return error.CurrentPolicyDetached;
}

fn currentDeny(key: rules.Key) !u32 {
    const current = ebpf.getPolicyEnforcer() orelse return error.NoPolicy;
    if (!try current.attachment.isCurrent()) return error.CurrentPolicyDetached;
    var action: u8 = 255;
    if (!maps.mapLookup(current.policy_fd, std.mem.asBytes(&key), std.mem.asBytes(&action)) or action != 0) return error.DenyMissing;
    return current.attachment.program_id;
}
