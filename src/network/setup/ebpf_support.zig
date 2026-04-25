const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const bridge = @import("../bridge.zig");
const nl = @import("../netlink.zig");
const policy = @import("../policy.zig");
const log = @import("../../lib/log.zig");
const ebpf = @import("ebpf_module.zig").ebpf;

pub fn loadDnsInterceptorOnBridge() void {
    if (ebpf.getDnsInterceptor() != null) return;

    const sock = nl.openSocket() catch return;
    defer linux_platform.posix.close(sock);

    const if_index = nl.getIfIndex(sock, bridge.default_bridge) catch return;
    if (if_index == 0) return;

    ebpf.loadPolicyEnforcer(if_index) catch |e| {
        log.info("ebpf policy enforcer not loaded: {}", .{e});
    };

    ebpf.loadDnsInterceptor(if_index) catch |e| {
        log.info("ebpf DNS interceptor not loaded (falling back to userspace): {}", .{e});
        return;
    };

    ebpf.loadLoadBalancer(if_index) catch |e| {
        log.info("ebpf load balancer not loaded: {}", .{e});
    };

    ebpf.loadPortMapper(if_index) catch |e| {
        log.info("ebpf port mapper not loaded (using iptables): {}", .{e});
    };

    if (ebpf.getPolicyEnforcer() != null) {
        policy.syncPolicies(std.heap.page_allocator);
    }
}
