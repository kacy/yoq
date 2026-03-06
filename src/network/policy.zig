// policy — network policy sync between SQLite and BPF maps
//
// bridges the gap between service-level policy rules (stored in SQLite
// as service name pairs) and the IP-level BPF maps that enforce them.
//
// default behavior: all traffic between containers is ALLOWED.
// network policies are opt-in — calling isolate() on a source IP
// switches it to allow-only mode, where only explicitly permitted
// destinations are reachable. containers without any policy rules
// can communicate freely with all other containers.
//
// service names are resolved to IPs via store.lookupServiceNames().
// BPF maps are updated when:
//   - policies are added/removed (full sync from SQLite)
//   - containers start (incremental — apply rules for new IP)
//   - containers stop (remove entries for old IP)
//
// full sync rebuilds both policy_map and isolation_map from scratch.
// incremental operations add/remove entries for a single IP.

const std = @import("std");
const builtin = @import("builtin");
const ebpf = if (builtin.os.tag == .linux) @import("ebpf.zig") else struct {
    pub const Enforcer = struct {
        pub fn isolate(_: *@This(), _: u32) void {}
        pub fn unisolate(_: *@This(), _: u32) void {}
        pub fn addAllow(_: *@This(), _: u32, _: u32) void {}
        pub fn addDeny(_: *@This(), _: u32, _: u32) void {}
        pub fn removeAllow(_: *@This(), _: u32, _: u32) void {}
        pub fn removeDeny(_: *@This(), _: u32, _: u32) void {}
    };

    var stub_enforcer: Enforcer = .{};

    pub fn getPolicyEnforcer() ?*Enforcer {
        return &stub_enforcer;
    }

    pub fn ipToNetworkOrder(addr: [4]u8) u32 {
        return std.mem.readInt(u32, &addr, .big);
    }
};
const store = @import("../state/store.zig");
const ip_mod = @import("ip.zig");
const log = @import("../lib/log.zig");

/// full sync: rebuild BPF maps from all policies in SQLite.
///
/// reads all network policy rules, resolves service names to IPs,
/// and populates the policy_map and isolation_map from scratch.
/// called after policy changes and during startup.
pub fn syncPolicies(alloc: std.mem.Allocator) void {
    const enforcer = ebpf.getPolicyEnforcer() orelse return;

    var policies = store.listNetworkPolicies(alloc) catch {
        log.warn("policy: failed to list policies for sync", .{});
        return;
    };
    defer {
        for (policies.items) |p| p.deinit(alloc);
        policies.deinit(alloc);
    }

    // for each policy, resolve both service names to IPs and populate maps
    for (policies.items) |pol| {
        var src_ips = store.lookupServiceNames(alloc, pol.source_service) catch {
            log.warn("policy: failed to resolve source service '{s}' during sync", .{pol.source_service});
            continue;
        };
        defer {
            for (src_ips.items) |s| alloc.free(s);
            src_ips.deinit(alloc);
        }

        var dst_ips = store.lookupServiceNames(alloc, pol.target_service) catch {
            log.warn("policy: failed to resolve target service '{s}' during sync", .{pol.target_service});
            continue;
        };
        defer {
            for (dst_ips.items) |d| alloc.free(d);
            dst_ips.deinit(alloc);
        }

        const is_allow = std.mem.eql(u8, pol.action, "allow");

        // add entries for each (src, dst) pair
        for (src_ips.items) |src_str| {
            const src_addr = ip_mod.parseIp(src_str) orelse continue;
            const src_net = ebpf.ipToNetworkOrder(src_addr);

            // if this is an allow rule, isolate the source
            if (is_allow) {
                enforcer.isolate(src_net);
            }

            for (dst_ips.items) |dst_str| {
                const dst_addr = ip_mod.parseIp(dst_str) orelse continue;
                const dst_net = ebpf.ipToNetworkOrder(dst_addr);

                if (is_allow) {
                    enforcer.addAllow(src_net, dst_net);
                } else {
                    enforcer.addDeny(src_net, dst_net);
                }
            }
        }
    }
}

/// incremental: apply relevant policy rules for a newly started container.
///
/// looks up all policies where the container's service name appears as
/// either source or target, then adds BPF map entries for the new IP.
pub fn applyForContainer(service_name: []const u8, container_ip: [4]u8, alloc: std.mem.Allocator) void {
    const enforcer = ebpf.getPolicyEnforcer() orelse return;
    const new_ip_net = ebpf.ipToNetworkOrder(container_ip);

    var policies = store.listNetworkPolicies(alloc) catch {
        log.warn("policy: failed to list policies for container '{s}'", .{service_name});
        return;
    };
    defer {
        for (policies.items) |p| p.deinit(alloc);
        policies.deinit(alloc);
    }

    for (policies.items) |pol| {
        const is_allow = std.mem.eql(u8, pol.action, "allow");
        const is_source = std.mem.eql(u8, pol.source_service, service_name);
        const is_target = std.mem.eql(u8, pol.target_service, service_name);

        if (!is_source and !is_target) continue;

        if (is_source) {
            // this container is the source — resolve target IPs
            if (is_allow) {
                enforcer.isolate(new_ip_net);
            }

            var dst_ips = store.lookupServiceNames(alloc, pol.target_service) catch {
                log.warn("policy: failed to resolve target service '{s}' for container apply", .{pol.target_service});
                continue;
            };
            defer {
                for (dst_ips.items) |d| alloc.free(d);
                dst_ips.deinit(alloc);
            }

            for (dst_ips.items) |dst_str| {
                const dst_addr = ip_mod.parseIp(dst_str) orelse continue;
                const dst_net = ebpf.ipToNetworkOrder(dst_addr);

                if (is_allow) {
                    enforcer.addAllow(new_ip_net, dst_net);
                } else {
                    enforcer.addDeny(new_ip_net, dst_net);
                }
            }
        }

        if (is_target) {
            // this container is the target — resolve source IPs
            var src_ips = store.lookupServiceNames(alloc, pol.source_service) catch {
                log.warn("policy: failed to resolve source service '{s}' for container apply", .{pol.source_service});
                continue;
            };
            defer {
                for (src_ips.items) |s| alloc.free(s);
                src_ips.deinit(alloc);
            }

            for (src_ips.items) |src_str| {
                const src_addr = ip_mod.parseIp(src_str) orelse continue;
                const src_net = ebpf.ipToNetworkOrder(src_addr);

                if (is_allow) {
                    enforcer.addAllow(src_net, new_ip_net);
                } else {
                    enforcer.addDeny(src_net, new_ip_net);
                }
            }
        }
    }
}

/// remove all policy map entries containing this IP.
///
/// called when a container stops. iterates all policies and removes
/// any (src, dst) entries that reference this IP.
pub fn removeForContainer(container_ip: [4]u8, alloc: std.mem.Allocator) void {
    const enforcer = ebpf.getPolicyEnforcer() orelse return;
    const old_ip_net = ebpf.ipToNetworkOrder(container_ip);

    // remove from isolation map
    enforcer.unisolate(old_ip_net);

    // remove all policy_map entries that reference this IP
    var policies = store.listNetworkPolicies(alloc) catch {
        log.warn("policy: failed to list policies for container removal", .{});
        return;
    };
    defer {
        for (policies.items) |p| p.deinit(alloc);
        policies.deinit(alloc);
    }

    for (policies.items) |pol| {
        const is_allow = std.mem.eql(u8, pol.action, "allow");

        // check if this IP was a source
        var src_ips = store.lookupServiceNames(alloc, pol.source_service) catch {
            log.warn("policy: failed to resolve source service '{s}' for container removal", .{pol.source_service});
            continue;
        };
        defer {
            for (src_ips.items) |s| alloc.free(s);
            src_ips.deinit(alloc);
        }

        for (src_ips.items) |src_str| {
            const src_addr = ip_mod.parseIp(src_str) orelse continue;
            if (ebpf.ipToNetworkOrder(src_addr) == old_ip_net) {
                // this IP was a source — remove all its entries for this policy's targets
                var dst_ips = store.lookupServiceNames(alloc, pol.target_service) catch {
                    log.warn("policy: failed to resolve target service '{s}' during removal", .{pol.target_service});
                    continue;
                };
                defer {
                    for (dst_ips.items) |d| alloc.free(d);
                    dst_ips.deinit(alloc);
                }
                for (dst_ips.items) |dst_str| {
                    const dst_addr = ip_mod.parseIp(dst_str) orelse continue;
                    const dst_net = ebpf.ipToNetworkOrder(dst_addr);
                    if (is_allow) {
                        enforcer.removeAllow(old_ip_net, dst_net);
                    } else {
                        enforcer.removeDeny(old_ip_net, dst_net);
                    }
                }
            }
        }

        // check if this IP was a target
        var dst_ips = store.lookupServiceNames(alloc, pol.target_service) catch {
            log.warn("policy: failed to resolve target service '{s}' during removal", .{pol.target_service});
            continue;
        };
        defer {
            for (dst_ips.items) |d| alloc.free(d);
            dst_ips.deinit(alloc);
        }

        for (dst_ips.items) |dst_str| {
            const dst_addr = ip_mod.parseIp(dst_str) orelse continue;
            if (ebpf.ipToNetworkOrder(dst_addr) == old_ip_net) {
                // this IP was a target — remove all entries pointing to it
                for (src_ips.items) |src_str| {
                    const src_addr = ip_mod.parseIp(src_str) orelse continue;
                    const src_net = ebpf.ipToNetworkOrder(src_addr);
                    if (is_allow) {
                        enforcer.removeAllow(src_net, old_ip_net);
                    } else {
                        enforcer.removeDeny(src_net, old_ip_net);
                    }
                }
            }
        }
    }
}

// -- tests --

test "syncPolicies — no-op without enforcer" {
    // when no policy enforcer is loaded, syncPolicies returns immediately.
    // this exercises the `orelse return` guard at the top.
    syncPolicies(std.testing.allocator);
}

test "applyForContainer — no-op without enforcer" {
    // when no policy enforcer is loaded, applyForContainer returns immediately.
    applyForContainer("myservice", .{ 10, 42, 0, 5 }, std.testing.allocator);
}

test "removeForContainer — no-op without enforcer" {
    // when no policy enforcer is loaded, removeForContainer returns immediately.
    removeForContainer(.{ 10, 42, 0, 5 }, std.testing.allocator);
}
