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
// service names are resolved to canonical service VIPs via
// store.lookupServiceAddresses().
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
    pub const PolicyEnforcer = struct {
        pub fn clear(_: *const @This()) void {}
        pub fn isolate(_: *const @This(), _: u32) void {}
        pub fn unisolate(_: *const @This(), _: u32) void {}
        pub fn addAllow(_: *const @This(), _: u32, _: u32) void {}
        pub fn addDeny(_: *const @This(), _: u32, _: u32) void {}
        pub fn removeAllow(_: *const @This(), _: u32, _: u32) void {}
        pub fn removeDeny(_: *const @This(), _: u32, _: u32) void {}
    };

    var stub_enforcer: PolicyEnforcer = .{};

    pub fn getPolicyEnforcer() ?*const PolicyEnforcer {
        return &stub_enforcer;
    }

    pub fn ipToNetworkOrder(addr: [4]u8) u32 {
        return std.mem.readInt(u32, &addr, .big);
    }
};
const store = @import("../state/store.zig");
const ip_mod = @import("ip.zig");
const log = @import("../lib/log.zig");

const PolicyAction = enum { allow, deny };

/// full sync: rebuild BPF maps from all policies in SQLite.
///
/// reads all network policy rules, resolves service names to IPs,
/// and populates the policy_map and isolation_map from scratch.
/// called after policy changes and during startup.
pub fn syncPolicies(alloc: std.mem.Allocator) void {
    const enforcer = ebpf.getPolicyEnforcer() orelse return;
    syncPoliciesWithEnforcer(alloc, enforcer);
}

fn syncPoliciesWithEnforcer(alloc: std.mem.Allocator, enforcer: anytype) void {
    var policies = store.listNetworkPolicies(alloc) catch {
        log.warn("policy: failed to list policies for sync", .{});
        return;
    };
    defer {
        for (policies.items) |p| p.deinit(alloc);
        policies.deinit(alloc);
    }

    enforcer.clear();

    // for each policy, resolve both service names to IPs and populate maps
    for (policies.items) |pol| {
        var src_ips = store.lookupServiceAddresses(alloc, pol.source_service) catch {
            log.warn("policy: failed to resolve source service '{s}' during sync", .{pol.source_service});
            continue;
        };
        defer {
            for (src_ips.items) |src_ip| alloc.free(src_ip);
            src_ips.deinit(alloc);
        }

        var dst_ips = store.lookupServiceAddresses(alloc, pol.target_service) catch {
            log.warn("policy: failed to resolve target service '{s}' during sync", .{pol.target_service});
            continue;
        };
        defer {
            for (dst_ips.items) |dst_ip| alloc.free(dst_ip);
            dst_ips.deinit(alloc);
        }

        const action = parsePolicyAction(pol.action) orelse {
            log.warn("policy: ignoring invalid action '{s}' for {s} -> {s}", .{ pol.action, pol.source_service, pol.target_service });
            continue;
        };

        // add entries for each (src, dst) pair
        for (src_ips.items) |src_str| {
            const src_addr = ip_mod.parseIp(src_str) orelse {
                log.warn("policy: invalid source IP '{s}' in {s} -> {s}", .{ src_str, pol.source_service, pol.target_service });
                continue;
            };
            const src_net = ebpf.ipToNetworkOrder(src_addr);

            // if this is an allow rule, isolate the source
            if (action == .allow) {
                enforcer.isolate(src_net);
            }

            for (dst_ips.items) |dst_str| {
                const dst_addr = ip_mod.parseIp(dst_str) orelse {
                    log.warn("policy: invalid destination IP '{s}' in {s} -> {s}", .{ dst_str, pol.source_service, pol.target_service });
                    continue;
                };
                const dst_net = ebpf.ipToNetworkOrder(dst_addr);

                switch (action) {
                    .allow => enforcer.addAllow(src_net, dst_net),
                    .deny => enforcer.addDeny(src_net, dst_net),
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
    applyForContainerWithEnforcer(service_name, container_ip, alloc, enforcer);
}

fn applyForContainerWithEnforcer(service_name: []const u8, container_ip: [4]u8, alloc: std.mem.Allocator, enforcer: anytype) void {
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
        const action = parsePolicyAction(pol.action) orelse {
            log.warn("policy: ignoring invalid action '{s}' for container apply", .{pol.action});
            continue;
        };
        const is_source = std.mem.eql(u8, pol.source_service, service_name);
        const is_target = std.mem.eql(u8, pol.target_service, service_name);

        if (!is_source and !is_target) continue;

        if (is_source) {
            // this container is the source — resolve target IPs
            if (action == .allow) {
                enforcer.isolate(new_ip_net);
            }

            var dst_ips = store.lookupServiceAddresses(alloc, pol.target_service) catch {
                log.warn("policy: failed to resolve target service '{s}' for container apply", .{pol.target_service});
                continue;
            };
            defer {
                for (dst_ips.items) |dst_ip| alloc.free(dst_ip);
                dst_ips.deinit(alloc);
            }

            for (dst_ips.items) |dst_str| {
                const dst_addr = ip_mod.parseIp(dst_str) orelse {
                    log.warn("policy: invalid target IP '{s}' for service '{s}'", .{ dst_str, pol.target_service });
                    continue;
                };
                const dst_net = ebpf.ipToNetworkOrder(dst_addr);

                switch (action) {
                    .allow => enforcer.addAllow(new_ip_net, dst_net),
                    .deny => enforcer.addDeny(new_ip_net, dst_net),
                }
            }
        }

        if (is_target) {
            // this container is the target — resolve source IPs
            var src_ips = store.lookupServiceAddresses(alloc, pol.source_service) catch {
                log.warn("policy: failed to resolve source service '{s}' for container apply", .{pol.source_service});
                continue;
            };
            defer {
                for (src_ips.items) |src_ip| alloc.free(src_ip);
                src_ips.deinit(alloc);
            }

            for (src_ips.items) |src_str| {
                const src_addr = ip_mod.parseIp(src_str) orelse {
                    log.warn("policy: invalid source IP '{s}' for service '{s}'", .{ src_str, pol.source_service });
                    continue;
                };
                const src_net = ebpf.ipToNetworkOrder(src_addr);

                switch (action) {
                    .allow => enforcer.addAllow(src_net, new_ip_net),
                    .deny => enforcer.addDeny(src_net, new_ip_net),
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
    removeForContainerWithEnforcer(container_ip, alloc, enforcer);
}

fn removeForContainerWithEnforcer(container_ip: [4]u8, alloc: std.mem.Allocator, enforcer: anytype) void {
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
        const action = parsePolicyAction(pol.action) orelse {
            log.warn("policy: ignoring invalid action '{s}' for container removal", .{pol.action});
            continue;
        };

        // check if this IP was a source
        var src_ips = store.lookupServiceAddresses(alloc, pol.source_service) catch {
            log.warn("policy: failed to resolve source service '{s}' for container removal", .{pol.source_service});
            continue;
        };
        defer {
            for (src_ips.items) |src_ip| alloc.free(src_ip);
            src_ips.deinit(alloc);
        }

        for (src_ips.items) |src_str| {
            const src_addr = ip_mod.parseIp(src_str) orelse continue;
            if (ebpf.ipToNetworkOrder(src_addr) == old_ip_net) {
                // this IP was a source — remove all its entries for this policy's targets
                var dst_ips = store.lookupServiceAddresses(alloc, pol.target_service) catch {
                    log.warn("policy: failed to resolve target service '{s}' during removal", .{pol.target_service});
                    continue;
                };
                defer {
                    for (dst_ips.items) |dst_ip| alloc.free(dst_ip);
                    dst_ips.deinit(alloc);
                }
                for (dst_ips.items) |dst_str| {
                    const dst_addr = ip_mod.parseIp(dst_str) orelse continue;
                    const dst_net = ebpf.ipToNetworkOrder(dst_addr);
                    switch (action) {
                        .allow => enforcer.removeAllow(old_ip_net, dst_net),
                        .deny => enforcer.removeDeny(old_ip_net, dst_net),
                    }
                }
            }
        }

        // check if this IP was a target
        var dst_ips = store.lookupServiceAddresses(alloc, pol.target_service) catch {
            log.warn("policy: failed to resolve target service '{s}' during removal", .{pol.target_service});
            continue;
        };
        defer {
            for (dst_ips.items) |dst_ip| alloc.free(dst_ip);
            dst_ips.deinit(alloc);
        }

        for (dst_ips.items) |dst_str| {
            const dst_addr = ip_mod.parseIp(dst_str) orelse continue;
            if (ebpf.ipToNetworkOrder(dst_addr) == old_ip_net) {
                // this IP was a target — remove all entries pointing to it
                for (src_ips.items) |src_str| {
                    const src_addr = ip_mod.parseIp(src_str) orelse continue;
                    const src_net = ebpf.ipToNetworkOrder(src_addr);
                    switch (action) {
                        .allow => enforcer.removeAllow(src_net, old_ip_net),
                        .deny => enforcer.removeDeny(src_net, old_ip_net),
                    }
                }
            }
        }
    }
}

fn parsePolicyAction(action: []const u8) ?PolicyAction {
    if (std.mem.eql(u8, action, "allow")) return .allow;
    if (std.mem.eql(u8, action, "deny")) return .deny;
    return null;
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

test "syncPolicies clears stale maps before writing deny rules" {
    try store.initTestDb();
    defer store.deinitTestDb();

    try seedService("api", "10.43.0.10");
    try seedService("web", "10.43.0.20");
    try store.addNetworkPolicy("api", "web", "deny");

    var recorder = RecordingSink.init();
    defer recorder.deinit();

    syncPoliciesWithEnforcer(std.testing.allocator, &recorder);

    try recorder.expectOps(&.{
        .{ .kind = .clear },
        .{ .kind = .add_deny, .src = netIp("10.43.0.10"), .dst = netIp("10.43.0.20") },
    });
}

test "syncPolicies isolates allow-list sources and writes allow pairs" {
    try store.initTestDb();
    defer store.deinitTestDb();

    try seedService("api", "10.43.0.10");
    try seedService("db", "10.43.0.30");
    try store.addNetworkPolicy("api", "db", "allow");

    var recorder = RecordingSink.init();
    defer recorder.deinit();

    syncPoliciesWithEnforcer(std.testing.allocator, &recorder);

    try recorder.expectOps(&.{
        .{ .kind = .clear },
        .{ .kind = .isolate, .src = netIp("10.43.0.10") },
        .{ .kind = .add_allow, .src = netIp("10.43.0.10"), .dst = netIp("10.43.0.30") },
    });
}

test "syncPolicies expands legacy service-name endpoints into all policy pairs" {
    try store.initTestDb();
    defer store.deinitTestDb();

    try store.registerServiceName("api", "api-1", "10.42.0.11");
    try store.registerServiceName("api", "api-2", "10.42.0.12");
    try store.registerServiceName("db", "db-1", "10.42.0.21");
    try store.registerServiceName("db", "db-2", "10.42.0.22");
    try store.addNetworkPolicy("api", "db", "deny");

    var recorder = RecordingSink.init();
    defer recorder.deinit();

    syncPoliciesWithEnforcer(std.testing.allocator, &recorder);

    try recorder.expectKindCount(.clear, 1);
    try recorder.expectOp(.{ .kind = .add_deny, .src = netIp("10.42.0.11"), .dst = netIp("10.42.0.21") });
    try recorder.expectOp(.{ .kind = .add_deny, .src = netIp("10.42.0.11"), .dst = netIp("10.42.0.22") });
    try recorder.expectOp(.{ .kind = .add_deny, .src = netIp("10.42.0.12"), .dst = netIp("10.42.0.21") });
    try recorder.expectOp(.{ .kind = .add_deny, .src = netIp("10.42.0.12"), .dst = netIp("10.42.0.22") });
    try std.testing.expectEqual(@as(usize, 5), recorder.ops.items.len);
}

test "applyForContainer adds source-side policy entries for a new container" {
    try store.initTestDb();
    defer store.deinitTestDb();

    try seedService("web", "10.43.0.20");
    try store.addNetworkPolicy("api", "web", "allow");

    var recorder = RecordingSink.init();
    defer recorder.deinit();

    applyForContainerWithEnforcer("api", .{ 10, 42, 0, 99 }, std.testing.allocator, &recorder);

    try recorder.expectOps(&.{
        .{ .kind = .isolate, .src = netIp("10.42.0.99") },
        .{ .kind = .add_allow, .src = netIp("10.42.0.99"), .dst = netIp("10.43.0.20") },
    });
}

test "applyForContainer adds target-side policy entries for a new container" {
    try store.initTestDb();
    defer store.deinitTestDb();

    try seedService("api", "10.43.0.10");
    try store.addNetworkPolicy("api", "web", "deny");

    var recorder = RecordingSink.init();
    defer recorder.deinit();

    applyForContainerWithEnforcer("web", .{ 10, 42, 0, 99 }, std.testing.allocator, &recorder);

    try recorder.expectOps(&.{
        .{ .kind = .add_deny, .src = netIp("10.43.0.10"), .dst = netIp("10.42.0.99") },
    });
}

test "removeForContainer removes source and target policy entries" {
    try store.initTestDb();
    defer store.deinitTestDb();

    try store.registerServiceName("api", "api-old", "10.42.0.99");
    try seedService("web", "10.43.0.20");
    try store.addNetworkPolicy("api", "web", "allow");

    var recorder = RecordingSink.init();
    defer recorder.deinit();

    removeForContainerWithEnforcer(.{ 10, 42, 0, 99 }, std.testing.allocator, &recorder);

    try recorder.expectOps(&.{
        .{ .kind = .unisolate, .src = netIp("10.42.0.99") },
        .{ .kind = .remove_allow, .src = netIp("10.42.0.99"), .dst = netIp("10.43.0.20") },
    });
}

test "policy sync skips unresolved services and malformed service IPs" {
    try store.initTestDb();
    defer store.deinitTestDb();

    try seedService("web", "10.43.0.20");
    try store.registerServiceName("bad", "bad-1", "not-an-ip");
    try store.addNetworkPolicy("missing", "web", "deny");
    try store.addNetworkPolicy("bad", "web", "allow");
    try store.addNetworkPolicy("web", "bad", "deny");

    var recorder = RecordingSink.init();
    defer recorder.deinit();

    syncPoliciesWithEnforcer(std.testing.allocator, &recorder);

    try recorder.expectOps(&.{
        .{ .kind = .clear },
    });
}

const RecordedKind = enum {
    clear,
    isolate,
    unisolate,
    add_allow,
    add_deny,
    remove_allow,
    remove_deny,
};

const RecordedOp = struct {
    kind: RecordedKind,
    src: u32 = 0,
    dst: u32 = 0,
};

const RecordingSink = struct {
    ops: std.ArrayListUnmanaged(RecordedOp),

    fn init() RecordingSink {
        return .{ .ops = .empty };
    }

    fn deinit(self: *RecordingSink) void {
        self.ops.deinit(std.testing.allocator);
    }

    fn clear(self: *RecordingSink) void {
        self.append(.{ .kind = .clear });
    }

    fn isolate(self: *RecordingSink, src_ip: u32) void {
        self.append(.{ .kind = .isolate, .src = src_ip });
    }

    fn unisolate(self: *RecordingSink, src_ip: u32) void {
        self.append(.{ .kind = .unisolate, .src = src_ip });
    }

    fn addAllow(self: *RecordingSink, src_ip: u32, dst_ip: u32) void {
        self.append(.{ .kind = .add_allow, .src = src_ip, .dst = dst_ip });
    }

    fn addDeny(self: *RecordingSink, src_ip: u32, dst_ip: u32) void {
        self.append(.{ .kind = .add_deny, .src = src_ip, .dst = dst_ip });
    }

    fn removeAllow(self: *RecordingSink, src_ip: u32, dst_ip: u32) void {
        self.append(.{ .kind = .remove_allow, .src = src_ip, .dst = dst_ip });
    }

    fn removeDeny(self: *RecordingSink, src_ip: u32, dst_ip: u32) void {
        self.append(.{ .kind = .remove_deny, .src = src_ip, .dst = dst_ip });
    }

    fn append(self: *RecordingSink, op: RecordedOp) void {
        self.ops.append(std.testing.allocator, op) catch @panic("policy test recorder out of memory");
    }

    fn expectOps(self: *const RecordingSink, expected: []const RecordedOp) !void {
        try std.testing.expectEqual(expected.len, self.ops.items.len);
        for (expected, self.ops.items) |want, got| {
            try std.testing.expectEqual(want.kind, got.kind);
            try std.testing.expectEqual(want.src, got.src);
            try std.testing.expectEqual(want.dst, got.dst);
        }
    }

    fn expectOp(self: *const RecordingSink, expected: RecordedOp) !void {
        for (self.ops.items) |got| {
            if (got.kind == expected.kind and got.src == expected.src and got.dst == expected.dst) return;
        }
        return error.ExpectedPolicyOperationMissing;
    }

    fn expectKindCount(self: *const RecordingSink, kind: RecordedKind, expected_count: usize) !void {
        var count: usize = 0;
        for (self.ops.items) |op| {
            if (op.kind == kind) count += 1;
        }
        try std.testing.expectEqual(expected_count, count);
    }
};

fn seedService(name: []const u8, vip: []const u8) !void {
    try store.createService(.{
        .service_name = name,
        .vip_address = vip,
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
}

fn netIp(ip: []const u8) u32 {
    return ebpf.ipToNetworkOrder(ip_mod.parseIp(ip) orelse @panic("invalid test IP"));
}
