const std = @import("std");
const builtin = @import("builtin");
const sqlite = @import("sqlite");
const log = @import("../../lib/log.zig");
const ip_mod = @import("../ip.zig");
const policy = @import("../policy.zig");
const packet_support = @import("packet_support.zig");
const service_observability = @import("../service_observability.zig");
const rollout = @import("../service_rollout.zig");
const store = @import("../../state/store.zig");

const ebpf = if (builtin.os.tag == .linux) @import("../ebpf.zig") else struct {
    pub const LoadBalancerBackends = struct {
        count: u32 = 0,
        ips: [16]u32 = [_]u32{0} ** 16,
    };

    pub const DnsInterceptor = struct {
        pub fn updateService(_: *@This(), _: []const u8, _: [4]u8) void {}
        pub fn deleteService(_: *@This(), _: []const u8) void {}
        pub fn lookupService(_: *@This(), _: []const u8) ?[4]u8 {
            return null;
        }
    };

    pub const LoadBalancer = struct {
        pub fn addBackend(_: *@This(), _: [4]u8, _: [4]u8) void {}
        pub fn removeBackend(_: *@This(), _: [4]u8, _: [4]u8) void {}
        pub fn lookupBackends(_: *@This(), _: [4]u8) ?LoadBalancerBackends {
            return null;
        }
    };

    var dns_interceptor: DnsInterceptor = .{};
    var load_balancer: LoadBalancer = .{};

    pub fn getDnsInterceptor() ?*DnsInterceptor {
        return &dns_interceptor;
    }

    pub fn getLoadBalancer() ?*LoadBalancer {
        return &load_balancer;
    }
};

pub const max_services = 1024;
pub const max_name_len = 63;
pub const max_backends_per_service = 64;

const ServiceEntry = struct {
    name: [max_name_len]u8,
    name_len: u8,
    container_id: [12]u8,
    container_id_len: u8,
    ip: [4]u8,
    active: bool,
};

const ServiceBackend = struct {
    container_id: [12]u8,
    container_id_len: u8,
    ip: [4]u8,
};

const ServiceView = struct {
    name: [max_name_len]u8,
    name_len: u8,
    dns_ip: [4]u8,
    backend_count: u8,
    backends: [max_backends_per_service]ServiceBackend,
    active: bool,
};

pub const ConflictInfo = struct {
    ip: [4]u8,
    container_id: [12]u8,
    container_id_len: u8,
};

pub const RegistryEntrySnapshot = struct {
    container_id: []const u8,
    ip: [4]u8,

    pub fn deinit(self: RegistryEntrySnapshot, alloc: std.mem.Allocator) void {
        alloc.free(self.container_id);
    }
};

pub const BackendBinding = struct {
    container_id: []const u8,
    ip: [4]u8,
};

pub const ClusterLookupFaultMode = enum {
    none,
    force_miss,
    stale_override,

    pub fn label(self: ClusterLookupFaultMode) []const u8 {
        return switch (self) {
            .none => "none",
            .force_miss => "force_miss",
            .stale_override => "stale_override",
        };
    }
};

pub const DnsInterceptorFaultMode = enum {
    none,
    unavailable,

    pub fn label(self: DnsInterceptorFaultMode) []const u8 {
        return switch (self) {
            .none => "none",
            .unavailable => "unavailable",
        };
    }
};

pub const LoadBalancerFaultMode = enum {
    none,
    endpoint_overflow,

    pub fn label(self: LoadBalancerFaultMode) []const u8 {
        return switch (self) {
            .none => "none",
            .endpoint_overflow => "endpoint_overflow",
        };
    }
};

var registry: [max_services]ServiceEntry = [_]ServiceEntry{.{
    .name = undefined,
    .name_len = 0,
    .container_id = undefined,
    .container_id_len = 0,
    .ip = .{ 0, 0, 0, 0 },
    .active = false,
}} ** max_services;
var registry_count: usize = 0;
var service_views: [max_services]ServiceView = [_]ServiceView{.{
    .name = undefined,
    .name_len = 0,
    .dns_ip = .{ 0, 0, 0, 0 },
    .backend_count = 0,
    .backends = undefined,
    .active = false,
}} ** max_services;
var registry_mutex: @import("compat").Mutex = .{};

var cluster_db: ?*sqlite.Db = null;
var cluster_db_mutex: @import("compat").Mutex = .{};
var cluster_lookup_fault_mode: ClusterLookupFaultMode = .none;
var cluster_lookup_fault_ip: [4]u8 = .{ 10, 255, 255, 254 };
var cluster_lookup_fault_injections: u64 = 0;
var dns_interceptor_fault_mutex: @import("compat").Mutex = .{};
var dns_interceptor_fault_mode: DnsInterceptorFaultMode = .none;
var dns_interceptor_fault_injections: u64 = 0;
var load_balancer_fault_mutex: @import("compat").Mutex = .{};
var load_balancer_fault_mode: LoadBalancerFaultMode = .none;
var load_balancer_fault_injections: u64 = 0;

pub fn setClusterDb(db: ?*sqlite.Db) void {
    cluster_db_mutex.lock();
    defer cluster_db_mutex.unlock();
    cluster_db = db;
}

pub fn currentClusterDb() ?*sqlite.Db {
    cluster_db_mutex.lock();
    defer cluster_db_mutex.unlock();
    return cluster_db;
}

pub fn lookupClusterService(name: []const u8) ?[4]u8 {
    if (name.len == 0 or name.len > max_name_len) return null;

    cluster_db_mutex.lock();
    defer cluster_db_mutex.unlock();

    switch (cluster_lookup_fault_mode) {
        .none => {},
        .force_miss => {
            cluster_lookup_fault_injections += 1;
            log.warn("dns: injected cluster lookup fault mode={s} for '{s}'", .{ cluster_lookup_fault_mode.label(), name });
            return null;
        },
        .stale_override => {
            cluster_lookup_fault_injections += 1;
            log.warn("dns: injected cluster lookup fault mode={s} for '{s}' -> {d}.{d}.{d}.{d}", .{
                cluster_lookup_fault_mode.label(),
                name,
                cluster_lookup_fault_ip[0],
                cluster_lookup_fault_ip[1],
                cluster_lookup_fault_ip[2],
                cluster_lookup_fault_ip[3],
            });
            return cluster_lookup_fault_ip;
        },
    }

    const db = cluster_db orelse return null;
    return lookupClusterServiceVip(db, name) orelse lookupClusterLegacyName(db, name);
}

fn lookupClusterServiceVip(db: *sqlite.Db, name: []const u8) ?[4]u8 {
    const Row = struct { vip_address: sqlite.Text };

    var stmt = db.prepare(
        "SELECT vip_address FROM services WHERE service_name = ? LIMIT 1;",
    ) catch return null;
    defer stmt.deinit();

    const row = stmt.oneAlloc(Row, std.heap.page_allocator, .{}, .{name}) catch return null;
    if (row) |r| {
        defer std.heap.page_allocator.free(r.vip_address.data);
        return ip_mod.parseIp(r.vip_address.data);
    }
    return null;
}

fn lookupClusterLegacyName(db: *sqlite.Db, name: []const u8) ?[4]u8 {
    const Row = struct { ip_address: sqlite.Text };

    var stmt = db.prepare(
        "SELECT ip_address FROM service_names WHERE name = ? ORDER BY registered_at DESC LIMIT 1;",
    ) catch return null;
    defer stmt.deinit();

    const row = stmt.oneAlloc(Row, std.heap.page_allocator, .{}, .{name}) catch return null;
    if (row) |r| {
        defer std.heap.page_allocator.free(r.ip_address.data);
        return ip_mod.parseIp(r.ip_address.data);
    }
    return null;
}

pub fn registerService(name: []const u8, container_id: []const u8, container_ip: [4]u8) void {
    if (name.len == 0 or name.len > max_name_len) return;

    if (container_id.len == 0) {
        log.warn("dns: rejected attempt to register service '{s}' with empty container_id", .{name});
        return;
    }

    for (name) |c| {
        if (c < 0x21 or c > 0x7e) return;
    }

    if (!isSafeIpForDns(container_ip)) {
        log.err("dns: rejected attempt to register service '{s}' with unsafe IP {d}.{d}.{d}.{d}", .{
            name, container_ip[0], container_ip[1], container_ip[2], container_ip[3],
        });
        return;
    }

    registry_mutex.lock();
    defer registry_mutex.unlock();

    for (&registry) |*entry| {
        if (entry.active and
            entry.name_len == name.len and
            std.mem.eql(u8, entry.name[0..entry.name_len], name) and
            entry.container_id_len == container_id.len and
            std.mem.eql(u8, entry.container_id[0..entry.container_id_len], container_id))
        {
            entry.ip = container_ip;
            updateBpfMap(name, container_ip);
            return;
        }
    }

    if (detectNameConflictLocked(name, container_id, container_ip)) |prev| {
        log.warn("dns: service name '{s}' reassigned from {d}.{d}.{d}.{d} ({s}) to {d}.{d}.{d}.{d} ({s})", .{
            name,
            prev.ip[0],
            prev.ip[1],
            prev.ip[2],
            prev.ip[3],
            prev.container_id[0..prev.container_id_len],
            container_ip[0],
            container_ip[1],
            container_ip[2],
            container_ip[3],
            container_id[0..@min(container_id.len, 12)],
        });
    }

    for (&registry) |*entry| {
        if (!entry.active) {
            entry.active = true;
            entry.name_len = @intCast(name.len);
            @memcpy(entry.name[0..name.len], name);
            const cid_len: usize = @min(container_id.len, 12);
            entry.container_id_len = @intCast(cid_len);
            @memcpy(entry.container_id[0..cid_len], container_id[0..cid_len]);
            entry.ip = container_ip;
            registry_count += 1;
            updateBpfMap(name, container_ip);
            return;
        }
    }

    log.warn("dns registry full, cannot register {s}", .{name});
}

pub fn unregisterService(container_id: []const u8) void {
    if (container_id.len == 0) {
        log.warn("dns: unregisterService called with empty container_id", .{});
        return;
    }

    registry_mutex.lock();
    defer registry_mutex.unlock();

    const cid_len = @min(container_id.len, 12);
    for (&registry) |*entry| {
        if (entry.active and
            entry.container_id_len == cid_len and
            std.mem.eql(u8, entry.container_id[0..entry.container_id_len], container_id[0..cid_len]))
        {
            const name = entry.name[0..entry.name_len];
            const old_ip = entry.ip;
            policy.removeForContainer(old_ip, std.heap.page_allocator);
            deleteBpfBackend(name, old_ip);
            entry.active = false;
            registry_count -= 1;

            if (findLatestActiveEntryLocked(name)) |survivor| {
                updateBpfMap(survivor.name[0..survivor.name_len], survivor.ip);
            } else {
                deleteBpfMap(name);
            }
        }
    }
}

pub fn unregisterServiceEndpoint(name: []const u8, container_id: []const u8) void {
    if (container_id.len == 0 or name.len == 0) {
        log.warn("dns: unregisterServiceEndpoint called with empty name/container_id", .{});
        return;
    }

    registry_mutex.lock();
    defer registry_mutex.unlock();

    const cid_len = @min(container_id.len, 12);
    for (&registry) |*entry| {
        if (entry.active and
            entry.name_len == name.len and
            std.mem.eql(u8, entry.name[0..entry.name_len], name) and
            entry.container_id_len == cid_len and
            std.mem.eql(u8, entry.container_id[0..entry.container_id_len], container_id[0..cid_len]))
        {
            const old_ip = entry.ip;
            policy.removeForContainer(old_ip, std.heap.page_allocator);
            deleteBpfBackend(name, old_ip);
            entry.active = false;
            registry_count -= 1;

            if (findLatestActiveEntryLocked(name)) |survivor| {
                updateBpfMap(survivor.name[0..survivor.name_len], survivor.ip);
            } else {
                deleteBpfMap(name);
            }
            return;
        }
    }
}

pub fn replaceServiceState(name: []const u8, dns_ip: [4]u8, backends: []const BackendBinding) void {
    if (name.len == 0 or name.len > max_name_len) return;
    if (!isSafeIpForDns(dns_ip)) return;

    registry_mutex.lock();
    defer registry_mutex.unlock();

    const view_index = findOrCreateServiceViewLocked(name) orelse {
        log.warn("dns: service view full, cannot replace state for {s}", .{name});
        return;
    };
    var view = &service_views[view_index];
    view.dns_ip = dns_ip;

    if (backends.len > max_backends_per_service) {
        log.warn("dns: service {s} has {d} backends, exceeds max {d}; programming zero-backend VIP", .{
            name,
            backends.len,
            max_backends_per_service,
        });
        view.backend_count = 0;
    } else {
        view.backend_count = @intCast(backends.len);
        for (backends, 0..) |backend, idx| {
            const cid_len = @min(backend.container_id.len, 12);
            view.backends[idx].container_id_len = @intCast(cid_len);
            @memcpy(view.backends[idx].container_id[0..cid_len], backend.container_id[0..cid_len]);
            view.backends[idx].ip = backend.ip;
        }
    }

    updateBpfMap(name, dns_ip);
    replaceBpfBackendsLocked(name, dns_ip, view.backends[0..view.backend_count]);
}

pub fn removeServiceState(name: []const u8) void {
    if (name.len == 0 or name.len > max_name_len) return;

    registry_mutex.lock();
    defer registry_mutex.unlock();

    const view_index = findServiceViewIndexLocked(name) orelse {
        deleteBpfMap(name);
        deleteAllBpfBackendsLocked(name);
        return;
    };
    const vip = service_views[view_index].dns_ip;
    service_views[view_index].active = false;
    service_views[view_index].backend_count = 0;

    deleteBpfMap(name);
    deleteAllBpfBackendsLockedVip(vip);
}

pub fn lookupService(name: []const u8) ?[4]u8 {
    {
        registry_mutex.lock();
        defer registry_mutex.unlock();

        if (findServiceViewLocked(name)) |view| return view.dns_ip;

        var i: usize = max_services;
        while (i > 0) {
            i -= 1;
            const entry = &registry[i];
            if (entry.active and
                entry.name_len == name.len and
                std.mem.eql(u8, entry.name[0..entry.name_len], name))
            {
                return entry.ip;
            }
        }
    }

    return lookupClusterService(name);
}

pub fn lookupServiceForDns(name: []const u8) ?[4]u8 {
    {
        registry_mutex.lock();
        defer registry_mutex.unlock();

        if (findServiceViewLocked(name)) |view| {
            if (ebpf.getLoadBalancer() == null and view.backend_count > 0) {
                return view.backends[0].ip;
            }
            return view.dns_ip;
        }

        var i: usize = max_services;
        while (i > 0) {
            i -= 1;
            const entry = &registry[i];
            if (entry.active and
                entry.name_len == name.len and
                std.mem.eql(u8, entry.name[0..entry.name_len], name))
            {
                return entry.ip;
            }
        }
    }

    if (lookupPersistedLocalService(name)) |ip| return ip;
    return lookupClusterService(name);
}

pub fn lookupLocalService(name: []const u8) ?[4]u8 {
    registry_mutex.lock();
    defer registry_mutex.unlock();

    if (findServiceViewLocked(name)) |view| return view.dns_ip;

    var i: usize = max_services;
    while (i > 0) {
        i -= 1;
        const entry = &registry[i];
        if (entry.active and
            entry.name_len == name.len and
            std.mem.eql(u8, entry.name[0..entry.name_len], name))
        {
            return entry.ip;
        }
    }
    return null;
}

fn lookupPersistedLocalService(name: []const u8) ?[4]u8 {
    var db = store.openDb() catch return null;
    defer db.deinit();

    const Row = struct { ip_address: sqlite.Text };

    var stmt = db.prepare(
        "SELECT ip_address FROM service_names WHERE name = ? ORDER BY registered_at DESC LIMIT 1;",
    ) catch return null;
    defer stmt.deinit();

    const row = stmt.oneAlloc(Row, std.heap.page_allocator, .{}, .{name}) catch return null;
    if (row) |r| {
        defer std.heap.page_allocator.free(r.ip_address.data);
        return ip_mod.parseIp(r.ip_address.data);
    }
    return null;
}

pub fn snapshotServiceEntries(alloc: std.mem.Allocator, name: []const u8) !std.ArrayList(RegistryEntrySnapshot) {
    var entries: std.ArrayList(RegistryEntrySnapshot) = .empty;
    errdefer {
        for (entries.items) |entry| entry.deinit(alloc);
        entries.deinit(alloc);
    }

    registry_mutex.lock();
    defer registry_mutex.unlock();

    if (findServiceViewLocked(name)) |view| {
        for (view.backends[0..view.backend_count]) |backend| {
            try entries.append(alloc, .{
                .container_id = try alloc.dupe(u8, backend.container_id[0..backend.container_id_len]),
                .ip = backend.ip,
            });
        }
        return entries;
    }

    for (&registry) |entry| {
        if (!entry.active) continue;
        if (entry.name_len != name.len) continue;
        if (!std.mem.eql(u8, entry.name[0..entry.name_len], name)) continue;

        try entries.append(alloc, .{
            .container_id = try alloc.dupe(u8, entry.container_id[0..entry.container_id_len]),
            .ip = entry.ip,
        });
    }

    return entries;
}

pub fn lookupDnsInterceptorService(name: []const u8) ?[4]u8 {
    if (ebpf.getDnsInterceptor()) |interceptor| {
        return interceptor.lookupService(name);
    }
    return null;
}

pub fn currentLoadBalancerVip(name: []const u8) ?[4]u8 {
    registry_mutex.lock();
    defer registry_mutex.unlock();
    if (findServiceViewLocked(name)) |view| return view.dns_ip;
    return getServiceVip(name);
}

pub fn snapshotLoadBalancerBackends(alloc: std.mem.Allocator, name: []const u8) !?std.ArrayList([4]u8) {
    const lb = ebpf.getLoadBalancer() orelse return null;
    var backends: std.ArrayList([4]u8) = .empty;
    errdefer backends.deinit(alloc);

    const vip = currentLoadBalancerVip(name) orelse return backends;
    const snapshot = lb.lookupBackends(vip) orelse return backends;
    const count: usize = @intCast(snapshot.count);
    for (0..count) |i| {
        try backends.append(alloc, @bitCast(snapshot.ips[i]));
    }
    return backends;
}

fn findServiceViewLocked(name: []const u8) ?*const ServiceView {
    const idx = findServiceViewIndexLocked(name) orelse return null;
    return &service_views[idx];
}

fn findServiceViewIndexLocked(name: []const u8) ?usize {
    for (&service_views, 0..) |*view, idx| {
        if (!view.active) continue;
        if (view.name_len != name.len) continue;
        if (std.mem.eql(u8, view.name[0..view.name_len], name)) return idx;
    }
    return null;
}

fn findOrCreateServiceViewLocked(name: []const u8) ?usize {
    if (findServiceViewIndexLocked(name)) |idx| return idx;

    for (&service_views, 0..) |*view, idx| {
        if (view.active) continue;
        view.active = true;
        view.name_len = @intCast(name.len);
        @memcpy(view.name[0..name.len], name);
        view.backend_count = 0;
        return idx;
    }
    return null;
}

pub fn parseResolvConf(content: []const u8) ?[4]u8 {
    var pos: usize = 0;
    while (pos < content.len) {
        const line_end = std.mem.indexOfPos(u8, content, pos, "\n") orelse content.len;
        const line = content[pos..line_end];
        pos = if (line_end < content.len) line_end + 1 else content.len;

        const trimmed = std.mem.trimStart(u8, line, " \t");
        if (trimmed.len == 0 or trimmed[0] == '#' or trimmed[0] == ';') continue;

        const prefix = "nameserver";
        if (trimmed.len <= prefix.len) continue;
        if (!std.mem.eql(u8, trimmed[0..prefix.len], prefix)) continue;
        if (trimmed[prefix.len] != ' ' and trimmed[prefix.len] != '\t') continue;

        const addr_str = std.mem.trimStart(u8, trimmed[prefix.len..], " \t");
        const addr_clean = std.mem.trimEnd(u8, addr_str, " \t\r");
        if (addr_clean.len == 0) continue;
        if (ip_mod.parseIp(addr_clean)) |addr| return addr;
    }
    return null;
}

pub fn detectNameConflict(name: []const u8, new_container_id: []const u8, ip_addr: [4]u8) ?ConflictInfo {
    registry_mutex.lock();
    defer registry_mutex.unlock();
    return detectNameConflictLocked(name, new_container_id, ip_addr);
}

fn detectNameConflictLocked(name: []const u8, new_container_id: []const u8, _: [4]u8) ?ConflictInfo {
    const new_cid_len = @min(new_container_id.len, 12);

    var i: usize = max_services;
    while (i > 0) {
        i -= 1;
        const entry = &registry[i];
        if (entry.active and
            entry.name_len == name.len and
            std.mem.eql(u8, entry.name[0..entry.name_len], name))
        {
            if (entry.container_id_len == new_cid_len and
                std.mem.eql(u8, entry.container_id[0..entry.container_id_len], new_container_id[0..new_cid_len]))
            {
                return null;
            }

            return .{
                .ip = entry.ip,
                .container_id = entry.container_id,
                .container_id_len = entry.container_id_len,
            };
        }
    }

    return null;
}

pub fn resetRegistryForTest() void {
    registry_mutex.lock();
    defer registry_mutex.unlock();

    for (&registry) |*entry| {
        entry.active = false;
    }
    for (&service_views) |*view| {
        view.active = false;
        view.backend_count = 0;
    }
    registry_count = 0;
}

pub fn clusterLookupFaultMode() ClusterLookupFaultMode {
    cluster_db_mutex.lock();
    defer cluster_db_mutex.unlock();
    return cluster_lookup_fault_mode;
}

pub fn clusterLookupFaultIp() [4]u8 {
    cluster_db_mutex.lock();
    defer cluster_db_mutex.unlock();
    return cluster_lookup_fault_ip;
}

pub fn clusterLookupFaultInjectionCount() u64 {
    cluster_db_mutex.lock();
    defer cluster_db_mutex.unlock();
    return cluster_lookup_fault_injections;
}

pub fn setClusterLookupFaultForTest(mode: ClusterLookupFaultMode, ip: ?[4]u8) void {
    cluster_db_mutex.lock();
    defer cluster_db_mutex.unlock();
    cluster_lookup_fault_mode = mode;
    if (ip) |fault_ip| cluster_lookup_fault_ip = fault_ip;
}

pub fn resetClusterLookupFaultsForTest() void {
    cluster_db_mutex.lock();
    defer cluster_db_mutex.unlock();
    cluster_lookup_fault_mode = .none;
    cluster_lookup_fault_ip = .{ 10, 255, 255, 254 };
    cluster_lookup_fault_injections = 0;
}

pub fn dnsInterceptorFaultMode() DnsInterceptorFaultMode {
    dns_interceptor_fault_mutex.lock();
    defer dns_interceptor_fault_mutex.unlock();
    return dns_interceptor_fault_mode;
}

pub fn dnsInterceptorFaultInjectionCount() u64 {
    dns_interceptor_fault_mutex.lock();
    defer dns_interceptor_fault_mutex.unlock();
    return dns_interceptor_fault_injections;
}

pub fn setDnsInterceptorFaultModeForTest(mode: DnsInterceptorFaultMode) void {
    dns_interceptor_fault_mutex.lock();
    defer dns_interceptor_fault_mutex.unlock();
    dns_interceptor_fault_mode = mode;
}

pub fn resetDnsInterceptorFaultsForTest() void {
    dns_interceptor_fault_mutex.lock();
    defer dns_interceptor_fault_mutex.unlock();
    dns_interceptor_fault_mode = .none;
    dns_interceptor_fault_injections = 0;
}

pub fn loadBalancerFaultMode() LoadBalancerFaultMode {
    load_balancer_fault_mutex.lock();
    defer load_balancer_fault_mutex.unlock();
    return load_balancer_fault_mode;
}

pub fn loadBalancerFaultInjectionCount() u64 {
    load_balancer_fault_mutex.lock();
    defer load_balancer_fault_mutex.unlock();
    return load_balancer_fault_injections;
}

pub fn setLoadBalancerFaultModeForTest(mode: LoadBalancerFaultMode) void {
    load_balancer_fault_mutex.lock();
    defer load_balancer_fault_mutex.unlock();
    load_balancer_fault_mode = mode;
}

pub fn resetLoadBalancerFaultsForTest() void {
    load_balancer_fault_mutex.lock();
    defer load_balancer_fault_mutex.unlock();
    load_balancer_fault_mode = .none;
    load_balancer_fault_injections = 0;
}

fn isSafeIpForDns(ip: [4]u8) bool {
    const ip_u32 = packet_support.ipToU32(ip);
    if (ip_u32 == 0) return false;
    if ((ip_u32 & 0xFF000000) == 0x7F000000) return false;
    if ((ip_u32 & 0xF0000000) == 0xE0000000) return false;
    if (ip_u32 == 0xFFFFFFFF) return false;
    if (ip_u32 == 0xFEA9FEA9) return false;
    return true;
}

fn updateBpfMap(name: []const u8, ip_addr: [4]u8) void {
    if (shouldSkipDnsInterceptorApply("update", name)) return;

    if (ebpf.getDnsInterceptor()) |interceptor| {
        interceptor.updateService(name, ip_addr);
    }
}

fn deleteBpfMap(name: []const u8) void {
    if (shouldSkipDnsInterceptorApply("delete", name)) return;

    if (ebpf.getDnsInterceptor()) |interceptor| {
        _ = interceptor.deleteService(name);
    }
}

fn deleteBpfBackend(name: []const u8, ip_addr: [4]u8) void {
    if (ebpf.getLoadBalancer()) |lb| {
        const vip = getServiceVip(name) orelse ip_addr;
        lb.removeBackend(vip, ip_addr);
    }
}

fn deleteAllBpfBackendsLocked(name: []const u8) void {
    const vip = currentLoadBalancerVipLocked(name) orelse return;
    deleteAllBpfBackendsLockedVip(vip);
}

fn deleteAllBpfBackendsLockedVip(vip: [4]u8) void {
    if (ebpf.getLoadBalancer()) |lb| {
        lb.deleteBackends(vip);
    }
}

fn getServiceVip(name: []const u8) ?[4]u8 {
    if (findServiceViewLocked(name)) |view| return view.dns_ip;

    for (&registry) |*entry| {
        if (entry.active and
            entry.name_len == name.len and
            std.mem.eql(u8, entry.name[0..entry.name_len], name))
        {
            return entry.ip;
        }
    }
    return null;
}

fn replaceBpfBackendsLocked(name: []const u8, dns_ip: [4]u8, backends: []const ServiceBackend) void {
    if (shouldSkipLoadBalancerAdd(name, dns_ip, if (backends.len > 0) backends[0].ip else dns_ip)) {
        return;
    }

    if (ebpf.getLoadBalancer()) |lb| {
        var backend_ips: [max_backends_per_service][4]u8 = undefined;
        for (backends, 0..) |backend, idx| backend_ips[idx] = backend.ip;
        lb.replaceBackends(dns_ip, backend_ips[0..backends.len]) catch |err| {
            service_observability.noteBpfSyncFailure(name, .load_balancer);
            log.warn("dns: failed to replace load balancer backends for {s}: {}", .{ name, err });
        };
    }
}

fn currentLoadBalancerVipLocked(name: []const u8) ?[4]u8 {
    if (findServiceViewLocked(name)) |view| return view.dns_ip;
    return getServiceVip(name);
}

fn findLatestActiveEntryLocked(name: []const u8) ?*const ServiceEntry {
    var i: usize = max_services;
    while (i > 0) {
        i -= 1;
        const entry = &registry[i];
        if (entry.active and
            entry.name_len == name.len and
            std.mem.eql(u8, entry.name[0..entry.name_len], name))
        {
            return entry;
        }
    }
    return null;
}

fn shouldSkipDnsInterceptorApply(operation: []const u8, name: []const u8) bool {
    dns_interceptor_fault_mutex.lock();
    defer dns_interceptor_fault_mutex.unlock();

    if (dns_interceptor_fault_mode == .none) return false;

    dns_interceptor_fault_injections += 1;
    service_observability.noteBpfSyncFailure(name, .dns_interceptor);
    log.warn("dns: injected interceptor fault mode={s} operation={s} name='{s}'", .{
        dns_interceptor_fault_mode.label(),
        operation,
        name,
    });
    return true;
}

fn shouldSkipLoadBalancerAdd(name: []const u8, vip: [4]u8, backend_ip: [4]u8) bool {
    load_balancer_fault_mutex.lock();
    defer load_balancer_fault_mutex.unlock();

    if (load_balancer_fault_mode == .none) return false;

    load_balancer_fault_injections += 1;
    service_observability.noteBpfSyncFailure(name, .load_balancer);
    log.warn("dns: injected load balancer fault mode={s} service='{s}' vip={d}.{d}.{d}.{d} backend={d}.{d}.{d}.{d}", .{
        load_balancer_fault_mode.label(),
        name,
        vip[0],
        vip[1],
        vip[2],
        vip[3],
        backend_ip[0],
        backend_ip[1],
        backend_ip[2],
        backend_ip[3],
    });
    return true;
}

test "snapshotServiceEntries returns active endpoints for a service" {
    resetRegistryForTest();
    defer resetRegistryForTest();

    registerService("api", "ctr-1", .{ 10, 42, 0, 9 });
    registerService("api", "ctr-2", .{ 10, 42, 0, 10 });
    registerService("web", "ctr-3", .{ 10, 42, 0, 11 });

    var entries = try snapshotServiceEntries(std.testing.allocator, "api");
    defer {
        for (entries.items) |entry| entry.deinit(std.testing.allocator);
        entries.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 2), entries.items.len);
    try std.testing.expectEqualStrings("ctr-1", entries.items[0].container_id);
    try std.testing.expectEqual(@as([4]u8, .{ 10, 42, 0, 9 }), entries.items[0].ip);
    try std.testing.expectEqualStrings("ctr-2", entries.items[1].container_id);
    try std.testing.expectEqual(@as([4]u8, .{ 10, 42, 0, 10 }), entries.items[1].ip);
}

test "replaceServiceState exposes stable vip and backend set" {
    rollout.setForTest(.{ .dns_returns_vip = true });
    defer rollout.resetForTest();
    resetRegistryForTest();
    defer resetRegistryForTest();

    const backends = [_]BackendBinding{
        .{ .container_id = "ctr-1", .ip = .{ 10, 42, 0, 9 } },
        .{ .container_id = "ctr-2", .ip = .{ 10, 42, 0, 10 } },
    };
    replaceServiceState("api", .{ 10, 43, 0, 2 }, &backends);

    try std.testing.expectEqual(@as(?[4]u8, .{ 10, 43, 0, 2 }), lookupLocalService("api"));

    var entries = try snapshotServiceEntries(std.testing.allocator, "api");
    defer {
        for (entries.items) |entry| entry.deinit(std.testing.allocator);
        entries.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 2), entries.items.len);
    try std.testing.expectEqualStrings("ctr-1", entries.items[0].container_id);
    try std.testing.expectEqual(@as([4]u8, .{ 10, 42, 0, 9 }), entries.items[0].ip);
    try std.testing.expectEqualStrings("ctr-2", entries.items[1].container_id);
    try std.testing.expectEqual(@as([4]u8, .{ 10, 42, 0, 10 }), entries.items[1].ip);
}
