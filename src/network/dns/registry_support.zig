const std = @import("std");
const builtin = @import("builtin");
const sqlite = @import("sqlite");
const log = @import("../../lib/log.zig");
const ip_mod = @import("../ip.zig");
const policy = @import("../policy.zig");
const packet_support = @import("packet_support.zig");

const ebpf = if (builtin.os.tag == .linux) @import("../ebpf.zig") else struct {
    pub const DnsInterceptor = struct {
        pub fn updateService(_: *@This(), _: []const u8, _: [4]u8) void {}
        pub fn deleteService(_: *@This(), _: []const u8) void {}
    };

    pub const LoadBalancer = struct {
        pub fn addBackend(_: *@This(), _: [4]u8, _: [4]u8) void {}
        pub fn removeBackend(_: *@This(), _: [4]u8, _: [4]u8) void {}
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

pub const max_services = 256;
pub const max_name_len = 63;

const ServiceEntry = struct {
    name: [max_name_len]u8,
    name_len: u8,
    container_id: [12]u8,
    container_id_len: u8,
    ip: [4]u8,
    active: bool,
};

pub const ConflictInfo = struct {
    ip: [4]u8,
    container_id: [12]u8,
    container_id_len: u8,
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

var registry: [max_services]ServiceEntry = [_]ServiceEntry{.{
    .name = undefined,
    .name_len = 0,
    .container_id = undefined,
    .container_id_len = 0,
    .ip = .{ 0, 0, 0, 0 },
    .active = false,
}} ** max_services;
var registry_count: usize = 0;
var registry_mutex: std.Thread.Mutex = .{};

var cluster_db: ?*sqlite.Db = null;
var cluster_db_mutex: std.Thread.Mutex = .{};
var cluster_lookup_fault_mode: ClusterLookupFaultMode = .none;
var cluster_lookup_fault_ip: [4]u8 = .{ 10, 255, 255, 254 };
var cluster_lookup_fault_injections: u64 = 0;

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

pub fn lookupService(name: []const u8) ?[4]u8 {
    {
        registry_mutex.lock();
        defer registry_mutex.unlock();

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

pub fn parseResolvConf(content: []const u8) ?[4]u8 {
    var pos: usize = 0;
    while (pos < content.len) {
        const line_end = std.mem.indexOfPos(u8, content, pos, "\n") orelse content.len;
        const line = content[pos..line_end];
        pos = if (line_end < content.len) line_end + 1 else content.len;

        const trimmed = std.mem.trimLeft(u8, line, " \t");
        if (trimmed.len == 0 or trimmed[0] == '#' or trimmed[0] == ';') continue;

        const prefix = "nameserver";
        if (trimmed.len <= prefix.len) continue;
        if (!std.mem.eql(u8, trimmed[0..prefix.len], prefix)) continue;
        if (trimmed[prefix.len] != ' ' and trimmed[prefix.len] != '\t') continue;

        const addr_str = std.mem.trimLeft(u8, trimmed[prefix.len..], " \t");
        const addr_clean = std.mem.trimRight(u8, addr_str, " \t\r");
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
    if (ebpf.getDnsInterceptor()) |interceptor| {
        interceptor.updateService(name, ip_addr);
    }

    if (ebpf.getLoadBalancer()) |lb| {
        const vip = getServiceVip(name) orelse ip_addr;
        lb.addBackend(vip, ip_addr);
    }

    policy.applyForContainer(name, ip_addr, std.heap.page_allocator);
}

fn deleteBpfMap(name: []const u8) void {
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

fn getServiceVip(name: []const u8) ?[4]u8 {
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
