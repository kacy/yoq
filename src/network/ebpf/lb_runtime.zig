const std = @import("std");
const platform = @import("platform");
const posix = std.posix;
const log = @import("../../lib/log.zig");
const attach_support = @import("attach_support.zig");
const common = @import("common.zig");
const map_support = @import("map_support.zig");
const program_support = @import("program_support.zig");
const resource_support = @import("resource_support.zig");

const lb_prog = @import("../bpf/lb.zig");

pub const max_backends = 64;

pub const ServiceBackends = extern struct {
    count: u32,
    ips: [max_backends]u32,
};

pub const LoadBalancer = struct {
    egress_prog_fd: posix.fd_t,
    prog_fd: posix.fd_t,
    backends_fd: posix.fd_t,
    conntrack_fd: posix.fd_t,
    rev_conntrack_fd: posix.fd_t,
    if_index: u32,

    pub fn addBackend(self: *const LoadBalancer, vip: [4]u8, backend_ip: [4]u8) void {
        const vip_net = ipToNetworkOrder(vip);
        const backend_net = ipToNetworkOrder(backend_ip);

        var backends: ServiceBackends = std.mem.zeroes(ServiceBackends);
        const key = std.mem.asBytes(&vip_net);

        if (map_support.mapLookup(self.backends_fd, key, std.mem.asBytes(&backends))) {
            if (backends.count >= max_backends) return;
            for (0..backends.count) |i| {
                if (backends.ips[i] == backend_net) return;
            }
            backends.ips[backends.count] = backend_net;
            backends.count += 1;
        } else {
            backends = std.mem.zeroes(ServiceBackends);
            backends.count = 1;
            backends.ips[0] = backend_net;
        }

        map_support.mapUpdate(self.backends_fd, key, std.mem.asBytes(&backends)) catch |e| {
            log.warn("ebpf: failed to update load balancer backends: {}", .{e});
        };
    }

    pub fn replaceBackends(self: *const LoadBalancer, vip: [4]u8, backend_ips: []const [4]u8) common.EbpfError!void {
        if (backend_ips.len > max_backends) return error.InvalidParameter;

        const vip_net = ipToNetworkOrder(vip);
        var backends: ServiceBackends = std.mem.zeroes(ServiceBackends);
        backends.count = @intCast(backend_ips.len);
        for (backend_ips, 0..) |backend_ip, idx| {
            backends.ips[idx] = ipToNetworkOrder(backend_ip);
        }

        try map_support.mapUpdate(self.backends_fd, std.mem.asBytes(&vip_net), std.mem.asBytes(&backends));
    }

    pub fn removeBackend(self: *const LoadBalancer, vip: [4]u8, backend_ip: [4]u8) void {
        const vip_net = ipToNetworkOrder(vip);
        const backend_net = ipToNetworkOrder(backend_ip);

        var backends: ServiceBackends = std.mem.zeroes(ServiceBackends);
        const key = std.mem.asBytes(&vip_net);

        if (!map_support.mapLookup(self.backends_fd, key, std.mem.asBytes(&backends))) return;

        var found: bool = false;
        for (0..backends.count) |i| {
            if (backends.ips[i] == backend_net) {
                var j: u32 = @intCast(i);
                while (j + 1 < backends.count) : (j += 1) {
                    backends.ips[j] = backends.ips[j + 1];
                }
                backends.count -= 1;
                found = true;
                break;
            }
        }

        if (!found) return;

        if (backends.count == 0) {
            _ = map_support.mapDelete(self.backends_fd, key);
        } else {
            map_support.mapUpdate(self.backends_fd, key, std.mem.asBytes(&backends)) catch |e| {
                log.warn("ebpf: failed to update load balancer backends after removal: {}", .{e});
            };
        }
    }

    pub fn lookupBackends(self: *const LoadBalancer, vip: [4]u8) ?ServiceBackends {
        const vip_net = ipToNetworkOrder(vip);
        var backends: ServiceBackends = std.mem.zeroes(ServiceBackends);
        if (!map_support.mapLookup(self.backends_fd, std.mem.asBytes(&vip_net), std.mem.asBytes(&backends))) return null;
        return backends;
    }

    pub fn deleteBackends(self: *const LoadBalancer, vip: [4]u8) void {
        const vip_net = ipToNetworkOrder(vip);
        _ = map_support.mapDelete(self.backends_fd, std.mem.asBytes(&vip_net));
    }

    pub fn deinit(self: *LoadBalancer) void {
        attach_support.detachTC(self.if_index) catch |e| {
            log.debug("ebpf: failed to detach load balancer: {}", .{e});
        };
        if (self.prog_fd >= 0) {
            platform.posix.close(self.prog_fd);
            resource_support.releaseBpfFd();
        }
        if (self.egress_prog_fd >= 0) {
            platform.posix.close(self.egress_prog_fd);
            resource_support.releaseBpfFd();
        }
        if (self.backends_fd >= 0) {
            platform.posix.close(self.backends_fd);
            resource_support.releaseBpfFd();
        }
        if (self.conntrack_fd >= 0) {
            platform.posix.close(self.conntrack_fd);
            resource_support.releaseBpfFd();
        }
        if (self.rev_conntrack_fd >= 0) {
            platform.posix.close(self.rev_conntrack_fd);
            resource_support.releaseBpfFd();
        }
    }
};

pub fn ipToNetworkOrder(ip_bytes: [4]u8) u32 {
    return @bitCast(ip_bytes);
}

pub fn load(bridge_if_index: u32) common.EbpfError!LoadBalancer {
    const backends_fd = try map_support.createMap(
        @enumFromInt(lb_prog.maps[0].map_type),
        lb_prog.maps[0].key_size,
        lb_prog.maps[0].value_size,
        lb_prog.maps[0].max_entries,
    );
    errdefer {
        platform.posix.close(backends_fd);
        resource_support.releaseBpfFd();
    }

    const conntrack_fd = try map_support.createMap(
        @enumFromInt(lb_prog.maps[1].map_type),
        lb_prog.maps[1].key_size,
        lb_prog.maps[1].value_size,
        lb_prog.maps[1].max_entries,
    );
    errdefer {
        platform.posix.close(conntrack_fd);
        resource_support.releaseBpfFd();
    }

    const rev_conntrack_fd = try map_support.createMap(
        @enumFromInt(lb_prog.maps[2].map_type),
        lb_prog.maps[2].key_size,
        lb_prog.maps[2].value_size,
        lb_prog.maps[2].max_entries,
    );
    errdefer {
        platform.posix.close(rev_conntrack_fd);
        resource_support.releaseBpfFd();
    }

    var map_fds = [_]posix.fd_t{ backends_fd, conntrack_fd, rev_conntrack_fd };
    const prog_fd = try program_support.loadProgram(lb_prog, &map_fds);
    errdefer {
        platform.posix.close(prog_fd);
        resource_support.releaseBpfFd();
    }

    try attach_support.attachTC(bridge_if_index, .ingress, prog_fd, 1);

    var egress_fd: posix.fd_t = -1;
    if (@hasDecl(lb_prog, "egress_insns")) {
        egress_fd = program_support.loadEgressProgram(lb_prog, &map_fds) catch -1;
        if (egress_fd >= 0) {
            attach_support.attachTC(bridge_if_index, .egress, egress_fd, 1) catch |e| {
                log.warn("ebpf: failed to attach LB egress: {}", .{e});
                platform.posix.close(egress_fd);
                resource_support.releaseBpfFd();
                egress_fd = -1;
            };
        }
    }

    return .{
        .egress_prog_fd = egress_fd,
        .prog_fd = prog_fd,
        .backends_fd = backends_fd,
        .conntrack_fd = conntrack_fd,
        .rev_conntrack_fd = rev_conntrack_fd,
        .if_index = bridge_if_index,
    };
}
