const std = @import("std");
const posix = std.posix;
const log = @import("../../lib/log.zig");
const attach_support = @import("attach_support.zig");
const common = @import("common.zig");
const lb_runtime = @import("lb_runtime.zig");
const map_support = @import("map_support.zig");
const program_support = @import("program_support.zig");
const resource_support = @import("resource_support.zig");

const port_map_prog = @import("../bpf/port_map.zig");

pub const PortKey = extern struct {
    dst_ip: u32,
    port: u16,
    protocol: u8,
    _pad: u8 = 0,
};

pub const PortTarget = extern struct {
    dst_ip: u32,
    dst_port: u16,
    _pad: u16 = 0,
};

pub const MappingEntry = struct {
    destination_ip: ?[4]u8,
    host_port: u16,
    protocol: u8,
    target_ip: [4]u8,
    target_port: u16,
};

pub const PortMapper = struct {
    prog_fd: posix.fd_t,
    map_fd: posix.fd_t,
    if_index: u32,

    pub fn addMapping(self: *const PortMapper, host_port: u16, protocol: u8, container_ip: [4]u8, container_port: u16) void {
        self.addMappingForDestination(null, host_port, protocol, container_ip, container_port);
    }

    pub fn addMappingForDestination(
        self: *const PortMapper,
        destination_ip: ?[4]u8,
        host_port: u16,
        protocol: u8,
        target_ip: [4]u8,
        target_port: u16,
    ) void {
        var key = PortKey{
            .dst_ip = if (destination_ip) |ip| lb_runtime.ipToNetworkOrder(ip) else 0,
            .port = std.mem.nativeToBig(u16, host_port),
            .protocol = protocol,
        };
        var target = PortTarget{
            .dst_ip = lb_runtime.ipToNetworkOrder(target_ip),
            .dst_port = std.mem.nativeToBig(u16, target_port),
        };
        map_support.mapUpdate(self.map_fd, std.mem.asBytes(&key), std.mem.asBytes(&target)) catch |e| {
            if (destination_ip) |ip| {
                log.warn(
                    "ebpf: failed to add port mapping {d}.{d}.{d}.{d}:{d}/{d} -> {d}.{d}.{d}.{d}:{d}: {}",
                    .{
                        ip[0],        ip[1],
                        ip[2],        ip[3],
                        host_port,    protocol,
                        target_ip[0], target_ip[1],
                        target_ip[2], target_ip[3],
                        target_port,  e,
                    },
                );
            } else {
                log.warn("ebpf: failed to add wildcard port mapping *:{d}/{d} -> {d}.{d}.{d}.{d}:{d}: {}", .{
                    host_port,    protocol,
                    target_ip[0], target_ip[1],
                    target_ip[2], target_ip[3],
                    target_port,  e,
                });
            }
        };
    }

    pub fn removeMapping(self: *const PortMapper, host_port: u16, protocol: u8) void {
        self.removeMappingForDestination(null, host_port, protocol);
    }

    pub fn removeMappingForDestination(self: *const PortMapper, destination_ip: ?[4]u8, host_port: u16, protocol: u8) void {
        var key = PortKey{
            .dst_ip = if (destination_ip) |ip| lb_runtime.ipToNetworkOrder(ip) else 0,
            .port = std.mem.nativeToBig(u16, host_port),
            .protocol = protocol,
        };
        _ = map_support.mapDelete(self.map_fd, std.mem.asBytes(&key));
    }

    pub fn listMappings(self: *const PortMapper, alloc: std.mem.Allocator) !std.ArrayList(MappingEntry) {
        var mappings: std.ArrayList(MappingEntry) = .empty;
        errdefer mappings.deinit(alloc);

        var key: PortKey = std.mem.zeroes(PortKey);
        var next_key: PortKey = std.mem.zeroes(PortKey);

        while (map_support.mapGetNextKey(self.map_fd, std.mem.asBytes(&key), std.mem.asBytes(&next_key))) {
            var target: PortTarget = std.mem.zeroes(PortTarget);
            if (map_support.mapLookup(self.map_fd, std.mem.asBytes(&next_key), std.mem.asBytes(&target))) {
                try mappings.append(alloc, .{
                    .destination_ip = if (next_key.dst_ip == 0) null else @as([4]u8, @bitCast(next_key.dst_ip)),
                    .host_port = std.mem.bigToNative(u16, next_key.port),
                    .protocol = next_key.protocol,
                    .target_ip = @bitCast(target.dst_ip),
                    .target_port = std.mem.bigToNative(u16, target.dst_port),
                });
            }
            key = next_key;
        }

        return mappings;
    }

    pub fn deinit(self: *PortMapper) void {
        attach_support.detachXdp(self.if_index) catch |e| {
            log.debug("ebpf: failed to detach port mapper: {}", .{e});
        };
        if (self.prog_fd >= 0) {
            posix.close(self.prog_fd);
            resource_support.releaseBpfFd();
        }
        if (self.map_fd >= 0) {
            posix.close(self.map_fd);
            resource_support.releaseBpfFd();
        }
    }
};

pub fn load(if_index: u32) common.EbpfError!PortMapper {
    const map_fd = try map_support.createMap(
        @enumFromInt(port_map_prog.maps[0].map_type),
        port_map_prog.maps[0].key_size,
        port_map_prog.maps[0].value_size,
        port_map_prog.maps[0].max_entries,
    );

    var map_fds = [_]posix.fd_t{map_fd};
    const prog_fd = program_support.loadProgramWithType(port_map_prog, &map_fds, .xdp) catch |e| {
        posix.close(map_fd);
        resource_support.releaseBpfFd();
        return e;
    };

    attach_support.attachXdp(if_index, prog_fd) catch |e| {
        log.warn("ebpf: failed to attach XDP on ifindex {d}: {}", .{ if_index, e });
        posix.close(prog_fd);
        resource_support.releaseBpfFd();
        posix.close(map_fd);
        resource_support.releaseBpfFd();
        return common.EbpfError.AttachFailed;
    };

    return .{
        .prog_fd = prog_fd,
        .map_fd = map_fd,
        .if_index = if_index,
    };
}
