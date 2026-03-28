const std = @import("std");
const builtin = @import("builtin");

pub const ebpf = if (builtin.os.tag == .linux) @import("../ebpf.zig") else struct {
    pub const MappingEntry = struct {
        destination_ip: ?[4]u8,
        host_port: u16,
        protocol: u8,
        target_ip: [4]u8,
        target_port: u16,
    };

    pub const PortMapper = struct {
        pub fn addMapping(_: *@This(), _: u16, _: u8, _: [4]u8, _: u16) void {}
        pub fn addMappingForDestination(_: *@This(), _: ?[4]u8, _: u16, _: u8, _: [4]u8, _: u16) void {}
        pub fn removeMapping(_: *@This(), _: u16, _: u8) void {}
        pub fn removeMappingForDestination(_: *@This(), _: ?[4]u8, _: u16, _: u8) void {}
        pub fn listMappings(_: *@This(), alloc: std.mem.Allocator) !std.ArrayList(MappingEntry) {
            return std.ArrayList(MappingEntry).initCapacity(alloc, 0);
        }
    };

    var port_mapper: PortMapper = .{};

    pub fn getPortMapper() ?*PortMapper {
        return &port_mapper;
    }

    pub fn getDnsInterceptor() ?*anyopaque {
        return null;
    }

    pub fn getPolicyEnforcer() ?*anyopaque {
        return null;
    }

    pub fn loadPolicyEnforcer(_: u32) error{NotSupported}!void {
        return error.NotSupported;
    }

    pub fn loadDnsInterceptor(_: u32) error{NotSupported}!void {
        return error.NotSupported;
    }

    pub fn loadLoadBalancer(_: u32) error{NotSupported}!void {
        return error.NotSupported;
    }

    pub fn loadPortMapper(_: u32) error{NotSupported}!void {
        return error.NotSupported;
    }
};
