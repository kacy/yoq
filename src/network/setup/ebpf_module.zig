const builtin = @import("builtin");

pub const ebpf = if (builtin.os.tag == .linux) @import("../ebpf.zig") else struct {
    pub const PortMapper = struct {
        pub fn addMapping(_: *@This(), _: u16, _: u8, _: [4]u8, _: u16) void {}
        pub fn removeMapping(_: *@This(), _: u16, _: u8) void {}
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
