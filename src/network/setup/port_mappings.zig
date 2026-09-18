const std = @import("std");
const common = @import("common.zig");
const nat = @import("../nat.zig");
const ebpf = @import("ebpf_module.zig").ebpf;

pub const Mapping = struct {
    address: [4]u8,
    address_text: []const u8,

    pub fn addNat(self: Mapping, port: common.PortMap) !void {
        try nat.addPortMap(port.host_port, self.address_text, port.container_port, port.protocol.toNat());
    }

    pub fn addXdp(self: Mapping, port: common.PortMap) void {
        if (ebpf.getPortMapper()) |mapper| mapper.addMapping(port.host_port, protocol(port), self.address, port.container_port);
    }

    pub fn remove(self: Mapping, port: common.PortMap) void {
        if (ebpf.getPortMapper()) |mapper| mapper.removeMapping(port.host_port, protocol(port));
        nat.removePortMap(port.host_port, self.address_text, port.container_port, port.protocol.toNat());
    }
};

fn protocol(port: common.PortMap) u8 {
    return if (port.protocol == .tcp) 6 else 17;
}

/// nat rolls back its own partial rules. publish xdp only after nat succeeds,
/// and unwind every completed mapping if a later mapping fails.
pub fn install(ports: []const common.PortMap, backend: anytype) !void {
    var completed: usize = 0;
    errdefer for (ports[0..completed]) |port| backend.remove(port);
    for (ports) |port| {
        try backend.addNat(port);
        backend.addXdp(port);
        completed += 1;
    }
}

test "network reliability rolls back each completed mapping after nat failure" {
    const Fake = struct {
        fail_port: u16,
        nat_count: usize = 0,
        xdp_count: usize = 0,
        removed: usize = 0,
        fn addNat(self: *@This(), port: common.PortMap) !void {
            if (port.host_port == self.fail_port) return error.InjectedNatFailure;
            self.nat_count += 1;
        }
        fn addXdp(self: *@This(), _: common.PortMap) void {
            self.xdp_count += 1;
        }
        fn remove(self: *@This(), _: common.PortMap) void {
            self.nat_count -= 1;
            self.xdp_count -= 1;
            self.removed += 1;
        }
    };
    const ports = [_]common.PortMap{
        .{ .host_port = 80, .container_port = 8080 },
        .{ .host_port = 81, .container_port = 8081 },
        .{ .host_port = 82, .container_port = 8082 },
    };
    for (ports, 0..) |port, index| {
        var fake: Fake = .{ .fail_port = port.host_port };
        try std.testing.expectError(error.InjectedNatFailure, install(&ports, &fake));
        try std.testing.expectEqual(@as(usize, 0), fake.nat_count);
        try std.testing.expectEqual(@as(usize, 0), fake.xdp_count);
        try std.testing.expectEqual(index, fake.removed);
    }
}
