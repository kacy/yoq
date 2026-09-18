const std = @import("std");
const firewall = @import("network/published_ports_firewall.zig");
const nat = @import("network/nat.zig");

pub fn main(init: std.process.Init) !void {
    const alloc = init.arena.allocator();
    const args = try init.minimal.args.toSlice(alloc);
    if (args.len != 2) return error.InvalidArguments;
    try nat.ensureContainerForwarding("yoq0", "10.42.0.0/16");
    var backends = [_]firewall.Backend{
        .{ .host_port = 18080, .target_port = 8080, .address = .{ 10, 42, 0, 2 }, .eligible = true },
        .{ .host_port = 18080, .target_port = 8080, .address = .{ 10, 42, 0, 3 }, .eligible = true },
    };
    if (std.mem.eql(u8, args[1], "full")) {
        try firewall.apply(alloc, &backends);
    } else if (std.mem.eql(u8, args[1], "one")) {
        try firewall.apply(alloc, backends[1..]);
    } else if (std.mem.eql(u8, args[1], "empty")) {
        for (&backends) |*backend| backend.eligible = false;
        try firewall.apply(alloc, &backends);
    } else if (std.mem.eql(u8, args[1], "clear")) {
        try firewall.apply(alloc, &.{});
    } else return error.InvalidArguments;
}
