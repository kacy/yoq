const std = @import("std");
const platform = @import("linux_platform");
const bridge = @import("network/bridge.zig");
const nl = @import("network/netlink.zig");
const lb_runtime = @import("network/ebpf/lb_runtime.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 6 and std.mem.eql(u8, args[1], "configure")) {
        try bridge.configurableContainer(
            try std.fmt.parseInt(std.posix.pid_t, args[2], 10),
            try parseIp(args[3]),
            try parseIp(args[4]),
            try std.fmt.parseInt(u8, args[5], 10),
        );
    } else if (args.len == 2 and std.mem.eql(u8, args[1], "forward")) {
        const nat = @import("network/nat.zig");
        try nat.ensureContainerForwarding(bridge.default_bridge, "10.42.0.0/16");
        try nat.ensureMasquerade(bridge.default_bridge, "10.42.0.0/16");
    } else if (args.len == 2 and std.mem.eql(u8, args[1], "load")) {
        const socket = try nl.openSocket();
        defer platform.posix.close(socket);
        const index = try nl.getIfIndex(socket, bridge.default_bridge);
        const lb = try lb_runtime.load(index);
        try lb.replaceBackends(.{ 10, 43, 0, 2 }, &.{.{ 10, 42, 0, 2 }});
        try lb.replaceBackends(.{ 10, 43, 0, 3 }, &.{.{ 10, 42, 2, 2 }});
        // The disposable namespace owns the attached programs and maps after
        // this process exits; destroying it releases their kernel references.
    } else return error.InvalidArguments;
}

fn parseIp(text: []const u8) ![4]u8 {
    var parts = std.mem.splitScalar(u8, text, '.');
    var result: [4]u8 = undefined;
    for (&result) |*part| part.* = try std.fmt.parseInt(u8, parts.next() orelse return error.InvalidIp, 10);
    if (parts.next() != null) return error.InvalidIp;
    return result;
}
