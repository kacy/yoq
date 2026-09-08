const std = @import("std");
const platform = @import("linux_platform");
const nl = @import("network/netlink.zig");
const policy_runtime = @import("network/ebpf/policy_runtime.zig");
const dns_runtime = @import("network/ebpf/dns_runtime.zig");
const lb_runtime = @import("network/ebpf/lb_runtime.zig");
const maps = @import("network/ebpf/map_support.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3 or !std.mem.eql(u8, args[1], "chain")) return @import("test_service_gateway.zig").main(init);
    const socket = try nl.openSocket();
    defer platform.posix.close(socket);
    const index = try nl.getIfIndex(socket, "yoq0");
    var metrics = try @import("network/ebpf/metrics_runtime.zig").load(index);
    defer metrics.deinit();
    var policy: policy_runtime.PolicyEnforcer = undefined;
    var dns: ?dns_runtime.DnsInterceptor = null;
    var lb: lb_runtime.LoadBalancer = undefined;
    if (std.mem.eql(u8, args[2], "reverse")) {
        lb = try lb_runtime.load(index);
        dns = try dns_runtime.load(index);
        policy = try policy_runtime.load(index);
    } else {
        policy = try policy_runtime.load(index);
        dns = try dns_runtime.load(index);
        lb = try lb_runtime.load(index);
    }
    defer policy.deinit();
    defer if (dns) |*interceptor| interceptor.deinit();
    defer lb.deinit();
    dns.?.updateService("fixture.local", .{ 10, 43, 0, 2 });
    try lb.replaceBackends(.{ 10, 43, 0, 2 }, &.{.{ 10, 42, 0, 2 }});
    try lb.replaceBackends(.{ 10, 43, 0, 3 }, &.{.{ 10, 42, 2, 2 }});
    const sources = [_]u32{ @bitCast([4]u8{ 10, 42, 0, 3 }), @bitCast([4]u8{ 10, 42, 0, 127 }) };
    const target: u32 = @bitCast([4]u8{ 10, 43, 0, 2 });
    try acknowledge();
    var command: [1]u8 = undefined;
    while (try platform.posix.read(0, &command) == 1) {
        switch (command[0]) {
            'd' => for (sources) |source| {
                policy.addDeny(source, target);
                var action: u8 = 255;
                const key: policy_runtime.PolicyKey = .{ .src_ip = source, .dst_ip = target };
                if (!maps.mapLookup(policy.policy_fd, std.mem.asBytes(&key), std.mem.asBytes(&action)) or action != 0) return error.DenyNotInstalled;
            },
            'r' => for (sources) |source| {
                policy.removeDeny(source, target);
            },
            'l' => try @import("network/ebpf/attach_support.zig").attachTC(index, .ingress, policy.prog_fd, 1),
            'q' => break,
            'p' => {
                var previous = policy;
                policy = try policy_runtime.load(index);
                if (try previous.attachment.isCurrent()) return error.OldOwnerStillCurrent;
                previous.deinit();
                if (!try policy.attachment.isCurrent()) return error.ReplacementMissing;
            },
            'u' => {
                if (dns) |*interceptor| interceptor.deinit();
                dns = null;
            },
            else => return error.InvalidCommand,
        }
        try acknowledge();
    }
}

fn acknowledge() !void {
    if (try platform.posix.write(1, "ok\n") != 3) return error.WriteFailed;
}
