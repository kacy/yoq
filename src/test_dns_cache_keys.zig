const std = @import("std");
const platform = @import("linux_platform");
const nl = @import("network/netlink.zig");
const dns_runtime = @import("network/ebpf/dns_runtime.zig");

pub fn main(_: std.process.Init) !void {
    const socket = try nl.openSocket();
    defer platform.posix.close(socket);
    const index = try nl.getIfIndex(socket, "yoq0");
    const interceptor = try dns_runtime.load(index);
    for ([_][]const u8{ "web", "fixture.local", "a" ** 61 }) |name| {
        interceptor.updateService(name, .{ 10, 43, 0, 2 });
        const address = interceptor.lookupService(name) orelse return error.MissingCacheEntry;
        if (!std.mem.eql(u8, &address, &.{ 10, 43, 0, 2 })) return error.WrongCacheEntry;
    }
    // The private network namespace owns the attached program and its map
    // after this process exits. No userspace DNS listener is started.
}
