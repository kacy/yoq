const std = @import("std");
const dns = @import("network/dns.zig");

pub fn main(init: std.process.Init) !void {
    dns.registerService("fixture", "fixture-container", .{ 10, 42, 2, 9 });
    dns.startResolver();
    if (!dns.resolverRunning()) return error.ResolverStartFailed;
    defer dns.stopResolver();
    try std.Io.sleep(init.io, std.Io.Duration.fromSeconds(30), .awake);
}
