const std = @import("std");
const dns = @import("network/dns.zig");

fn startGateways() !void {
    dns.startResolver();
    if (!dns.resolverRunningAt(.{ 10, 42, 0, 1 })) return error.ResolverStartFailed;
    dns.startResolverAt(.{ 10, 42, 2, 1 });
    if (!dns.resolverRunningAt(.{ 10, 42, 2, 1 })) return error.ResolverStartFailed;
}

pub fn main(init: std.process.Init) !void {
    dns.registerService("fixture", "fixture-container", .{ 10, 42, 2, 9 });
    try startGateways();
    defer dns.stopResolver();
    dns.stopResolver();
    if (dns.resolverRunning()) return error.ResolverStopFailed;
    try startGateways();
    try std.Io.sleep(init.io, std.Io.Duration.fromSeconds(30), .awake);
}
