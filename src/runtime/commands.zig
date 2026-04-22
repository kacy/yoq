// commands — runtime CLI facade
//
// keep the public runtime command entrypoints stable while the concrete
// status and metrics flows live in runtime/cli/.

const std = @import("std");

const status_command = @import("cli/status_command.zig");
const metrics_command = @import("cli/metrics_command.zig");

pub fn status(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return status_command.status(args, alloc);
}

pub fn apps(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return status_command.apps(args, alloc);
}

pub fn metrics(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return metrics_command.metrics(args, alloc);
}
