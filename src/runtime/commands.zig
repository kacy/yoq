// commands — runtime CLI facade
//
// keep the public runtime command entrypoints stable while the concrete
// status and metrics flows live in runtime/cli/.

const std = @import("std");
const AppContext = @import("../lib/app_context.zig").AppContext;

const status_command = @import("cli/status_command.zig");
const metrics_command = @import("cli/metrics_command.zig");

pub fn status(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return status_command.status(args, ctx.io, ctx.alloc);
}

pub fn apps(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return status_command.apps(args, ctx.io, ctx.alloc);
}

pub fn metrics(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return metrics_command.metrics(args, ctx.io, ctx.alloc);
}
