const std = @import("std");
const AppContext = @import("../lib/app_context.zig").AppContext;
// commands — image CLI facade
//
// keep the public image entrypoints stable while grouping the concrete
// command flows under image/cli/.

const transfer_command = @import("cli/transfer_command.zig");
const query_command = @import("cli/query_command.zig");
const prune_command = @import("cli/prune_command.zig");
const resolution = @import("cli/resolution.zig");
const common = @import("cli/common.zig");

pub const ImageCommandsError = common.ImageCommandsError;
pub const ImageResolution = resolution.ImageResolution;

pub fn pullAndResolveImage(io: std.Io, alloc: std.mem.Allocator, target: []const u8) ImageCommandsError!ImageResolution {
    return resolution.pullAndResolveImage(io, alloc, target);
}

pub fn pull(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return transfer_command.pull(ctx.io, args, ctx.alloc);
}

pub fn push(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return transfer_command.push(ctx.io, args, ctx.alloc);
}

pub fn images(alloc: std.mem.Allocator) !void {
    return query_command.images(alloc);
}

pub fn rmi(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return query_command.rmi(args, ctx.alloc);
}

pub fn inspect(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return query_command.inspect(args, ctx.alloc);
}

pub fn prune(alloc: std.mem.Allocator) !void {
    return prune_command.prune(alloc);
}
