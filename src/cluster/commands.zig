// commands — cluster CLI facade
//
// keep the public cluster entrypoints stable while grouping the
// concrete command flows under cluster/cli/.

const std = @import("std");
const AppContext = @import("../lib/app_context.zig").AppContext;

const server_command = @import("cli/server_command.zig");
const membership_command = @import("cli/membership_command.zig");
const query_command = @import("cli/query_command.zig");

pub fn serve(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return server_command.serve(args, ctx.io, ctx.alloc);
}

pub fn initServer(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return server_command.initServer(args, ctx.io, ctx.alloc);
}

pub fn join(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return membership_command.join(args, ctx.alloc);
}

pub fn cluster(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return query_command.cluster(args, ctx.io, ctx.alloc);
}

pub fn nodes(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return query_command.nodes(args, ctx.io, ctx.alloc);
}

pub fn drain(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return query_command.drain(args, ctx.io, ctx.alloc);
}
