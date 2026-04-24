// container_commands — runtime container CLI facade
//
// keep the public container command entrypoints stable while the concrete
// run, query, lifecycle, and supervisor flows live under runtime/cli/container/.

const std = @import("std");
const AppContext = @import("../lib/app_context.zig").AppContext;

const common = @import("cli/container/common.zig");
const run_command = @import("cli/container/run_command.zig");
const query_commands = @import("cli/container/query_commands.zig");
const lifecycle_commands = @import("cli/container/lifecycle_commands.zig");
const supervisor_runtime = @import("cli/container/supervisor_runtime.zig");

pub const ContainerError = common.ContainerError;

pub fn cleanupStoppedContainer(id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    lifecycle_commands.cleanupStoppedContainer(id, ip_address, veth_host);
}

pub fn cleanupNetwork(container_id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    lifecycle_commands.cleanupNetwork(container_id, ip_address, veth_host);
}

pub fn run(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return run_command.run(args, ctx);
}

pub fn ps(alloc: std.mem.Allocator) !void {
    return query_commands.ps(alloc);
}

pub fn stop(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return lifecycle_commands.stop(args, ctx.alloc);
}

pub fn exec_cmd(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return query_commands.exec_cmd(args, ctx.alloc);
}

pub fn rm(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return lifecycle_commands.rm(args, ctx.alloc);
}

pub fn log(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return query_commands.log(args, ctx.alloc);
}

pub fn restart(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return lifecycle_commands.restart(ctx.io, args, ctx.alloc);
}

pub fn runSupervisor(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return supervisor_runtime.runSupervisor(args, ctx.alloc);
}
