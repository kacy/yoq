const std = @import("std");
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

pub fn pullAndResolveImage(alloc: std.mem.Allocator, target: []const u8) ImageCommandsError!ImageResolution {
    return resolution.pullAndResolveImage(alloc, target);
}

pub fn pull(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return transfer_command.pull(args, alloc);
}

pub fn push(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return transfer_command.push(args, alloc);
}

pub fn images(alloc: std.mem.Allocator) !void {
    return query_command.images(alloc);
}

pub fn rmi(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return query_command.rmi(args, alloc);
}

pub fn inspect(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return query_command.inspect(args, alloc);
}

pub fn prune(alloc: std.mem.Allocator) !void {
    return prune_command.prune(alloc);
}
