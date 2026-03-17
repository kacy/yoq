// commands — cluster CLI facade
//
// keep the public cluster entrypoints stable while grouping the
// concrete command flows under cluster/cli/.

const std = @import("std");

const server_command = @import("cli/server_command.zig");
const membership_command = @import("cli/membership_command.zig");
const query_command = @import("cli/query_command.zig");

pub fn serve(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    return server_command.serve(args, alloc);
}

pub fn initServer(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    return server_command.initServer(args, alloc);
}

pub fn join(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    return membership_command.join(args, alloc);
}

pub fn cluster(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    return query_command.cluster(args, alloc);
}

pub fn nodes(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    return query_command.nodes(args, alloc);
}

pub fn drain(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    return query_command.drain(args, alloc);
}
