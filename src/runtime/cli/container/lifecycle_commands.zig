const std = @import("std");
const lifecycle = @import("../../local_lifecycle.zig");
const state_support = @import("state_support.zig");
const cli = @import("../../../lib/cli.zig");

pub const cleanupStoppedContainer = lifecycle.cleanupStoppedContainer;
pub const cleanupNetwork = lifecycle.cleanupNetwork;

pub fn stop(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    const ref = cli.requireArg(args, "usage: yoq stop <container-id|name>\n");
    const record = try state_support.resolveContainerRef(alloc, ref);
    defer record.deinit(alloc);
    try lifecycle.stop(record.id, alloc);
    cli.write("{s}\n", .{record.id});
}

pub fn rm(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var ref = cli.requireArg(args, "usage: yoq rm [-v] <container-id|name>\n");
    const remove_volumes = std.mem.eql(u8, ref, "-v") or std.mem.eql(u8, ref, "--volumes");
    if (remove_volumes) ref = cli.requireArg(args, "missing container\n");
    if (args.next() != null) return error.InvalidArgument;
    const record = try state_support.resolveContainerRef(alloc, ref);
    defer record.deinit(alloc);
    try lifecycle.removeWithVolumes(record.id, alloc, remove_volumes);
    cli.write("{s}\n", .{record.id});
}

pub fn restart(io: std.Io, args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    const ref = cli.requireArg(args, "usage: yoq restart <container-id|name>\n");
    const record = try state_support.resolveContainerRef(alloc, ref);
    defer record.deinit(alloc);
    try lifecycle.restart(io, alloc, record.id);
    cli.write("{s}\n", .{record.id});
}
