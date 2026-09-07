//! Runs the production registry pull without starting a container or control plane.
const std = @import("std");
const registry = @import("image/registry.zig");
const spec = @import("image/spec.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.MissingImage;
    const reference = spec.parseImageRef(args[1]);
    var result = registry.pull(init.io, init.gpa, reference) catch |err| {
        std.debug.print("registry pull rejected: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
    defer result.deinit();
    if (result.layer_digests.len != 3) return error.IncompletePull;
    std.debug.print("registry pull verified all three layers\n", .{});
}
