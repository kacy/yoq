const std = @import("std");
const dockerfile = @import("dockerfile.zig");
const types = @import("engine/types.zig");
const executor = @import("engine/executor.zig");

pub const BuildError = types.BuildError;
pub const BuildResult = types.BuildResult;

pub fn build(
    alloc: std.mem.Allocator,
    instructions: []const dockerfile.Instruction,
    context_dir: []const u8,
    tag: ?[]const u8,
    cli_build_args: ?[]const []const u8,
) BuildError!BuildResult {
    var engine = executor.Engine.init(alloc, instructions, context_dir, tag, cli_build_args);
    return engine.run();
}

comptime {
    _ = @import("engine/stages.zig");
    _ = @import("engine/cache.zig");
    _ = @import("engine/handlers_meta.zig");
    _ = @import("engine/handlers_fs.zig");
    _ = @import("engine/onbuild.zig");
    _ = @import("engine/image_output.zig");
}

test "no from instruction returns error" {
    const alloc = std.testing.allocator;
    const result = build(alloc, &.{}, ".", null, null);
    try std.testing.expectError(BuildError.NoFromInstruction, result);
}

test "first instruction not from returns error" {
    const alloc = std.testing.allocator;
    const instructions = [_]dockerfile.Instruction{
        .{ .kind = .run, .args = "echo hello", .line_number = 1 },
    };
    const result = build(alloc, &instructions, ".", null, null);
    try std.testing.expectError(BuildError.NoFromInstruction, result);
}
