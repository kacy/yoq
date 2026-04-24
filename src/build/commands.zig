const impl = @import("cli/build_command.zig");

pub const BuildCommandsError = impl.BuildCommandsError;

pub fn build_cmd(args: *@import("std").process.Args.Iterator, ctx: @import("../lib/app_context.zig").AppContext) !void {
    return impl.build_cmd(args, ctx.alloc);
}
