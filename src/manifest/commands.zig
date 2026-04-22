// commands — manifest CLI facade
//
// keep the public manifest command surface stable while grouping the
// concrete command flows under manifest/cli/.

const std = @import("std");
const AppContext = @import("../lib/app_context.zig").AppContext;

const init_validate = @import("cli/init_validate.zig");
const deploy = @import("cli/deploy.zig");
const ops = @import("cli/ops.zig");
const train_cmd = @import("cli/train.zig");

pub fn init(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return init_validate.init(args, ctx.alloc);
}

pub fn validate(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return init_validate.validate(args, ctx.alloc);
}

pub fn up(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return deploy.up(args, ctx.alloc);
}

pub fn down(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return deploy.down(args, ctx.alloc);
}

pub fn rollback(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return ops.rollback(args, ctx.alloc);
}

pub fn history(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return ops.history(args, ctx.alloc);
}

pub fn rollout(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return ops.rollout(args, ctx.alloc);
}

pub fn runWorker(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return ops.runWorker(args, ctx.alloc);
}

pub fn train(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return train_cmd.train(args, ctx.alloc);
}
