// commands — manifest CLI facade
//
// keep the public manifest command surface stable while grouping the
// concrete command flows under manifest/cli/.

const std = @import("std");

const init_validate = @import("cli/init_validate.zig");
const deploy = @import("cli/deploy.zig");
const ops = @import("cli/ops.zig");
const train_cmd = @import("cli/train.zig");

pub fn init(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return init_validate.init(args, alloc);
}

pub fn validate(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return init_validate.validate(args, alloc);
}

pub fn up(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return deploy.up(args, alloc);
}

pub fn down(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return deploy.down(args, alloc);
}

pub fn rollback(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return ops.rollback(args, alloc);
}

pub fn history(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return ops.history(args, alloc);
}

pub fn rollout(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return ops.rollout(args, alloc);
}

pub fn runWorker(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return ops.runWorker(args, alloc);
}

pub fn train(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    return train_cmd.train(args, alloc);
}
