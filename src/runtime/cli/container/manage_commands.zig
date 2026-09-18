const std = @import("std");
const AppContext = @import("../../../lib/app_context.zig").AppContext;
const cli = @import("../../../lib/cli.zig");
const state = @import("state_support.zig");
const store = @import("../../../state/store.zig");
const control = @import("../../local_control.zig");
const lifecycle = @import("../../local_lifecycle.zig");
const run_state = @import("../../run_state.zig");
const process = @import("../../process.zig");
const runtime_wait = @import("../../../lib/runtime_wait.zig");

pub fn start(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const ref = cli.requireArg(args, "usage: yoq start <id|name>\n");
    if (args.next() != null) return error.InvalidArgument;
    const record = try state.resolveContainerRef(ctx.alloc, ref);
    defer record.deinit(ctx.alloc);
    try lifecycle.start(ctx.io, ctx.alloc, record.id);
    cli.write("{s}\n", .{record.id});
}

pub fn wait(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const ref = cli.requireArg(args, "usage: yoq wait <id|name>\n");
    if (args.next() != null) return error.InvalidArgument;
    const original = try state.resolveContainerRef(ctx.alloc, ref);
    defer original.deinit(ctx.alloc);
    while (true) {
        const record = try store.load(ctx.alloc, original.id);
        defer record.deinit(ctx.alloc);
        if (std.mem.eql(u8, record.status, "cleanup_failed")) return error.CleanupFailed;
        if (record.pid == null and record.exit_code != null) {
            cli.write("{d}\n", .{record.exit_code.?});
            return;
        }
        if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(50), "container wait")) return error.WaitFailed;
    }
}

pub fn kill(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    var ref = cli.requireArg(args, "usage: yoq kill [--signal SIGNAL] <id|name>\n");
    var signal: u8 = 9;
    if (std.mem.eql(u8, ref, "--signal") or std.mem.eql(u8, ref, "-s")) {
        signal = @import("../../signals.zig").parse(cli.requireArg(args, "missing signal\n")) orelse return error.InvalidArgument;
        ref = cli.requireArg(args, "missing container\n");
    }
    if (args.next() != null) return error.InvalidArgument;
    const record = try state.resolveContainerRef(ctx.alloc, ref);
    defer record.deinit(ctx.alloc);
    const command_lock = try control.lock(record.id, .command, true);
    defer command_lock.deinit();
    const transition = try control.lock(record.id, .transition, true);
    defer transition.deinit();
    const current = try store.load(ctx.alloc, record.id);
    defer current.deinit(ctx.alloc);
    const pid = state.currentOwnedRunningPid(&current) orelse return error.NotRunning;
    try process.sendSignal(pid, signal);
    cli.write("{s}\n", .{record.id});
}

pub fn inspect(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const ref = cli.requireArg(args, "usage: yoq container inspect <id|name>\n");
    if (args.next() != null) return error.InvalidArgument;
    const record = try state.resolveContainerRef(ctx.alloc, ref);
    defer record.deinit(ctx.alloc);
    const cfg = run_state.loadConfig(ctx.alloc, record.id) catch |err| switch (err) {
        error.NotFound => null,
        else => return err,
    };
    defer if (cfg) |value| value.deinit(ctx.alloc);
    const name = try control.nameForId(ctx.alloc, record.id);
    defer if (name) |value| ctx.alloc.free(value);
    const output = try std.json.Stringify.valueAlloc(ctx.alloc, .{
        .name = name orelse record.hostname,
        .state = record,
        .desired_running = try control.wantsRunning(record.id),
        .config = cfg,
    }, .{ .whitespace = .indent_2 });
    defer ctx.alloc.free(output);
    cli.write("{s}\n", .{output});
}

pub fn containerCommand(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const name = cli.requireArg(args, "usage: yoq container <create|run|start|stop|restart|rm|wait|kill|inspect|exec|logs|ls>\n");
    const commands = @import("../../container_commands.zig");
    const resources = @import("resource_commands.zig");
    if (std.mem.eql(u8, name, "cp")) return @import("filesystem_commands.zig").cp(args, ctx);
    if (std.mem.eql(u8, name, "diff")) return @import("filesystem_commands.zig").diff(args, ctx);
    if (std.mem.eql(u8, name, "rename")) return @import("list_commands.zig").rename(args, ctx);
    if (std.mem.eql(u8, name, "top")) return resources.top(args, ctx);
    if (std.mem.eql(u8, name, "stats")) return resources.stats(args, ctx);
    if (std.mem.eql(u8, name, "pause")) return resources.pause(args, ctx);
    if (std.mem.eql(u8, name, "unpause")) return resources.unpause(args, ctx);
    if (std.mem.eql(u8, name, "update")) return resources.update(args, ctx);
    if (std.mem.eql(u8, name, "recover")) return recover(args, ctx);
    if (std.mem.eql(u8, name, "attach")) return commands.attach(args, ctx);
    if (std.mem.eql(u8, name, "inspect")) return inspect(args, ctx);
    if (std.mem.eql(u8, name, "create")) return @import("run_command.zig").create(args, ctx);
    if (std.mem.eql(u8, name, "start")) return start(args, ctx);
    if (std.mem.eql(u8, name, "wait")) return wait(args, ctx);
    if (std.mem.eql(u8, name, "kill")) return kill(args, ctx);
    if (std.mem.eql(u8, name, "run")) return commands.run(args, ctx);
    if (std.mem.eql(u8, name, "stop")) return commands.stop(args, ctx);
    if (std.mem.eql(u8, name, "restart")) return commands.restart(args, ctx);
    if (std.mem.eql(u8, name, "rm")) return commands.rm(args, ctx);
    if (std.mem.eql(u8, name, "exec")) return commands.exec_cmd(args, ctx);
    if (std.mem.eql(u8, name, "logs")) return commands.log(args, ctx);
    if (std.mem.eql(u8, name, "ls")) return @import("list_commands.zig").ps(args, ctx);
    cli.writeErr("unknown container command: {s}\n", .{name});
    return error.InvalidArgument;
}

pub fn recover(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    if (args.next() != null) return error.InvalidArgument;
    var ids = try store.listIds(ctx.alloc);
    defer {
        for (ids.items) |id| ctx.alloc.free(id);
        ids.deinit(ctx.alloc);
    }
    var failed = false;
    for (ids.items) |id| {
        const restarted = lifecycle.recover(ctx.io, ctx.alloc, id) catch |err| {
            if (err == error.NotFound) continue; // manifest services have another owner.
            cli.writeErr("could not recover container {s}: {}\n", .{ id, err });
            failed = true;
            continue;
        };
        if (restarted) cli.write("{s}\n", .{id});
    }
    if (failed) return error.RecoveryFailed;
}
