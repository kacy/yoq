// upgrade_commands — CLI handler for `yoq upgrade`.
//
// `yoq upgrade preflight` runs cluster readiness checks against the local agent
// before a rolling upgrade: version skew, clock skew, and bpf map headroom. it
// reuses the doctor check model and renderers.

const std = @import("std");
const AppContext = @import("app_context.zig").AppContext;
const cli = @import("cli.zig");
const json_out = @import("json_output.zig");
const doctor_cluster = @import("doctor_cluster.zig");
const doctor_commands = @import("doctor_commands.zig");

const write = cli.write;
const writeErr = cli.writeErr;

const UpgradeCommandError = error{
    InvalidArgument,
    ValidationFailed,
};

pub fn upgradeCmd(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const sub = args.next() orelse {
        writeErr("usage: upgrade preflight [--server addr] [--json]\n", .{});
        return UpgradeCommandError.InvalidArgument;
    };
    if (!std.mem.eql(u8, sub, "preflight")) {
        writeErr("unknown upgrade subcommand: {s}\n", .{sub});
        return UpgradeCommandError.InvalidArgument;
    }

    var server = cli.ServerAddr{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--server")) {
            const addr = args.next() orelse {
                writeErr("--server requires an address\n", .{});
                return UpgradeCommandError.InvalidArgument;
            };
            server = cli.parseServerAddr(addr);
        } else {
            writeErr("unknown option: {s}\n", .{arg});
            return UpgradeCommandError.InvalidArgument;
        }
    }

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiTokenWithIo(ctx.io, &token_buf);
    var result = doctor_cluster.run(ctx.alloc, server.ip, server.port, token);

    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginArray();
        doctor_commands.writeCheckSliceJson(&w, result.slice());
        w.endArray();
        w.flush();
    } else {
        doctor_commands.writeCheckTable("cluster preflight", result.slice());
        if (result.hasFailures()) {
            write("\nsome checks failed — see messages above\n", .{});
        } else {
            write("\nall checks passed\n", .{});
        }
    }

    if (result.hasFailures()) return UpgradeCommandError.ValidationFailed;
}

// -- tests --

test "upgradeCmd handler has correct signature" {
    const handler: @import("command_registry.zig").CommandHandler = upgradeCmd;
    _ = handler;
}
