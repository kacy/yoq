const std = @import("std");
const AppContext = @import("../lib/app_context.zig").AppContext;
const cli = @import("../lib/cli.zig");
const common = @import("cli/common.zig");
const acme_command = @import("cli/acme_command.zig");
const install_command = @import("cli/install_command.zig");
const list_command = @import("cli/list_command.zig");
const remove_command = @import("cli/remove_command.zig");

const writeErr = cli.writeErr;

pub const TlsCommandsError = common.TlsCommandsError;

pub fn cert(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    var subcmd: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else {
            subcmd = arg;
            break;
        }
    }

    const cmd = subcmd orelse {
        writeErr(
            \\usage: yoq cert <command> [options]
            \\
            \\commands:
            \\  install <domain> --cert <path> --key <path>   store a certificate
            \\  provision <domain> [--email <email>] [--staging] [--dns-provider <provider>]
            \\                                                  obtain via ACME
            \\  renew <domain> [--email <email>] [--staging] [--dns-provider <provider>]
            \\                                                  renew via ACME
            \\  list                                           list certificates
            \\  rm <domain>                                    remove a certificate
            \\
        , .{});
        return TlsCommandsError.InvalidArgument;
    };

    if (std.mem.eql(u8, cmd, "install")) {
        return install_command.run(args, ctx.alloc);
    }
    if (std.mem.eql(u8, cmd, "provision")) {
        return cmdCertProvision(ctx.io, args, ctx.alloc);
    }
    if (std.mem.eql(u8, cmd, "renew")) {
        return cmdCertRenew(ctx.io, args, ctx.alloc);
    }
    if (std.mem.eql(u8, cmd, "list")) {
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--json")) cli.output_mode = .json;
        }
        return list_command.run(ctx.alloc);
    }
    if (std.mem.eql(u8, cmd, "rm")) {
        return remove_command.run(args, ctx.alloc);
    }

    writeErr("unknown cert command: {s}\n", .{cmd});
    return TlsCommandsError.InvalidArgument;
}

fn cmdCertProvision(io: std.Io, args: *std.process.Args.Iterator, alloc: std.mem.Allocator) TlsCommandsError!void {
    return acme_command.provision(io, args, alloc);
}

fn cmdCertRenew(io: std.Io, args: *std.process.Args.Iterator, alloc: std.mem.Allocator) TlsCommandsError!void {
    return acme_command.renew(io, args, alloc);
}
