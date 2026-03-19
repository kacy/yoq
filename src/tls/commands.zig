const std = @import("std");
const cli = @import("../lib/cli.zig");
const common = @import("cli/common.zig");
const install_command = @import("cli/install_command.zig");
const list_command = @import("cli/list_command.zig");
const remove_command = @import("cli/remove_command.zig");

const writeErr = cli.writeErr;

pub const TlsCommandsError = common.TlsCommandsError;

pub fn cert(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
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
            \\  provision <domain> --email <email> [--staging] obtain via ACME
            \\  renew <domain>                                 renew via ACME
            \\  list                                           list certificates
            \\  rm <domain>                                    remove a certificate
            \\
        , .{});
        return TlsCommandsError.InvalidArgument;
    };

    if (std.mem.eql(u8, cmd, "install")) {
        return install_command.run(args, alloc);
    }
    if (std.mem.eql(u8, cmd, "provision")) {
        return cmdCertProvision(args, alloc);
    }
    if (std.mem.eql(u8, cmd, "renew")) {
        return cmdCertRenew(args, alloc);
    }
    if (std.mem.eql(u8, cmd, "list")) {
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--json")) cli.output_mode = .json;
        }
        return list_command.run(alloc);
    }
    if (std.mem.eql(u8, cmd, "rm")) {
        return remove_command.run(args, alloc);
    }

    writeErr("unknown cert command: {s}\n", .{cmd});
    return TlsCommandsError.InvalidArgument;
}

fn cmdCertProvision(args: *std.process.ArgIterator, alloc: std.mem.Allocator) TlsCommandsError!void {
    _ = args;
    _ = alloc;
    writeErr("acme provisioning is not yet production-safe; use 'yoq cert install' for now\n", .{});
    return TlsCommandsError.NotSupported;
}

fn cmdCertRenew(args: *std.process.ArgIterator, alloc: std.mem.Allocator) TlsCommandsError!void {
    _ = args;
    _ = alloc;
    writeErr("acme renewal is not yet production-safe; renew manually with 'yoq cert install'\n", .{});
    return TlsCommandsError.NotSupported;
}
