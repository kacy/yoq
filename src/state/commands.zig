const std = @import("std");
const AppContext = @import("../lib/app_context.zig").AppContext;
const cli = @import("../lib/cli.zig");
const json_out = @import("../lib/json_output.zig");
const secrets = @import("secrets.zig");
const store = @import("store.zig");
const secrets_cli = @import("secrets_cli.zig");
const backup_mod = @import("backup.zig");
const schema = @import("schema.zig");
const paths = @import("../lib/paths.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const requireArg = cli.requireArg;

const SecretCommandsError = error{
    InvalidArgument,
    SecretNotFound,
    StoreFailed,
    NotSupported,
    OutOfMemory,
};

pub fn secret(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const alloc = ctx.alloc;
    var subcmd: ?[]const u8 = null;

    // peek at first arg — could be subcommand or --json
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
            \\usage: yoq secret <command> [options]
            \\
            \\commands:
            \\  set <name> [--value <val>]  store a secret (reads stdin if no --value)
            \\  get <name>                  print decrypted value
            \\  rm <name>                   remove a secret
            \\  list                        list secret names
            \\  rotate <name>               re-encrypt with current key
            \\
        , .{});
        return SecretCommandsError.InvalidArgument;
    };

    if (std.mem.eql(u8, cmd, "set")) {
        set(args, alloc) catch |e| return e;
    } else if (std.mem.eql(u8, cmd, "get")) {
        get(args, alloc) catch |e| return e;
    } else if (std.mem.eql(u8, cmd, "rm")) {
        rm(args, alloc) catch |e| return e;
    } else if (std.mem.eql(u8, cmd, "list")) {
        // also check remaining args for --json
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--json")) cli.output_mode = .json;
        }
        list(alloc) catch |e| return e;
    } else if (std.mem.eql(u8, cmd, "rotate")) {
        rotate(args, alloc) catch |e| return e;
    } else {
        writeErr("unknown secret command: {s}\n", .{cmd});
        return SecretCommandsError.InvalidArgument;
    }
}

fn set(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) SecretCommandsError!void {
    var name: ?[]const u8 = null;
    var value_flag: ?[]const u8 = null;
    var stdin_data_owned: ?[]u8 = null;
    defer if (stdin_data_owned) |buf| {
        std.crypto.secureZero(u8, buf);
        alloc.free(buf);
    };

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--value")) {
            value_flag = args.next() orelse {
                writeErr("--value requires a value\n", .{});
                return SecretCommandsError.InvalidArgument;
            };
        } else if (name == null) {
            name = arg;
        }
    }

    const secret_name = name orelse {
        writeErr("usage: yoq secret set <name> [--value <val>]\n", .{});
        return SecretCommandsError.InvalidArgument;
    };

    // get value from --value flag or stdin
    const value = if (value_flag) |v|
        v
    else blk: {
        // read from stdin
        var stdin_reader = std.Io.File.stdin().reader(std.Options.debug_io, &.{});
        const stdin_data = stdin_reader.interface.allocRemaining(alloc, .limited(1024 * 1024)) catch {
            writeErr("failed to read from stdin\n", .{});
            return SecretCommandsError.StoreFailed;
        };
        stdin_data_owned = stdin_data;
        // trim trailing newline — users typically pipe from echo or here-string
        break :blk std.mem.trimEnd(u8, stdin_data, "\n\r");
    };

    var sec_store = secrets_cli.open(alloc);
    defer secrets_cli.close(alloc, &sec_store);

    sec_store.set(secret_name, value) catch {
        writeErr("failed to store secret\n", .{});
        return SecretCommandsError.StoreFailed;
    };

    write("{s}\n", .{secret_name});
}

fn get(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) SecretCommandsError!void {
    const name = requireArg(args, "usage: yoq secret get <name>\n");

    var sec_store = secrets_cli.open(alloc);
    defer secrets_cli.close(alloc, &sec_store);

    const value = sec_store.get(name) catch |err| {
        if (err == secrets.SecretsError.NotFound) {
            writeErr("secret not found: {s}\n", .{name});
            return SecretCommandsError.SecretNotFound;
        } else {
            writeErr("failed to read secret\n", .{});
            return SecretCommandsError.StoreFailed;
        }
    };
    defer {
        // zero before freeing — don't leave secrets in freed memory
        std.crypto.secureZero(u8, value);
        alloc.free(value);
    }

    write("{s}\n", .{value});
}

fn rm(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) SecretCommandsError!void {
    const name = requireArg(args, "usage: yoq secret rm <name>\n");

    var sec_store = secrets_cli.open(alloc);
    defer secrets_cli.close(alloc, &sec_store);

    sec_store.remove(name) catch |err| {
        if (err == secrets.SecretsError.NotFound) {
            writeErr("secret not found: {s}\n", .{name});
            return SecretCommandsError.SecretNotFound;
        } else {
            writeErr("failed to remove secret\n", .{});
            return SecretCommandsError.StoreFailed;
        }
    };

    write("{s}\n", .{name});
}

fn list(alloc: std.mem.Allocator) SecretCommandsError!void {
    var sec_store = secrets_cli.open(alloc);
    defer secrets_cli.close(alloc, &sec_store);

    var names = sec_store.list() catch {
        writeErr("failed to list secrets\n", .{});
        return SecretCommandsError.StoreFailed;
    };
    defer {
        for (names.items) |n| alloc.free(n);
        names.deinit(alloc);
    }

    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginArray();
        for (names.items) |name| {
            w.stringValue(name);
        }
        w.endArray();
        w.flush();
        return;
    }

    if (names.items.len == 0) {
        write("no secrets\n", .{});
        return;
    }

    for (names.items) |name| {
        write("{s}\n", .{name});
    }
}

fn rotate(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) SecretCommandsError!void {
    const name = requireArg(args, "usage: yoq secret rotate <name>\n");

    var sec_store = secrets_cli.open(alloc);
    defer secrets_cli.close(alloc, &sec_store);

    sec_store.rotate(name) catch |err| {
        if (err == secrets.SecretsError.NotFound) {
            writeErr("secret not found: {s}\n", .{name});
            return SecretCommandsError.SecretNotFound;
        } else {
            writeErr("failed to rotate secret\n", .{});
            return SecretCommandsError.StoreFailed;
        }
    };

    write("{s}\n", .{name});
}

// -- backup/restore commands --

const BackupCommandsError = error{
    InvalidArgument,
    BackupFailed,
    RestoreFailed,
};

pub fn backupCmd(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    _ = ctx;
    var output_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--output")) {
            output_path = args.next() orelse {
                writeErr("--output requires a file path\n", .{});
                return BackupCommandsError.InvalidArgument;
            };
        }
    }

    // default output path with timestamp
    var default_buf: [256]u8 = undefined;
    const ts = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    const path = output_path orelse std.fmt.bufPrint(&default_buf, "yoq-backup-{d}.db", .{ts}) catch {
        writeErr("failed to generate backup filename\n", .{});
        return BackupCommandsError.BackupFailed;
    };

    // null-terminate path for sqlite
    var path_z_buf: [paths.max_path]u8 = undefined;
    if (path.len >= path_z_buf.len) {
        writeErr("output path too long\n", .{});
        return BackupCommandsError.InvalidArgument;
    }
    @memcpy(path_z_buf[0..path.len], path);
    path_z_buf[path.len] = 0;
    const path_z: [:0]const u8 = path_z_buf[0..path.len :0];

    backup_mod.backup(path_z) catch |err| {
        writeErr("backup failed: {}\n", .{err});
        return BackupCommandsError.BackupFailed;
    };

    write("backup saved to {s}\n", .{path});
}

pub fn restoreCmd(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    _ = ctx;
    var input_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--input")) {
            input_path = args.next() orelse {
                writeErr("--input requires a file path\n", .{});
                return BackupCommandsError.InvalidArgument;
            };
        } else if (input_path == null) {
            input_path = arg;
        }
    }

    const path = input_path orelse {
        writeErr("usage: yoq restore <path> or yoq restore --input <path>\n", .{});
        return BackupCommandsError.InvalidArgument;
    };

    // null-terminate path for sqlite
    var path_z_buf: [paths.max_path]u8 = undefined;
    if (path.len >= path_z_buf.len) {
        writeErr("input path too long\n", .{});
        return BackupCommandsError.InvalidArgument;
    }
    @memcpy(path_z_buf[0..path.len], path);
    path_z_buf[path.len] = 0;
    const path_z: [:0]const u8 = path_z_buf[0..path.len :0];

    // check if the input file exists
    std.Io.Dir.cwd().access(std.Options.debug_io, path, .{}) catch {
        writeErr("backup file not found: {s}\n", .{path});
        return BackupCommandsError.RestoreFailed;
    };

    backup_mod.restore(path_z) catch |err| {
        switch (err) {
            backup_mod.BackupError.SchemaValidationFailed => writeErr("restore failed: backup has invalid schema\n", .{}),
            else => writeErr("restore failed: {}\n", .{err}),
        }
        return BackupCommandsError.RestoreFailed;
    };

    write("database restored from {s}\n", .{path});
}
