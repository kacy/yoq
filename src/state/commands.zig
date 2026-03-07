const std = @import("std");
const cli = @import("../lib/cli.zig");
const json_out = @import("../lib/json_output.zig");
const secrets = @import("secrets.zig");
const store = @import("store.zig");
const sqlite = @import("sqlite");

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

pub fn secret(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
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

fn set(args: *std.process.ArgIterator, alloc: std.mem.Allocator) SecretCommandsError!void {
    var name: ?[]const u8 = null;
    var value_flag: ?[]const u8 = null;

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
        const stdin_file: std.fs.File = .{ .handle = std.posix.STDIN_FILENO };
        const stdin_data = stdin_file.readToEndAlloc(alloc, 1024 * 1024) catch {
            writeErr("failed to read from stdin\n", .{});
            return SecretCommandsError.StoreFailed;
        };
        // trim trailing newline — users typically pipe from echo or here-string
        break :blk std.mem.trimRight(u8, stdin_data, "\n\r");
    };

    var sec_store = openSecretsStore(alloc);
    defer closeSecretsStore(alloc, &sec_store);

    sec_store.set(secret_name, value) catch {
        writeErr("failed to store secret\n", .{});
        return SecretCommandsError.StoreFailed;
    };

    write("{s}\n", .{secret_name});
}

fn get(args: *std.process.ArgIterator, alloc: std.mem.Allocator) SecretCommandsError!void {
    const name = requireArg(args, "usage: yoq secret get <name>\n");

    var sec_store = openSecretsStore(alloc);
    defer closeSecretsStore(alloc, &sec_store);

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

fn rm(args: *std.process.ArgIterator, alloc: std.mem.Allocator) SecretCommandsError!void {
    const name = requireArg(args, "usage: yoq secret rm <name>\n");

    var sec_store = openSecretsStore(alloc);
    defer closeSecretsStore(alloc, &sec_store);

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
    var sec_store = openSecretsStore(alloc);
    defer closeSecretsStore(alloc, &sec_store);

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

fn rotate(args: *std.process.ArgIterator, alloc: std.mem.Allocator) SecretCommandsError!void {
    const name = requireArg(args, "usage: yoq secret rotate <name>\n");

    var sec_store = openSecretsStore(alloc);
    defer closeSecretsStore(alloc, &sec_store);

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

/// open a SecretsStore with a heap-allocated database connection.
/// exits on failure — used by CLI commands where there's nothing to recover from.
/// caller must call closeSecretsStore() when done.
fn openSecretsStore(alloc: std.mem.Allocator) secrets.SecretsStore {
    const db_ptr = alloc.create(sqlite.Db) catch {
        writeErr("failed to allocate database\n", .{});
        std.process.exit(1);
    };
    db_ptr.* = store.openDb() catch {
        alloc.destroy(db_ptr);
        writeErr("failed to open database\n", .{});
        std.process.exit(1);
    };

    return secrets.SecretsStore.init(db_ptr, alloc) catch |err| {
        db_ptr.deinit();
        alloc.destroy(db_ptr);
        if (err == secrets.SecretsError.HomeDirNotFound) {
            writeErr("HOME directory not found\n", .{});
        } else {
            writeErr("failed to initialize secrets store\n", .{});
        }
        std.process.exit(1);
    };
}

/// close a secrets store opened with openSecretsStore.
fn closeSecretsStore(alloc: std.mem.Allocator, sec: *secrets.SecretsStore) void {
    sec.db.deinit();
    alloc.destroy(sec.db);
}
