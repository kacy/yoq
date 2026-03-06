const std = @import("std");
const cli = @import("../lib/cli.zig");
const json_out = @import("../lib/json_output.zig");
const cert_store = @import("cert_store.zig");
const store = @import("../state/store.zig");
const sqlite = @import("sqlite");

const write = cli.write;
const writeErr = cli.writeErr;
const requireArg = cli.requireArg;
const formatTimestamp = cli.formatTimestamp;

pub fn cert(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
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
        std.process.exit(1);
    };

    if (std.mem.eql(u8, cmd, "install")) {
        cmdCertInstall(args, alloc);
    } else if (std.mem.eql(u8, cmd, "provision")) {
        cmdCertProvision(args, alloc);
    } else if (std.mem.eql(u8, cmd, "renew")) {
        cmdCertRenew(args, alloc);
    } else if (std.mem.eql(u8, cmd, "list")) {
        // also check remaining args for --json
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--json")) cli.output_mode = .json;
        }
        cmdCertList(alloc);
    } else if (std.mem.eql(u8, cmd, "rm")) {
        cmdCertRm(args, alloc);
    } else {
        writeErr("unknown cert command: {s}\n", .{cmd});
        std.process.exit(1);
    }
}

fn cmdCertInstall(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var domain: ?[]const u8 = null;
    var cert_path: ?[]const u8 = null;
    var key_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--cert")) {
            cert_path = args.next() orelse {
                writeErr("--cert requires a file path\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--key")) {
            key_path = args.next() orelse {
                writeErr("--key requires a file path\n", .{});
                std.process.exit(1);
            };
        } else if (domain == null) {
            domain = arg;
        }
    }

    const dom = domain orelse {
        writeErr("usage: yoq cert install <domain> --cert <path> --key <path>\n", .{});
        std.process.exit(1);
    };
    const cp = cert_path orelse {
        writeErr("--cert is required\n", .{});
        std.process.exit(1);
    };
    const kp = key_path orelse {
        writeErr("--key is required\n", .{});
        std.process.exit(1);
    };

    // read cert file
    const cert_pem = std.fs.cwd().readFileAlloc(alloc, cp, 1024 * 1024) catch {
        writeErr("failed to read certificate file: {s}\n", .{cp});
        std.process.exit(1);
    };
    defer alloc.free(cert_pem);

    // read key file
    const key_pem = std.fs.cwd().readFileAlloc(alloc, kp, 1024 * 1024) catch {
        writeErr("failed to read key file: {s}\n", .{kp});
        std.process.exit(1);
    };
    defer {
        std.crypto.secureZero(u8, key_pem);
        alloc.free(key_pem);
    }

    var cs = openCertStore(alloc);
    defer closeCertStore(alloc, &cs);

    cs.install(dom, cert_pem, key_pem, "manual") catch |err| {
        if (err == cert_store.CertError.InvalidCert) {
            writeErr("failed to parse certificate (invalid PEM or X.509)\n", .{});
        } else {
            writeErr("failed to store certificate\n", .{});
        }
        std.process.exit(1);
    };

    write("{s}\n", .{dom});
}

fn cmdCertList(alloc: std.mem.Allocator) void {
    var cs = openCertStore(alloc);
    defer closeCertStore(alloc, &cs);

    var certs = cs.list() catch {
        writeErr("failed to list certificates\n", .{});
        std.process.exit(1);
    };
    defer {
        for (certs.items) |c| c.deinit(alloc);
        certs.deinit(alloc);
    }

    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginArray();
        for (certs.items) |c| {
            w.beginObject();
            w.stringField("domain", c.domain);
            w.intField("not_after", c.not_after);
            w.stringField("source", c.source);
            w.intField("created_at", c.created_at);
            w.endObject();
        }
        w.endArray();
        w.flush();
        return;
    }

    if (certs.items.len == 0) {
        write("no certificates\n", .{});
        return;
    }

    for (certs.items) |c| {
        var ts_buf: [20]u8 = undefined;
        const expires = formatTimestamp(&ts_buf, c.not_after);
        write("{s}  expires={s}  source={s}\n", .{ c.domain, expires, c.source });
    }
}

fn cmdCertRm(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const domain = requireArg(args, "usage: yoq cert rm <domain>\n");

    var cs = openCertStore(alloc);
    defer closeCertStore(alloc, &cs);

    cs.remove(domain) catch |err| {
        if (err == cert_store.CertError.NotFound) {
            writeErr("certificate not found: {s}\n", .{domain});
        } else {
            writeErr("failed to remove certificate\n", .{});
        }
        std.process.exit(1);
    };

    write("{s}\n", .{domain});
}

fn cmdCertProvision(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    _ = args;
    _ = alloc;
    writeErr("acme provisioning is not yet production-safe; use 'yoq cert install' for now\n", .{});
    std.process.exit(1);
}

fn cmdCertRenew(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    _ = args;
    _ = alloc;
    writeErr("acme renewal is not yet production-safe; renew manually with 'yoq cert install'\n", .{});
    std.process.exit(1);
}

fn openCertStore(alloc: std.mem.Allocator) cert_store.CertStore {
    const db_ptr = alloc.create(sqlite.Db) catch {
        writeErr("failed to allocate database\n", .{});
        std.process.exit(1);
    };
    db_ptr.* = store.openDb() catch {
        alloc.destroy(db_ptr);
        writeErr("failed to open database\n", .{});
        std.process.exit(1);
    };

    return cert_store.CertStore.init(db_ptr, alloc) catch |err| {
        db_ptr.deinit();
        alloc.destroy(db_ptr);
        if (err == cert_store.CertError.HomeDirNotFound) {
            writeErr("HOME directory not found\n", .{});
        } else {
            writeErr("failed to initialize certificate store\n", .{});
        }
        std.process.exit(1);
    };
}

/// close a cert store opened with openCertStore.
fn closeCertStore(alloc: std.mem.Allocator, cs: *cert_store.CertStore) void {
    cs.db.deinit();
    alloc.destroy(cs.db);
}
