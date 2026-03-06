const std = @import("std");
const cli = @import("../lib/cli.zig");
const json_out = @import("../lib/json_output.zig");
const cert_store = @import("cert_store.zig");
const acme = @import("acme.zig");
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
    var domain: ?[]const u8 = null;
    var email: ?[]const u8 = null;
    var use_staging = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--email")) {
            email = args.next() orelse {
                writeErr("--email requires an address\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--staging")) {
            use_staging = true;
        } else if (arg[0] != '-') {
            domain = arg;
        } else {
            writeErr("unknown option: {s}\n", .{arg});
            std.process.exit(1);
        }
    }

    const dom = domain orelse {
        writeErr("usage: yoq cert provision <domain> --email <email> [--staging]\n", .{});
        std.process.exit(1);
    };
    const em = email orelse {
        writeErr("--email is required for ACME provisioning\n", .{});
        std.process.exit(1);
    };

    const directory_url = if (use_staging)
        acme.letsencrypt_staging
    else
        acme.letsencrypt_production;

    writeErr("provisioning certificate for {s}...\n", .{dom});
    if (use_staging) writeErr("  using staging environment\n", .{});

    var client = acme.AcmeClient.init(alloc, directory_url);
    defer client.deinit();

    // step 1: discover endpoints
    client.fetchDirectory() catch {
        writeErr("failed to fetch ACME directory\n", .{});
        std.process.exit(1);
    };

    // step 2: create account
    client.createAccount(em) catch {
        writeErr("failed to create ACME account\n", .{});
        std.process.exit(1);
    };
    writeErr("  account registered\n", .{});

    // step 3: create order
    var order = client.createOrder(dom) catch {
        writeErr("failed to create certificate order\n", .{});
        std.process.exit(1);
    };
    defer order.deinit();

    // step 4: handle HTTP-01 challenge
    if (order.authorization_urls.len > 0) {
        var challenge = client.getHttpChallenge(order.authorization_urls[0]) catch {
            writeErr("failed to get HTTP-01 challenge\n", .{});
            std.process.exit(1);
        };
        defer challenge.deinit();

        writeErr("  challenge token: {s}\n", .{challenge.token});
        writeErr("  place at: /.well-known/acme-challenge/{s}\n", .{challenge.token});

        client.respondToChallenge(challenge.url) catch {
            writeErr("failed to respond to challenge\n", .{});
            std.process.exit(1);
        };
    }

    // step 5: finalize, export as PEM, and store
    var exported = client.finalizeAndExport(order.finalize_url, dom) catch {
        writeErr("failed to finalize certificate order\n", .{});
        std.process.exit(1);
    };
    defer exported.deinit();

    var cs = openCertStore(alloc);
    defer closeCertStore(alloc, &cs);

    cs.install(dom, exported.cert_pem, exported.key_pem, "acme") catch {
        writeErr("failed to store certificate\n", .{});
        std.process.exit(1);
    };

    writeErr("certificate provisioned for {s}\n", .{dom});
}

fn cmdCertRenew(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const domain = requireArg(args, "usage: yoq cert renew <domain>\n");

    // check if cert exists and get its source
    var cs = openCertStore(alloc);
    defer closeCertStore(alloc, &cs);

    // verify the domain has an existing certificate
    const needs = cs.needsRenewal(domain, 90) catch |err| {
        if (err == cert_store.CertError.NotFound) {
            writeErr("no certificate found for {s}\n", .{domain});
        } else {
            writeErr("failed to check certificate for {s}\n", .{domain});
        }
        std.process.exit(1);
    };

    if (!needs) {
        writeErr("certificate for {s} does not need renewal yet\n", .{domain});
        return;
    }

    writeErr("certificate for {s} needs renewal\n", .{domain});
    writeErr("run: yoq cert provision {s} --email <email>\n", .{domain});
    writeErr("automatic renewal via the orchestrator is available in the next release\n", .{});
}

/// open a CertStore with a heap-allocated database connection.
/// exits on failure — used by CLI commands.
/// caller must call closeCertStore() when done.
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
