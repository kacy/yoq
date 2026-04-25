const std = @import("std");
const cli = @import("../../lib/cli.zig");
const cert_store = @import("../cert_store.zig");
const common = @import("common.zig");
const store_support = @import("store_support.zig");

const write = cli.write;
const writeErr = cli.writeErr;

pub fn run(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) common.TlsCommandsError!void {
    var domain: ?[]const u8 = null;
    var cert_path: ?[]const u8 = null;
    var key_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--cert")) {
            cert_path = args.next() orelse {
                writeErr("--cert requires a file path\n", .{});
                return common.TlsCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--key")) {
            key_path = args.next() orelse {
                writeErr("--key requires a file path\n", .{});
                return common.TlsCommandsError.InvalidArgument;
            };
        } else if (domain == null) {
            domain = arg;
        }
    }

    const dom = domain orelse {
        writeErr("usage: yoq cert install <domain> --cert <path> --key <path>\n", .{});
        return common.TlsCommandsError.InvalidArgument;
    };
    const cp = cert_path orelse {
        writeErr("--cert is required\n", .{});
        return common.TlsCommandsError.InvalidArgument;
    };
    const kp = key_path orelse {
        writeErr("--key is required\n", .{});
        return common.TlsCommandsError.InvalidArgument;
    };

    const cert_pem = std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, cp, alloc, .limited(1024 * 1024)) catch {
        writeErr("failed to read certificate file: {s}\n", .{cp});
        return common.TlsCommandsError.ReadFailed;
    };
    defer alloc.free(cert_pem);

    const key_pem = std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, kp, alloc, .limited(1024 * 1024)) catch {
        writeErr("failed to read key file: {s}\n", .{kp});
        return common.TlsCommandsError.ReadFailed;
    };
    defer {
        std.crypto.secureZero(u8, key_pem);
        alloc.free(key_pem);
    }

    var opened = store_support.openCertStore(alloc) catch |err|
        return store_support.reportOpenStoreError(err);
    defer store_support.closeCertStore(alloc, &opened);

    opened.store.install(dom, cert_pem, key_pem, "manual") catch |err| {
        if (err == cert_store.CertError.InvalidCert) {
            writeErr("failed to parse certificate (invalid PEM or X.509)\n", .{});
        } else {
            writeErr("failed to store certificate\n", .{});
        }
        return common.TlsCommandsError.StoreFailed;
    };

    write("{s}\n", .{dom});
}
