const std = @import("std");
const cli = @import("../../lib/cli.zig");
const cert_store = @import("../cert_store.zig");
const common = @import("common.zig");
const store_support = @import("store_support.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const requireArg = cli.requireArg;

pub fn run(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) common.TlsCommandsError!void {
    const domain = requireArg(args, "usage: yoq cert rm <domain>\n");

    var opened = store_support.openCertStore(alloc) catch |err|
        return store_support.reportOpenStoreError(err);
    defer store_support.closeCertStore(alloc, &opened);

    opened.store.remove(domain) catch |err| {
        if (err == cert_store.CertError.NotFound) {
            writeErr("certificate not found: {s}\n", .{domain});
            return common.TlsCommandsError.CertificateNotFound;
        }

        writeErr("failed to remove certificate\n", .{});
        return common.TlsCommandsError.StoreFailed;
    };

    write("{s}\n", .{domain});
}
