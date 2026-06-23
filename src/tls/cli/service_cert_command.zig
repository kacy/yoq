// service_cert_command — `yoq cert service <name>` inspector.
//
// shows the raft-replicated mTLS leaf cert for a service: when it was
// issued, when it expires, and its SAN identity. read-only — useful for
// debugging issuance / rotation issues without needing direct sqlite
// access.

const std = @import("std");
const cli = @import("../../lib/cli.zig");
const json_out = @import("../../lib/json_output.zig");
const store = @import("../../state/store.zig");
const x509_verify = @import("../x509_verify.zig");
const pem_mod = @import("../pem.zig");
const common = @import("common.zig");

const write = cli.write;
const writeErr = cli.writeErr;

pub const Error = common.TlsCommandsError;

pub fn run(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) Error!void {
    const service_name = args.next() orelse {
        writeErr("usage: yoq cert service <name>\n", .{});
        return Error.InvalidArgument;
    };

    const rec_opt = store.getMtlsCert(alloc, service_name) catch |err| {
        writeErr("failed to read certificate store: {}\n", .{err});
        return Error.ReadFailed;
    };
    const rec = rec_opt orelse {
        writeErr("no mtls cert issued for service '{s}' (issuer may not have run yet)\n", .{service_name});
        return Error.CertificateNotFound;
    };
    defer rec.deinit(alloc);

    // parse the leaf to surface the SAN URI alongside the row's stored
    // timestamps. parse errors are non-fatal — we still show what we
    // have from the row.
    var san_buf: [x509_verify.max_san_uris][]const u8 = undefined;
    var san: ?[]const u8 = null;
    var subject_cn: ?[]const u8 = null;
    var parsed_der: ?[]u8 = null;
    defer if (parsed_der) |d| alloc.free(d);

    if (pem_mod.parseCertDer(alloc, rec.cert_pem)) |der| {
        parsed_der = der;
        if (x509_verify.parseDer(der, &san_buf)) |parsed| {
            subject_cn = parsed.subject_cn;
            if (parsed.san_uris.len > 0) san = parsed.san_uris[0];
        } else |_| {}
    } else |_| {}

    if (cli.output_mode == .json) {
        writeJson(rec, subject_cn, san);
    } else {
        writeHuman(service_name, rec, subject_cn, san);
    }
}

fn writeHuman(service_name: []const u8, rec: store.MtlsCertRecord, subject_cn: ?[]const u8, san: ?[]const u8) void {
    write("service: {s}\n", .{service_name});
    write("source:  mtls (raft-replicated)\n", .{});
    if (subject_cn) |cn| write("subject: {s}\n", .{cn});
    if (san) |uri| write("identity: {s}\n", .{uri});
    write("issued:  {d} (unix)\n", .{rec.created_at});
    write("expires: {d} (unix)\n", .{rec.not_after});

    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    const remaining = rec.not_after - now;
    if (remaining <= 0) {
        write("status:  expired\n", .{});
    } else {
        const hours = @divFloor(remaining, 3600);
        write("status:  valid for ~{d}h\n", .{hours});
    }
}

fn writeJson(rec: store.MtlsCertRecord, subject_cn: ?[]const u8, san: ?[]const u8) void {
    var w = json_out.JsonWriter{};
    w.beginObject();
    w.stringField("source", "mtls");
    if (subject_cn) |cn| w.stringField("subject", cn);
    if (san) |uri| w.stringField("identity", uri);
    w.intField("created_at", rec.created_at);
    w.intField("not_after", rec.not_after);
    w.endObject();
    w.flush();
}
