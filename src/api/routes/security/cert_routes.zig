const std = @import("std");
const json_helpers = @import("../../../lib/json_helpers.zig");
const cert_store = @import("../../../tls/cert_store.zig");
const common = @import("../common.zig");
const store_support = @import("store_support.zig");

const Response = common.Response;
const CertificateListContext = struct {
    certs: []const cert_store.CertInfo,
};

pub fn handleListCertificates(alloc: std.mem.Allocator) Response {
    var cs = store_support.openCertStore(alloc) orelse return common.internalError();
    defer store_support.closeCertStore(alloc, &cs);

    var certs = cs.list() catch return common.internalError();
    defer {
        for (certs.items) |c| c.deinit(alloc);
        certs.deinit(alloc);
    }

    return common.jsonOkWrite(alloc, CertificateListContext{
        .certs = certs.items,
    }, writeCertificateListJson);
}

pub fn handleDeleteCertificate(alloc: std.mem.Allocator, domain: []const u8) Response {
    var cs = store_support.openCertStore(alloc) orelse return common.internalError();
    defer store_support.closeCertStore(alloc, &cs);

    cs.remove(domain) catch |err| {
        if (err == cert_store.CertError.NotFound) return common.notFound();
        return common.internalError();
    };

    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}

fn writeCertificateListJson(writer: *std.Io.Writer, ctx: CertificateListContext) !void {
    try writer.writeByte('[');
    for (ctx.certs, 0..) |cert, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll("{\"domain\":\"");
        try json_helpers.writeJsonEscaped(writer, cert.domain);
        try writer.writeAll("\",\"not_after\":");
        try writer.print("{d}", .{cert.not_after});
        try writer.writeAll(",\"source\":\"");
        try json_helpers.writeJsonEscaped(writer, cert.source);
        try writer.writeAll("\"}");
    }
    try writer.writeByte(']');
}
