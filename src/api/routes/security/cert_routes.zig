const std = @import("std");
const platform = @import("platform");
const json_helpers = @import("../../../lib/json_helpers.zig");
const cert_store = @import("../../../tls/cert_store.zig");
const common = @import("../common.zig");
const store_support = @import("store_support.zig");

const Response = common.Response;

pub fn handleListCertificates(alloc: std.mem.Allocator) Response {
    var cs = store_support.openCertStore(alloc) orelse return common.internalError();
    defer store_support.closeCertStore(alloc, &cs);

    var certs = cs.list() catch return common.internalError();
    defer {
        for (certs.items) |c| c.deinit(alloc);
        certs.deinit(alloc);
    }

    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;

    writer.writeByte('[') catch return common.internalError();
    for (certs.items, 0..) |cert, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writer.writeAll("{\"domain\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, cert.domain) catch return common.internalError();
        writer.writeAll("\",\"not_after\":") catch return common.internalError();
        writer.print("{d}", .{cert.not_after}) catch return common.internalError();
        writer.writeAll(",\"source\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, cert.source) catch return common.internalError();
        writer.writeAll("\"}") catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf_writer.toOwnedSlice() catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
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
