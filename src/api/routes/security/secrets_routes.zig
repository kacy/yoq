const std = @import("std");
const http = @import("../../http.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const secrets = @import("../../../state/secrets.zig");
const common = @import("../common.zig");
const store_support = @import("store_support.zig");

const Response = common.Response;
const extractJsonString = json_helpers.extractJsonString;

pub fn handleListSecrets(alloc: std.mem.Allocator) Response {
    var sec = store_support.openSecretsStore(alloc) orelse return common.internalError();
    defer store_support.closeSecretsStore(alloc, &sec);

    var names = sec.list() catch return common.internalError();
    defer {
        for (names.items) |n| alloc.free(n);
        names.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();
    for (names.items, 0..) |name, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writer.writeByte('"') catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, name) catch return common.internalError();
        writer.writeByte('"') catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleSetSecret(alloc: std.mem.Allocator, request: http.Request) Response {
    if (request.body.len == 0) return common.badRequest("missing request body");

    const name = extractJsonString(request.body, "name") orelse return common.badRequest("missing name field");
    const value = extractJsonString(request.body, "value") orelse return common.badRequest("missing value field");

    if (name.len == 0) return common.badRequest("name cannot be empty");

    var sec = store_support.openSecretsStore(alloc) orelse return common.internalError();
    defer store_support.closeSecretsStore(alloc, &sec);

    sec.set(name, value) catch return common.internalError();

    return .{ .status = .ok, .body = "{\"status\":\"ok\"}", .allocated = false };
}

pub fn handleDeleteSecret(alloc: std.mem.Allocator, name: []const u8) Response {
    var sec = store_support.openSecretsStore(alloc) orelse return common.internalError();
    defer store_support.closeSecretsStore(alloc, &sec);

    sec.remove(name) catch |err| {
        if (err == secrets.SecretsError.NotFound) return common.notFound();
        return common.internalError();
    };

    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}
