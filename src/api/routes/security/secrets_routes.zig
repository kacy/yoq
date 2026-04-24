const std = @import("std");
const http = @import("../../http.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const secrets = @import("../../../state/secrets.zig");
const common = @import("../common.zig");
const store_support = @import("store_support.zig");

const Response = common.Response;
const extractJsonString = json_helpers.extractJsonString;
const SecretListContext = struct {
    names: []const []const u8,
};

pub fn handleListSecrets(alloc: std.mem.Allocator) Response {
    var sec = store_support.openSecretsStore(alloc) orelse return common.internalError();
    defer store_support.closeSecretsStore(alloc, &sec);

    var names = sec.list() catch return common.internalError();
    defer {
        for (names.items) |n| alloc.free(n);
        names.deinit(alloc);
    }

    return common.jsonOkWrite(alloc, SecretListContext{
        .names = names.items,
    }, writeSecretListJson);
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

fn writeSecretListJson(writer: *std.Io.Writer, ctx: SecretListContext) !void {
    try writer.writeByte('[');
    for (ctx.names, 0..) |name, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeByte('"');
        try json_helpers.writeJsonEscaped(writer, name);
        try writer.writeByte('"');
    }
    try writer.writeByte(']');
}
