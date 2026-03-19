const std = @import("std");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const writers = @import("writers.zig");

const Response = common.Response;

pub fn handleListImages(alloc: std.mem.Allocator) Response {
    var images = store.listImages(alloc) catch return common.internalError();
    defer {
        for (images.items) |img| img.deinit(alloc);
        images.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();

    var first = true;
    for (images.items) |img| {
        if (!first) writer.writeByte(',') catch return common.internalError();
        first = false;

        writers.writeImageJson(writer, img) catch return common.internalError();
    }

    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleRemoveImage(id: []const u8) Response {
    store.removeImage(id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };

    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}
