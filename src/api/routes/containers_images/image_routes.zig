const std = @import("std");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const writers = @import("writers.zig");

const Response = common.Response;
const ImageListContext = struct {
    images: []const store.ImageRecord,
};

pub fn handleListImages(alloc: std.mem.Allocator) Response {
    var images = store.listImages(alloc) catch return common.internalError();
    defer {
        for (images.items) |img| img.deinit(alloc);
        images.deinit(alloc);
    }

    return common.jsonOkWrite(alloc, ImageListContext{
        .images = images.items,
    }, writeImageListJson);
}

pub fn handleRemoveImage(id: []const u8) Response {
    store.removeImage(id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };

    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}

fn writeImageListJson(writer: *std.Io.Writer, ctx: ImageListContext) !void {
    try writer.writeByte('[');
    for (ctx.images, 0..) |image, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writers.writeImageJson(writer, image);
    }
    try writer.writeByte(']');
}
