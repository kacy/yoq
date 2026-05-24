const std = @import("std");
const store = @import("../../../state/store.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const common = @import("../common.zig");

const Response = common.Response;

/// list recent audit entries, newest first, as a JSON array.
pub fn handleListAudit(alloc: std.mem.Allocator, limit: u32) Response {
    var entries = store.listAuditEntries(alloc, limit) catch return common.internalError();
    defer {
        for (entries.items) |e| e.deinit(alloc);
        entries.deinit(alloc);
    }

    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();
    const writer = &json_buf_writer.writer;

    writer.writeByte('[') catch return common.internalError();
    for (entries.items, 0..) |e, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writeEntryJson(writer, e) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf_writer.toOwnedSlice() catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn writeEntryJson(writer: *std.Io.Writer, entry: store.AuditLogRecord) !void {
    try writer.print("{{\"recorded_at\":{d},\"actor\":\"", .{entry.recorded_at});
    try json_helpers.writeJsonEscaped(writer, entry.actor);
    try writer.writeAll("\",\"action\":\"");
    try json_helpers.writeJsonEscaped(writer, entry.action);
    try writer.writeAll("\",\"target\":");
    if (entry.target) |t| {
        try writer.writeByte('"');
        try json_helpers.writeJsonEscaped(writer, t);
        try writer.writeByte('"');
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"outcome\":\"");
    try json_helpers.writeJsonEscaped(writer, entry.outcome);
    try writer.writeAll("\"}");
}
