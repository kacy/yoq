const std = @import("std");
const store = @import("../../../state/store.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const health = @import("../../../manifest/health.zig");

pub fn writeContainerJson(writer: anytype, record: store.ContainerRecord) !void {
    try writer.writeAll("{\"id\":\"");
    try writer.writeAll(record.id);
    try writer.writeAll("\",\"command\":\"");
    try json_helpers.writeJsonEscaped(writer, record.command);
    try writer.writeAll("\",\"status\":\"");
    try writer.writeAll(record.status);
    try writer.writeAll("\",\"hostname\":\"");
    try json_helpers.writeJsonEscaped(writer, record.hostname);
    try writer.writeAll("\",\"pid\":");
    if (record.pid) |pid| {
        try @import("compat").format(writer, "{d}", .{pid});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"created_at\":");
    try @import("compat").format(writer, "{d}", .{record.created_at});

    if (health.getServiceHealth(record.hostname)) |service_health| {
        const health_str = switch (service_health.status) {
            .starting => "starting",
            .healthy => "healthy",
            .unhealthy => "unhealthy",
        };
        try writer.writeAll(",\"health\":\"");
        try writer.writeAll(health_str);
        try writer.writeByte('"');
    }

    try writer.writeByte('}');
}

pub fn writeImageJson(writer: anytype, img: store.ImageRecord) !void {
    try writer.writeAll("{\"id\":\"");
    try json_helpers.writeJsonEscaped(writer, img.id);
    try writer.writeAll("\",\"repository\":\"");
    try json_helpers.writeJsonEscaped(writer, img.repository);
    try writer.writeAll("\",\"tag\":\"");
    try json_helpers.writeJsonEscaped(writer, img.tag);
    try writer.writeAll("\",\"size\":");
    try @import("compat").format(writer, "{d}", .{img.total_size});
    try writer.writeAll(",\"created_at\":");
    try @import("compat").format(writer, "{d}", .{img.created_at});
    try writer.writeByte('}');
}
