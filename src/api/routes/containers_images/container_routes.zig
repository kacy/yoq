const std = @import("std");
const store = @import("../../../state/store.zig");
const logs = @import("../../../runtime/logs.zig");
const common = @import("../common.zig");
const writers = @import("writers.zig");

const Response = common.Response;
const ContainerListContext = struct {
    alloc: std.mem.Allocator,
    ids: []const []const u8,
};
const ContainerContext = struct {
    record: store.ContainerRecord,
};
const ContainerLogsContext = struct {
    log_data: []const u8,
};

pub fn handleListContainers(alloc: std.mem.Allocator) Response {
    var ids = store.listIds(alloc) catch return common.internalError();
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    return common.jsonOkWrite(alloc, ContainerListContext{
        .alloc = alloc,
        .ids = ids.items,
    }, writeContainerListJson);
}

pub fn handleGetContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };
    defer record.deinit(alloc);

    return common.jsonOkWrite(alloc, ContainerContext{
        .record = record,
    }, writeContainerJson);
}

pub fn handleGetLogs(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };
    record.deinit(alloc);

    const log_data = logs.readLogs(alloc, id) catch {
        const empty = alloc.dupe(u8, "{\"logs\":\"\"}") catch return common.internalError();
        return .{ .status = .ok, .body = empty, .allocated = true };
    };
    defer alloc.free(log_data);

    return common.jsonOkWrite(alloc, ContainerLogsContext{
        .log_data = log_data,
    }, writeContainerLogsJson);
}

pub fn handleStopContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const outcome = @import("../../../runtime/container_lifecycle.zig").stop(alloc, id, .brief) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        error.InvalidStatus, error.NotRunning => common.badRequest("container is not running"),
        else => common.internalError(),
    };
    return .{ .status = .ok, .body = if (outcome == .stopped) "{\"status\":\"stopped\"}" else "{\"status\":\"stopping\"}", .allocated = false };
}

pub const waitForProcessExit = @import("../../../runtime/container_lifecycle.zig").waitForProcessExit;

pub fn handleRemoveContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    @import("../../../runtime/container_lifecycle.zig").remove(alloc, id, false) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        error.ContainerRunning => common.badRequest("cannot remove running container"),
        else => common.internalError(),
    };
    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}

fn writeContainerListJson(writer: *std.Io.Writer, ctx: ContainerListContext) !void {
    try writer.writeByte('[');
    var first = true;
    for (ctx.ids) |id| {
        const record = store.load(ctx.alloc, id) catch continue;
        defer record.deinit(ctx.alloc);

        if (!first) try writer.writeByte(',');
        first = false;
        try writers.writeContainerJson(writer, record);
    }
    try writer.writeByte(']');
}

fn writeContainerJson(writer: *std.Io.Writer, ctx: ContainerContext) !void {
    try writers.writeContainerJson(writer, ctx.record);
}

fn writeContainerLogsJson(writer: *std.Io.Writer, ctx: ContainerLogsContext) !void {
    try writer.writeAll("{\"logs\":\"");
    try @import("../../../lib/json_helpers.zig").writeJsonEscaped(writer, ctx.log_data);
    try writer.writeAll("\"}");
}

test {
    _ = @import("../../../runtime/container_lifecycle.zig");
}
