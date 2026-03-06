const std = @import("std");
const http = @import("../http.zig");
const store = @import("../../state/store.zig");
const process = @import("../../runtime/process.zig");
const logs = @import("../../runtime/logs.zig");
const container = @import("../../runtime/container.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const log = @import("../../lib/log.zig");
const health = @import("../../manifest/health.zig");
const common = @import("common.zig");

const Response = common.Response;

pub fn route(request: http.Request, alloc: std.mem.Allocator) ?Response {
    const path = request.path_only;

    if (request.method == .GET) {
        if (std.mem.eql(u8, path, "/containers")) return handleListContainers(alloc);
        if (std.mem.eql(u8, path, "/images")) return handleListImages(alloc);
    }

    if (path.len > "/containers/".len and std.mem.startsWith(u8, path, "/containers/")) {
        const rest = path["/containers/".len..];
        const container_id_end = std.mem.indexOf(u8, rest, "/") orelse rest.len;
        if (!common.validateContainerId(rest[0..container_id_end])) return common.badRequest("invalid container id");

        if (common.matchSubpath(rest, "/logs")) |id| {
            if (request.method != .GET) return common.methodNotAllowed();
            return handleGetLogs(alloc, id);
        }

        if (common.matchSubpath(rest, "/stop")) |id| {
            if (request.method != .POST) return common.methodNotAllowed();
            return handleStopContainer(alloc, id);
        }

        if (std.mem.indexOf(u8, rest, "/") == null) {
            const id = rest;
            if (request.method == .GET) return handleGetContainer(alloc, id);
            if (request.method == .DELETE) return handleRemoveContainer(alloc, id);
            return common.methodNotAllowed();
        }
    }

    if (path.len > "/images/".len and std.mem.startsWith(u8, path, "/images/")) {
        const id = path["/images/".len..];
        if (std.mem.indexOf(u8, id, "/") == null) {
            if (request.method == .DELETE) return handleRemoveImage(id);
            return common.methodNotAllowed();
        }
    }

    return null;
}

fn handleListContainers(alloc: std.mem.Allocator) Response {
    var ids = store.listIds(alloc) catch return common.internalError();
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();

    var first = true;
    for (ids.items) |id| {
        const record = store.load(alloc, id) catch continue;
        defer record.deinit(alloc);

        if (!first) writer.writeByte(',') catch return common.internalError();
        first = false;

        writeContainerJson(writer, record) catch return common.internalError();
    }

    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleGetContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };
    defer record.deinit(alloc);

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writeContainerJson(writer, record) catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleGetLogs(alloc: std.mem.Allocator, id: []const u8) Response {
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

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeAll("{\"logs\":\"") catch return common.internalError();
    json_helpers.writeJsonEscaped(writer, log_data) catch return common.internalError();
    writer.writeAll("\"}") catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleStopContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };
    defer record.deinit(alloc);

    if (!std.mem.eql(u8, record.status, "running")) {
        return common.badRequest("container is not running");
    }

    const pid = record.pid orelse return common.badRequest("container has no pid");

    process.terminate(pid) catch return common.internalError();
    store.updateStatus(id, "stopped", null, null) catch |e| {
        log.warn("failed to update status after stopping {s}: {}", .{ id, e });
    };

    return .{ .status = .ok, .body = "{\"status\":\"stopped\"}", .allocated = false };
}

fn handleRemoveContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };

    if (std.mem.eql(u8, record.status, "running")) {
        record.deinit(alloc);
        return common.badRequest("cannot remove running container");
    }
    record.deinit(alloc);

    store.remove(id) catch return common.internalError();
    logs.deleteLogFile(id);
    container.cleanupContainerDirs(id);

    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}

fn handleListImages(alloc: std.mem.Allocator) Response {
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

        writeImageJson(writer, img) catch return common.internalError();
    }

    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleRemoveImage(id: []const u8) Response {
    store.removeImage(id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };

    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}

fn writeContainerJson(writer: anytype, record: store.ContainerRecord) !void {
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
        try std.fmt.format(writer, "{d}", .{pid});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"created_at\":");
    try std.fmt.format(writer, "{d}", .{record.created_at});

    if (health.getServiceHealth(record.hostname)) |sh| {
        const health_str = switch (sh.status) {
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
    try std.fmt.format(writer, "{d}", .{img.total_size});
    try writer.writeAll(",\"created_at\":");
    try std.fmt.format(writer, "{d}", .{img.created_at});
    try writer.writeByte('}');
}
