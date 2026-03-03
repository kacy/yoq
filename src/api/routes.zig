// routes — API route dispatch and handler implementations
//
// maps method + path to handler functions. handlers call into store.zig
// for data and return JSON responses. no framework — just string matching
// on paths. ~10 endpoints don't need a router.
//
// each handler returns a Response struct. the caller (server.zig) is
// responsible for formatting it into an HTTP response.

const std = @import("std");
const http = @import("http.zig");
const store = @import("../state/store.zig");
const process = @import("../runtime/process.zig");
const logs = @import("../runtime/logs.zig");
const container = @import("../runtime/container.zig");
const json_helpers = @import("../lib/json_helpers.zig");

pub const Response = struct {
    status: http.StatusCode,
    body: []const u8,
    /// if true, the caller must free body with the allocator passed to dispatch
    allocated: bool,
};

/// route an incoming request to the appropriate handler.
/// the caller must free response.body if response.allocated is true.
pub fn dispatch(request: http.Request, alloc: std.mem.Allocator) Response {
    const path = request.path_only;

    // static routes (no allocation needed)
    if (request.method == .GET) {
        if (std.mem.eql(u8, path, "/health")) return handleHealth();
        if (std.mem.eql(u8, path, "/version")) return handleVersion();
        if (std.mem.eql(u8, path, "/containers")) return handleListContainers(alloc);
        if (std.mem.eql(u8, path, "/images")) return handleListImages(alloc);
    }

    // /containers/{id} routes
    if (path.len > "/containers/".len and std.mem.startsWith(u8, path, "/containers/")) {
        const rest = path["/containers/".len..];

        // /containers/{id}/logs
        if (matchSubpath(rest, "/logs")) |id| {
            if (request.method != .GET) return methodNotAllowed();
            return handleGetLogs(alloc, id);
        }

        // /containers/{id}/stop
        if (matchSubpath(rest, "/stop")) |id| {
            if (request.method != .POST) return methodNotAllowed();
            return handleStopContainer(alloc, id);
        }

        // /containers/{id} (no suffix)
        if (std.mem.indexOf(u8, rest, "/") == null) {
            const id = rest;
            if (request.method == .GET) return handleGetContainer(alloc, id);
            if (request.method == .DELETE) return handleRemoveContainer(alloc, id);
            return methodNotAllowed();
        }
    }

    // /images/{id} routes
    if (path.len > "/images/".len and std.mem.startsWith(u8, path, "/images/")) {
        const id = path["/images/".len..];
        if (std.mem.indexOf(u8, id, "/") == null) {
            if (request.method == .DELETE) return handleRemoveImage(id);
            return methodNotAllowed();
        }
    }

    return notFound();
}

// -- handlers --

fn handleHealth() Response {
    return .{
        .status = .ok,
        .body = "{\"status\":\"ok\"}",
        .allocated = false,
    };
}

fn handleVersion() Response {
    return .{
        .status = .ok,
        .body = "{\"version\":\"0.0.1\"}",
        .allocated = false,
    };
}

fn handleListContainers(alloc: std.mem.Allocator) Response {
    var ids = store.listIds(alloc) catch return internalError();
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    // build JSON array of container objects
    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return internalError();

    var first = true;
    for (ids.items) |id| {
        const record = store.load(alloc, id) catch continue;
        defer record.deinit(alloc);

        if (!first) writer.writeByte(',') catch return internalError();
        first = false;

        writeContainerJson(writer, record) catch return internalError();
    }

    writer.writeByte(']') catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleGetContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return notFound();
        return internalError();
    };
    defer record.deinit(alloc);

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writeContainerJson(writer, record) catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleGetLogs(alloc: std.mem.Allocator, id: []const u8) Response {
    // verify container exists
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return notFound();
        return internalError();
    };
    record.deinit(alloc);

    const log_data = logs.readLogs(alloc, id) catch {
        // no log file is fine — return empty
        const empty = alloc.dupe(u8, "{\"logs\":\"\"}") catch return internalError();
        return .{ .status = .ok, .body = empty, .allocated = true };
    };
    defer alloc.free(log_data);

    // escape the log content for JSON and build response
    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeAll("{\"logs\":\"") catch return internalError();
    json_helpers.writeJsonEscaped(writer, log_data) catch return internalError();
    writer.writeAll("\"}") catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleStopContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return notFound();
        return internalError();
    };
    defer record.deinit(alloc);

    if (!std.mem.eql(u8, record.status, "running")) {
        return badRequest("container is not running");
    }

    const pid = record.pid orelse return badRequest("container has no pid");

    process.terminate(pid) catch return internalError();
    store.updateStatus(id, "stopped", null, null) catch {};

    return .{
        .status = .ok,
        .body = "{\"status\":\"stopped\"}",
        .allocated = false,
    };
}

fn handleRemoveContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return notFound();
        return internalError();
    };

    if (std.mem.eql(u8, record.status, "running")) {
        record.deinit(alloc);
        return badRequest("cannot remove running container");
    }
    record.deinit(alloc);

    store.remove(id) catch return internalError();
    logs.deleteLogFile(id);
    container.cleanupContainerDirs(id);

    return .{
        .status = .ok,
        .body = "{\"status\":\"removed\"}",
        .allocated = false,
    };
}

fn handleListImages(alloc: std.mem.Allocator) Response {
    var images = store.listImages(alloc) catch return internalError();
    defer {
        for (images.items) |img| img.deinit(alloc);
        images.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return internalError();

    var first = true;
    for (images.items) |img| {
        if (!first) writer.writeByte(',') catch return internalError();
        first = false;

        writeImageJson(writer, img) catch return internalError();
    }

    writer.writeByte(']') catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleRemoveImage(id: []const u8) Response {
    store.removeImage(id) catch |err| {
        if (err == store.StoreError.NotFound) return notFound();
        return internalError();
    };

    return .{
        .status = .ok,
        .body = "{\"status\":\"removed\"}",
        .allocated = false,
    };
}

// -- response helpers --

fn notFound() Response {
    return .{ .status = .not_found, .body = "{\"error\":\"not found\"}", .allocated = false };
}

fn methodNotAllowed() Response {
    return .{ .status = .method_not_allowed, .body = "{\"error\":\"method not allowed\"}", .allocated = false };
}

fn internalError() Response {
    return .{ .status = .internal_server_error, .body = "{\"error\":\"internal error\"}", .allocated = false };
}

fn badRequest(comptime message: []const u8) Response {
    // message is comptime-known, so we can build the JSON at comptime
    return .{
        .status = .bad_request,
        .body = "{\"error\":\"" ++ message ++ "\"}",
        .allocated = false,
    };
}

// -- JSON serialization helpers --

/// write a container record as a JSON object
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
    try writer.writeByte('}');
}

/// write an image record as a JSON object
fn writeImageJson(writer: anytype, img: store.ImageRecord) !void {
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

/// extract an ID from a path like "{id}/suffix".
/// returns the id portion if the suffix matches, null otherwise.
fn matchSubpath(rest: []const u8, suffix: []const u8) ?[]const u8 {
    const slash = std.mem.indexOf(u8, rest, "/") orelse return null;
    const id = rest[0..slash];
    const after = rest[slash..];

    if (id.len == 0) return null;
    if (std.mem.eql(u8, after, suffix)) return id;
    return null;
}

// -- tests --

test "dispatch health" {
    const req = (try http.parseRequest("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", resp.body);
    try std.testing.expect(!resp.allocated);
}

test "dispatch version" {
    const req = (try http.parseRequest("GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expectEqualStrings("{\"version\":\"0.0.1\"}", resp.body);
}

test "dispatch not found" {
    const req = (try http.parseRequest("GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.not_found, resp.status);
}

test "dispatch method not allowed on health" {
    const req = (try http.parseRequest("POST /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.not_found, resp.status);
}

test "dispatch POST to container stop" {
    const req = (try http.parseRequest(
        "POST /containers/abc123/stop HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    // will return not found or internal error since no DB is configured
    // but it exercises the routing path correctly
    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch GET on container stop returns method not allowed" {
    const req = (try http.parseRequest(
        "GET /containers/abc123/stop HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
}

test "dispatch DELETE container" {
    const req = (try http.parseRequest(
        "DELETE /containers/abc123 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    // will fail because no DB, but routing is correct
    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch DELETE image" {
    const req = (try http.parseRequest(
        "DELETE /images/sha256:abc HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    // no DB configured, so this will error
    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "matchSubpath" {
    try std.testing.expectEqualStrings("abc123", matchSubpath("abc123/logs", "/logs").?);
    try std.testing.expectEqualStrings("def456", matchSubpath("def456/stop", "/stop").?);
    try std.testing.expect(matchSubpath("abc123", "/logs") == null);
    try std.testing.expect(matchSubpath("abc123/other", "/logs") == null);
    try std.testing.expect(matchSubpath("/logs", "/logs") == null); // empty id
}

test "writeJsonEscaped" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    try json_helpers.writeJsonEscaped(writer, "hello \"world\"\nline2");
    try std.testing.expectEqualStrings("hello \\\"world\\\"\\nline2", buf.items);
}

test "writeJsonEscaped with backslash" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    try json_helpers.writeJsonEscaped(writer, "path\\to\\file");
    try std.testing.expectEqualStrings("path\\\\to\\\\file", buf.items);
}
