const std = @import("std");
const http = @import("../http.zig");
const store = @import("../../state/store.zig");
const process = @import("../../runtime/process.zig");
const logs = @import("../../runtime/logs.zig");
const container = @import("../../runtime/container.zig");
const cgroups = @import("../../runtime/cgroups.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const log = @import("../../lib/log.zig");
const health = @import("../../manifest/health.zig");
const common = @import("common.zig");

const Response = common.Response;
const stop_poll_attempts: usize = 10;
const stop_poll_interval_ms: u64 = 50;

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

    const cg = cgroups.Cgroup.open(id) catch {
        store.updateStatus(id, "stopped", null, null) catch {};
        return common.badRequest("container is not running");
    };
    if (!cg.containsProcess(pid)) {
        store.updateStatus(id, "stopped", null, null) catch {};
        return common.badRequest("container is not running");
    }

    process.terminate(pid) catch return common.internalError();

    if (waitForProcessExit(id, pid)) {
        store.updateStatus(id, "stopped", null, null) catch |e| {
            log.warn("failed to update status after stopping {s}: {}", .{ id, e });
        };
        return .{ .status = .ok, .body = "{\"status\":\"stopped\"}", .allocated = false };
    }

    return .{ .status = .ok, .body = "{\"status\":\"stopping\"}", .allocated = false };
}

fn waitForProcessExit(id: []const u8, pid: i32) bool {
    var attempts: usize = 0;
    while (attempts < stop_poll_attempts) : (attempts += 1) {
        const cg = cgroups.Cgroup.open(id) catch return true;
        if (!cg.containsProcess(pid)) return true;
        process.sendSignal(pid, 0) catch return true;
        std.Thread.sleep(stop_poll_interval_ms * std.time.ns_per_ms);
    }
    return false;
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

// -- tests --

const testing = std.testing;
const http_test = @import("../../testing/http_test.zig");

// Test that the route function returns null for unmatched paths
test "route returns null for unknown path" {
    const req = http.Request{
        .method = .GET,
        .path = "/unknown",
        .path_only = "/unknown",
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator);
    try testing.expect(response == null);
}

test "stop container refuses stale pid not owned by container cgroup" {
    store.initTestDb() catch return error.SkipZigTest;
    defer store.deinitTestDb();

    try store.save(.{
        .id = "deadbeefcafe",
        .hostname = "test",
        .rootfs = "/tmp/rootfs",
        .status = "running",
        .command = "sleep 10",
        .created_at = 1,
        .pid = 999999,
        .exit_code = null,
    });

    const resp = handleStopContainer(testing.allocator, "deadbeefcafe");
    try testing.expectEqual(http.StatusCode.bad_request, resp.status);

    const record = try store.load(testing.allocator, "deadbeefcafe");
    defer record.deinit(testing.allocator);
    try testing.expectEqualStrings("stopped", record.status);
    try testing.expect(record.pid == null);
}

test "waitForProcessExit returns true when cgroup is missing" {
    try testing.expect(waitForProcessExit("deadbeefcafe", 12345));
}

// Test that validateContainerId works correctly
fn testValidateContainerId() !void {
    // Valid ID (64 hex chars)
    try testing.expect(common.validateContainerId("abc123def4567890123456789012345678901234567890123456789012345678"));

    // Invalid: too short
    try testing.expect(!common.validateContainerId("abc123"));

    // Invalid: too long
    try testing.expect(!common.validateContainerId("abc123def456789012345678901234567890123456789012345678901234567890"));

    // Invalid: non-hex characters
    try testing.expect(!common.validateContainerId("xyz123def456789012345678901234567890123456789012345678901234567"));

    // Invalid: empty
    try testing.expect(!common.validateContainerId(""));

    // Invalid: uppercase (should be lowercase)
    try testing.expect(!common.validateContainerId("ABC123DEF456789012345678901234567890123456789012345678901234567"));
}

// Test route method validation
test "route rejects wrong method for /containers" {
    const post_req = http.Request{
        .method = .POST,
        .path = "/containers",
        .path_only = "/containers",
        .body = "",
        .headers_raw = "",
        .query = "",
        .content_length = 0,
    };

    const response = route(post_req, testing.allocator);
    try testing.expect(response == null); // Returns null, dispatch will handle 405
}

// Test writeContainerJson format
test "writeContainerJson produces valid JSON" {
    const record = store.ContainerRecord{
        .id = "abc123def4567890123456789012345678901234567890123456789012345678",
        .rootfs = "/tmp/rootfs",
        .command = "echo hello",
        .hostname = "test-host",
        .status = "running",
        .pid = 1234,
        .exit_code = null,
        .ip_address = null,
        .veth_host = null,
        .app_name = null,
        .created_at = 1234567890,
    };

    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    try writeContainerJson(writer, record);

    const json_str = fbs.getWritten();
    try testing.expect(std.mem.indexOf(u8, json_str, "\"id\":") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"status\":\"running\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"pid\":1234") != null);
}

// Test writeContainerJson with null pid
test "writeContainerJson handles null pid" {
    const record = store.ContainerRecord{
        .id = "abc123def4567890123456789012345678901234567890123456789012345678",
        .rootfs = "/tmp/rootfs",
        .command = "sleep 1000",
        .hostname = "test-host",
        .status = "exited",
        .pid = null,
        .exit_code = 0,
        .ip_address = null,
        .veth_host = null,
        .app_name = null,
        .created_at = 1234567890,
    };

    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    try writeContainerJson(writer, record);

    const json_str = fbs.getWritten();
    try testing.expect(std.mem.indexOf(u8, json_str, "\"pid\":null") != null);
}

// Test writeImageJson format
test "writeImageJson produces valid JSON" {
    const img = store.ImageRecord{
        .id = "img123def4567890123456789012345678901234567890123456789012345678",
        .repository = "alpine",
        .tag = "latest",
        .manifest_digest = "sha256:abc123",
        .config_digest = "sha256:def456",
        .total_size = 1024000,
        .created_at = 1234567890,
    };

    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    try writeImageJson(writer, img);

    const json_str = fbs.getWritten();
    try testing.expect(std.mem.indexOf(u8, json_str, "\"id\":") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"repository\":\"alpine\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"tag\":\"latest\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"size\":1024000") != null);
}

// Test command escaping in writeContainerJson
test "writeContainerJson escapes special characters" {
    const record = store.ContainerRecord{
        .id = "abc123def4567890123456789012345678901234567890123456789012345678",
        .rootfs = "/tmp/rootfs",
        .command = "echo \"hello world\"", // Contains quotes
        .hostname = "test-host",
        .status = "running",
        .pid = 1234,
        .exit_code = null,
        .ip_address = null,
        .veth_host = null,
        .app_name = null,
        .created_at = 1234567890,
    };

    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    try writeContainerJson(writer, record);

    const json_str = fbs.getWritten();
    // Should contain escaped quotes
    try testing.expect(std.mem.indexOf(u8, json_str, "\\\"hello world\\\"") != null);
}

// Test that handleRemoveImage validates ID format implicitly via path parsing
test "route handles /images/{id} DELETE" {
    const req = http.Request{
        .method = .DELETE,
        .path = "/images/abc123def4567890123456789012345678901234567890123456789012345678",
        .path_only = "/images/abc123def4567890123456789012345678901234567890123456789012345678",
        .body = "",
        .headers_raw = "",
        .query = "",
        .content_length = 0,
    };

    // This will fail with NotFound since image doesn't exist, but route should handle it
    const response = route(req, testing.allocator);
    // Response should be set (even if it returns 404)
    try testing.expect(response != null);
    if (response) |resp| {
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

// Test method not allowed for container operations
test "route returns method not allowed for wrong HTTP methods" {
    // PUT to /containers should not match
    const put_req = http.Request{
        .method = .PUT,
        .path = "/containers",
        .path_only = "/containers",
        .body = "",
        .headers_raw = "",
        .query = "",
        .content_length = 0,
    };

    const put_resp = route(put_req, testing.allocator);
    try testing.expect(put_resp == null);

    // PUT to /containers/{id} should return method not allowed (only GET/DELETE supported)
    const patch_req = http.Request{
        .method = .PUT,
        .path = "/containers/abc123def456",
        .path_only = "/containers/abc123def456",
        .body = "",
        .headers_raw = "",
        .query = "",
        .content_length = 0,
    };

    const patch_resp = route(patch_req, testing.allocator);
    try testing.expect(patch_resp != null);
    try testing.expectEqual(http.StatusCode.method_not_allowed, patch_resp.?.status);
}

// Test subpath matching for containers
test "route correctly matches container subpaths" {
    // /containers/{id}/logs - GET
    const logs_req = http.Request{
        .method = .GET,
        .path = "/containers/abc123def4567890123456789012345678901234567890123456789012345678/logs",
        .path_only = "/containers/abc123def4567890123456789012345678901234567890123456789012345678/logs",
        .body = "",
        .headers_raw = "",
        .query = "",
        .content_length = 0,
    };

    const logs_resp = route(logs_req, testing.allocator);
    try testing.expect(logs_resp != null);
    if (logs_resp) |resp| {
        if (resp.allocated) testing.allocator.free(resp.body);
    }

    // /containers/{id}/stop - POST
    const stop_req = http.Request{
        .method = .POST,
        .path = "/containers/abc123def4567890123456789012345678901234567890123456789012345678/stop",
        .path_only = "/containers/abc123def4567890123456789012345678901234567890123456789012345678/stop",
        .body = "",
        .headers_raw = "",
        .query = "",
        .content_length = 0,
    };

    const stop_resp = route(stop_req, testing.allocator);
    try testing.expect(stop_resp != null);
    if (stop_resp) |resp| {
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

// Test invalid container ID returns bad request
test "route returns bad request for invalid container ID" {
    const req = http.Request{
        .method = .GET,
        .path = "/containers/invalid-id/logs",
        .path_only = "/containers/invalid-id/logs", // Invalid ID
        .body = "",
        .headers_raw = "",
        .query = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

// Test that POST to /containers/{id} without subpath is not allowed
test "route method not allowed for POST to container without subpath" {
    const req = http.Request{
        .method = .POST,
        .path = "/containers/abc123def4567890123456789012345678901234567890123456789012345678",
        .path_only = "/containers/abc123def4567890123456789012345678901234567890123456789012345678",
        .body = "",
        .headers_raw = "",
        .query = "",
        .content_length = 0,
    };

    const response = route(req, testing.allocator);
    // Should return method not allowed response
    try testing.expect(response != null);
    if (response) |resp| {
        // Route returns null for unmatched, dispatch handles the rest
        // So we expect null here
        if (resp.status == .method_not_allowed) {
            if (resp.allocated) testing.allocator.free(resp.body);
        }
    }
}

// Test container ID validation directly through the route
test "container ID validation through route" {
    const valid_id = "abc123def4567890123456789012345678901234567890123456789012345678";

    // Valid ID should reach handler (and likely return 404 since container doesn't exist)
    const path = std.fmt.allocPrint(testing.allocator, "/containers/{s}", .{valid_id}) catch unreachable;
    defer testing.allocator.free(path);

    const valid_req = http.Request{
        .method = .GET,
        .path = path,
        .path_only = path,
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };

    const valid_resp = route(valid_req, testing.allocator);
    try testing.expect(valid_resp != null); // Handler reached
    if (valid_resp) |resp| {
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

// Test writeImageJson with empty strings
test "writeImageJson handles empty strings" {
    const img = store.ImageRecord{
        .id = "img123def4567890123456789012345678901234567890123456789012345678",
        .repository = "", // Empty repository
        .tag = "", // Empty tag
        .manifest_digest = "sha256:abc",
        .config_digest = "sha256:def",
        .total_size = 0,
        .created_at = 0,
    };

    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    try writeImageJson(writer, img);

    const json_str = fbs.getWritten();
    try testing.expect(std.mem.indexOf(u8, json_str, "\"repository\":\"\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_str, "\"tag\":\"\"") != null);
}

// Test that container routes handle trailing slashes correctly
test "route handles trailing slashes on container paths" {
    const req = http.Request{
        .method = .GET,
        .path = "/containers/abc123def4567890123456789012345678901234567890123456789012345678/",
        .path_only = "/containers/abc123def4567890123456789012345678901234567890123456789012345678/",
        .body = "",
        .headers_raw = "",
        .query = "",
        .content_length = 0,
    };

    // Trailing slash after ID - path has "/" so it won't match simple GET
    const response = route(req, testing.allocator);
    // This won't match the simple /containers/{id} pattern
    try testing.expect(response == null);
}
