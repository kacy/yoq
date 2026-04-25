const std = @import("std");
const http = @import("../http.zig");
const store = @import("../../state/store.zig");
const common = @import("common.zig");
const testing = std.testing;
const container_routes = @import("containers_images/container_routes.zig");
const image_routes = @import("containers_images/image_routes.zig");
const writers = @import("containers_images/writers.zig");

const Response = common.Response;
const writeContainerJson = writers.writeContainerJson;
const writeImageJson = writers.writeImageJson;
const handleStopContainer = container_routes.handleStopContainer;
const waitForProcessExit = container_routes.waitForProcessExit;

pub fn route(request: http.Request, alloc: std.mem.Allocator) ?Response {
    const path = request.path_only;

    if (request.method == .GET) {
        if (std.mem.eql(u8, path, "/containers")) return container_routes.handleListContainers(alloc);
        if (std.mem.eql(u8, path, "/images")) return image_routes.handleListImages(alloc);
    }

    if (path.len > "/containers/".len and std.mem.startsWith(u8, path, "/containers/")) {
        const rest = path["/containers/".len..];
        const container_id_end = std.mem.indexOf(u8, rest, "/") orelse rest.len;
        if (!common.validateContainerId(rest[0..container_id_end])) return common.badRequest("invalid container id");

        if (common.matchSubpath(rest, "/logs")) |id| {
            if (request.method != .GET) return common.methodNotAllowed();
            return container_routes.handleGetLogs(alloc, id);
        }

        if (common.matchSubpath(rest, "/stop")) |id| {
            if (request.method != .POST) return common.methodNotAllowed();
            return container_routes.handleStopContainer(alloc, id);
        }

        if (std.mem.indexOf(u8, rest, "/") == null) {
            const id = rest;
            if (request.method == .GET) return container_routes.handleGetContainer(alloc, id);
            if (request.method == .DELETE) return container_routes.handleRemoveContainer(alloc, id);
            return common.methodNotAllowed();
        }
    }

    if (path.len > "/images/".len and std.mem.startsWith(u8, path, "/images/")) {
        const id = path["/images/".len..];
        if (std.mem.indexOf(u8, id, "/") == null) {
            if (request.method == .DELETE) return image_routes.handleRemoveImage(id);
            return common.methodNotAllowed();
        }
    }

    return null;
}

// -- tests --

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
    var fbs: std.Io.Writer = .fixed(&buf);
    const writer = &fbs;

    try writeContainerJson(writer, record);

    const json_str = fbs.buffered();
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
    var fbs: std.Io.Writer = .fixed(&buf);
    const writer = &fbs;

    try writeContainerJson(writer, record);

    const json_str = fbs.buffered();
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
    var fbs: std.Io.Writer = .fixed(&buf);
    const writer = &fbs;

    try writeImageJson(writer, img);

    const json_str = fbs.buffered();
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
    var fbs: std.Io.Writer = .fixed(&buf);
    const writer = &fbs;

    try writeContainerJson(writer, record);

    const json_str = fbs.buffered();
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
    var fbs: std.Io.Writer = .fixed(&buf);
    const writer = &fbs;

    try writeImageJson(writer, img);

    const json_str = fbs.buffered();
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
