//! http_test.zig - HTTP testing utilities for API route tests
//!
//! Provides helpers for creating test HTTP requests and validating
//! responses in unit tests.

const std = @import("std");
const http = @import("../api/http.zig");
const routes = @import("../api/routes.zig");

/// HTTP test context for route testing
pub const TestContext = struct {
    alloc: std.mem.Allocator,
    response_buffer: []u8,

    pub fn init(alloc: std.mem.Allocator, buffer_size: usize) !TestContext {
        const buf = try alloc.alloc(u8, buffer_size);
        return .{
            .alloc = alloc,
            .response_buffer = buf,
        };
    }

    pub fn deinit(self: *TestContext) void {
        self.alloc.free(self.response_buffer);
    }
};

/// Create a simple GET request
pub fn createGetRequest(path: []const u8) http.Request {
    return .{
        .method = .GET,
        .path = path,
        .body = null,
        .headers = &.{},
    };
}

/// Create a POST request with body
pub fn createPostRequest(path: []const u8, body: []const u8) http.Request {
    return .{
        .method = .POST,
        .path = path,
        .body = body,
        .headers = &.{},
    };
}

/// Create a DELETE request
pub fn createDeleteRequest(path: []const u8) http.Request {
    return .{
        .method = .DELETE,
        .path = path,
        .body = null,
        .headers = &.{},
    };
}

/// Parse a simple JSON response (extracts first string value)
pub fn extractJsonString(json: []const u8, key: []const u8) ?[]const u8 {
    // Simple string search for "key":"value" pattern
    const key_pattern = std.fmt.allocPrint(std.heap.page_allocator, "\"{s}\":\"", .{key}) catch return null;
    defer std.heap.page_allocator.free(key_pattern);

    if (std.mem.indexOf(u8, json, key_pattern)) |start| {
        const value_start = start + key_pattern.len;
        if (std.mem.indexOfScalarPos(u8, json, value_start, '"')) |end| {
            return json[value_start..end];
        }
    }
    return null;
}

/// Check if response status is success (2xx)
pub fn isSuccessStatus(status: http.StatusCode) bool {
    return @intFromEnum(status) >= 200 and @intFromEnum(status) < 300;
}

/// Check if response status is client error (4xx)
pub fn isClientError(status: http.StatusCode) bool {
    return @intFromEnum(status) >= 400 and @intFromEnum(status) < 500;
}

/// Check if response status is server error (5xx)
pub fn isServerError(status: http.StatusCode) bool {
    return @intFromEnum(status) >= 500 and @intFromEnum(status) < 600;
}

/// Assert response status equals expected
pub fn expectStatus(response: http.Response, expected: http.StatusCode) !void {
    if (response.status != expected) {
        std.debug.print("Expected status {d}, got {d}: {s}\n", .{
            @intFromEnum(expected),
            @intFromEnum(response.status),
            response.body,
        });
        return error.UnexpectedStatus;
    }
}

/// Assert response body contains expected string
pub fn expectBodyContains(response: http.Response, expected: []const u8) !void {
    if (!std.mem.containsAtLeast(u8, response.body, 1, expected)) {
        std.debug.print("Response body does not contain '{s}'\nBody: {s}\n", .{
            expected,
            response.body,
        });
        return error.BodyNotFound;
    }
}

/// Assert response body is valid JSON (starts with { or [)
pub fn expectValidJson(response: http.Response) !void {
    const trimmed = std.mem.trim(u8, response.body, &std.ascii.whitespace);
    if (trimmed.len == 0) {
        return error.EmptyBody;
    }

    const first_char = trimmed[0];
    if (first_char != '{' and first_char != '[') {
        std.debug.print("Response body is not valid JSON. First char: {c}\nBody: {s}\n", .{
            first_char,
            response.body,
        });
        return error.InvalidJson;
    }
}

// -- Tests --

test "createGetRequest" {
    const req = createGetRequest("/containers");
    try std.testing.expectEqual(http.Method.GET, req.method);
    try std.testing.expectEqualStrings("/containers", req.path);
    try std.testing.expect(req.body == null);
}

test "createPostRequest" {
    const body = "{\"key\":\"value\"}";
    const req = createPostRequest("/containers", body);
    try std.testing.expectEqual(http.Method.POST, req.method);
    try std.testing.expectEqualStrings("/containers", req.path);
    try std.testing.expectEqualStrings(body, req.body.?);
}

test "createDeleteRequest" {
    const req = createDeleteRequest("/containers/123");
    try std.testing.expectEqual(http.Method.DELETE, req.method);
    try std.testing.expectEqualStrings("/containers/123", req.path);
}

test "extractJsonString" {
    const json = "{\"name\":\"test\",\"status\":\"running\"}";

    const name = extractJsonString(json, "name");
    try std.testing.expect(name != null);
    try std.testing.expectEqualStrings("test", name.?);

    const status = extractJsonString(json, "status");
    try std.testing.expect(status != null);
    try std.testing.expectEqualStrings("running", status.?);

    const missing = extractJsonString(json, "missing");
    try std.testing.expect(missing == null);
}

test "isSuccessStatus" {
    try std.testing.expect(isSuccessStatus(.OK));
    try std.testing.expect(isSuccessStatus(.Created));
    try std.testing.expect(!isSuccessStatus(.NotFound));
    try std.testing.expect(!isSuccessStatus(.InternalServerError));
}

test "isClientError" {
    try std.testing.expect(isClientError(.BadRequest));
    try std.testing.expect(isClientError(.NotFound));
    try std.testing.expect(!isClientError(.OK));
    try std.testing.expect(!isClientError(.InternalServerError));
}

test "expectStatus success" {
    const response = http.Response{
        .status = .OK,
        .body = "OK",
    };
    try expectStatus(response, .OK);
}

test "expectBodyContains" {
    const response = http.Response{
        .status = .OK,
        .body = "{\"name\":\"test\"}",
    };
    try expectBodyContains(response, "name");
    try expectBodyContains(response, "test");
}

test "expectValidJson" {
    const obj_response = http.Response{
        .status = .OK,
        .body = "{\"key\":\"value\"}",
    };
    try expectValidJson(obj_response);

    const arr_response = http.Response{
        .status = .OK,
        .body = "[{\"key\":\"value\"}]",
    };
    try expectValidJson(arr_response);
}
