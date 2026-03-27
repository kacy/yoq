// http — HTTP 1.1 request parser and response formatter
//
// standalone HTTP parsing with no I/O dependencies. operates on
// byte buffers: parseRequest slices into the input (zero-alloc),
// formatResponse writes into a caller-provided buffer.
//
// designed for a management API — simple and correct, not high-performance.
// only supports methods we actually use (GET, POST, PUT, DELETE).

const std = @import("std");

pub const Method = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
};

pub const StatusCode = enum(u16) {
    ok = 200,
    created = 201,
    no_content = 204,
    bad_request = 400,
    unauthorized = 401,
    content_too_large = 413,
    not_found = 404,
    method_not_allowed = 405,
    too_many_requests = 429,
    request_header_fields_too_large = 431,
    internal_server_error = 500,
    service_unavailable = 503,

    pub fn phrase(self: StatusCode) []const u8 {
        return switch (self) {
            .ok => "OK",
            .created => "Created",
            .no_content => "No Content",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .content_too_large => "Content Too Large",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .too_many_requests => "Too Many Requests",
            .request_header_fields_too_large => "Request Header Fields Too Large",
            .internal_server_error => "Internal Server Error",
            .service_unavailable => "Service Unavailable",
        };
    }
};

pub const HttpError = error{
    BadMethod,
    BadRequest,
    UriTooLong,
    HeadersTooLarge,
    BodyTooLarge,
};

pub const max_uri_bytes: usize = 2048;
pub const max_header_bytes: usize = 16 * 1024;
pub const max_body_bytes: usize = 32 * 1024;

/// a parsed HTTP request. all slices reference the original input buffer —
/// no allocations, no copies. the caller must keep the input alive.
pub const Request = struct {
    method: Method,
    /// full path including query string
    path: []const u8,
    /// path without query string
    path_only: []const u8,
    /// query string after '?', or empty
    query: []const u8,
    /// raw header block (everything between request line and body)
    headers_raw: []const u8,
    /// request body (may be empty)
    body: []const u8,
    /// parsed Content-Length value
    content_length: usize,
};

/// try to parse an HTTP request from a buffer.
///
/// returns null if the request is incomplete (not enough data yet).
/// returns an error if the request is malformed.
/// on success, all slices in the returned Request point into `buf`.
pub fn parseRequest(buf: []const u8) HttpError!?Request {
    const header_end = findHeaderEnd(buf) orelse return null;
    if (header_end > max_header_bytes) return HttpError.HeadersTooLarge;
    const body_start = header_end + 4; // include the \r\n\r\n

    const line = try parseRequestLine(buf);
    const uri_parts = splitUri(line.uri);

    // request line must end before the header terminator
    if (line.headers_start > header_end) return HttpError.BadRequest;
    const headers_raw = buf[line.headers_start..header_end];
    const content_length = findContentLength(headers_raw);
    if (content_length > max_body_bytes) return HttpError.BodyTooLarge;
    if (body_start + content_length > buf.len) return null;

    const body = buf[body_start .. body_start + content_length];

    return Request{
        .method = line.method,
        .path = line.uri,
        .path_only = uri_parts.path_only,
        .query = uri_parts.query,
        .headers_raw = headers_raw,
        .body = body,
        .content_length = content_length,
    };
}

/// extract Content-Length from raw headers. case-insensitive.
/// returns 0 if not found or unparseable.
pub fn findContentLength(headers: []const u8) usize {
    const needle = "content-length:";
    var pos: usize = 0;

    while (pos < headers.len) {
        // find next line
        const line_end = std.mem.indexOfPos(u8, headers, pos, "\r\n") orelse headers.len;
        const line = headers[pos..line_end];

        if (line.len >= needle.len) {
            // case-insensitive compare of the header name
            var match = true;
            for (line[0..needle.len], needle) |a, b| {
                if (toLower(a) != b) {
                    match = false;
                    break;
                }
            }

            if (match) {
                // skip header name and any whitespace
                var val_start = needle.len;
                while (val_start < line.len and line[val_start] == ' ') {
                    val_start += 1;
                }
                return std.fmt.parseInt(usize, line[val_start..], 10) catch 0;
            }
        }

        pos = if (line_end + 2 <= headers.len) line_end + 2 else headers.len;
    }

    return 0;
}

/// format a complete HTTP response into a buffer.
/// returns the slice of `buf` containing the formatted response.
pub fn formatResponse(buf: []u8, status: StatusCode, body: []const u8) []const u8 {
    return formatResponseWithType(buf, status, "application/json", body);
}

/// format a complete HTTP response with a custom content type.
pub fn formatResponseWithType(buf: []u8, status: StatusCode, content_type: []const u8, body: []const u8) []const u8 {
    const code: u16 = @intFromEnum(status);
    const phrase = status.phrase();

    const result = std.fmt.bufPrint(buf, "HTTP/1.1 {d} {s}\r\n" ++
        "Content-Type: {s}\r\n" ++
        "Content-Length: {d}\r\n" ++
        "Connection: close\r\n" ++
        "\r\n" ++
        "{s}", .{ code, phrase, content_type, body.len, body }) catch {
        // buffer too small — return a minimal error
        const fallback = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if (buf.len >= fallback.len) {
            @memcpy(buf[0..fallback.len], fallback);
            return buf[0..fallback.len];
        }
        return buf[0..0];
    };

    return result;
}

/// shorthand for a JSON error response body.
/// formats: {"error":"<message>"}
pub fn formatError(buf: []u8, status: StatusCode, message: []const u8) []const u8 {
    // build the JSON error body first in a temp buffer
    var body_buf: [512]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"error\":\"{s}\"}}", .{message}) catch
        "{\"error\":\"internal error\"}";

    return formatResponse(buf, status, body);
}

/// find a header value by name (case-insensitive) in raw headers.
/// returns the trimmed value, or null if the header is not present.
pub fn findHeaderValue(headers: []const u8, name: []const u8) ?[]const u8 {
    var pos: usize = 0;

    while (pos < headers.len) {
        const line_end = std.mem.indexOfPos(u8, headers, pos, "\r\n") orelse headers.len;
        const line = headers[pos..line_end];

        // check if this line starts with "name:" (case-insensitive)
        if (line.len > name.len and line[name.len] == ':') {
            var match = true;
            for (line[0..name.len], name) |a, b| {
                if (toLower(a) != toLower(b)) {
                    match = false;
                    break;
                }
            }

            if (match) {
                // skip "name:" and leading whitespace
                var val_start = name.len + 1;
                while (val_start < line.len and line[val_start] == ' ') {
                    val_start += 1;
                }
                return line[val_start..];
            }
        }

        pos = if (line_end + 2 <= headers.len) line_end + 2 else headers.len;
    }

    return null;
}

// -- internal helpers --

fn parseMethod(str: []const u8) ?Method {
    if (std.mem.eql(u8, str, "GET")) return .GET;
    if (std.mem.eql(u8, str, "HEAD")) return .HEAD;
    if (std.mem.eql(u8, str, "POST")) return .POST;
    if (std.mem.eql(u8, str, "PUT")) return .PUT;
    if (std.mem.eql(u8, str, "DELETE")) return .DELETE;
    return null;
}

const ParsedRequestLine = struct {
    method: Method,
    uri: []const u8,
    headers_start: usize,
};

const UriParts = struct {
    path_only: []const u8,
    query: []const u8,
};

fn parseRequestLine(buf: []const u8) HttpError!ParsedRequestLine {
    const line_end = std.mem.indexOf(u8, buf, "\r\n") orelse return HttpError.BadRequest;
    const line = buf[0..line_end];

    const method_end = std.mem.indexOf(u8, line, " ") orelse return HttpError.BadRequest;
    const method_str = line[0..method_end];
    const method = parseMethod(method_str) orelse return HttpError.BadMethod;

    const after_method = line[method_end + 1 ..];
    const uri_end = std.mem.indexOf(u8, after_method, " ") orelse return HttpError.BadRequest;
    const uri = after_method[0..uri_end];
    if (uri.len == 0) return HttpError.BadRequest;
    if (uri.len > max_uri_bytes) return HttpError.UriTooLong;

    return .{
        .method = method,
        .uri = uri,
        .headers_start = line_end + 2,
    };
}

fn splitUri(uri: []const u8) UriParts {
    const query_start = std.mem.indexOf(u8, uri, "?");
    return .{
        .path_only = if (query_start) |qs| uri[0..qs] else uri,
        .query = if (query_start) |qs| uri[qs + 1 ..] else "",
    };
}

fn findHeaderEnd(buf: []const u8) ?usize {
    return std.mem.indexOf(u8, buf, "\r\n\r\n");
}

fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

// -- tests --

test "parse simple GET request" {
    const raw = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const req = (try parseRequest(raw)).?;

    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/health", req.path);
    try std.testing.expectEqualStrings("/health", req.path_only);
    try std.testing.expectEqualStrings("", req.query);
    try std.testing.expectEqual(@as(usize, 0), req.content_length);
    try std.testing.expectEqualStrings("", req.body);
}

test "parse GET with query string" {
    const raw = "GET /containers?status=running HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const req = (try parseRequest(raw)).?;

    try std.testing.expectEqualStrings("/containers?status=running", req.path);
    try std.testing.expectEqualStrings("/containers", req.path_only);
    try std.testing.expectEqualStrings("status=running", req.query);
}

test "parse POST with body" {
    const raw = "POST /containers/abc123/stop HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Content-Length: 14\r\n" ++
        "\r\n" ++
        "{\"force\":true}";
    const req = (try parseRequest(raw)).?;

    try std.testing.expectEqual(Method.POST, req.method);
    try std.testing.expectEqualStrings("/containers/abc123/stop", req.path_only);
    try std.testing.expectEqual(@as(usize, 14), req.content_length);
    try std.testing.expectEqualStrings("{\"force\":true}", req.body);
}

test "parse DELETE request" {
    const raw = "DELETE /containers/abc123 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const req = (try parseRequest(raw)).?;

    try std.testing.expectEqual(Method.DELETE, req.method);
    try std.testing.expectEqualStrings("/containers/abc123", req.path_only);
}

test "incomplete request returns null" {
    // no \r\n\r\n yet
    const partial = "GET /health HTTP/1.1\r\nHost: local";
    try std.testing.expect(try parseRequest(partial) == null);
}

test "incomplete body returns null" {
    const raw = "POST /data HTTP/1.1\r\n" ++
        "Content-Length: 100\r\n" ++
        "\r\n" ++
        "short";
    try std.testing.expect(try parseRequest(raw) == null);
}

test "bad method returns error" {
    const raw = "PATCH /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    try std.testing.expectError(HttpError.BadMethod, parseRequest(raw));
}

test "malformed request line returns error" {
    const raw = "GETHTTP/1.1\r\n\r\n";
    try std.testing.expectError(HttpError.BadRequest, parseRequest(raw));
}

test "empty URI returns error" {
    const raw = "GET  HTTP/1.1\r\n\r\n";
    try std.testing.expectError(HttpError.BadRequest, parseRequest(raw));
}

test "content-length case insensitive" {
    try std.testing.expectEqual(@as(usize, 42), findContentLength("Content-Length: 42\r\n"));
    try std.testing.expectEqual(@as(usize, 42), findContentLength("content-length: 42\r\n"));
    try std.testing.expectEqual(@as(usize, 42), findContentLength("CONTENT-LENGTH: 42\r\n"));
    try std.testing.expectEqual(@as(usize, 42), findContentLength("Content-length:42\r\n"));
}

test "content-length missing returns 0" {
    try std.testing.expectEqual(@as(usize, 0), findContentLength("Host: localhost\r\n"));
    try std.testing.expectEqual(@as(usize, 0), findContentLength(""));
}

test "format response" {
    var buf: [1024]u8 = undefined;
    const resp = formatResponse(&buf, .ok, "{\"status\":\"ok\"}");

    try std.testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, resp, "Content-Type: application/json") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "Content-Length: 15") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "Connection: close") != null);
    try std.testing.expect(std.mem.endsWith(u8, resp, "{\"status\":\"ok\"}"));
}

test "format error response" {
    var buf: [1024]u8 = undefined;
    const resp = formatError(&buf, .not_found, "container not found");

    try std.testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 404 Not Found\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, resp, "\"error\":\"container not found\"") != null);
}

test "status code phrases" {
    try std.testing.expectEqualStrings("OK", StatusCode.ok.phrase());
    try std.testing.expectEqualStrings("Not Found", StatusCode.not_found.phrase());
    try std.testing.expectEqualStrings("Internal Server Error", StatusCode.internal_server_error.phrase());
    try std.testing.expectEqualStrings("Service Unavailable", StatusCode.service_unavailable.phrase());
    try std.testing.expectEqualStrings("Method Not Allowed", StatusCode.method_not_allowed.phrase());
    try std.testing.expectEqualStrings("Too Many Requests", StatusCode.too_many_requests.phrase());
}

test "format response with empty body" {
    var buf: [1024]u8 = undefined;
    const resp = formatResponse(&buf, .no_content, "");

    try std.testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 204 No Content\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, resp, "Content-Length: 0") != null);
}

test "GET request with multiple headers" {
    const raw = "GET /version HTTP/1.1\r\n" ++
        "Host: localhost:7700\r\n" ++
        "Accept: application/json\r\n" ++
        "User-Agent: curl/8.0\r\n" ++
        "\r\n";
    const req = (try parseRequest(raw)).?;

    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/version", req.path_only);
    try std.testing.expect(req.headers_raw.len > 0);
}

test "PUT request" {
    const raw = "PUT /containers/abc HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const req = (try parseRequest(raw)).?;

    try std.testing.expectEqual(Method.PUT, req.method);
}

test "unauthorized status code phrase" {
    try std.testing.expectEqualStrings("Unauthorized", StatusCode.unauthorized.phrase());
}

test "payload too large status code phrase" {
    try std.testing.expectEqualStrings("Content Too Large", StatusCode.content_too_large.phrase());
}

test "header too large status code phrase" {
    try std.testing.expectEqualStrings("Request Header Fields Too Large", StatusCode.request_header_fields_too_large.phrase());
}

test "findHeaderValue extracts authorization" {
    const headers = "Host: localhost\r\nAuthorization: Bearer my-token-123\r\n";
    const value = findHeaderValue(headers, "Authorization");
    try std.testing.expect(value != null);
    try std.testing.expectEqualStrings("Bearer my-token-123", value.?);
}

test "findHeaderValue case insensitive" {
    const headers = "authorization: Bearer abc\r\n";
    const value = findHeaderValue(headers, "Authorization");
    try std.testing.expect(value != null);
    try std.testing.expectEqualStrings("Bearer abc", value.?);
}

test "findHeaderValue returns null for missing header" {
    const headers = "Host: localhost\r\nContent-Type: application/json\r\n";
    try std.testing.expect(findHeaderValue(headers, "Authorization") == null);
}

test "findHeaderValue handles empty headers" {
    try std.testing.expect(findHeaderValue("", "Authorization") == null);
}

test "parse request rejects long URI" {
    var uri_buf: [max_uri_bytes + 32]u8 = undefined;
    const long_uri = std.fmt.bufPrint(&uri_buf, "/{s}", .{"a" ** max_uri_bytes}) catch unreachable;
    var raw_buf: [max_uri_bytes + 64]u8 = undefined;
    const raw = std.fmt.bufPrint(&raw_buf, "GET {s} HTTP/1.1\r\nHost: localhost\r\n\r\n", .{long_uri}) catch unreachable;
    try std.testing.expectError(HttpError.UriTooLong, parseRequest(raw));
}

test "parse request rejects large body" {
    var body_buf: [16]u8 = undefined;
    const raw = std.fmt.bufPrint(&body_buf, "{d}", .{max_body_bytes + 1}) catch unreachable;
    var req_buf: [128]u8 = undefined;
    const req = std.fmt.bufPrint(&req_buf, "POST /data HTTP/1.1\r\nContent-Length: {s}\r\n\r\n", .{raw}) catch unreachable;
    try std.testing.expectError(HttpError.BodyTooLarge, parseRequest(req));
}
