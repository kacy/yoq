const std = @import("std");
const posix = std.posix;
const http = @import("../http.zig");
const routes = @import("../routes.zig");
const log = @import("../../lib/log.zig");
const rate_limit = @import("rate_limit.zig");

pub const max_connections: u32 = 128;
pub var active_connections: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

pub const OwnedRequest = struct {
    buffer: []u8,
    request: http.Request,

    pub fn deinit(self: OwnedRequest, alloc: std.mem.Allocator) void {
        alloc.free(self.buffer);
    }
};

pub fn connectionWrapper(alloc: std.mem.Allocator, client_fd: posix.fd_t) void {
    defer releaseConnectionSlot();
    handleConnection(alloc, client_fd);
}

pub fn tryAcquireConnectionSlot() bool {
    while (true) {
        const current = active_connections.load(.acquire);
        if (current >= max_connections) return false;
        if (active_connections.cmpxchgWeak(current, current + 1, .acq_rel, .acquire) == null) {
            return true;
        }
    }
}

pub fn releaseConnectionSlot() void {
    _ = active_connections.fetchSub(1, .acq_rel);
}

fn getPeerIp(fd: posix.fd_t) u32 {
    var addr: posix.sockaddr.in = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    posix.getpeername(fd, @ptrCast(&addr), &addr_len) catch return 0;
    return addr.addr;
}

pub fn handleConnection(alloc: std.mem.Allocator, client_fd: posix.fd_t) void {
    defer posix.close(client_fd);

    const client_ip = getPeerIp(client_fd);
    if (client_ip != 0 and !rate_limit.rate_limiter.checkRate(client_ip)) {
        sendError(client_fd, .too_many_requests, "rate limit exceeded");
        return;
    }

    setReadTimeout(client_fd, 5);

    const owned_request = readRequestAlloc(alloc, client_fd) catch |err| switch (err) {
        error.MalformedRequest => {
            sendError(client_fd, .bad_request, "malformed request");
            return;
        },
        error.UriTooLong => {
            sendError(client_fd, .bad_request, "request uri too long");
            return;
        },
        error.HeadersTooLarge => {
            sendError(client_fd, .request_header_fields_too_large, "headers too large");
            return;
        },
        error.BodyTooLarge => {
            sendError(client_fd, .content_too_large, "request body too large");
            return;
        },
        error.ReadIncomplete => {
            sendError(client_fd, .bad_request, "request too large or timed out");
            return;
        },
        error.AllocFailed => {
            sendError(client_fd, .internal_server_error, "request allocation failed");
            return;
        },
    };
    defer owned_request.deinit(alloc);

    var trace_id: [16]u8 = undefined;
    log.generateTraceId(&trace_id);
    log.setTraceId(&trace_id);
    defer log.clearTraceId();

    const response = routes.dispatch(owned_request.request, alloc);
    defer if (response.allocated) alloc.free(response.body);

    const content_type = response.content_type orelse "application/json";
    writeResponse(
        client_fd,
        response.status,
        content_type,
        response.body,
        owned_request.request.method == .HEAD,
    );
}

pub const ReadRequestError = error{
    MalformedRequest,
    UriTooLong,
    HeadersTooLarge,
    BodyTooLarge,
    ReadIncomplete,
    AllocFailed,
};

pub fn readRequestAlloc(alloc: std.mem.Allocator, fd: posix.fd_t) ReadRequestError!OwnedRequest {
    var data: std.ArrayListUnmanaged(u8) = .empty;
    errdefer data.deinit(alloc);

    var expected_total: ?usize = null;
    var chunk: [8192]u8 = undefined;

    while (true) {
        if (expected_total) |needed| {
            if (data.items.len >= needed) break;
        }

        const bytes_read = posix.read(fd, &chunk) catch break;
        if (bytes_read == 0) break;

        data.appendSlice(alloc, chunk[0..bytes_read]) catch return error.AllocFailed;

        if (expected_total == null) {
            if (findHeaderEnd(data.items)) |header_end| {
                const request_line_end = std.mem.indexOf(u8, data.items, "\r\n") orelse return error.MalformedRequest;
                if (request_line_end + 2 > header_end) return error.MalformedRequest;

                const headers_raw = data.items[request_line_end + 2 .. header_end];
                const content_length = http.findContentLength(headers_raw) catch return error.MalformedRequest;
                if (content_length > http.max_body_bytes) return error.BodyTooLarge;

                expected_total = header_end + 4 + content_length;
                data.ensureTotalCapacity(alloc, expected_total.?) catch return error.AllocFailed;
            } else if (data.items.len > http.max_header_bytes) {
                return error.HeadersTooLarge;
            }
        }
    }

    const required_len = expected_total orelse return error.ReadIncomplete;
    if (data.items.len < required_len) return error.ReadIncomplete;

    const buffer = data.toOwnedSlice(alloc) catch return error.AllocFailed;
    errdefer alloc.free(buffer);

    const parsed = http.parseRequest(buffer) catch |err| return switch (err) {
        error.UriTooLong => error.UriTooLong,
        error.HeadersTooLarge => error.HeadersTooLarge,
        error.BodyTooLarge => error.BodyTooLarge,
        else => error.MalformedRequest,
    };
    const request = parsed orelse return error.ReadIncomplete;

    return .{
        .buffer = buffer,
        .request = request,
    };
}

pub fn readRequest(fd: posix.fd_t, buf: []u8) ReadRequestError!http.Request {
    var total: usize = 0;
    while (total < buf.len) {
        const bytes_read = posix.read(fd, buf[total..]) catch break;
        if (bytes_read == 0) break;
        total += bytes_read;

        if (findHeaderEnd(buf[0..total]) == null and total > http.max_header_bytes) {
            return error.HeadersTooLarge;
        }

        const parsed = http.parseRequest(buf[0..total]) catch |err| return switch (err) {
            error.UriTooLong => error.UriTooLong,
            error.HeadersTooLarge => error.HeadersTooLarge,
            error.BodyTooLarge => error.BodyTooLarge,
            else => error.MalformedRequest,
        };
        if (parsed) |request| return request;
    }

    return error.ReadIncomplete;
}

pub fn findHeaderEnd(buf: []const u8) ?usize {
    return std.mem.indexOf(u8, buf, "\r\n\r\n");
}

fn setReadTimeout(fd: posix.fd_t, seconds: i64) void {
    const timeout = posix.timeval{ .sec = seconds, .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |e| {
        log.warn("api server failed to set read timeout: {}", .{e});
    };
}

fn sendError(fd: posix.fd_t, status: http.StatusCode, message: []const u8) void {
    var resp_buf: [1024]u8 = undefined;
    const resp = http.formatError(&resp_buf, status, message);
    writeAll(fd, resp);
}

fn writeResponse(fd: posix.fd_t, status: http.StatusCode, content_type: []const u8, body: []const u8, omit_body: bool) void {
    var header_buf: [512]u8 = undefined;
    const headers = http.formatResponseHeaders(&header_buf, status, content_type, body.len);
    if (headers.len == 0) {
        sendError(fd, .internal_server_error, "response formatting failed");
        return;
    }

    writeAll(fd, headers);
    if (!omit_body and body.len > 0) writeAll(fd, body);
}

fn writeAll(fd: posix.fd_t, data: []const u8) void {
    var written: usize = 0;
    while (written < data.len) {
        const bytes_written = posix.write(fd, data[written..]) catch return;
        if (bytes_written == 0) return;
        written += bytes_written;
    }
}

test "readRequestAlloc handles body larger than legacy buffer" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("large-request.txt", .{ .read = true });
    defer file.close();

    const body_len = 96 * 1024;
    const body = try std.testing.allocator.alloc(u8, body_len);
    defer std.testing.allocator.free(body);
    @memset(body, 'Z');

    const request_head = try std.fmt.allocPrint(
        std.testing.allocator,
        "POST /s3/bucket/object HTTP/1.1\r\nHost: localhost\r\nContent-Length: {d}\r\n\r\n",
        .{body.len},
    );
    defer std.testing.allocator.free(request_head);

    try file.writeAll(request_head);
    try file.writeAll(body);
    try file.seekTo(0);

    const owned = try readRequestAlloc(std.testing.allocator, file.handle);
    defer owned.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, body_len), owned.request.body.len);
    try std.testing.expectEqualStrings("/s3/bucket/object", owned.request.path_only);
    try std.testing.expectEqualSlices(u8, body, owned.request.body);
}

test "writeResponse streams body larger than response scratch buffer" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("large-response.txt", .{ .read = true });
    defer file.close();

    const body_len = 12 * 1024;
    const body = try std.testing.allocator.alloc(u8, body_len);
    defer std.testing.allocator.free(body);
    @memset(body, 'R');

    writeResponse(file.handle, .ok, "application/octet-stream", body, false);
    try file.seekTo(0);

    const response = try file.readToEndAlloc(std.testing.allocator, body_len + 512);
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Content-Length: 12288\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, response, body));
}

test "writeResponse omits body for HEAD semantics while preserving content length" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("head-response.txt", .{ .read = true });
    defer file.close();

    writeResponse(file.handle, .ok, "application/json", "metadata", true);
    try file.seekTo(0);

    const response = try file.readToEndAlloc(std.testing.allocator, 512);
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Content-Length: 8\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\n"));
}
