const std = @import("std");
const posix = std.posix;
const http = @import("../http.zig");
const routes = @import("../routes.zig");
const log = @import("../../lib/log.zig");
const rate_limit = @import("rate_limit.zig");

pub const max_connections: u32 = 128;
pub var active_connections: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

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

    var buf: [65536]u8 = undefined;
    const request = readRequest(client_fd, &buf) catch |err| switch (err) {
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
    };

    var trace_id: [16]u8 = undefined;
    log.generateTraceId(&trace_id);
    log.setTraceId(&trace_id);
    defer log.clearTraceId();

    const response = routes.dispatch(request, alloc);
    defer if (response.allocated) alloc.free(response.body);

    var resp_buf: [4096]u8 = undefined;
    const content_type = response.content_type orelse "application/json";
    const resp = http.formatResponseWithType(&resp_buf, response.status, content_type, response.body);
    writeAll(client_fd, resp);
}

pub const ReadRequestError = error{
    MalformedRequest,
    UriTooLong,
    HeadersTooLarge,
    BodyTooLarge,
    ReadIncomplete,
};

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
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
}

fn sendError(fd: posix.fd_t, status: http.StatusCode, message: []const u8) void {
    var resp_buf: [1024]u8 = undefined;
    const resp = http.formatError(&resp_buf, status, message);
    writeAll(fd, resp);
}

fn writeAll(fd: posix.fd_t, data: []const u8) void {
    var written: usize = 0;
    while (written < data.len) {
        const bytes_written = posix.write(fd, data[written..]) catch return;
        if (bytes_written == 0) return;
        written += bytes_written;
    }
}
