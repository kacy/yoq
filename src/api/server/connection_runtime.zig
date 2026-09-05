const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const http = @import("../http.zig");
const routes = @import("../routes.zig");
const log = @import("../../lib/log.zig");
const transport = @import("../../lib/socket_stream.zig");
const audit = @import("../../state/audit.zig");
const rate_limit = @import("rate_limit.zig");

pub const max_connections: u32 = 128;
pub const drain_timeout_ms: u64 = 5000;
const drain_poll_interval_ms: u64 = 10;

pub var active_connections: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

pub const OwnedRequest = struct {
    buffer: []u8,
    request: http.Request,
    reserved_bytes: usize,

    pub fn deinit(self: OwnedRequest, alloc: std.mem.Allocator) void {
        alloc.free(self.buffer);
        releaseRequestBytes(self.reserved_bytes);
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

pub fn activeConnectionCount() u32 {
    return active_connections.load(.acquire);
}

pub fn waitForConnectionsToDrain(timeout_ms: u64) bool {
    var waited_ms: u64 = 0;
    while (activeConnectionCount() != 0 and waited_ms < timeout_ms) {
        std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(drain_poll_interval_ms), .awake) catch return false;
        waited_ms += drain_poll_interval_ms;
    }
    return activeConnectionCount() == 0;
}

fn getPeerIp(fd: posix.fd_t) u32 {
    var addr: posix.sockaddr.in = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    posix.getpeername(fd, @ptrCast(&addr), &addr_len) catch return 0;
    return addr.addr;
}

pub fn handleConnection(alloc: std.mem.Allocator, client_fd: posix.fd_t) void {
    defer linux_platform.posix.close(client_fd);

    const client_ip = getPeerIp(client_fd);
    if (client_ip != 0 and !rate_limit.rate_limiter.checkRate(client_ip)) {
        sendError(client_fd, .too_many_requests, "rate limit exceeded");
        return;
    }

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
        error.Unauthorized => {
            sendError(client_fd, .unauthorized, "unauthorized");
            return;
        },
        error.Forbidden => {
            sendError(client_fd, .forbidden, "forbidden");
            return;
        },
        error.BudgetExhausted => {
            sendError(client_fd, .service_unavailable, "request capacity exhausted");
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
    Unauthorized,
    Forbidden,
    BudgetExhausted,
};

// Headers have their own fixed stack bound. The shared budget covers all owned
// request buffers through dispatch, including slow uploads and error cleanup.
const max_request_bytes: usize = http.max_body_bytes + http.max_header_bytes + 4;
var request_bytes = std.atomic.Value(usize).init(0);

fn reserveRequestBytes(bytes: usize) bool {
    var current = request_bytes.load(.acquire);
    while (true) {
        if (bytes > max_request_bytes - current) return false;
        current = request_bytes.cmpxchgWeak(current, current + bytes, .acq_rel, .acquire) orelse return true;
    }
}

fn releaseRequestBytes(bytes: usize) void {
    _ = request_bytes.fetchSub(bytes, .acq_rel);
}

fn bodyLimit(request: http.Request) usize {
    if (request.method == .GET or request.method == .HEAD or request.method == .DELETE) return 0;
    if (std.mem.eql(u8, request.path_only, "/health") or std.mem.eql(u8, request.path_only, "/version")) return 0;
    if (request.method == .PUT and std.mem.startsWith(u8, request.path_only, "/s3/")) {
        const rest = request.path_only[4..];
        if (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
            if (slash != 0 and slash + 1 < rest.len) return http.max_body_bytes;
        }
    }
    if (std.mem.startsWith(u8, request.path_only, "/agents/")) return 256 * 1024;
    return 1024 * 1024;
}

pub fn readRequestAlloc(alloc: std.mem.Allocator, fd: posix.fd_t) ReadRequestError!OwnedRequest {
    // Both budgets start at admission. A trickling peer cannot renew either.
    const headers = transport.Stream{ .fd = fd, .deadline = transport.Deadline.afterMilliseconds(5000) };
    const body = transport.Stream{ .fd = fd, .deadline = transport.Deadline.afterMilliseconds(30000) };
    return readRequestFrom(alloc, headers, body);
}

fn readRequestFrom(alloc: std.mem.Allocator, header_reader: anytype, body_reader: anytype) ReadRequestError!OwnedRequest {
    var head_buf: [http.max_header_bytes + 4]u8 = undefined;
    var head_len: usize = 0;
    const head = while (true) {
        if (head_len == head_buf.len) return error.HeadersTooLarge;
        const n = header_reader.read(head_buf[head_len..]) catch return error.ReadIncomplete;
        if (n == 0) return error.ReadIncomplete;
        head_len += n;
        if (http.parseRequestHead(head_buf[0..head_len]) catch |err| return parseError(err)) |head| break head;
    };

    // Check exactly the same authentication and scopes as dispatch, before any
    // body allocation. Dispatch checks again in case a token was revoked during upload.
    defer audit.resetActor();
    if (routes.authorizeRequest(head, alloc)) |denied| {
        return if (denied.status == .forbidden) error.Forbidden else error.Unauthorized;
    }
    if (head.content_length > bodyLimit(head)) return error.BodyTooLarge;

    const body_start = findHeaderEnd(head_buf[0..head_len]).? + 4;
    const total = body_start + head.content_length;
    if (!reserveRequestBytes(total)) return error.BudgetExhausted;
    errdefer releaseRequestBytes(total);
    const buffer = alloc.alloc(u8, total) catch return error.AllocFailed;
    errdefer alloc.free(buffer);
    var received = @min(head_len, total);
    @memcpy(buffer[0..received], head_buf[0..received]);
    while (received < total) {
        const n = body_reader.read(buffer[received..]) catch return error.ReadIncomplete;
        if (n == 0) return error.ReadIncomplete;
        received += n;
    }
    const request = (http.parseRequest(buffer) catch |err| return parseError(err)) orelse return error.ReadIncomplete;
    return .{ .buffer = buffer, .request = request, .reserved_bytes = total };
}

fn parseError(err: http.HttpError) ReadRequestError {
    return switch (err) {
        error.UriTooLong => error.UriTooLong,
        error.HeadersTooLarge => error.HeadersTooLarge,
        error.BodyTooLarge => error.BodyTooLarge,
        else => error.MalformedRequest,
    };
}

pub fn findHeaderEnd(buf: []const u8) ?usize {
    return std.mem.indexOf(u8, buf, "\r\n\r\n");
}

fn sendError(fd: posix.fd_t, status: http.StatusCode, message: []const u8) void {
    var resp_buf: [1024]u8 = undefined;
    const resp = http.formatError(&resp_buf, status, message);
    const wire = transport.Stream{ .fd = fd, .deadline = transport.Deadline.afterMilliseconds(5000) };
    wire.writeAll(resp) catch {};
}

fn writeResponse(fd: posix.fd_t, status: http.StatusCode, content_type: []const u8, body: []const u8, omit_body: bool) void {
    const wire = transport.Stream{ .fd = fd, .deadline = transport.Deadline.afterMilliseconds(5000) };
    writeResponseTo(wire, status, content_type, body, omit_body) catch {};
}

fn writeResponseTo(writer: anytype, status: http.StatusCode, content_type: []const u8, body: []const u8, omit_body: bool) !void {
    var header_buf: [512]u8 = undefined;
    const headers = http.formatResponseHeaders(&header_buf, status, content_type, body.len);
    if (headers.len == 0) return error.ResponseFormattingFailed;
    try writer.writeAll(headers);
    if (!omit_body) try writer.writeAll(body);
}

const TestFile = struct {
    fd: posix.fd_t,
    fn read(self: @This(), bytes: []u8) !usize {
        return posix.read(self.fd, bytes);
    }
    fn writeAll(self: @This(), bytes: []const u8) !void {
        var sent: usize = 0;
        while (sent < bytes.len) sent += try linux_platform.posix.write(self.fd, bytes[sent..]);
    }
};

test "readRequestAlloc handles body larger than legacy buffer" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile(std.testing.io, "large-request.txt", .{ .read = true });
    defer file.close(std.testing.io);

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

    try file.writeStreamingAll(std.testing.io, request_head);
    try file.writeStreamingAll(std.testing.io, body);
    _ = try linux_platform.posix.lseek(file.handle, 0, std.os.linux.SEEK.SET);

    const owned = try readRequestFrom(std.testing.allocator, TestFile{ .fd = file.handle }, TestFile{ .fd = file.handle });
    defer owned.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, body_len), owned.request.body.len);
    try std.testing.expectEqualStrings("/s3/bucket/object", owned.request.path_only);
    try std.testing.expectEqualSlices(u8, body, owned.request.body);
}

test "writeResponse streams body larger than response scratch buffer" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile(std.testing.io, "large-response.txt", .{ .read = true });
    defer file.close(std.testing.io);

    const body_len = 12 * 1024;
    const body = try std.testing.allocator.alloc(u8, body_len);
    defer std.testing.allocator.free(body);
    @memset(body, 'R');

    try writeResponseTo(TestFile{ .fd = file.handle }, .ok, "application/octet-stream", body, false);
    _ = try linux_platform.posix.lseek(file.handle, 0, std.os.linux.SEEK.SET);

    const response = try tmp.dir.readFileAlloc(std.testing.io, "large-response.txt", std.testing.allocator, .limited(body_len + 512));
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Content-Length: 12288\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, response, body));
}

test "writeResponse omits body for HEAD semantics while preserving content length" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile(std.testing.io, "head-response.txt", .{ .read = true });
    defer file.close(std.testing.io);

    try writeResponseTo(TestFile{ .fd = file.handle }, .ok, "application/json", "metadata", true);
    _ = try linux_platform.posix.lseek(file.handle, 0, std.os.linux.SEEK.SET);

    const response = try tmp.dir.readFileAlloc(std.testing.io, "head-response.txt", std.testing.allocator, .limited(512));
    defer std.testing.allocator.free(response);

    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Content-Length: 8\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\n"));
}

test "api request budget rejects unauthorized uploads before allocating bodies" {
    const prior = routes.api_token;
    routes.api_token = "admin";
    defer routes.api_token = prior;
    const Upload = struct {
        fn run() !void {
            var fds = try testSocketPair();
            defer for (fds) |fd| linux_platform.posix.close(fd);
            const wire = transport.Stream{ .fd = fds[0], .deadline = transport.Deadline.afterMilliseconds(1000) };
            try wire.writeAll("PUT /s3/bucket/key HTTP/1.1\r\nHost: local\r\nContent-Length: 268435456\r\n\r\n");
            // No body is sent. A zero-capacity allocator proves rejection comes
            // before reservation/allocation and before waiting for that body.
            var storage: [0]u8 = .{};
            var fixed = std.heap.FixedBufferAllocator.init(&storage);
            try std.testing.expectError(error.Unauthorized, readRequestAlloc(fixed.allocator(), fds[1]));
        }
        fn worker(result: *?anyerror) void {
            run() catch |err| {
                result.* = err;
            };
        }
    };
    var errors: [8]?anyerror = @splat(null);
    var threads: [8]?std.Thread = @splat(null);
    defer for (&threads) |*thread| {
        if (thread.*) |t| t.join();
    };
    for (&threads, &errors) |*thread, *err| thread.* = try std.Thread.spawn(.{}, Upload.worker, .{err});
    for (&threads) |*thread| {
        thread.*.?.join();
        thread.* = null;
    }
    for (errors) |err| if (err) |failure| return failure;
    try std.testing.expectEqual(@as(usize, 0), request_bytes.load(.acquire));
}

fn testSocketPair() ![2]posix.fd_t {
    var fds: [2]posix.fd_t = undefined;
    if (std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &fds) != 0) return error.SocketFailed;
    return fds;
}

test "api request budget covers retained requests and releases on errors" {
    const prior = routes.api_token;
    routes.api_token = "admin";
    defer routes.api_token = prior;
    const Reader = struct {
        data: []const u8,
        fn read(self: *@This(), out: []u8) !usize {
            const n = @min(out.len, self.data.len);
            @memcpy(out[0..n], self.data[0..n]);
            self.data = self.data[n..];
            return n;
        }
    };
    const raw = "POST /apps/apply HTTP/1.1\r\nAuthorization: Bearer admin\r\nContent-Length: 4\r\n\r\nbody";
    var reader = Reader{ .data = raw };
    const owned = try readRequestFrom(std.testing.allocator, &reader, &reader);
    try std.testing.expectEqual(raw.len, request_bytes.load(.acquire));
    owned.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), request_bytes.load(.acquire));

    try std.testing.expect(reserveRequestBytes(max_request_bytes));
    reader.data = raw;
    const rejected = readRequestFrom(std.testing.allocator, &reader, &reader);
    releaseRequestBytes(max_request_bytes);
    try std.testing.expectError(error.BudgetExhausted, rejected);

    reader.data = raw[0 .. raw.len - 2];
    try std.testing.expectError(error.ReadIncomplete, readRequestFrom(std.testing.allocator, &reader, &reader));
    var storage: [0]u8 = .{};
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    reader.data = raw;
    try std.testing.expectError(error.AllocFailed, readRequestFrom(fixed.allocator(), &reader, &reader));
    try std.testing.expectEqual(@as(usize, 0), request_bytes.load(.acquire));

    reader.data = "POST /apps/apply HTTP/1.1\r\nAuthorization: Bearer admin\r\nContent-Length: 1048577\r\n\r\n";
    try std.testing.expectError(error.BodyTooLarge, readRequestFrom(fixed.allocator(), &reader, &reader));
    reader.data = "GET /health HTTP/1.1\r\nHost: local\r\nContent-Length: 1\r\n\r\n";
    try std.testing.expectError(error.BodyTooLarge, readRequestFrom(fixed.allocator(), &reader, &reader));
}

test "api request deadlines stop trickling uploads and nonreading response peers" {
    const prior = routes.api_token;
    routes.api_token = null;
    defer routes.api_token = prior;
    const prior_join = routes.join_token;
    routes.join_token = null;
    defer routes.join_token = prior_join;
    const fds = try testSocketPair();
    defer for (fds) |fd| linux_platform.posix.close(fd);
    const Trickle = struct {
        fn run(fd: posix.fd_t) void {
            const wire = transport.Stream{ .fd = fd, .deadline = transport.Deadline.afterMilliseconds(1000) };
            wire.writeAll("POST /apps/apply HTTP/1.1\r\nHost: local\r\nContent-Length: 100000\r\n\r\n") catch return;
            while (true) {
                wire.writeAll("x") catch return;
                std.Io.sleep(std.testing.io, .fromMilliseconds(5), .awake) catch return;
            }
        }
    };
    const thread = try std.Thread.spawn(.{}, Trickle.run, .{fds[0]});
    defer thread.join();
    defer posix.shutdown(fds[0], .both) catch {};
    const wire = transport.Stream{ .fd = fds[1], .deadline = transport.Deadline.afterMilliseconds(50) };
    try std.testing.expectError(error.ReadIncomplete, readRequestFrom(std.testing.allocator, wire, wire));
    try std.testing.expectEqual(@as(usize, 0), request_bytes.load(.acquire));

    const size: c_int = 4096;
    try posix.setsockopt(fds[1], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&size));
    const body = try std.testing.allocator.alloc(u8, 1024 * 1024);
    defer std.testing.allocator.free(body);
    @memset(body, 'r');
    const output = transport.Stream{ .fd = fds[1], .deadline = transport.Deadline.afterMilliseconds(50) };
    try std.testing.expectError(error.TimedOut, writeResponseTo(output, .ok, "application/octet-stream", body, false));
}
