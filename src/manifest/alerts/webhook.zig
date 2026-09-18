const std = @import("std");

pub const timeout_ms = 10_000;
pub const Delivery = struct { status: ?u16 = null, failure: ?[]const u8 = null };

pub fn send(alloc: std.mem.Allocator, io: std.Io, url: []const u8, body: []const u8) Delivery {
    return sendWithTimeout(alloc, io, url, body, timeout_ms);
}

fn sendWithTimeout(alloc: std.mem.Allocator, io: std.Io, url: []const u8, body: []const u8, limit_ms: u64) Delivery {
    const Result = union(enum) { delivered: Delivery, expired: void };
    var completed: [2]Result = undefined;
    var pending = std.Io.Select(Result).init(io, &completed);
    defer while (pending.cancel()) |_| {};
    pending.concurrent(.expired, sleep, .{ io, limit_ms }) catch return .{ .failure = "TaskUnavailable" };
    pending.async(.delivered, sendInner, .{ alloc, io, url, body });
    return switch (pending.await() catch return .{ .failure = "Canceled" }) {
        .expired => .{ .failure = "Timeout" },
        .delivered => |result| result,
    };
}

fn sleep(io: std.Io, limit_ms: u64) void {
    std.Io.sleep(io, .fromMilliseconds(@intCast(limit_ms)), .awake) catch {};
}

fn sendInner(alloc: std.mem.Allocator, io: std.Io, url: []const u8, body: []const u8) Delivery {
    const uri = std.Uri.parse(url) catch return .{ .failure = "InvalidUrl" };
    if ((!std.ascii.eqlIgnoreCase(uri.scheme, "http") and !std.ascii.eqlIgnoreCase(uri.scheme, "https")) or
        uri.host == null or uri.user != null or uri.password != null or uri.fragment != null)
        return .{ .failure = "InvalidUrl" };
    var client: std.http.Client = .{ .allocator = alloc, .io = io, .read_buffer_size = 8192 };
    defer client.deinit();
    var request = client.request(.POST, uri, .{
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
        .headers = .{ .content_type = .{ .override = "application/json" } },
    }) catch |err| return .{ .failure = @errorName(err) };
    defer request.deinit();
    request.sendBodyComplete(@constCast(body)) catch |err| return .{ .failure = @errorName(err) };
    var headers: [8192]u8 = undefined;
    const response = request.receiveHead(&headers) catch |err| return .{ .failure = @errorName(err) };
    // the stdlib parser decodes status arithmetic without checking its digits.
    const head = response.head.bytes;
    if (head.len < 12 or head[9] < '1' or head[9] > '5' or !std.ascii.isDigit(head[10]) or !std.ascii.isDigit(head[11]))
        return .{ .failure = "MalformedStatus" };
    const status: u16 = @intFromEnum(response.head.status);
    return .{ .status = status, .failure = if (status >= 200 and status < 300) null else "UnexpectedStatus" };
}

test "alert webhook refuses credentials fragments and unsupported schemes before dialing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_][]const u8{ "ftp://localhost/hook", "http://user:secret@localhost/hook", "http://localhost/hook#fragment" }) |url| {
        const result = send(std.testing.allocator, threaded.io(), url, "{}");
        try std.testing.expectEqualStrings("InvalidUrl", result.failure.?);
    }
}

test "alert webhook reports success non-success redirects malformed responses and deadlines" {
    const Server = @import("../../image/registry/test_support.zig").Server;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const cases = [_]struct { reply: Server.Reply, failure: ?[]const u8, status: ?u16, timeout: u64 = 2000 }{
        .{ .reply = .{ .status = "204 No Content" }, .failure = null, .status = 204 },
        .{ .reply = .{ .status = "503 Service Unavailable" }, .failure = "UnexpectedStatus", .status = 503 },
        .{ .reply = .{ .status = "302 Found", .headers = "Location: http://127.0.0.1:1/private\r\n" }, .failure = "TooManyHttpRedirects", .status = null },
        .{ .reply = .{ .status = "invalid" }, .failure = "MalformedStatus", .status = null },
        .{ .reply = .{ .delay_ms = 250 }, .failure = "Timeout", .status = null, .timeout = 40 },
    };
    for (cases) |case| {
        var server = try Server.init(&.{case.reply});
        defer server.deinit();
        try server.start();
        var host_buffer: [64]u8 = undefined;
        var url_buffer: [128]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buffer, "http://{s}/hook", .{try server.host(&host_buffer)});
        const result = sendWithTimeout(std.testing.allocator, threaded.io(), url, "{\"state\":\"firing\"}", case.timeout);
        if (case.failure) |failure| {
            // parser error names are implementation details; malformed heads
            // must fail before a status is accepted.
            if (case.status == null and case.timeout == 2000) {
                try std.testing.expect(result.failure != null);
            } else try std.testing.expectEqualStrings(failure, result.failure.?);
        } else try std.testing.expect(result.failure == null);
        try std.testing.expectEqual(case.status, result.status);
        server.worker.?.join();
        server.worker = null;
        try std.testing.expectEqual(@as(usize, 1), server.requests);
        try std.testing.expect(std.mem.startsWith(u8, server.last_request[0..server.last_request_length], "POST /hook HTTP/1.1\r\n"));
    }
}
