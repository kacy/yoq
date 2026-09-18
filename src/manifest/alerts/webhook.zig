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
    var client: std.http.Client = .{ .allocator = alloc, .io = io };
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
