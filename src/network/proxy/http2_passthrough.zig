const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const hpack = @import("hpack.zig");
const http2 = @import("http2.zig");
const http2_request = @import("http2_request.zig");
const socket_helpers = @import("socket_helpers.zig");

const stream_buffer_size = 16 * 1024;

pub const Error = error{
    InvalidResponse,
    ReceiveFailed,
    WriteFailed,
};

pub fn parseStatusCode(alloc: std.mem.Allocator, response: []const u8) (Error || hpack.Error)!u16 {
    var decoder: hpack.Decoder = .{};
    defer decoder.deinit(alloc);
    var pos: usize = 0;
    while (pos + http2.frame_header_len <= response.len) {
        const header = http2.parseFrameHeader(response[pos..]) orelse return error.InvalidResponse;
        if (http2.frame_header_len + header.length > response.len - pos) return error.InvalidResponse;
        if (header.frame_type != .headers) {
            pos += http2.frame_header_len + header.length;
            continue;
        }
        var sequence = http2_request.decodeHeaderSequence(alloc, &decoder, response, pos) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidResponse,
        };
        defer sequence.deinit(alloc);
        pos += sequence.consumed;
        for (sequence.headers.items) |field| {
            if (std.mem.eql(u8, field.name, ":status")) {
                const status = std.fmt.parseInt(u16, field.value, 10) catch return error.InvalidResponse;
                if (status < 100 or status > 599) return error.InvalidResponse;
                // informational blocks can insert entries used by the final
                // response; keep decoding with the same connection table.
                if (status < 200) break;
                return status;
            }
        }
    }

    return error.InvalidResponse;
}

pub fn streamEndSeen(buf: []const u8, target_stream_id: u32) bool {
    if (!http2.startsWithClientPreface(buf)) return false;

    var pos: usize = http2.client_preface.len;
    while (pos + http2.frame_header_len <= buf.len) {
        const header = http2.parseFrameHeader(buf[pos .. pos + http2.frame_header_len]) orelse return false;
        if (pos + http2.frame_header_len + header.length > buf.len) return false;

        if (header.stream_id == target_stream_id and ((header.flags & 0x1) != 0 or header.frame_type == .rst_stream)) {
            return true;
        }
        pos += http2.frame_header_len + header.length;
    }

    return false;
}

pub fn relaySocketConnection(
    client_fd: linux_platform.posix.socket_t,
    upstream_fd: linux_platform.posix.socket_t,
    timeout_ms: u32,
) Error!void {
    var client_open = true;
    var upstream_open = true;

    var client_buf: [stream_buffer_size]u8 = undefined;
    var upstream_buf: [stream_buffer_size]u8 = undefined;

    while (client_open and upstream_open) {
        var poll_fds = [_]posix.pollfd{
            .{
                .fd = if (client_open) client_fd else -1,
                .events = if (client_open) posix.POLL.IN else 0,
                .revents = 0,
            },
            .{
                .fd = if (upstream_open) upstream_fd else -1,
                .events = if (upstream_open) posix.POLL.IN else 0,
                .revents = 0,
            },
        };

        const ready = posix.poll(&poll_fds, socket_helpers.clampPollTimeout(timeout_ms)) catch return error.ReceiveFailed;
        if (ready == 0) return;

        if (client_open and poll_fds[0].revents & posix.POLL.IN != 0) {
            const bytes_read = posix.read(client_fd, &client_buf) catch return error.ReceiveFailed;
            if (bytes_read == 0) {
                client_open = false;
            } else {
                try socket_helpers.writeAll(upstream_fd, client_buf[0..bytes_read]);
            }
        } else if (client_open and (poll_fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP)) != 0) {
            client_open = false;
        }

        if (upstream_open and poll_fds[1].revents & posix.POLL.IN != 0) {
            const bytes_read = posix.read(upstream_fd, &upstream_buf) catch return error.ReceiveFailed;
            if (bytes_read == 0) {
                upstream_open = false;
            } else {
                try socket_helpers.writeAll(client_fd, upstream_buf[0..bytes_read]);
            }
        } else if (upstream_open and (poll_fds[1].revents & (posix.POLL.ERR | posix.POLL.HUP)) != 0) {
            upstream_open = false;
        }
    }
}

test "http2 compression buffered status preserves informational header entries" {
    const alloc = std.testing.allocator;
    const informational = [_]u8{ 0x08, 3, '1', '0', '3', 0x40, 1, 'x', 1, 'a' };
    const early = try http2.buildFrame(alloc, .{ .length = informational.len, .frame_type = .headers, .flags = 4, .stream_id = 1 }, &informational);
    defer alloc.free(early);
    const final = try http2.buildFrame(alloc, .{ .length = 2, .frame_type = .headers, .flags = 5, .stream_id = 1 }, &.{ 0x88, 0xbe });
    defer alloc.free(final);
    const response = try std.mem.concat(alloc, u8, &.{ early, final });
    defer alloc.free(response);
    try std.testing.expectEqual(@as(u16, 200), try parseStatusCode(alloc, response));
}

test "http2 compression buffered status joins final continuation blocks" {
    const alloc = std.testing.allocator;
    const informational = [_]u8{ 0x08, 3, '1', '0', '3', 0x40, 1, 'x', 1, 'a' };
    const early = try http2.buildFrame(alloc, .{ .length = informational.len, .frame_type = .headers, .flags = 4, .stream_id = 1 }, &informational);
    defer alloc.free(early);
    const final = try http2.buildFrame(alloc, .{ .length = 3, .frame_type = .headers, .flags = 1, .stream_id = 1 }, &.{ 0x08, 3, '5' });
    defer alloc.free(final);
    const continuation = try http2.buildFrame(alloc, .{ .length = 3, .frame_type = .continuation, .flags = 4, .stream_id = 1 }, &.{ '0', '3', 0xbe });
    defer alloc.free(continuation);
    const response = try std.mem.concat(alloc, u8, &.{ early, final, continuation });
    defer alloc.free(response);
    try std.testing.expectEqual(@as(u16, 503), try parseStatusCode(alloc, response));
}
