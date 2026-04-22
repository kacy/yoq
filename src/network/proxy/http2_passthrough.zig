const std = @import("std");
const posix = std.posix;
const hpack = @import("hpack.zig");
const http2 = @import("http2.zig");
const socket_helpers = @import("socket_helpers.zig");

const stream_buffer_size = 16 * 1024;

pub const Error = error{
    InvalidResponse,
    ReceiveFailed,
    WriteFailed,
};

pub fn parseStatusCode(alloc: std.mem.Allocator, response: []const u8) (Error || hpack.Error)!u16 {
    var pos: usize = 0;
    while (pos + http2.frame_header_len <= response.len) {
        const header = http2.parseFrameHeader(response[pos .. pos + http2.frame_header_len]) orelse return error.InvalidResponse;
        pos += http2.frame_header_len;
        if (pos + header.length > response.len) return error.InvalidResponse;
        const payload = response[pos .. pos + header.length];
        pos += header.length;

        if (header.frame_type != .headers) continue;
        var decoded = try hpack.decodeHeaderBlock(alloc, payload);
        defer {
            for (decoded.items) |field| field.deinit(alloc);
            decoded.deinit(alloc);
        }

        for (decoded.items) |field| {
            if (std.mem.eql(u8, field.name, ":status")) {
                return std.fmt.parseInt(u16, field.value, 10) catch error.InvalidResponse;
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
    client_fd: @import("compat").posix.socket_t,
    upstream_fd: @import("compat").posix.socket_t,
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
