const std = @import("std");
const platform = @import("linux_platform");
const posix = std.posix;

/// One joined loopback worker serves predetermined HTTP responses. It also
/// supports bodies larger than the client's cap without allocating them.
pub const Server = struct {
    pub const Reply = struct {
        body: []const u8 = "",
        headers: []const u8 = "",
        framing: enum { length, chunked, close } = .length,
        repeated_bytes: ?usize = null,
    };
    fd: posix.fd_t,
    replies: []const Reply,
    worker: ?std.Thread = null,
    requests: usize = 0,

    pub fn init(replies: []const Reply) !Server {
        const fd = try platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
        errdefer platform.posix.close(fd);
        const addr = platform.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
        try platform.posix.bind(fd, &addr.any, addr.getOsSockLen());
        try platform.posix.listen(fd, 8);
        return .{ .fd = fd, .replies = replies };
    }

    pub fn start(self: *Server) !void {
        self.worker = try std.Thread.spawn(.{}, serve, .{self});
    }

    pub fn host(self: *Server, buf: []u8) ![]const u8 {
        var addr: posix.sockaddr.in = undefined;
        var size: posix.socklen_t = @sizeOf(@TypeOf(addr));
        try platform.posix.getsockname(self.fd, @ptrCast(&addr), &size);
        return std.fmt.bufPrint(buf, "127.0.0.1:{d}", .{std.mem.bigToNative(u16, addr.port)});
    }

    pub fn deinit(self: *Server) void {
        _ = std.os.linux.shutdown(self.fd, 2);
        if (self.worker) |worker| worker.join();
        platform.posix.close(self.fd);
    }

    fn writeAll(fd: posix.fd_t, bytes: []const u8) !void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const count = try platform.posix.send(fd, bytes[offset..], posix.MSG.NOSIGNAL);
            if (count == 0) return error.ConnectionClosed;
            offset += count;
        }
    }

    fn serve(self: *Server) void {
        for (self.replies) |reply| {
            var pending = [_]posix.pollfd{.{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 }};
            if ((posix.poll(&pending, 5000) catch return) == 0) return;
            const fd = platform.posix.accept(self.fd, null, null, posix.SOCK.CLOEXEC) catch return;
            defer platform.posix.close(fd);
            const timeout = posix.timeval{ .sec = 5, .usec = 0 };
            posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch return;
            posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch return;
            var request: [8192]u8 = undefined;
            var used: usize = 0;
            while (used < request.len) {
                const count = platform.posix.recv(fd, request[used..], 0) catch return;
                if (count == 0) return;
                used += count;
                if (std.mem.indexOf(u8, request[0..used], "\r\n\r\n") != null) break;
            }
            self.requests += 1;
            sendReply(fd, reply) catch return; // early client refusal is expected
        }
    }

    fn sendReply(fd: posix.fd_t, reply: Reply) !void {
        try writeAll(fd, "HTTP/1.1 200 OK\r\nConnection: close\r\n");
        try writeAll(fd, reply.headers);
        var header_buf: [128]u8 = undefined;
        const size = reply.repeated_bytes orelse reply.body.len;
        switch (reply.framing) {
            .length => try writeAll(fd, try std.fmt.bufPrint(&header_buf, "Content-Length: {d}\r\n", .{size})),
            .chunked => try writeAll(fd, "Transfer-Encoding: chunked\r\n"),
            .close => {},
        }
        try writeAll(fd, "\r\n");
        var remaining = size;
        const repeated = [_]u8{'x'} ** 8192;
        while (remaining > 0) {
            const count = @min(remaining, repeated.len);
            if (reply.framing == .chunked)
                try writeAll(fd, try std.fmt.bufPrint(&header_buf, "{x}\r\n", .{count}));
            try writeAll(fd, if (reply.repeated_bytes != null) repeated[0..count] else reply.body[size - remaining ..][0..count]);
            if (reply.framing == .chunked) try writeAll(fd, "\r\n");
            remaining -= count;
        }
        if (reply.framing == .chunked) try writeAll(fd, "0\r\n\r\n");
    }
};
