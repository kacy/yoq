const std = @import("std");
const posix = std.posix;

const log = @import("../lib/log.zig");
const proxy = @import("proxy.zig");
const http_support = @import("proxy/http_support.zig");
const socket_support = @import("proxy/socket_support.zig");

pub const ChallengeServerError = error{
    SocketFailed,
};

pub const ChallengeServer = struct {
    store: *proxy.ChallengeStore,
    fd: posix.fd_t,
    running: std.atomic.Value(bool),
    thread: ?std.Thread,

    pub fn init(store: *proxy.ChallengeStore, port: u16) ChallengeServerError!ChallengeServer {
        const fd = socket_support.createListenSocket(port) catch return ChallengeServerError.SocketFailed;
        return .{
            .store = store,
            .fd = fd,
            .running = std.atomic.Value(bool).init(false),
            .thread = null,
        };
    }

    pub fn deinit(self: *ChallengeServer) void {
        self.stop();
        @import("compat").posix.close(self.fd);
    }

    pub fn start(self: *ChallengeServer) void {
        if (self.running.load(.acquire)) return;
        self.running.store(true, .release);
        self.thread = std.Thread.spawn(.{}, acceptLoop, .{self}) catch {
            self.running.store(false, .release);
            return;
        };
    }

    pub fn stop(self: *ChallengeServer) void {
        self.running.store(false, .release);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }

    fn acceptLoop(self: *ChallengeServer) void {
        while (self.running.load(.acquire)) {
            var poll_fds = [_]posix.pollfd{
                .{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 },
            };
            const poll_result = posix.poll(&poll_fds, 1000) catch continue;
            if (poll_result == 0) continue;

            const client_fd = @import("compat").posix.accept(self.fd, null, null, posix.SOCK.CLOEXEC) catch |err| {
                if (err == error.WouldBlock) continue;
                log.warn("acme challenge accept error: {}", .{err});
                continue;
            };

            const thread = std.Thread.spawn(.{}, connectionHandler, .{ self.store, client_fd }) catch {
                @import("compat").posix.close(client_fd);
                continue;
            };
            thread.detach();
        }
    }

    fn connectionHandler(store: *proxy.ChallengeStore, client_fd: posix.fd_t) void {
        defer @import("compat").posix.close(client_fd);

        var buf: [4096]u8 = undefined;
        const bytes_read = socket_support.readWithTimeout(client_fd, &buf, 5000) catch return;
        if (bytes_read == 0) return;

        const request = buf[0..bytes_read];
        const token = http_support.extractAcmeChallengeToken(request) orelse {
            http_support.sendHttpResponse(client_fd, "404 Not Found", "not found");
            return;
        };

        const key_auth = store.get(token) orelse {
            http_support.sendHttpResponse(client_fd, "404 Not Found", "not found");
            return;
        };

        var response_buf: [1024]u8 = undefined;
        const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
            key_auth.len,
            key_auth,
        }) catch return;
        _ = @import("compat").posix.write(client_fd, response) catch |e| {
            log.warn("acme challenge response write failed: {}", .{e});
        };
    }
};
