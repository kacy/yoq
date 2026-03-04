// server — HTTP API server with io_uring accept and thread pool
//
// the server uses io_uring multishot accept to efficiently accept
// connections on the main thread, then dispatches each connection
// to a detached worker thread for handling.
//
// worker threads: blocking read → parse HTTP → route to handler →
// write response → close. each thread can safely open its own
// SQLite connection through store.zig.
//
// falls back to a blocking accept loop if io_uring is unavailable
// (e.g., running in a container without io_uring support).
//
// all connections use Connection: close — no keep-alive. this is
// fine for a management API and keeps the implementation simple.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const http = @import("http.zig");
const routes = @import("routes.zig");
const log = @import("../lib/log.zig");
const orchestrator = @import("../manifest/orchestrator.zig");

// connection limit — prevents thread exhaustion under load or attack.
// 128 is generous for a management API where most operations complete
// in milliseconds.
const max_connections: u32 = 128;
var active_connections: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

pub const ServerError = error{
    BindFailed,
    ListenFailed,
    SocketFailed,
};

pub const Server = struct {
    alloc: std.mem.Allocator,
    listen_fd: posix.fd_t,
    port: u16,

    /// create a server bound to the given port.
    /// sets up the socket, binds, and starts listening.
    pub fn init(alloc: std.mem.Allocator, port: u16) ServerError!Server {
        // create TCP socket
        const fd = posix.socket(
            posix.AF.INET,
            posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
            0,
        ) catch return ServerError.SocketFailed;
        errdefer posix.close(fd);

        // allow address reuse so we can restart quickly
        const optval: c_int = 1;
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&optval)) catch {};

        // bind to 0.0.0.0:port
        const addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        posix.bind(fd, &addr.any, addr.getOsSockLen()) catch return ServerError.BindFailed;

        // start listening with a backlog of 128
        posix.listen(fd, 128) catch return ServerError.ListenFailed;

        return .{
            .alloc = alloc,
            .listen_fd = fd,
            .port = port,
        };
    }

    pub fn deinit(self: *Server) void {
        posix.close(self.listen_fd);
    }

    /// run the server event loop. blocks until shutdown is requested.
    /// tries io_uring first, falls back to blocking accept.
    pub fn run(self: *Server) void {
        log.info("listening on 0.0.0.0:{d}", .{self.port});

        // try io_uring first
        if (self.runIoUring()) return;

        // fallback to blocking accept
        log.warn("io_uring unavailable, using blocking accept", .{});
        self.runBlocking();
    }

    /// io_uring-based accept loop using multishot accept.
    /// returns true if it ran successfully, false if io_uring isn't available.
    fn runIoUring(self: *Server) bool {
        var ring = linux.IoUring.init(64, 0) catch return false;
        defer ring.deinit();

        // submit initial multishot accept
        _ = ring.accept_multishot(0, self.listen_fd, null, null, 0) catch return false;
        _ = ring.submit() catch return false;

        var cqes: [32]linux.io_uring_cqe = undefined;

        while (!orchestrator.shutdown_requested.load(.acquire)) {
            // wait for at least one completion
            const count = ring.copy_cqes(&cqes, 1) catch |err| {
                // if the listen fd was closed (shutdown), we'll get an error
                if (orchestrator.shutdown_requested.load(.acquire)) break;
                log.warn("io_uring copy_cqes failed: {}", .{err});
                break;
            };

            for (cqes[0..count]) |cqe| {
                if (cqe.res < 0) {
                    // accept error — might be shutdown
                    if (orchestrator.shutdown_requested.load(.acquire)) break;

                    // if IORING_CQE_F_MORE is not set, multishot ended
                    if (cqe.flags & linux.IORING_CQE_F_MORE == 0) {
                        // re-submit multishot accept
                        _ = ring.accept_multishot(0, self.listen_fd, null, null, 0) catch break;
                        _ = ring.submit() catch break;
                    }
                    continue;
                }

                const client_fd: posix.fd_t = @intCast(cqe.res);
                self.spawnWorker(client_fd);

                // if IORING_CQE_F_MORE is not set, multishot needs to be re-armed
                if (cqe.flags & linux.IORING_CQE_F_MORE == 0) {
                    _ = ring.accept_multishot(0, self.listen_fd, null, null, 0) catch break;
                    _ = ring.submit() catch break;
                }
            }
        }

        return true;
    }

    /// blocking accept loop fallback.
    fn runBlocking(self: *Server) void {
        while (!orchestrator.shutdown_requested.load(.acquire)) {
            const client_fd = posix.accept(self.listen_fd, null, null, posix.SOCK.CLOEXEC) catch {
                if (orchestrator.shutdown_requested.load(.acquire)) break;
                continue;
            };

            self.spawnWorker(client_fd);
        }
    }

    /// spawn a detached worker thread to handle a single connection.
    fn spawnWorker(self: *Server, client_fd: posix.fd_t) void {
        // reject if at connection limit
        const current = active_connections.load(.acquire);
        if (current >= max_connections) {
            posix.close(client_fd);
            return;
        }
        _ = active_connections.fetchAdd(1, .acq_rel);

        const alloc = self.alloc;
        const thread = std.Thread.spawn(.{}, connectionWrapper, .{ alloc, client_fd }) catch {
            _ = active_connections.fetchSub(1, .acq_rel);
            posix.close(client_fd);
            return;
        };
        thread.detach();
    }
};

/// wrapper that decrements the connection counter on exit.
fn connectionWrapper(alloc: std.mem.Allocator, client_fd: posix.fd_t) void {
    defer _ = active_connections.fetchSub(1, .acq_rel);
    handleConnection(alloc, client_fd);
}

/// handle a single HTTP connection. runs in a worker thread.
/// reads the request, dispatches to route handler, writes response, closes.
fn handleConnection(alloc: std.mem.Allocator, client_fd: posix.fd_t) void {
    defer posix.close(client_fd);

    // set receive timeout to 5 seconds
    const timeout = posix.timeval{ .sec = 5, .usec = 0 };
    posix.setsockopt(
        client_fd,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        std.mem.asBytes(&timeout),
    ) catch {};

    // read request into a stack buffer
    var buf: [65536]u8 = undefined;
    var total: usize = 0;

    while (total < buf.len) {
        const n = posix.read(client_fd, buf[total..]) catch break;
        if (n == 0) break; // EOF
        total += n;

        // try to parse what we have
        const request = http.parseRequest(buf[0..total]) catch {
            // malformed request — send 400
            var resp_buf: [1024]u8 = undefined;
            const resp = http.formatError(&resp_buf, .bad_request, "malformed request");
            writeAll(client_fd, resp);
            return;
        };

        if (request) |req| {
            // got a complete request — handle it
            const response = routes.dispatch(req, alloc);
            defer if (response.allocated) alloc.free(response.body);

            var resp_buf: [4096]u8 = undefined;
            const resp = http.formatResponse(&resp_buf, response.status, response.body);
            writeAll(client_fd, resp);
            return;
        }

        // request incomplete — keep reading
    }

    // if we get here, we ran out of buffer or timed out
    var resp_buf: [1024]u8 = undefined;
    const resp = http.formatError(&resp_buf, .bad_request, "request too large or timed out");
    writeAll(client_fd, resp);
}

/// write all bytes to a file descriptor, handling partial writes.
fn writeAll(fd: posix.fd_t, data: []const u8) void {
    var written: usize = 0;
    while (written < data.len) {
        const n = posix.write(fd, data[written..]) catch return;
        written += n;
    }
}

// -- tests --

test "server init and deinit" {
    // use port 0 to let the OS assign a free port
    var server = Server.init(std.testing.allocator, 0) catch {
        // socket creation might fail in restricted environments
        return;
    };
    defer server.deinit();

    // the listen fd should be valid
    try std.testing.expect(server.listen_fd >= 0);
}
