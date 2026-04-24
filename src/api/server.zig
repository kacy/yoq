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
const platform = @import("platform");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const http = @import("http.zig");
const log = @import("../lib/log.zig");
const orchestrator = @import("../manifest/orchestrator.zig");
const rate_limit = @import("server/rate_limit.zig");
const connection_runtime = @import("server/connection_runtime.zig");

const max_connections = connection_runtime.max_connections;
const connectionWrapper = connection_runtime.connectionWrapper;
const tryAcquireConnectionSlot = connection_runtime.tryAcquireConnectionSlot;
const releaseConnectionSlot = connection_runtime.releaseConnectionSlot;
pub const RateLimiter = rate_limit.RateLimiter;
const rate_limit_burst = rate_limit.rate_limit_burst;
const rate_table_size = rate_limit.rate_table_size;

pub const ServerError = error{
    BindFailed,
    ListenFailed,
    SocketFailed,
};

pub const Server = struct {
    alloc: std.mem.Allocator,
    listen_fd: posix.fd_t,
    port: u16,
    bind_addr: [4]u8,

    /// create a server bound to the given port.
    /// bind_addr controls the listen address:
    ///   - .{ 127, 0, 0, 1 } for single-node mode (localhost only)
    ///   - .{ 0, 0, 0, 0 }   for cluster mode (all interfaces)
    pub fn init(alloc: std.mem.Allocator, port: u16, bind_addr: [4]u8) ServerError!Server {
        // create TCP socket
        const fd = platform.posix.socket(
            posix.AF.INET,
            posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
            0,
        ) catch return ServerError.SocketFailed;
        errdefer platform.posix.close(fd);

        // allow address reuse so we can restart quickly
        const optval: c_int = 1;
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&optval)) catch |e| {
            log.warn("api server failed to set SO_REUSEADDR: {}", .{e});
        };

        const addr = platform.net.Address.initIp4(bind_addr, port);
        platform.posix.bind(fd, &addr.any, addr.getOsSockLen()) catch return ServerError.BindFailed;

        // start listening with a backlog of 128
        platform.posix.listen(fd, 128) catch return ServerError.ListenFailed;

        return .{
            .alloc = alloc,
            .listen_fd = fd,
            .port = port,
            .bind_addr = bind_addr,
        };
    }

    pub fn deinit(self: *Server) void {
        platform.posix.close(self.listen_fd);
    }

    /// run the server event loop. blocks until shutdown is requested.
    /// tries io_uring first, falls back to blocking accept.
    pub fn run(self: *Server) void {
        log.info("listening on {d}.{d}.{d}.{d}:{d}", .{
            self.bind_addr[0], self.bind_addr[1],
            self.bind_addr[2], self.bind_addr[3],
            self.port,
        });

        // try io_uring first
        if (self.runIoUring()) return;

        // fallback to blocking accept
        log.warn("io_uring unavailable, using blocking accept", .{});
        self.runBlocking();
    }

    /// io_uring-based accept loop using multishot accept.
    /// returns true if it ran successfully, false if io_uring isn't available.
    fn runIoUring(self: *Server) bool {
        if (builtin.os.tag != .linux) return false;

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
            const client_fd = platform.posix.accept(self.listen_fd, null, null, posix.SOCK.CLOEXEC) catch {
                if (orchestrator.shutdown_requested.load(.acquire)) break;
                continue;
            };

            self.spawnWorker(client_fd);
        }
    }

    /// spawn a detached worker thread to handle a single connection.
    fn spawnWorker(self: *Server, client_fd: posix.fd_t) void {
        if (!tryAcquireConnectionSlot()) {
            platform.posix.close(client_fd);
            return;
        }

        const alloc = self.alloc;
        const thread = std.Thread.spawn(.{}, connectionWrapper, .{ alloc, client_fd }) catch {
            releaseConnectionSlot();
            platform.posix.close(client_fd);
            return;
        };
        thread.detach();
    }
};

// -- tests --

test "server init and deinit" {
    // use port 0 to let the OS assign a free port
    var server = Server.init(std.testing.allocator, 0, .{ 127, 0, 0, 1 }) catch {
        // socket creation might fail in restricted environments
        return;
    };
    defer server.deinit();

    // the listen fd should be valid
    try std.testing.expect(server.listen_fd >= 0);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, server.bind_addr);
}

test "connection slot limit enforcement" {
    connection_runtime.active_connections.store(0, .release);
    defer connection_runtime.active_connections.store(0, .release);

    var acquired: usize = 0;
    while (acquired < max_connections and tryAcquireConnectionSlot()) : (acquired += 1) {}
    try std.testing.expectEqual(max_connections, acquired);
    try std.testing.expect(!tryAcquireConnectionSlot());

    while (acquired > 0) : (acquired -= 1) {
        releaseConnectionSlot();
    }
}

// -- rate limiter tests --

test "rate limiter allows requests under limit" {
    var limiter = RateLimiter.init();
    const ip: u32 = 0x0A000001; // 10.0.0.1
    const now: i64 = 1000;

    // first 10 requests should all be allowed (per-second rate)
    for (0..10) |_| {
        try std.testing.expect(limiter.checkRateAt(ip, now));
    }
}

test "rate limiter allows burst up to limit" {
    var limiter = RateLimiter.init();
    const ip: u32 = 0x0A000002; // 10.0.0.2
    const now: i64 = 2000;

    // burst limit is 50 — all should be allowed
    for (0..rate_limit_burst) |_| {
        try std.testing.expect(limiter.checkRateAt(ip, now));
    }

    // request 51 should be rejected
    try std.testing.expect(!limiter.checkRateAt(ip, now));
}

test "rate limiter resets on new window" {
    var limiter = RateLimiter.init();
    const ip: u32 = 0x0A000003; // 10.0.0.3

    // exhaust the burst limit at time 3000
    for (0..rate_limit_burst + 1) |_| {
        _ = limiter.checkRateAt(ip, 3000);
    }

    // verify we're rate limited
    try std.testing.expect(!limiter.checkRateAt(ip, 3000));

    // new second — should be allowed again
    try std.testing.expect(limiter.checkRateAt(ip, 3001));
}

test "rate limiter tracks different IPs independently" {
    var limiter = RateLimiter.init();
    const ip_a: u32 = 0x0A000004;
    const ip_b: u32 = 0xC0A80001; // 192.168.0.1
    const now: i64 = 4000;

    // exhaust burst for ip_a
    for (0..rate_limit_burst + 1) |_| {
        _ = limiter.checkRateAt(ip_a, now);
    }

    // ip_a should be limited, ip_b should be fine
    try std.testing.expect(!limiter.checkRateAt(ip_a, now));
    try std.testing.expect(limiter.checkRateAt(ip_b, now));
}

test "rate limiter handles table collision gracefully" {
    var limiter = RateLimiter.init();
    const now: i64 = 5000;

    // fill the table with different IPs
    for (0..rate_table_size) |i| {
        const ip: u32 = @intCast(i + 1);
        try std.testing.expect(limiter.checkRateAt(ip, now));
    }

    // a new IP when table is full should be rejected (fail-closed)
    try std.testing.expect(!limiter.checkRateAt(0xFFFFFFFF, now));
}

test "rate limiter reuses stale slots for new ips" {
    var limiter = RateLimiter.init();

    for (0..rate_table_size) |i| {
        const ip: u32 = @intCast(i + 1);
        try std.testing.expect(limiter.checkRateAt(ip, 6000));
    }

    try std.testing.expect(limiter.checkRateAt(0xABCDEF01, 6001));
}
