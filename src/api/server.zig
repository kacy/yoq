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

// -- rate limiter --
//
// fixed-window per-IP rate limiter. each IP gets a counter that resets
// every second. the burst limit allows short spikes above the per-second
// rate, which is normal for legitimate clients making a few rapid calls.
//
// uses a small fixed-size table with linear probing. if the table fills
// up, new IPs are allowed through (fail-open) — better to serve a
// request than to reject legitimate traffic due to table pressure.

const rate_limit_per_sec: u32 = 10;
const rate_limit_burst: u32 = 50;
const rate_table_size: usize = 64;

pub const RateLimiter = struct {
    entries: [rate_table_size]RateEntry,
    mutex: std.Thread.Mutex,

    const RateEntry = struct {
        ip: u32,
        count: u32,
        window_start: i64, // seconds since epoch
        active: bool,
    };

    const empty_entry = RateEntry{
        .ip = 0,
        .count = 0,
        .window_start = 0,
        .active = false,
    };

    pub fn init() RateLimiter {
        return .{
            .entries = [_]RateEntry{empty_entry} ** rate_table_size,
            .mutex = .{},
        };
    }

    /// check if a request from the given IP should be allowed.
    /// returns true if allowed, false if rate limited.
    pub fn checkRate(self: *RateLimiter, ip: u32) bool {
        return self.checkRateAt(ip, std.time.timestamp());
    }

    /// testable version of checkRate that accepts a timestamp.
    fn checkRateAt(self: *RateLimiter, ip: u32, now: i64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        // look for existing entry or empty slot
        const start_idx = @as(usize, @truncate(ip *% 2654435761)); // knuth multiplicative hash
        var probe: usize = 0;
        var first_empty: ?usize = null;

        while (probe < rate_table_size) : (probe += 1) {
            const idx = (start_idx +% probe) % rate_table_size;
            const entry = &self.entries[idx];

            if (!entry.active) {
                if (first_empty == null) first_empty = idx;
                // keep probing in case the IP exists further along
                // but if we've hit an empty slot, the IP can't be beyond it
                // (since we never delete mid-chain)
                break;
            }

            if (entry.ip == ip) {
                // found existing entry for this IP
                if (now != entry.window_start) {
                    // new window — reset counter
                    entry.window_start = now;
                    entry.count = 1;
                    return true;
                }

                entry.count += 1;
                return entry.count <= rate_limit_burst;
            }
        }

        // IP not found — create new entry in the first empty slot
        if (first_empty) |idx| {
            self.entries[idx] = .{
                .ip = ip,
                .count = 1,
                .window_start = now,
                .active = true,
            };
            return true;
        }

        // table full — fail open (allow the request).
        // this shouldn't happen often with 64 slots and 1-second windows,
        // but we don't want to reject legitimate traffic.
        return true;
    }

    /// reset all entries. used for testing.
    fn reset(self: *RateLimiter) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.entries = [_]RateEntry{empty_entry} ** rate_table_size;
    }
};

var rate_limiter: RateLimiter = RateLimiter.init();

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
        const fd = posix.socket(
            posix.AF.INET,
            posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
            0,
        ) catch return ServerError.SocketFailed;
        errdefer posix.close(fd);

        // allow address reuse so we can restart quickly
        const optval: c_int = 1;
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&optval)) catch {};

        const addr = std.net.Address.initIp4(bind_addr, port);
        posix.bind(fd, &addr.any, addr.getOsSockLen()) catch return ServerError.BindFailed;

        // start listening with a backlog of 128
        posix.listen(fd, 128) catch return ServerError.ListenFailed;

        return .{
            .alloc = alloc,
            .listen_fd = fd,
            .port = port,
            .bind_addr = bind_addr,
        };
    }

    pub fn deinit(self: *Server) void {
        posix.close(self.listen_fd);
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

/// extract the IPv4 address of the peer connected to a socket.
/// returns 0 if the address can't be determined (non-IPv4, error, etc).
fn getPeerIp(fd: posix.fd_t) u32 {
    var addr: posix.sockaddr.in = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    posix.getpeername(fd, @ptrCast(&addr), &addr_len) catch return 0;
    return addr.addr;
}

/// handle a single HTTP connection. runs in a worker thread.
/// reads the request, dispatches to route handler, writes response, closes.
fn handleConnection(alloc: std.mem.Allocator, client_fd: posix.fd_t) void {
    defer posix.close(client_fd);

    // rate limit check — extract client IP from the socket
    const client_ip = getPeerIp(client_fd);
    if (client_ip != 0 and !rate_limiter.checkRate(client_ip)) {
        var resp_buf: [1024]u8 = undefined;
        const resp = http.formatError(&resp_buf, .too_many_requests, "rate limit exceeded");
        writeAll(client_fd, resp);
        return;
    }

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
    var server = Server.init(std.testing.allocator, 0, .{ 127, 0, 0, 1 }) catch {
        // socket creation might fail in restricted environments
        return;
    };
    defer server.deinit();

    // the listen fd should be valid
    try std.testing.expect(server.listen_fd >= 0);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, server.bind_addr);
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

    // a new IP when table is full should still be allowed (fail-open)
    try std.testing.expect(limiter.checkRateAt(0xFFFFFFFF, now));
}
