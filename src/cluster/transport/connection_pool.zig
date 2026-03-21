const std = @import("std");
const posix = std.posix;
const types = @import("../raft_types.zig");
const common = @import("common.zig");

const NodeId = types.NodeId;
const TransportError = common.TransportError;

pub const ConnectionPool = struct {
    connections: std.AutoHashMap(NodeId, posix.socket_t),
    mu: std.Thread.Mutex = .{},

    pub fn init(alloc: std.mem.Allocator) ConnectionPool {
        return .{
            .connections = std.AutoHashMap(NodeId, posix.socket_t).init(alloc),
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        self.mu.lock();
        var iter = self.connections.iterator();
        while (iter.next()) |entry| {
            posix.close(entry.value_ptr.*);
        }
        self.connections.deinit();
    }

    pub fn getOrConnect(self: *ConnectionPool, peer_id: NodeId, addr: std.net.Address) !posix.socket_t {
        self.mu.lock();
        if (self.connections.get(peer_id)) |fd| {
            self.mu.unlock();
            return fd;
        }
        self.mu.unlock();

        const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
        errdefer posix.close(fd);

        const timeout = posix.timeval{ .sec = 1, .usec = 0 };
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

        const one: i32 = 1;
        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&one)) catch {};
        const keepalive_time: i32 = 5;
        const TCP_KEEPIDLE = 4;
        const TCP_KEEPINTVL = 5;
        posix.setsockopt(fd, posix.IPPROTO.TCP, TCP_KEEPIDLE, std.mem.asBytes(&keepalive_time)) catch {};
        posix.setsockopt(fd, posix.IPPROTO.TCP, TCP_KEEPINTVL, std.mem.asBytes(&keepalive_time)) catch {};

        const flags = posix.fcntl(fd, posix.F.GETFL, 0) catch return TransportError.ConnectFailed;
        const nonblock_flag: usize = @as(u32, @bitCast(std.os.linux.O{ .NONBLOCK = true }));
        _ = posix.fcntl(fd, posix.F.SETFL, flags | nonblock_flag) catch return TransportError.ConnectFailed;

        posix.connect(fd, &addr.any, addr.getOsSockLen()) catch |err| {
            if (err != error.WouldBlock) {
                return TransportError.ConnectFailed;
            }
        };

        var poll_fds = [1]posix.pollfd{.{
            .fd = fd,
            .events = posix.POLL.OUT,
            .revents = 0,
        }};
        const poll_result = posix.poll(&poll_fds, 500) catch {
            return TransportError.ConnectFailed;
        };
        if (poll_result == 0 or (poll_fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP)) != 0) {
            return TransportError.ConnectFailed;
        }

        var err_buf = std.mem.toBytes(@as(i32, 0));
        posix.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, &err_buf) catch {
            return TransportError.ConnectFailed;
        };
        if (std.mem.bytesToValue(i32, &err_buf) != 0) {
            return TransportError.ConnectFailed;
        }

        _ = posix.fcntl(fd, posix.F.SETFL, flags) catch {};

        self.mu.lock();
        defer self.mu.unlock();
        // Re-check: another thread may have connected while we were dialing.
        if (self.connections.get(peer_id)) |existing_fd| {
            posix.close(fd);
            return existing_fd;
        }
        try self.connections.put(peer_id, fd);
        return fd;
    }

    pub fn removeConn(self: *ConnectionPool, peer_id: NodeId) void {
        self.mu.lock();
        const maybe_kv = self.connections.fetchRemove(peer_id);
        self.mu.unlock();
        if (maybe_kv) |kv| {
            posix.close(kv.value);
        }
    }

    pub fn closeAll(self: *ConnectionPool) void {
        self.mu.lock();
        var iter = self.connections.iterator();
        while (iter.next()) |entry| {
            posix.close(entry.value_ptr.*);
        }
        self.connections.clearRetainingCapacity();
        self.mu.unlock();
    }
};

test "ConnectionPool concurrent getOrConnect and removeConn" {
    const testing = std.testing;

    // Set up a local TCP listener so connect() can succeed.
    const listen_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(listen_fd);
    const reuse: i32 = 1;
    posix.setsockopt(listen_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuse)) catch {};

    const bind_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    posix.bind(listen_fd, &bind_addr.any, bind_addr.getOsSockLen()) catch return error.SkipZigTest;
    posix.listen(listen_fd, 128) catch return error.SkipZigTest;

    // Read back the ephemeral port.
    var sa: posix.sockaddr = undefined;
    var sa_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    posix.getsockname(listen_fd, &sa, &sa_len) catch return error.SkipZigTest;
    const addr = std.net.Address{ .any = sa };

    var pool = ConnectionPool.init(testing.allocator);
    defer pool.deinit();

    const iterations = 200;

    const Worker = struct {
        fn run(p: *ConnectionPool, a: std.net.Address, base_id: NodeId) void {
            for (0..iterations) |i| {
                const peer: NodeId = base_id +% @as(NodeId, @intCast(i));
                _ = p.getOrConnect(peer, a) catch {};
                p.removeConn(peer);
            }
        }
    };

    const t1 = try std.Thread.spawn(.{}, Worker.run, .{ &pool, addr, 1000 });
    const t2 = try std.Thread.spawn(.{}, Worker.run, .{ &pool, addr, 2000 });

    t1.join();
    t2.join();

    // Accept and discard any pending connections on the listener.
    pool.closeAll();
}
