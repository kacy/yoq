const std = @import("std");
const posix = std.posix;
const types = @import("../raft_types.zig");
const common = @import("common.zig");

const NodeId = types.NodeId;
const TransportError = common.TransportError;

pub const ConnectionPool = struct {
    connections: std.AutoHashMap(NodeId, posix.socket_t),

    pub fn init(alloc: std.mem.Allocator) ConnectionPool {
        return .{
            .connections = std.AutoHashMap(NodeId, posix.socket_t).init(alloc),
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        var iter = self.connections.iterator();
        while (iter.next()) |entry| {
            posix.close(entry.value_ptr.*);
        }
        self.connections.deinit();
    }

    pub fn getOrConnect(self: *ConnectionPool, peer_id: NodeId, addr: std.net.Address) !posix.socket_t {
        if (self.connections.get(peer_id)) |fd| return fd;

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
                posix.close(fd);
                return TransportError.ConnectFailed;
            }
        };

        var poll_fds = [1]posix.pollfd{.{
            .fd = fd,
            .events = posix.POLL.OUT,
            .revents = 0,
        }};
        const poll_result = posix.poll(&poll_fds, 500) catch {
            posix.close(fd);
            return TransportError.ConnectFailed;
        };
        if (poll_result == 0 or (poll_fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP)) != 0) {
            posix.close(fd);
            return TransportError.ConnectFailed;
        }

        var err_buf = std.mem.toBytes(@as(i32, 0));
        posix.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, &err_buf) catch {
            posix.close(fd);
            return TransportError.ConnectFailed;
        };
        if (std.mem.bytesToValue(i32, &err_buf) != 0) {
            posix.close(fd);
            return TransportError.ConnectFailed;
        }

        _ = posix.fcntl(fd, posix.F.SETFL, flags) catch {};

        try self.connections.put(peer_id, fd);
        return fd;
    }

    pub fn removeConn(self: *ConnectionPool, peer_id: NodeId) void {
        if (self.connections.fetchRemove(peer_id)) |kv| {
            posix.close(kv.value);
        }
    }

    pub fn closeAll(self: *ConnectionPool) void {
        var iter = self.connections.iterator();
        while (iter.next()) |entry| {
            posix.close(entry.value_ptr.*);
        }
        self.connections.clearRetainingCapacity();
    }
};
