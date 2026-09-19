const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const platform = @import("linux_platform").posix;
const paths = @import("../../lib/paths.zig");
const process = @import("../process.zig");
const channels = @import("process_io.zig");
const protocol = @import("protocol.zig");
const terminal = @import("terminal.zig");

pub fn address(id: []const u8, path_buf: *[paths.max_path]u8) !struct { addr: posix.sockaddr.un, len: posix.socklen_t, path: []const u8 } {
    if (id.len != 12) return error.InvalidId;
    for (id) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidId;
    const path = try paths.dataPathFmt(path_buf, "sessions/{s}.sock", .{id});
    var addr: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = @splat(0) };
    if (path.len >= addr.path.len) return error.PathTooLong;
    @memcpy(addr.path[0..path.len], path);
    return .{ .addr = addr, .len = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1), .path = path };
}

const Client = struct { fd: posix.fd_t = -1, ready: bool = false };
const max_clients = 8;
const history_count = 16;

/// the supervisor owns this object until every capture worker has joined.
/// slow readers are disconnected; log storage never waits on an attach client.
pub const Server = struct {
    listener: posix.fd_t,
    path: [paths.max_path]u8,
    path_len: usize,
    interactive: bool,
    tty: bool,
    mutex: std.Io.Mutex = .init,
    clients: [max_clients]Client = .{Client{}} ** max_clients,
    input_client: ?posix.fd_t = null,
    input_fd: posix.fd_t = -1,
    pid: ?posix.pid_t = null,
    forking: bool = false,
    terminal_size: terminal.Size = .{},
    input_buffer: [64 * 1024]u8 = undefined,
    input_len: usize = 0,
    eof_pending: bool = false,
    history: [history_count]protocol.Packet = undefined,
    history_len: usize = 0,
    history_next: usize = 0,
    exit_code: ?u8 = null,
    ever_attached: std.atomic.Value(bool) = .init(false),
    stopping: std.atomic.Value(bool) = .init(false),
    worker: ?std.Thread = null,

    pub fn init(id: []const u8, interactive: bool, tty: bool) !Server {
        try paths.ensureDataDirStrict("sessions");
        var path_buf: [paths.max_path]u8 = undefined;
        const endpoint = try address(id, &path_buf);
        // the caller already holds the durable container owner lock.
        std.Io.Dir.cwd().deleteFile(std.Options.debug_io, endpoint.path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        const listener = try platform.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
        errdefer platform.close(listener);
        try platform.bind(listener, @ptrCast(&endpoint.addr), endpoint.len);
        errdefer std.Io.Dir.cwd().deleteFile(std.Options.debug_io, endpoint.path) catch {};
        try platform.listen(listener, max_clients);
        return .{ .listener = listener, .path = path_buf, .path_len = endpoint.path.len, .interactive = interactive, .tty = tty };
    }

    pub fn start(self: *Server) !void {
        self.worker = try std.Thread.spawn(.{}, run, .{self});
    }

    pub fn deinit(self: *Server) void {
        self.stopping.store(true, .release);
        if (self.worker) |worker| worker.join();
        for (&self.clients) |*client| channels.close(&client.fd);
        channels.close(&self.input_fd);
        channels.close(&self.listener);
        std.Io.Dir.cwd().deleteFile(std.Options.debug_io, self.path[0..self.path_len]) catch {};
    }

    pub fn prepareChild(self: *Server, io: *channels.ProcessIo) void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        // a new execution attempt starts a new attachment history.
        if (self.exit_code != null) {
            self.exit_code = null;
            self.history_len = 0;
            self.history_next = 0;
            self.input_len = 0;
            self.eof_pending = false;
        }
        self.forking = true;
        io.close_in_child[0] = self.listener;
        for (self.clients, 1..) |client, i| io.close_in_child[i] = client.fd;
    }

    pub fn childStarted(self: *Server) void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        self.forking = false;
    }

    pub fn setInput(self: *Server, io: *channels.ProcessIo, pid: posix.pid_t) void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        channels.close(&self.input_fd);
        self.input_fd = io.input;
        io.input = -1;
        self.pid = pid;
        if (self.tty) terminal.resize(self.input_fd, self.terminal_size);
        if (self.input_fd >= 0) {
            const flags = linux.fcntl(self.input_fd, linux.F.GETFL, 0);
            if (linux.errno(flags) == .SUCCESS) _ = linux.fcntl(self.input_fd, linux.F.SETFL, flags | @as(u32, @bitCast(linux.O{ .NONBLOCK = true })));
        }
    }

    pub fn clearInput(self: *Server) void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        channels.close(&self.input_fd);
        self.pid = null;
        self.input_len = 0;
        self.eof_pending = false;
    }

    pub fn output(context: *anyopaque, stream: []const u8, bytes: []const u8) void {
        const self: *Server = @ptrCast(@alignCast(context));
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        const kind: protocol.Kind = if (std.mem.eql(u8, stream, "stderr")) .stderr else .stdout;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const end = offset + @min(protocol.max_payload, bytes.len - offset);
            const chunk = bytes[offset..end];
            const record = &self.history[self.history_next];
            record.bytes[0] = @intFromEnum(kind);
            @memcpy(record.bytes[1..][0..chunk.len], chunk);
            record.len = chunk.len + 1;
            self.history_next = (self.history_next + 1) % history_count;
            self.history_len = @min(history_count, self.history_len + 1);
            for (&self.clients) |*client| if (client.ready) {
                protocol.send(client.fd, kind, chunk, true) catch self.disconnect(client);
            };
            offset = end;
        }
    }

    pub fn finish(self: *Server, code: u8) void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        self.exit_code = code;
        for (&self.clients) |*client| if (client.ready) {
            protocol.send(client.fd, .exit, &.{code}, true) catch {};
            self.disconnect(client);
        };
    }

    fn disconnect(self: *Server, client: *Client) void {
        if (self.input_client == client.fd) self.input_client = null;
        channels.close(&client.fd);
        client.ready = false;
    }

    fn hello(self: *Server, client: *Client, data: []const u8) !void {
        if (data.len != 1 or data[0] > 1 or client.ready) return error.InvalidPacket;
        const owns_input = data[0] == 1 and self.interactive;
        if (owns_input and self.input_client != null) {
            try protocol.send(client.fd, .failure, "stdin is already attached", true);
            return error.InputBusy;
        }
        if (owns_input) self.input_client = client.fd;
        try protocol.send(client.fd, .ready, &.{ @intFromBool(self.tty), @intFromBool(owns_input) }, true);
        const oldest = (self.history_next + history_count - self.history_len) % history_count;
        for (0..self.history_len) |i| {
            const entry = &self.history[(oldest + i) % history_count];
            try protocol.send(client.fd, try entry.kind(), entry.payload(), true);
        }
        if (self.exit_code) |code| {
            try protocol.send(client.fd, .exit, &.{code}, true);
            // this attachment belongs to the completed attempt. it must not
            // enqueue stdin or retain ownership for the next automatic run.
            self.disconnect(client);
            return;
        }
        client.ready = true;
        self.ever_attached.store(true, .release);
    }

    fn receive(self: *Server, client: *Client) !void {
        var packet: protocol.Packet = .{};
        try protocol.receive(client.fd, &packet, true);
        const data = packet.payload();
        const kind = try packet.kind();
        if (kind == .hello) return self.hello(client, data);
        if (!client.ready) return error.InvalidPacket;
        switch (kind) {
            .detach => self.disconnect(client),
            .signal => {
                if (data.len != 1 or data[0] == 0 or data[0] > 64) return error.InvalidPacket;
                if (self.pid) |pid| try process.sendSignal(pid, data[0]);
            },
            .stdin => {
                if (self.input_client != client.fd or self.eof_pending) return error.InputNotOwned;
                if (self.pid != null and self.input_fd < 0) return error.InputClosed;
                if (data.len > self.input_buffer.len - self.input_len) return error.InputOverflow;
                @memcpy(self.input_buffer[self.input_len..][0..data.len], data);
                self.input_len += data.len;
            },
            .eof => {
                if (self.input_client != client.fd) return error.InputNotOwned;
                if (self.pid != null and self.input_fd < 0) return error.InputClosed;
                self.eof_pending = true;
            },
            .resize => {
                if (self.input_client != client.fd or data.len != @sizeOf(terminal.Size)) return error.InvalidPacket;
                const size = std.mem.bytesToValue(terminal.Size, data);
                self.terminal_size = size;
                if (self.tty and self.input_fd >= 0) terminal.resize(self.input_fd, size);
            },
            else => return error.InvalidPacket,
        }
    }

    fn flushInput(self: *Server) void {
        if (self.input_fd < 0) return;
        if (self.input_len != 0) {
            const count = self.writeInput(self.input_buffer[0..self.input_len]) orelse return;
            std.mem.copyForwards(u8, &self.input_buffer, self.input_buffer[count..self.input_len]);
            self.input_len -= count;
        }
        if (self.input_len == 0 and self.eof_pending) {
            if (self.tty) {
                const count = self.writeInput("\x04") orelse return;
                if (count == 0) return;
            } else channels.close(&self.input_fd);
            self.eof_pending = false;
        }
    }

    fn writeInput(self: *Server, bytes: []const u8) ?usize {
        return platform.write(self.input_fd, bytes) catch |err| {
            if (err == error.WouldBlock or err == error.Interrupted) return null;
            // no future write can drain this queue once the input is closed.
            channels.close(&self.input_fd);
            self.input_len = 0;
            self.eof_pending = false;
            return null;
        };
    }

    fn run(self: *Server) void {
        var blocked = posix.sigemptyset();
        posix.sigaddset(&blocked, .PIPE);
        posix.sigprocmask(posix.SIG.BLOCK, &blocked, null);
        while (!self.stopping.load(.acquire)) {
            var polls: [max_clients + 1]linux.pollfd = undefined;
            self.mutex.lockUncancelable(std.Options.debug_io);
            polls[0] = .{ .fd = self.listener, .events = linux.POLL.IN, .revents = 0 };
            // only the stdin owner can add to the queue. observers must still
            // be able to attach, send signals, and detach while it is full.
            const input_full = self.input_len > self.input_buffer.len - protocol.max_payload;
            for (self.clients, 1..) |client, i| polls[i] = .{
                .fd = if (input_full and self.input_client == client.fd) -1 else client.fd,
                .events = linux.POLL.IN,
                .revents = 0,
            };
            self.flushInput();
            self.mutex.unlock(std.Options.debug_io);
            _ = linux.poll(&polls, polls.len, 20);
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);
            if (self.forking) continue;
            if (polls[0].revents & linux.POLL.IN != 0) {
                const fd = platform.accept(self.listener, null, null, posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK) catch continue;
                var accepted = false;
                for (&self.clients) |*client| if (client.fd < 0) {
                    client.* = .{ .fd = fd };
                    accepted = true;
                    break;
                };
                if (!accepted) platform.close(fd);
            }
            for (&self.clients, 1..) |*client, i| {
                if (client.fd >= 0 and polls[i].fd == client.fd and polls[i].revents != 0)
                    self.receive(client) catch |err| {
                        if (err != error.WouldBlock) self.disconnect(client);
                    };
            }
        }
    }
};

fn testConnect(id: []const u8) !posix.fd_t {
    var path_buf: [paths.max_path]u8 = undefined;
    const endpoint = try address(id, &path_buf);
    const fd = try platform.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0);
    errdefer platform.close(fd);
    const timeout: posix.timeval = .{ .sec = 2, .usec = 0 };
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    try platform.connect(fd, @ptrCast(&endpoint.addr), endpoint.len);
    return fd;
}

test "session server replays raw output and grants stdin to one client" {
    var server = try Server.init("fe0123456789", true, false);
    defer server.deinit();
    Server.output(&server, "stdout", "early prompt> ");
    try server.start();
    const client = try testConnect("fe0123456789");
    defer platform.close(client);
    try protocol.send(client, .hello, &.{1}, false);
    var packet: protocol.Packet = .{};
    try protocol.receive(client, &packet, false);
    try std.testing.expectEqual(protocol.Kind.ready, try packet.kind());
    try std.testing.expectEqualSlices(u8, &.{ 0, 1 }, packet.payload());
    try protocol.receive(client, &packet, false);
    try std.testing.expectEqualStrings("early prompt> ", packet.payload());

    const competing = try testConnect("fe0123456789");
    defer platform.close(competing);
    try protocol.send(competing, .hello, &.{1}, false);
    try protocol.receive(competing, &packet, false);
    try std.testing.expectEqual(protocol.Kind.failure, try packet.kind());

    var io = try channels.ProcessIo.init(true, false);
    defer io.deinit();
    server.setInput(&io, 1);
    try protocol.send(client, .stdin, "hello\x00", false);
    var polls = [_]linux.pollfd{.{ .fd = io.child_input, .events = linux.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), linux.poll(&polls, 1, 2000));
    var bytes: [32]u8 = undefined;
    const count = try platform.read(io.child_input, &bytes);
    try std.testing.expectEqualStrings("hello\x00", bytes[0..count]);
    Server.output(&server, "stderr", "error\r");
    try protocol.receive(client, &packet, false);
    try std.testing.expectEqual(protocol.Kind.stderr, try packet.kind());
    try std.testing.expectEqualStrings("error\r", packet.payload());
    server.finish(23);
    try protocol.receive(client, &packet, false);
    try std.testing.expectEqual(protocol.Kind.exit, try packet.kind());
    try std.testing.expectEqualSlices(u8, &.{23}, packet.payload());
}

test "session attachment after exit cannot feed the next attempt" {
    var server = try Server.init("fe1234567890", true, false);
    defer server.deinit();
    Server.output(&server, "stdout", "first attempt");
    server.finish(23);
    var sockets: [2]posix.fd_t = undefined;
    if (linux.socketpair(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0, &sockets) != 0) return error.SocketFailed;
    defer platform.close(sockets[1]);
    var client: Client = .{ .fd = sockets[0] };
    defer channels.close(&client.fd);
    try server.hello(&client, &.{1});
    try std.testing.expectEqual(@as(posix.fd_t, -1), client.fd);
    try std.testing.expect(server.input_client == null);
    var packet: protocol.Packet = .{};
    try protocol.receive(sockets[1], &packet, false);
    try std.testing.expectEqual(protocol.Kind.ready, try packet.kind());
    try protocol.receive(sockets[1], &packet, false);
    try std.testing.expectEqualStrings("first attempt", packet.payload());
    try protocol.receive(sockets[1], &packet, false);
    try std.testing.expectEqual(protocol.Kind.exit, try packet.kind());
    server.input_len = 3;
    server.eof_pending = true;
    var io = try channels.ProcessIo.init(true, false);
    defer io.deinit();
    server.prepareChild(&io);
    server.childStarted();
    try std.testing.expectEqual(@as(usize, 0), server.input_len);
    try std.testing.expectEqual(@as(usize, 0), server.history_len);
    try std.testing.expect(!server.eof_pending);
    try std.testing.expect(server.exit_code == null);
}

test "session observers attach and detach while stdin is backpressured" {
    var server = try Server.init("fe2345678901", true, false);
    defer server.deinit();
    try server.start();
    const owner = try testConnect("fe2345678901");
    defer platform.close(owner);
    try protocol.send(owner, .hello, &.{1}, false);
    var packet: protocol.Packet = .{};
    try protocol.receive(owner, &packet, false);
    try std.testing.expectEqual(protocol.Kind.ready, try packet.kind());

    // hold a full queue before the child has supplied its input fd.
    server.mutex.lockUncancelable(std.Options.debug_io);
    @memset(&server.input_buffer, 'i');
    server.input_len = server.input_buffer.len;
    server.mutex.unlock(std.Options.debug_io);

    const observer = try testConnect("fe2345678901");
    defer platform.close(observer);
    try protocol.send(observer, .hello, &.{0}, false);
    try protocol.receive(observer, &packet, false);
    try std.testing.expectEqual(protocol.Kind.ready, try packet.kind());
    try std.testing.expectEqualSlices(u8, &.{ 0, 0 }, packet.payload());
    try protocol.send(observer, .detach, "", false);
    try std.testing.expectError(error.Disconnected, protocol.receive(observer, &packet, false));
}

test "session discards pending stdin when the child closes its input" {
    const ignored: posix.Sigaction = .{ .handler = .{ .handler = posix.SIG.IGN }, .mask = posix.sigemptyset(), .flags = 0 };
    var previous: posix.Sigaction = undefined;
    posix.sigaction(.PIPE, &ignored, &previous);
    defer posix.sigaction(.PIPE, &previous, null);

    var server = try Server.init("fe3456789012", true, false);
    defer server.deinit();
    var io = try channels.ProcessIo.init(true, false);
    defer io.deinit();
    server.setInput(&io, 1);
    channels.close(&io.child_input);
    @memset(&server.input_buffer, 'i');
    server.input_len = server.input_buffer.len;
    server.eof_pending = true;
    server.flushInput();
    try std.testing.expectEqual(@as(posix.fd_t, -1), server.input_fd);
    try std.testing.expectEqual(@as(usize, 0), server.input_len);
    try std.testing.expect(!server.eof_pending);

    var sockets: [2]posix.fd_t = undefined;
    if (linux.socketpair(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0, &sockets) != 0) return error.SocketFailed;
    defer platform.close(sockets[0]);
    defer platform.close(sockets[1]);
    var client: Client = .{ .fd = sockets[0], .ready = true };
    server.input_client = client.fd;
    try protocol.send(sockets[1], .stdin, "more input", false);
    try std.testing.expectError(error.InputClosed, server.receive(&client));
    try protocol.send(sockets[1], .eof, "", false);
    try std.testing.expectError(error.InputClosed, server.receive(&client));
    try std.testing.expectEqual(@as(usize, 0), server.input_len);
    try std.testing.expect(!server.eof_pending);
}
