const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const platform = @import("linux_platform").posix;
const paths = @import("../../lib/paths.zig");
const server = @import("server.zig");
const protocol = @import("protocol.zig");
const terminal = @import("terminal.zig");
const foreground = @import("foreground.zig");

var pending_signal = std.atomic.Value(u8).init(0);
fn receiveSignal(signal: linux.SIG) callconv(.c) void {
    pending_signal.store(@intCast(@intFromEnum(signal)), .release);
}

pub const Outcome = union(enum) { exited: u8, detached };

pub fn attach(id: []const u8, interactive: bool) !u8 {
    return switch (try attachOutcome(id, interactive)) {
        .exited => |code| code,
        .detached => 0,
    };
}

pub fn attachOutcome(id: []const u8, interactive: bool) !Outcome {
    var path_buf: [paths.max_path]u8 = undefined;
    const endpoint = try server.address(id, &path_buf);
    const fd = try platform.socket(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0);
    defer platform.close(fd);
    var connected = false;
    for (0..200) |_| {
        platform.connect(fd, @ptrCast(&endpoint.addr), endpoint.len) catch |err| switch (err) {
            error.FileNotFound, error.ConnectionRefused => {
                try std.Io.sleep(std.Options.debug_io, .fromMilliseconds(50), .awake);
                continue;
            },
            else => return err,
        };
        connected = true;
        break;
    }
    if (!connected) return error.SessionNotFound;
    try protocol.send(fd, .hello, &.{@intFromBool(interactive)}, false);
    return runOutcome(fd);
}

pub fn run(fd: posix.fd_t) !u8 {
    return switch (try runOutcome(fd)) {
        .exited => |code| code,
        .detached => 0,
    };
}

fn runOutcome(fd: posix.fd_t) !Outcome {
    var packet: protocol.Packet = .{};
    try protocol.receive(fd, &packet, false);
    if (try packet.kind() == .failure) {
        try foreground.writeAll(posix.STDERR_FILENO, packet.payload());
        try foreground.writeAll(posix.STDERR_FILENO, "\n");
        return error.AttachFailed;
    }
    if (try packet.kind() != .ready or packet.payload().len != 2) return error.InvalidPacket;
    const tty = packet.payload()[0] != 0;
    var stdin_open = packet.payload()[1] & protocol.ready_input != 0;
    var outgoing: Outgoing = .{ .flow_pending = packet.payload()[1] & protocol.ready_flow != 0 };
    if (outgoing.flow_pending) outgoing.credit = 0;
    const raw = if (tty and stdin_open) terminal.Raw.enter(posix.STDIN_FILENO) catch null else null;
    defer if (raw) |value| value.deinit();

    const signals = [_]linux.SIG{ .INT, .TERM, .HUP };
    var previous: [signals.len]posix.Sigaction = undefined;
    pending_signal.store(0, .release);
    const action: posix.Sigaction = .{ .handler = .{ .handler = receiveSignal }, .mask = posix.sigemptyset(), .flags = 0 };
    for (signals, 0..) |signal, i| posix.sigaction(signal, &action, &previous[i]);
    defer for (signals, 0..) |signal, i| posix.sigaction(signal, &previous[i], null);

    var detach: protocol.DetachKeys = .{};
    var input: [protocol.max_payload - 1]u8 = undefined;
    var last_size: ?terminal.Size = null;
    while (true) {
        const signal = pending_signal.swap(0, .acq_rel);
        if (signal != 0) outgoing.signal = signal;
        if (tty and stdin_open) if (terminal.size(posix.STDIN_FILENO)) |size| {
            if (last_size == null or !std.meta.eql(last_size.?, size)) {
                outgoing.size = size;
                last_size = size;
            }
        };
        outgoing.flush(fd) catch |err| return drainExit(fd, err);
        var polls = [_]linux.pollfd{
            .{ .fd = fd, .events = linux.POLL.IN | @as(i16, if (outgoing.canSend()) linux.POLL.OUT else 0), .revents = 0 },
            .{ .fd = if (stdin_open and outgoing.len == 0) posix.STDIN_FILENO else -1, .events = linux.POLL.IN, .revents = 0 },
        };
        const rc = linux.poll(&polls, polls.len, 100);
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS) return error.PollFailed;
        if (polls[0].revents & (linux.POLL.IN | linux.POLL.HUP | linux.POLL.ERR) != 0) receive: {
            protocol.receive(fd, &packet, true) catch |err| {
                if (err == error.WouldBlock or err == error.Interrupted) break :receive;
                return err;
            };
            if (try packet.kind() == .input_credit) {
                try outgoing.addCredit(packet.payload());
            } else if (try handleOutput(&packet)) |code| return .{ .exited = code };
        }
        if (stdin_open and polls[1].revents != 0) {
            const count = platform.read(posix.STDIN_FILENO, &input) catch |err| {
                if (err == error.Interrupted) continue;
                return err;
            };
            if (count == 0) {
                if (detach.pending) {
                    outgoing.bytes[0] = 0x10;
                    outgoing.len = 1;
                }
                outgoing.eof = true;
                stdin_open = false;
                continue;
            }
            if (raw != null) {
                const result = detach.consume(input[0..count], &outgoing.bytes);
                outgoing.len = result.count;
                if (result.detached) {
                    // detach discards locally unsent input. closing the socket
                    // also releases ownership if its send buffer is full.
                    protocol.send(fd, .detach, "", true) catch {};
                    return .detached;
                }
            } else {
                @memcpy(outgoing.bytes[0..count], input[0..count]);
                outgoing.len = count;
            }
        }
    }
}

// keep at most one stdin packet locally. signals and the latest terminal size
// can still be sent when stdin has no credit. local reads pause while this
// packet is pending, so detach keys cannot bypass an arbitrary input backlog.
const Outgoing = struct {
    bytes: [protocol.max_payload]u8 = undefined,
    len: usize = 0,
    credit: ?usize = null, // null preserves compatibility with older servers
    flow_pending: bool = false,
    signal: u8 = 0,
    size: ?terminal.Size = null,
    eof: bool = false,

    fn addCredit(self: *Outgoing, data: []const u8) !void {
        const current = self.credit orelse return error.InvalidPacket;
        const amount = try inputCredit(data);
        if (amount > protocol.input_capacity - current) return error.InvalidPacket;
        self.credit = current + amount;
    }

    fn canSend(self: *const Outgoing) bool {
        return self.flow_pending or self.signal != 0 or self.size != null or
            (self.len != 0 and (self.credit == null or self.credit.? != 0)) or
            (self.eof and self.len == 0);
    }

    fn flush(self: *Outgoing, fd: posix.fd_t) !void {
        if (self.flow_pending) {
            if (!try sendPending(fd, .input_flow, "")) return;
            self.flow_pending = false;
        }
        if (self.signal != 0) {
            if (!try sendPending(fd, .signal, &.{self.signal})) return;
            self.signal = 0;
        }
        if (self.size) |size| {
            if (!try sendPending(fd, .resize, std.mem.asBytes(&size))) return;
            self.size = null;
        }
        const count = @min(self.len, self.credit orelse self.len);
        if (count != 0) {
            if (!try sendPending(fd, .stdin, self.bytes[0..count])) return;
            if (self.credit) |credit| self.credit = credit - count;
            std.mem.copyForwards(u8, &self.bytes, self.bytes[count..self.len]);
            self.len -= count;
        }
        // EOF shares the ordered socket with stdin and follows all local bytes.
        if (self.eof and self.len == 0) {
            if (!try sendPending(fd, .eof, "")) return;
            self.eof = false;
        }
    }
};

fn sendPending(fd: posix.fd_t, kind: protocol.Kind, bytes: []const u8) !bool {
    protocol.send(fd, kind, bytes, true) catch |err| {
        if (err == error.WouldBlock or err == error.Interrupted) return false;
        return err;
    };
    return true;
}

fn inputCredit(data: []const u8) !usize {
    if (data.len != 4) return error.InvalidPacket;
    const amount = std.mem.readInt(u32, data[0..4], .little);
    if (amount == 0 or amount > protocol.input_capacity) return error.InvalidPacket;
    return amount;
}

// the server sends exit before closing its socket. a simultaneous stdin,
// resize, or signal write can fail while that exit is still queued.
fn drainExit(fd: posix.fd_t, write_error: anyerror) !Outcome {
    var packet: protocol.Packet = .{};
    while (true) {
        protocol.receive(fd, &packet, true) catch return write_error;
        if (try handleOutput(&packet)) |code| return .{ .exited = code };
    }
}

// output and exit packets have the same meaning during normal reads and
// after a failed write. an exit code is returned only for a valid exit packet.
fn handleOutput(packet: *const protocol.Packet) !?u8 {
    const data = packet.payload();
    switch (try packet.kind()) {
        .stdout => try foreground.writeAll(posix.STDOUT_FILENO, data),
        .stderr => try foreground.writeAll(posix.STDERR_FILENO, data),
        .input_credit => _ = try inputCredit(data), // an exit may follow queued credits
        .exit => {
            if (data.len != 1) return error.InvalidPacket;
            return data[0];
        },
        else => return error.InvalidPacket,
    }
    return null;
}

test "session client restores terminal on remote exit and detach" {
    for ([_]bool{ false, true }) |detach| {
        var io = try @import("process_io.zig").ProcessIo.init(true, true);
        defer io.deinit();
        var sockets: [2]posix.fd_t = undefined;
        if (linux.socketpair(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0, &sockets) != 0) return error.SocketFailed;
        defer platform.close(sockets[0]);
        const timeout: posix.timeval = .{ .sec = 2, .usec = 0 };
        try posix.setsockopt(sockets[0], posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
        const rc = linux.fork();
        if (linux.errno(rc) != .SUCCESS) return error.ForkFailed;
        if (rc == 0) {
            platform.close(sockets[0]);
            io.applyChild() catch linux.exit_group(125);
            const before = posix.tcgetattr(posix.STDIN_FILENO) catch linux.exit_group(124);
            const code = run(sockets[1]) catch linux.exit_group(123);
            const after = posix.tcgetattr(posix.STDIN_FILENO) catch linux.exit_group(122);
            if (!std.meta.eql(before, after)) linux.exit_group(121);
            linux.exit_group(code);
        }
        const pid: posix.pid_t = @intCast(rc);
        defer {
            @import("../process.zig").kill(pid) catch {};
            _ = @import("../process.zig").waitForExit(pid) catch {};
        }
        platform.close(sockets[1]);
        io.closeChild();
        try protocol.send(sockets[0], .ready, &.{ 1, 1 }, false);
        var packet: protocol.Packet = .{};
        // resize is sent after entering raw mode and installing signal handlers.
        try protocol.receive(sockets[0], &packet, false);
        try std.testing.expectEqual(protocol.Kind.resize, try packet.kind());
        const raw = try posix.tcgetattr(io.input);
        try std.testing.expect(!raw.lflag.ICANON and !raw.lflag.ECHO);
        if (detach) {
            try foreground.writeAll(io.input, "\x10\x11");
            try protocol.receive(sockets[0], &packet, false);
            try std.testing.expectEqual(protocol.Kind.detach, try packet.kind());
        } else try protocol.send(sockets[0], .exit, &.{23}, false);
        const waited = try @import("../process.zig").waitForExit(pid);
        try std.testing.expectEqual(@import("../process.zig").ExitStatus{ .exited = if (detach) 0 else 23 }, waited.status);
    }
}

test "session client preserves a queued exit when its final stdin write fails" {
    var sockets: [2]posix.fd_t = undefined;
    if (linux.socketpair(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0, &sockets) != 0) return error.SocketFailed;
    defer platform.close(sockets[0]);
    const input = try platform.pipe();
    defer platform.close(input[0]);
    _ = try platform.write(input[1], "pending input");
    platform.close(input[1]);
    try protocol.send(sockets[1], .ready, &.{ 0, 1 }, false);
    try protocol.send(sockets[1], .stdout, "", false);
    try protocol.send(sockets[1], .exit, &.{23}, false);
    platform.close(sockets[1]);
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.ForkFailed;
    if (forked == 0) {
        platform.dup2(input[0], posix.STDIN_FILENO) catch linux.exit_group(125);
        platform.close(input[0]);
        const code = run(sockets[0]) catch linux.exit_group(124);
        linux.exit_group(code);
    }
    const pid: posix.pid_t = @intCast(forked);
    defer {
        @import("../process.zig").kill(pid) catch {};
        _ = @import("../process.zig").waitForExit(pid) catch {};
    }
    const result = try @import("../process.zig").waitForExit(pid);
    try std.testing.expectEqual(@import("../process.zig").ExitStatus{ .exited = 23 }, result.status);
}

test "session client keeps controls writable and orders EOF after credited input" {
    var sockets: [2]posix.fd_t = undefined;
    if (linux.socketpair(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0, &sockets) != 0) return error.SocketFailed;
    defer platform.close(sockets[0]);
    defer platform.close(sockets[1]);
    var outgoing: Outgoing = .{ .credit = 0, .len = 3, .eof = true, .signal = @intFromEnum(linux.SIG.TERM), .size = .{ .rows = 31, .columns = 83 } };
    @memcpy(outgoing.bytes[0..3], "abc");
    try outgoing.flush(sockets[0]);
    var packet: protocol.Packet = .{};
    try protocol.receive(sockets[1], &packet, false);
    try std.testing.expectEqual(protocol.Kind.signal, try packet.kind());
    try protocol.receive(sockets[1], &packet, false);
    try std.testing.expectEqual(protocol.Kind.resize, try packet.kind());
    try std.testing.expectError(error.WouldBlock, protocol.receive(sockets[1], &packet, true));
    try std.testing.expect(!outgoing.canSend());

    try outgoing.addCredit(&.{ 2, 0, 0, 0 });
    try outgoing.flush(sockets[0]);
    try protocol.receive(sockets[1], &packet, false);
    try std.testing.expectEqual(protocol.Kind.stdin, try packet.kind());
    try std.testing.expectEqualStrings("ab", packet.payload());
    try std.testing.expectError(error.WouldBlock, protocol.receive(sockets[1], &packet, true));
    try std.testing.expect(!outgoing.canSend());
    try outgoing.addCredit(&.{ 1, 0, 0, 0 });
    try outgoing.flush(sockets[0]);
    try protocol.receive(sockets[1], &packet, false);
    try std.testing.expectEqual(protocol.Kind.stdin, try packet.kind());
    try std.testing.expectEqualStrings("c", packet.payload());
    try protocol.receive(sockets[1], &packet, false);
    try std.testing.expectEqual(protocol.Kind.eof, try packet.kind());
    try std.testing.expect(!outgoing.canSend());
    try std.testing.expectError(error.InvalidPacket, outgoing.addCredit(&.{ 0, 0, 0, 0 }));
    try outgoing.addCredit(&.{ 0, 0, 1, 0 });
    try std.testing.expectError(error.InvalidPacket, outgoing.addCredit(&.{ 1, 0, 0, 0 }));
}

test "session client drains exit while a legacy server stops reading stdin" {
    var sockets: [2]posix.fd_t = undefined;
    if (linux.socketpair(posix.AF.UNIX, posix.SOCK.SEQPACKET | posix.SOCK.CLOEXEC, 0, &sockets) != 0) return error.SocketFailed;
    defer platform.close(sockets[0]);
    defer platform.close(sockets[1]);
    const send_buffer: c_int = 8192;
    try posix.setsockopt(sockets[0], posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&send_buffer));
    const bytes = [_]u8{'i'} ** protocol.max_payload;
    while (true) {
        protocol.send(sockets[0], .stdin, &bytes, true) catch |err| {
            if (err == error.WouldBlock) break;
            return err;
        };
    }
    const input = try platform.pipe();
    defer platform.close(input[0]);
    _ = try platform.write(input[1], "pending input");
    platform.close(input[1]);
    try protocol.send(sockets[1], .ready, &.{ 0, 1 }, false);
    try protocol.send(sockets[1], .stdout, "", false);
    try protocol.send(sockets[1], .exit, &.{23}, false);
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.ForkFailed;
    if (forked == 0) {
        platform.close(sockets[1]);
        platform.dup2(input[0], posix.STDIN_FILENO) catch linux.exit_group(125);
        platform.close(input[0]);
        const code = run(sockets[0]) catch linux.exit_group(124);
        linux.exit_group(code);
    }
    const pid: posix.pid_t = @intCast(forked);
    defer {
        @import("../process.zig").kill(pid) catch {};
        _ = @import("../process.zig").waitForExit(pid) catch {};
    }
    const handle = linux.pidfd_open(pid, 0);
    if (linux.errno(handle) != .SUCCESS) return error.ParentHandleFailed;
    defer platform.close(@intCast(handle));
    var polls = [_]linux.pollfd{.{ .fd = @intCast(handle), .events = linux.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), linux.poll(&polls, 1, 2000));
    const result = try @import("../process.zig").waitForExit(pid);
    try std.testing.expectEqual(@import("../process.zig").ExitStatus{ .exited = 23 }, result.status);
}
