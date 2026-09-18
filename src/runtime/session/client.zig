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
    var stdin_open = packet.payload()[1] != 0;
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
    var filtered: [protocol.max_payload]u8 = undefined;
    var last_size: ?terminal.Size = null;
    while (true) {
        const signal = pending_signal.swap(0, .acq_rel);
        if (signal != 0) try protocol.send(fd, .signal, &.{signal}, false);
        if (tty and stdin_open) if (terminal.size(posix.STDIN_FILENO)) |size| {
            if (last_size == null or !std.meta.eql(last_size.?, size)) {
                try protocol.send(fd, .resize, std.mem.asBytes(&size), false);
                last_size = size;
            }
        };
        var polls = [_]linux.pollfd{
            .{ .fd = fd, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = if (stdin_open) posix.STDIN_FILENO else -1, .events = linux.POLL.IN, .revents = 0 },
        };
        const rc = linux.poll(&polls, polls.len, 100);
        if (linux.errno(rc) == .INTR) continue;
        if (linux.errno(rc) != .SUCCESS) return error.PollFailed;
        if (polls[0].revents != 0) {
            try protocol.receive(fd, &packet, false);
            switch (try packet.kind()) {
                .stdout => try foreground.writeAll(posix.STDOUT_FILENO, packet.payload()),
                .stderr => try foreground.writeAll(posix.STDERR_FILENO, packet.payload()),
                .exit => {
                    if (packet.payload().len != 1) return error.InvalidPacket;
                    return .{ .exited = packet.payload()[0] };
                },
                else => return error.InvalidPacket,
            }
        }
        if (stdin_open and polls[1].revents != 0) {
            const count = try platform.read(posix.STDIN_FILENO, &input);
            if (count == 0) {
                if (detach.pending) try protocol.send(fd, .stdin, "\x10", false);
                try protocol.send(fd, .eof, "", false);
                stdin_open = false;
                continue;
            }
            if (raw != null) {
                const result = detach.consume(input[0..count], &filtered);
                if (result.count != 0) try protocol.send(fd, .stdin, filtered[0..result.count], false);
                if (result.detached) {
                    try protocol.send(fd, .detach, "", false);
                    return .detached;
                }
            } else try protocol.send(fd, .stdin, input[0..count], false);
        }
    }
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
        // Resize is sent after entering raw mode and installing signal handlers.
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
