const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const platform = @import("linux_platform").posix;
const terminal = @import("terminal.zig");

pub fn close(fd: *posix.fd_t) void {
    if (fd.* >= 0) platform.close(fd.*);
    fd.* = -1;
}

/// parent and child endpoints are owned separately so a capture worker may own
/// output while the session server owns stdin. transfer a descriptor by setting
/// its source field to -1.
pub const ProcessIo = struct {
    input: posix.fd_t = -1,
    stdout: posix.fd_t = -1,
    stderr: posix.fd_t = -1,
    child_input: posix.fd_t = -1,
    child_stdout: posix.fd_t = -1,
    child_stderr: posix.fd_t = -1,
    close_in_child: [9]posix.fd_t = @splat(-1),
    tty: bool = false,
    interactive: bool = false,

    pub fn init(interactive: bool, tty: bool) !ProcessIo {
        return initInPts(interactive, tty, "/dev");
    }

    /// Allocates an exec terminal from the devpts instance of a running
    /// container, so its path resolves there and ttyname() works. Containers
    /// without an accessible instance use the host's.
    pub fn initForProcess(interactive: bool, tty: bool, pid: posix.pid_t) !ProcessIo {
        if (!tty) return init(interactive, false);
        var root_buf: [64]u8 = undefined;
        const root = try std.fmt.bufPrint(&root_buf, "/proc/{d}/root/dev/pts", .{pid});
        var ptmx_buf: [80]u8 = undefined;
        const ptmx = try std.fmt.bufPrintSentinel(&ptmx_buf, "{s}/ptmx", .{root}, 0);
        const fd = platform.open(ptmx, .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true }, 0) catch
            return initInPts(interactive, tty, "/dev");
        platform.close(fd);
        return initInPts(interactive, tty, root);
    }

    /// `pts_dir` is /dev for the host's default instance, which keeps its
    /// multiplexer at /dev/ptmx and its terminals in /dev/pts.
    fn initInPts(interactive: bool, tty: bool, pts_dir: []const u8) !ProcessIo {
        var self: ProcessIo = .{ .interactive = interactive, .tty = tty };
        errdefer self.deinit();
        if (tty) {
            const host = std.mem.eql(u8, pts_dir, "/dev");
            var ptmx_buf: [80]u8 = undefined;
            const ptmx = try std.fmt.bufPrintSentinel(&ptmx_buf, "{s}/ptmx", .{pts_dir}, 0);
            self.stdout = try platform.open(ptmx, .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true }, 0);
            var unlock: c_int = 0;
            if (linux.errno(linux.ioctl(self.stdout, linux.T.IOCSPTLCK, @intFromPtr(&unlock))) != .SUCCESS) return error.TerminalFailed;
            var number: c_uint = 0;
            if (linux.errno(linux.ioctl(self.stdout, linux.T.IOCGPTN, @intFromPtr(&number))) != .SUCCESS) return error.TerminalFailed;
            var path_buf: [96]u8 = undefined;
            const path = try std.fmt.bufPrintSentinel(&path_buf, "{s}{s}/{d}", .{ pts_dir, if (host) "/pts" else "", number }, 0);
            self.child_input = try platform.open(path, .{ .ACCMODE = .RDWR, .NOCTTY = true, .CLOEXEC = true }, 0);
            self.child_stdout = self.child_input;
            self.child_stderr = self.child_input;
            const duplicate = linux.fcntl(self.stdout, linux.F.DUPFD_CLOEXEC, 3);
            if (linux.errno(duplicate) != .SUCCESS) return error.TerminalFailed;
            self.input = @intCast(duplicate);
            terminal.resize(self.input, terminal.size(posix.STDIN_FILENO) orelse .{});
            return self;
        }
        if (interactive) {
            const input = try platform.pipe();
            self.child_input = input[0];
            self.input = input[1];
        } else {
            self.child_input = try platform.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        }
        const output = try platform.pipe();
        self.stdout = output[0];
        self.child_stdout = output[1];
        const errors = try platform.pipe();
        self.stderr = errors[0];
        self.child_stderr = errors[1];
        return self;
    }

    pub fn closeChild(self: *ProcessIo) void {
        if (self.child_stderr == self.child_input) self.child_stderr = -1;
        if (self.child_stdout == self.child_input) self.child_stdout = -1;
        close(&self.child_input);
        close(&self.child_stdout);
        close(&self.child_stderr);
    }

    pub fn deinit(self: *ProcessIo) void {
        self.closeChild();
        close(&self.input);
        close(&self.stdout);
        close(&self.stderr);
    }

    /// called once in the final child, before its root changes.
    pub fn applyChild(self: *ProcessIo) !void {
        for (self.close_in_child) |fd| if (fd >= 0) platform.close(fd);
        close(&self.input);
        close(&self.stdout);
        close(&self.stderr);
        if (self.tty) {
            if (linux.errno(linux.setsid()) != .SUCCESS) return error.TerminalFailed;
            if (linux.errno(linux.ioctl(self.child_input, linux.T.IOCSCTTY, 0)) != .SUCCESS) return error.TerminalFailed;
        }
        try platform.dup2(self.child_input, posix.STDIN_FILENO);
        try platform.dup2(self.child_stdout, posix.STDOUT_FILENO);
        try platform.dup2(self.child_stderr, posix.STDERR_FILENO);
        self.closeChild();
    }
};

fn spawnFixture(io: *ProcessIo, script: []const u8) !posix.pid_t {
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.ForkFailed;
    if (rc == 0) {
        io.applyChild() catch linux.exit_group(125);
        linux.exit_group(@import("../process_config.zig").execCommand("/bin/sh", &.{ "-c", script }, &.{"PATH=/usr/bin:/bin"}));
    }
    io.closeChild();
    return @intCast(rc);
}

fn readUntilClosed(fd: posix.fd_t, bytes: []u8) ![]const u8 {
    var len: usize = 0;
    while (len < bytes.len) {
        var polls = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        if (linux.poll(&polls, 1, 2000) != 1) return error.ReadTimeout;
        const count = platform.read(fd, bytes[len..]) catch break; // PTY EOF is EIO.
        if (count == 0) break;
        len += count;
    }
    return bytes[0..len];
}

test "session pipes preserve stdin and separate stdout from stderr" {
    var io = try ProcessIo.init(true, false);
    defer io.deinit();
    const pid = try spawnFixture(&io, "IFS= read -r text; printf 'out:%s' \"$text\"; printf err >&2");
    defer _ = @import("../process.zig").waitForExit(pid) catch {};
    _ = try platform.write(io.input, "hello\n");
    close(&io.input);
    var output: [128]u8 = undefined;
    try std.testing.expectEqualStrings("out:hello", try readUntilClosed(io.stdout, &output));
    try std.testing.expectEqualStrings("err", try readUntilClosed(io.stderr, &output));
}

test "session terminal becomes controlling tty and preserves requested size" {
    var io = try ProcessIo.init(true, true);
    defer io.deinit();
    terminal.resize(io.input, .{ .rows = 37, .columns = 91 });
    const pid = try spawnFixture(&io, "test -t 0 && test -t 1 && test -t 2 && stty size");
    defer _ = @import("../process.zig").waitForExit(pid) catch {};
    var output: [128]u8 = undefined;
    try std.testing.expectEqualStrings("37 91\r\n", try readUntilClosed(io.stdout, &output));
}
