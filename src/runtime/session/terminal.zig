const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

pub const Size = extern struct { rows: u16 = 24, columns: u16 = 80, x_pixels: u16 = 0, y_pixels: u16 = 0 };

pub fn size(fd: posix.fd_t) ?Size {
    var value: Size = .{};
    if (linux.errno(linux.ioctl(fd, linux.T.IOCGWINSZ, @intFromPtr(&value))) != .SUCCESS) return null;
    return value;
}

pub fn resize(fd: posix.fd_t, value: Size) void {
    _ = linux.ioctl(fd, linux.T.IOCSWINSZ, @intFromPtr(&value));
}

pub const Raw = struct {
    fd: posix.fd_t,
    previous: posix.termios,

    pub fn enter(fd: posix.fd_t) !Raw {
        const previous = try posix.tcgetattr(fd);
        var value = previous;
        value.iflag.BRKINT = false;
        value.iflag.ICRNL = false;
        value.iflag.INPCK = false;
        value.iflag.ISTRIP = false;
        value.iflag.IXON = false;
        value.oflag.OPOST = false;
        value.cflag.CSIZE = .CS8;
        value.lflag.ECHO = false;
        value.lflag.ICANON = false;
        value.lflag.IEXTEN = false;
        value.lflag.ISIG = false;
        value.cc[@intFromEnum(linux.V.MIN)] = 1;
        value.cc[@intFromEnum(linux.V.TIME)] = 0;
        try posix.tcsetattr(fd, .FLUSH, value);
        return .{ .fd = fd, .previous = previous };
    }

    pub fn deinit(self: Raw) void {
        posix.tcsetattr(self.fd, .FLUSH, self.previous) catch {};
    }
};
