const std = @import("std");
const posix = std.posix;

pub const Error = error{ WouldBlock, Retry, Fatal };

/// Linux can report pending network errors directly from accept4. Those and
/// temporary resource exhaustion leave the listening socket usable.
pub fn accept(fd: posix.fd_t) Error!posix.fd_t {
    const result = std.os.linux.accept4(fd, null, null, posix.SOCK.CLOEXEC);
    return switch (posix.errno(result)) {
        .SUCCESS => @intCast(result),
        .AGAIN => error.WouldBlock,
        .INTR, .CONNABORTED, .NETDOWN, .PROTO, .NOPROTOOPT, .HOSTDOWN, .NONET, .HOSTUNREACH, .OPNOTSUPP, .NETUNREACH, .MFILE, .NFILE, .NOBUFS, .NOMEM => error.Retry,
        else => error.Fatal,
    };
}

pub const Backoff = struct {
    delay_ms: u32 = 1,

    pub fn pause(self: *Backoff) void {
        std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(self.delay_ms), .awake) catch {};
        self.delay_ms = @min(self.delay_ms * 2, 100);
    }

    pub fn reset(self: *Backoff) void {
        self.delay_ms = 1;
    }
};

/// Nonblocking listeners poll in short intervals so stop never depends on a
/// wake-up connection, closing an fd in another thread, or an interrupt.
pub fn ready(fd: posix.fd_t) Error!bool {
    var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    const timeout = posix.timespec{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
    const count = posix.ppoll(&fds, &timeout, null) catch |err| switch (err) {
        error.SignalInterrupt => return false,
        error.SystemResources => return error.Retry,
        else => return error.Fatal,
    };
    if (fds[0].revents & (posix.POLL.NVAL | posix.POLL.HUP | posix.POLL.ERR) != 0) return error.Fatal;
    return count != 0 and fds[0].revents & posix.POLL.IN != 0;
}
