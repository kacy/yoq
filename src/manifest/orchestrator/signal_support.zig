const std = @import("std");

const posix = std.posix;

var shutdown_target: ?*std.atomic.Value(bool) = null;

pub fn installSignalHandlers(target: *std.atomic.Value(bool)) void {
    shutdown_target = target;
    const act = posix.Sigaction{
        .handler = .{ .handler = sigHandler },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.TERM, &act, null);
}

fn sigHandler(_: c_int) callconv(.c) void {
    const target = shutdown_target orelse return;
    target.store(true, .release);
}
