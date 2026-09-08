const std = @import("std");
const bridge = @import("network/bridge.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.ExpectedHostNameAndPid;
    const pid = try std.fmt.parseInt(std.posix.pid_t, args[2], 10);
    if (pid == -1) {
        // Reproduce the old setup path before it could move the peer.
        try bridge.createVethPair(args[1], "eth0", "yoq-fixture");
    } else if (pid == 0) {
        // Exercise the existing same-namespace API as well.
        try bridge.createVethPair(args[1], "local_peer", "yoq-fixture");
    } else {
        try bridge.createVethPairForContainer(args[1], "eth0", "yoq-fixture", pid);
    }
}
