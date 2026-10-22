const std = @import("std");
const platform = @import("linux_platform");
const posix = std.posix;

test "bind reports an occupied udp address and permits distinct loopback addresses" {
    const first = try platform.posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer platform.posix.close(first);
    var address = platform.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try platform.posix.bind(first, &address.any, address.getOsSockLen());
    var length = address.getOsSockLen();
    try platform.posix.getsockname(first, &address.any, &length);

    const second = try platform.posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer platform.posix.close(second);
    try std.testing.expectError(error.AddressInUse, platform.posix.bind(second, &address.any, length));

    // Sharing a port on distinct local addresses is valid without SO_REUSEPORT.
    address.in.addr = @bitCast([4]u8{ 127, 0, 0, 2 });
    try platform.posix.bind(second, &address.any, length);
    try std.testing.expectError(error.InvalidArgument, platform.posix.bind(second, &address.any, length));
}

test "bind distinguishes invalid descriptors and socket arguments" {
    const address = platform.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try std.testing.expectError(error.InvalidFileDescriptor, platform.posix.bind(-1, &address.any, address.getOsSockLen()));
    const pipe = try platform.posix.pipe();
    defer for (pipe) |fd| platform.posix.close(fd);
    try std.testing.expectError(error.NotSocket, platform.posix.bind(pipe[0], &address.any, address.getOsSockLen()));
    const socket = try platform.posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer platform.posix.close(socket);
    try std.testing.expectError(error.InvalidArgument, platform.posix.bind(socket, &address.any, 0));
}

test "bind preserves unix socket path errors" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const base = try directory.dir.realPathFileAlloc(std.Options.debug_io, ".", std.testing.allocator);
    defer std.testing.allocator.free(base);
    const socket = try platform.posix.socket(posix.AF.UNIX, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer platform.posix.close(socket);
    var address: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = @splat(0) };
    const path = try std.fmt.bufPrint(&address.path, "{s}/missing/socket", .{base});
    const length: posix.socklen_t = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1);
    try std.testing.expectError(error.FileNotFound, platform.posix.bind(socket, @ptrCast(&address), length));
}

fn expectCloseOnExec(fd: posix.fd_t) !void {
    const flags = try platform.posix.fcntl(fd, posix.F.GETFD, 0);
    try std.testing.expect(flags & posix.FD_CLOEXEC != 0);
}

test "pipe socket and accept descriptors are close-on-exec by default" {
    const pipe = try platform.posix.pipe();
    defer for (pipe) |fd| platform.posix.close(fd);
    for (pipe) |fd| try expectCloseOnExec(fd);

    // no CLOEXEC flag passed: the wrapper adds it
    const listener = try platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer platform.posix.close(listener);
    try expectCloseOnExec(listener);
    var address = platform.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try platform.posix.bind(listener, &address.any, address.getOsSockLen());
    try platform.posix.listen(listener, 1);
    var length = address.getOsSockLen();
    try platform.posix.getsockname(listener, &address.any, &length);

    const client = try platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer platform.posix.close(client);
    try platform.posix.connect(client, &address.any, length);
    const accepted = try platform.posix.accept(listener, null, null, 0);
    defer platform.posix.close(accepted);
    try expectCloseOnExec(accepted);
}

test "dup2 onto the same descriptor clears close-on-exec" {
    const pipe = try platform.posix.pipe();
    defer for (pipe) |fd| platform.posix.close(fd);
    try platform.posix.dup2(pipe[0], pipe[0]);
    const flags = try platform.posix.fcntl(pipe[0], posix.F.GETFD, 0);
    try std.testing.expectEqual(@as(usize, 0), flags & posix.FD_CLOEXEC);
}

test "closeInheritedFds keeps stdio and the requested descriptor only" {
    const drop = try platform.posix.pipe();
    defer for (drop) |fd| platform.posix.close(fd);
    const keep = try platform.posix.pipe();
    defer for (keep) |fd| platform.posix.close(fd);

    const rc = std.os.linux.fork();
    if (std.os.linux.errno(rc) != .SUCCESS) return error.ForkFailed;
    if (rc == 0) {
        platform.posix.closeInheritedFds(keep[1]);
        const open = struct {
            fn check(fd: posix.fd_t) bool {
                return std.os.linux.errno(std.os.linux.fcntl(fd, posix.F.GETFD, 0)) == .SUCCESS;
            }
        }.check;
        // report through the exit status: 0 means only stdio and keep[1] survived
        var status: u8 = 0;
        for ([_]posix.fd_t{ 0, 1, 2, keep[1] }) |fd| if (!open(fd)) {
            status |= 1;
        };
        for ([_]posix.fd_t{ drop[0], drop[1], keep[0] }) |fd| if (open(fd)) {
            status |= 2;
        };
        std.os.linux.exit_group(status);
    }

    var status: u32 = 0;
    _ = std.os.linux.waitpid(@intCast(rc), &status, 0);
    try std.testing.expect(std.os.linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u32, 0), std.os.linux.W.EXITSTATUS(status));
}
