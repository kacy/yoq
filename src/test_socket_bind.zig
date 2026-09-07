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
