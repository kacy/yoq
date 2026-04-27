const std = @import("std");
const build_options = @import("build_options");
const linux_platform = @import("linux_platform");

const cwd = std.Io.Dir.cwd;
const posix = linux_platform.posix;

pub const PortRange = struct {
    base: u16,
    count: usize,
};

pub fn requireRuntimeCore() !void {
    try requireLinux();
    try requireOptIn();
    try requireRoot();
    try requireYoqBinary();
    try requireCgroupV2();
    try requireOverlayfs();
}

pub fn requireRuntimeNetwork() !void {
    try requireRuntimeCore();
    try requireExecutable("zig-out/bin/yoq-test-http-server");
    try requireExecutable("zig-out/bin/yoq-test-net-probe");
    try requirePortsAvailable(18080, 2);
}

pub fn requireRuntimeCluster(ranges: []const PortRange) !void {
    try requireRuntimeCore();
    for (ranges) |range| {
        try requirePortsAvailable(range.base, range.count);
    }
}

fn requireLinux() !void {
    if (@import("builtin").os.tag != .linux) {
        return skip("privileged runtime tests require Linux", .{});
    }
}

fn requireOptIn() !void {
    if (build_options.run_privileged_tests) return;

    const environ = cwd().readFileAlloc(
        std.testing.io,
        "/proc/self/environ",
        std.testing.allocator,
        .limited(64 * 1024),
    ) catch |err| {
        return skip("cannot read /proc/self/environ for opt-in check: {s}", .{@errorName(err)});
    };
    defer std.testing.allocator.free(environ);

    var entries = std.mem.splitScalar(u8, environ, 0);
    while (entries.next()) |entry| {
        if (std.mem.eql(u8, entry, "YOQ_RUN_PRIVILEGED_TESTS=1")) return;
    }
    return skip("set YOQ_RUN_PRIVILEGED_TESTS=1 to run privileged runtime tests", .{});
}

fn requireRoot() !void {
    if (posix.getuid() != 0) {
        return skip("privileged runtime tests require root; rerun with sudo", .{});
    }
}

fn requireYoqBinary() !void {
    try requireExecutable("zig-out/bin/yoq");
}

fn requireExecutable(path: []const u8) !void {
    cwd().access(std.testing.io, path, .{}) catch |err| {
        return skip("missing required test binary {s}: {s}", .{ path, @errorName(err) });
    };
}

fn requireCgroupV2() !void {
    cwd().access(std.testing.io, "/sys/fs/cgroup/cgroup.controllers", .{}) catch |err| {
        return skip("cgroup v2 is unavailable or unreadable: {s}", .{@errorName(err)});
    };
}

fn requireOverlayfs() !void {
    const filesystems = cwd().readFileAlloc(
        std.testing.io,
        "/proc/filesystems",
        std.testing.allocator,
        .limited(64 * 1024),
    ) catch |err| {
        return skip("cannot read /proc/filesystems: {s}", .{@errorName(err)});
    };
    defer std.testing.allocator.free(filesystems);

    if (std.mem.indexOf(u8, filesystems, "overlay") == null) {
        return skip("overlayfs is not available on this host", .{});
    }
}

pub fn requirePortsAvailable(base: u16, count: usize) !void {
    var offset: usize = 0;
    while (offset < count) : (offset += 1) {
        const port = base + @as(u16, @intCast(offset));
        try requirePortAvailable(port);
    }
}

fn requirePortAvailable(port: u16) !void {
    const addr = linux_platform.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, port);
    const fd = posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch |err| {
        return skip("cannot create socket for port preflight: {s}", .{@errorName(err)});
    };
    defer posix.close(fd);

    posix.bind(fd, &addr.any, addr.getOsSockLen()) catch |err| {
        return skip("required localhost port {d} is not available: {s}", .{ port, @errorName(err) });
    };
}

fn skip(comptime fmt: []const u8, args: anytype) error{SkipZigTest}!void {
    std.debug.print("skipping privileged runtime test: " ++ fmt ++ "\n", args);
    return error.SkipZigTest;
}
