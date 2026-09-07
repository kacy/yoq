const std = @import("std");
const build_options = @import("build_options");
const linux_platform = @import("linux_platform");

const cwd = std.Io.Dir.cwd;
const posix = linux_platform.posix;

pub const PortRange = struct {
    base: u16,
    count: usize,
};

pub fn requireMountNamespace() !void {
    try requireLinux();
    try requireOptIn();
    try requireRoot();
}

pub fn requireRuntimeCore() !void {
    try requireMountNamespace();
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

    const environ = readProcFile("/proc/self/environ") catch |err| {
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
    const filesystems = readProcFile("/proc/filesystems") catch |err| {
        return skip("cannot read /proc/filesystems: {s}", .{@errorName(err)});
    };
    defer std.testing.allocator.free(filesystems);

    if (std.mem.indexOf(u8, filesystems, "overlay") == null) {
        return skip("overlayfs is not available on this host", .{});
    }
}

fn readProcFile(path: []const u8) ![]u8 {
    const file = try cwd().openFile(std.testing.io, path, .{});
    defer file.close(std.testing.io);
    // Proc files report size zero but provide data when read as streams.
    var reader = file.readerStreaming(std.testing.io, &.{});
    return reader.interface.allocRemaining(std.testing.allocator, .limited(64 * 1024));
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

fn skip(comptime fmt: []const u8, args: anytype) error{ SkipZigTest, MissingRuntimePrerequisite }!void {
    if (build_options.run_privileged_tests) {
        std.debug.print("missing privileged runtime prerequisite: " ++ fmt ++ "\n", args);
        return error.MissingRuntimePrerequisite;
    }
    std.debug.print("skipping privileged runtime test: " ++ fmt ++ "\n", args);
    return error.SkipZigTest;
}
