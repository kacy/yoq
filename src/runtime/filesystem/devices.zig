//! Populate a fresh private /dev before pivot_root hides the host devices.
const std = @import("std");
const linux = std.os.linux;
const platform = @import("linux_platform");

pub fn populate(dev_fd: std.posix.fd_t) !void {
    // A user namespace cannot create host device nodes. Bind only these
    // explicitly supported devices into the fresh, private /dev tmpfs.
    for ([_][:0]const u8{ "null", "zero", "full", "random", "urandom", "tty" }) |name| try bindDevice(dev_fd, name);
    const links = [_]struct { name: [:0]const u8, target: [:0]const u8 }{
        .{ .name = "fd", .target = "/proc/self/fd" },
        .{ .name = "stdin", .target = "/proc/self/fd/0" },
        .{ .name = "stdout", .target = "/proc/self/fd/1" },
        .{ .name = "stderr", .target = "/proc/self/fd/2" },
        .{ .name = "ptmx", .target = "pts/ptmx" },
    };
    for (links) |link| {
        if (linux.errno(linux.symlinkat(link.target.ptr, dev_fd, link.name.ptr)) != .SUCCESS) return error.MountFailed;
    }
}

fn bindDevice(dev_fd: std.posix.fd_t, name: [:0]const u8) !void {
    var source_buf: [64]u8 = undefined;
    const source_path = try std.fmt.bufPrint(&source_buf, "/dev/{s}", .{name});
    try bindDeviceFrom(dev_fd, name, source_path);
}

fn bindDeviceFrom(dev_fd: std.posix.fd_t, name: [:0]const u8, source_path: []const u8) !void {
    const source = try platform.posix.open(source_path, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    defer platform.posix.close(source);
    if ((try platform.posix.fstat(source)).mode & std.posix.S.IFMT != std.posix.S.IFCHR) return error.MountFailed;
    const created = linux.openat(dev_fd, name.ptr, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true, .CLOEXEC = true }, 0o600);
    if (linux.errno(created) != .SUCCESS) return error.MountFailed;
    const target: std.posix.fd_t = @intCast(created);
    defer platform.posix.close(target);
    var from_buf: [64]u8 = undefined;
    var to_buf: [64]u8 = undefined;
    if (linux.errno(linux.mount((try fdPath(source, &from_buf)).ptr, (try fdPath(target, &to_buf)).ptr, null, linux.MS.BIND, 0)) != .SUCCESS) return error.MountFailed;
    // Reopen through /dev after attachment: the original target fd refers to
    // the covered placeholder, while this fd belongs to the device bind.
    const attached = linux.openat(dev_fd, name.ptr, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.errno(attached) != .SUCCESS) return error.MountFailed;
    const mounted: std.posix.fd_t = @intCast(attached);
    defer platform.posix.close(mounted);
    // Read-only mount metadata prevents chmod/chown from changing the host
    // device inode. Device reads and writes still reach the character driver.
    if (linux.errno(linux.mount(null, (try fdPath(mounted, &to_buf)).ptr, null, linux.MS.BIND | linux.MS.REMOUNT | linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NOEXEC, 0)) != .SUCCESS) return error.MountFailed;
}

fn fdPath(fd: std.posix.fd_t, buf: []u8) ![:0]const u8 {
    return std.fmt.bufPrintZ(buf, "/proc/self/fd/{d}", .{fd});
}

fn testDeviceMounts(runtime: bool) !void {
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const child_exec = @import("../../build/engine/child_exec.zig");
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "root", .default_dir);
    if (linux.errno(linux.mknodat(tmp.dir.handle, "owned-null", std.posix.S.IFCHR | 0o600, (1 << 8) | 3)) != .SUCCESS) return error.CreateFailed;
    const before = try tmp.dir.statFile(std.testing.io, "owned-null", .{});
    var path_buf: [4096]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &path_buf);
    const root = try std.fmt.allocPrint(alloc, "{s}/root", .{path_buf[0..len]});
    defer alloc.free(root);
    const source = try std.fmt.allocPrint(alloc, "{s}/owned-null", .{path_buf[0..len]});
    defer alloc.free(source);
    const Fixture = struct {
        root: []const u8,
        source: []const u8,
        runtime: bool,
        fn run(arg: ?*anyopaque) callconv(.c) u8 {
            const self: *@This() = @ptrCast(@alignCast(arg));
            if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS) return 10;
            if (self.runtime) {
                @import("essential_mounts.zig").mountEssentialAt(self.root) catch return 11;
            } else {
                @import("build_mounts.zig").mountAt(self.root) catch return 11;
            }
            const root_fd = platform.posix.open(self.root, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0) catch return 12;
            defer platform.posix.close(root_fd);
            const dev = openTestPath(root_fd, "dev", .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0) catch return 13;
            defer platform.posix.close(dev);
            bindDeviceFrom(dev, "owned-null", self.source) catch return 14;
            child_exec.dropMountCapability() catch return 15;
            if (linux.errno(linux.fchmodat(dev, "owned-null", 0o777)) != .ROFS) return 16;
            if (linux.errno(linux.fchownat(dev, "owned-null", 123, 123, 0)) != .ROFS) return 20;
            checkStandardDevices(dev) catch return 21;
            const file = linux.openat(dev, "owned-null", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
            if (linux.errno(file) != .SUCCESS) return 17;
            const fd: std.posix.fd_t = @intCast(file);
            defer platform.posix.close(fd);
            if ((platform.posix.write(fd, "x") catch return 18) != 1) return 19;
            return 0;
        }
    };
    var fixture: Fixture = .{ .root = root, .source = source, .runtime = runtime };
    var child = try @import("../namespaces.zig").spawn(.{ .net = runtime, .cgroup = false }, .{
        .outer_uid = 0,
        .outer_gid = 0,
        .count = std.math.maxInt(u32),
        .gid_count = std.math.maxInt(u32),
        .allow_setgroups = true,
    }, Fixture.run, @ptrCast(&fixture));
    defer platform.posix.close(child.stdout_fd);
    defer platform.posix.close(child.stderr_fd);
    child.signalReady();
    const result = try @import("../process.zig").wait(child.pid, false);
    try std.testing.expectEqual(@import("../process.zig").ExitStatus{ .exited = 0 }, result.status);
    const after = try tmp.dir.statFile(std.testing.io, "owned-null", .{});
    try std.testing.expectEqual(before.permissions.toMode(), after.permissions.toMode());
    try std.testing.expectEqual(before.inode, after.inode);
}

fn checkStandardDevices(dev_fd: std.posix.fd_t) !void {
    for ([_][:0]const u8{ "null", "zero", "full", "random", "urandom", "tty" }) |name| {
        const fd = try openTestPath(dev_fd, name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer platform.posix.close(fd);
        if ((try platform.posix.fstat(fd)).mode & std.posix.S.IFMT != std.posix.S.IFCHR) return error.NotCharacterDevice;
    }
    const null_fd = try openTestPath(dev_fd, "null", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    defer platform.posix.close(null_fd);
    if (try platform.posix.write(null_fd, "discard") != 7) return error.WriteFailed;
    var bytes: [32]u8 = undefined;
    if (try std.posix.read(null_fd, &bytes) != 0) return error.ReadFailed;
    for ([_][:0]const u8{ "zero", "random", "urandom" }) |name| {
        const fd = try openTestPath(dev_fd, name, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true }, 0);
        defer platform.posix.close(fd);
        if (try std.posix.read(fd, &bytes) != bytes.len) return error.ReadFailed;
        if (std.mem.eql(u8, name, "zero") and !std.mem.allEqual(u8, &bytes, 0)) return error.ReadFailed;
    }
    const full_fd = try openTestPath(dev_fd, "full", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    defer platform.posix.close(full_fd);
    if (linux.errno(linux.write(full_fd, "x", 1)) != .NOSPC) return error.WriteFailed;
}

test "runtime standard devices work in user namespaces without mutable source metadata" {
    try testDeviceMounts(true);
}

test "build standard devices work in user namespaces without mutable source metadata" {
    try testDeviceMounts(false);
}

fn openTestPath(dir: std.posix.fd_t, name: [:0]const u8, flags: linux.O, mode: u32) !std.posix.fd_t {
    const fd = linux.openat(dir, name.ptr, flags, mode);
    if (linux.errno(fd) != .SUCCESS) return error.OpenFailed;
    return @intCast(fd);
}
