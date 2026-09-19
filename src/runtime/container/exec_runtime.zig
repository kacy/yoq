const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const linux = std.os.linux;

const filesystem = @import("../filesystem.zig");
const security = @import("../security.zig");
const init = @import("../init.zig");
const identity = @import("../identity.zig");
const process_config = @import("../process_config.zig");
const log = @import("../../lib/log.zig");
const startup = @import("startup_channel.zig");
const net_setup = @import("../../network/setup.zig");
const gpu_passthrough = @import("../../gpu/passthrough.zig");

pub const ExitCode = enum(u8) {
    success = 0,
    general_error = 1,
    filesystem_error = 120,
    bind_mount_denied = 121,
    essential_mount_failed = 122,
    security_failed = 123,
    permission_denied = 126,
    command_not_found = 127,
};

pub const BindMount = struct {
    source: []const u8,
    target: []const u8,
    read_only: bool = true,

    pub fn isSourceAllowed(self: BindMount) bool {
        return @import("source_policy.zig").isAllowed(self.source);
    }
};

pub const ChildExecContext = struct {
    user: ?[]const u8 = null,
    rootless: bool = false,
    startup_fd: posix.fd_t = -1,
    parent_startup_fd: posix.fd_t = -1,
    gpu_indices: []const u32 = &.{},
    has_overlay: bool,
    host_mode: bool,
    fs_config: filesystem.FilesystemConfig,
    rootfs: []const u8,
    command: []const u8,
    args: []const []const u8,
    env: []const []const u8,
    working_dir: []const u8,
    hostname: []const u8,
    mounts: []const BindMount,
    shm_size: u64 = filesystem.default_shm_size,
    tmpfs_mounts: []const filesystem.TmpfsMount = &.{},
};

pub fn childMain(arg: ?*anyopaque) callconv(.c) u8 {
    const ctx: *const ChildExecContext = @ptrCast(@alignCast(arg));

    if (ctx.parent_startup_fd >= 0) linux_platform.posix.close(ctx.parent_startup_fd);
    defer if (ctx.startup_fd >= 0) linux_platform.posix.close(ctx.startup_fd);
    const host_mode = ctx.host_mode;

    if (!host_mode) {
        const result = prepareFilesystemRoot(ctx);
        if (result != .success) {
            log.err("container filesystem preparation failed: {s}", .{@tagName(result)});
            return @intFromEnum(result);
        }
    }

    startup.notify(ctx.startup_fd, .overlay_ready) catch return @intFromEnum(ExitCode.general_error);
    startup.expect(ctx.startup_fd, .volumes_ready) catch return @intFromEnum(ExitCode.general_error);
    if (!host_mode) {
        const result = mountContainerFilesystems(ctx);
        if (result != .success) return @intFromEnum(result);
    }

    // Parent network setup needs the child's PID, while generated files must
    // target mounts visible only in this namespace. Hand off data, not paths.
    startup.notify(ctx.startup_fd, .filesystem_ready) catch return @intFromEnum(ExitCode.general_error);
    const network_files = startup.receiveNetwork(ctx.startup_fd) catch return @intFromEnum(ExitCode.general_error);
    if (!host_mode) {
        const result = completeFilesystem(ctx, network_files, gpu_passthrough.setupGpuPassthrough);
        if (result != .success) {
            log.err("container root finalization failed: {s}", .{@tagName(result)});
            return @intFromEnum(result);
        }
    }

    if (host_mode) {
        if (ctx.user != null) return @intFromEnum(ExitCode.security_failed);
        startup.notify(ctx.startup_fd, .prepared) catch return @intFromEnum(ExitCode.general_error);
        startup.expect(ctx.startup_fd, .execute) catch return @intFromEnum(ExitCode.general_error);
        linux_platform.posix.chdir(ctx.working_dir) catch return @intFromEnum(ExitCode.filesystem_error);
        return execCommandWrapper(@ptrCast(@constCast(ctx)));
    }

    setHostname(ctx.hostname);
    _ = linux.syscall1(.umask, 0o022);

    linux_platform.posix.chdir(ctx.working_dir) catch return @intFromEnum(ExitCode.filesystem_error);

    const account = identity.resolve(ctx.user) catch |err| {
        log.err("container identity resolution failed: {}", .{err});
        return @intFromEnum(ExitCode.security_failed);
    };
    security.apply() catch |err| {
        log.err("container security configuration failed: {}", .{err});
        return @intFromEnum(ExitCode.security_failed);
    };
    identity.apply(account, ctx.rootless and ctx.user == null) catch |err| {
        log.err("container identity change failed: {}", .{err});
        return @intFromEnum(ExitCode.security_failed);
    };
    startup.notify(ctx.startup_fd, .prepared) catch return @intFromEnum(ExitCode.general_error);
    startup.expect(ctx.startup_fd, .execute) catch return @intFromEnum(ExitCode.general_error);
    return init.run(execCommandWrapper, @ptrCast(@constCast(ctx)));
}

fn prepareFilesystemRoot(ctx: *const ChildExecContext) ExitCode {
    const root = if (ctx.has_overlay) ctx.fs_config.merged_dir else ctx.rootfs;
    if (!isSafeRoot(root)) return .filesystem_error;
    // Do this before the first mount, not just when pivoting the finished root.
    if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS) return .filesystem_error;
    if (ctx.has_overlay) filesystem.mountOverlay(ctx.fs_config) catch return .filesystem_error;
    return .success;
}

fn mountContainerFilesystems(ctx: *const ChildExecContext) ExitCode {
    const root = if (ctx.has_overlay) ctx.fs_config.merged_dir else ctx.rootfs;
    filesystem.mountEssentialWithShm(root, ctx.shm_size) catch return .essential_mount_failed;
    const Mount = union(enum) {
        bind: *const BindMount,
        tmpfs: *const filesystem.TmpfsMount,
        fn target(self: @This()) []const u8 {
            return switch (self) {
                .bind => |mount| mount.target,
                .tmpfs => |mount| mount.target,
            };
        }
        fn less(_: void, a: @This(), b: @This()) bool {
            return std.mem.lessThan(u8, a.target(), b.target());
        }
    };
    var ordered: [512]Mount = undefined;
    const count = ctx.mounts.len + ctx.tmpfs_mounts.len;
    if (count > ordered.len) return .filesystem_error;
    for (ctx.mounts, 0..) |*mount, index| ordered[index] = .{ .bind = mount };
    for (ctx.tmpfs_mounts, ctx.mounts.len..) |*mount, index| ordered[index] = .{ .tmpfs = mount };
    // mount essentials first, then explicit mounts with parents before children
    // so nested bind mounts remain visible.
    std.mem.sort(Mount, ordered[0..count], {}, Mount.less);
    for (ordered[0..count]) |entry| switch (entry) {
        .bind => |mount| {
            if (!mount.isSourceAllowed()) return .permission_denied;
            if (!isCanonicalBindSource(mount.source)) return .bind_mount_denied;
            filesystem.bindMount(root, mount.source, mount.target, mount.read_only) catch |err| {
                log.err("container: bind mount failed for {s}: {}", .{ mount.source, err });
                return .filesystem_error;
            };
        },
        .tmpfs => |mount| filesystem.mountTmpfsAt(root, mount.*) catch return .filesystem_error,
    };
    return .success;
}

fn completeFilesystem(ctx: *const ChildExecContext, files: startup.NetworkFiles, comptime setup_gpu: anytype) ExitCode {
    const root = if (ctx.has_overlay) ctx.fs_config.merged_dir else ctx.rootfs;
    // /dev is final now. Mount host GPU libraries before pivot hides them.
    if (ctx.gpu_indices.len > 0) {
        var gpu_env_buf: [4096]u8 = undefined;
        _ = setup_gpu(root, ctx.gpu_indices, &gpu_env_buf) catch return .filesystem_error;
    }
    filesystem.pivotRoot(root) catch |err| {
        log.err("container pivot root failed: {}", .{err});
        return .filesystem_error;
    };
    // Resolve image-provided /etc symlinks only within the container root.
    if (files.enabled) net_setup.writeNetworkFiles("/", files.address, files.gateway, ctx.hostname) catch return .filesystem_error;
    return .success;
}

fn execCommandWrapper(arg: ?*anyopaque) callconv(.c) u8 {
    const ctx: *const ChildExecContext = @ptrCast(@alignCast(arg));
    return execCommand(ctx.command, ctx.args, ctx.env);
}

pub fn execCommand(command: []const u8, args: []const []const u8, env: []const []const u8) u8 {
    return process_config.execCommand(command, args, env);
}

fn setHostname(name: []const u8) void {
    if (name.len == 0) return;
    _ = linux.syscall2(.sethostname, @intFromPtr(name.ptr), name.len);
}

fn shouldRefuseIsolationFallback(requested_host_mode: bool, setup_failed: bool) bool {
    return !requested_host_mode and setup_failed;
}

pub fn isCanonicalBindSource(source: []const u8) bool {
    if (source.len == 0) return false;
    return filesystem.isCanonicalAbsolutePath(source);
}

test "should refuse implicit host mode fallback when isolation was requested" {
    try std.testing.expect(shouldRefuseIsolationFallback(false, true));
    try std.testing.expect(!shouldRefuseIsolationFallback(true, true));
    try std.testing.expect(!shouldRefuseIsolationFallback(false, false));
}

// Runs only when the parent explicitly executes the suite with mount privileges.
// No host GPU or downloaded image is needed: a fixture device is created at the
// same stage as GPU passthrough, then checked from the final mounted root.
test "startup mounted overlay and raw root retain generated network and device files" {
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const Fixture = struct {
        fn device(root: []const u8, _: []const u32, buffer: *[4096]u8) ![]const u8 {
            var path_buf: [4096]u8 = undefined;
            const path = try std.fmt.bufPrintZ(&path_buf, "{s}/dev/startup-gpu", .{root});
            const fd = try linux_platform.posix.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .CLOEXEC = true }, 0o600);
            defer linux_platform.posix.close(fd);
            if (try linux_platform.posix.write(fd, "visible") != 7) return error.WriteFailed;
            return buffer[0..0];
        }

        fn contains(path: [:0]const u8, expected: []const u8) bool {
            const fd = linux_platform.posix.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch return false;
            defer linux_platform.posix.close(fd);
            var bytes: [1024]u8 = undefined;
            const count = linux_platform.posix.read(fd, &bytes) catch return false;
            return std.mem.indexOf(u8, bytes[0..count], expected) != null;
        }

        fn mountOption(target: []const u8, expected: []const u8) bool {
            const fd = linux_platform.posix.open("/proc/self/mountinfo", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch return false;
            defer linux_platform.posix.close(fd);
            var buffer: [65536]u8 = undefined;
            var count: usize = 0;
            while (count < buffer.len) {
                const read = linux_platform.posix.read(fd, buffer[count..]) catch return false;
                if (read == 0) break;
                count += read;
            }
            var lines = std.mem.splitScalar(u8, buffer[0..count], '\n');
            while (lines.next()) |line| {
                var fields = std.mem.tokenizeScalar(u8, line, ' ');
                for (0..4) |_| _ = fields.next() orelse return false;
                const mounted_at = fields.next() orelse return false;
                if (std.mem.eql(u8, mounted_at, target) and std.mem.indexOf(u8, line, expected) != null) return true;
            }
            return false;
        }

        fn run(ctx: *const ChildExecContext) u8 {
            if (linux.errno(linux.unshare(linux.CLONE.NEWNS)) != .SUCCESS) return 10;
            const prepared = prepareFilesystemRoot(ctx);
            if (prepared != .success) return @intFromEnum(prepared);
            const mounted = mountContainerFilesystems(ctx);
            if (mounted != .success) return @intFromEnum(mounted);
            const completed = completeFilesystem(ctx, .{
                .enabled = true,
                .address = .{ 10, 42, 0, 7 },
                .gateway = .{ 10, 42, 0, 1 },
            }, device);
            if (completed != .success) return @intFromEnum(completed);
            if (!contains("/etc/hosts", "10.42.0.7\tstartup-test")) return 20;
            if (!contains("/etc/resolv.conf", "nameserver 10.42.0.1")) return 21;
            if (!contains("/dev/startup-gpu", "visible")) return 22;
            if (!mountOption("/dev/shm", "size=12288k")) return 23;
            if (!mountOption("/tmp", "size=65536k")) return 24;
            if (!mountOption("/cache", "size=8192k")) return 25;
            if (!mountOption("/cache/sub", "size=4096k")) return 26;
            if (!mountOption("/readonly", "ro,")) return 27;
            if (!mountOption("/cache", "noexec")) return 28;
            const cache = linux_platform.posix.open("/cache", .{ .DIRECTORY = true, .CLOEXEC = true }, 0) catch return 29;
            const stat = linux_platform.posix.fstat(cache) catch return 30;
            linux_platform.posix.close(cache);
            if (stat.mode & 0o7777 != 0o750) return 31;
            const denied = linux.open("/readonly/file", .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0o600);
            if (linux.errno(denied) != .ROFS) return 32;
            return 0;
        }
    };
    for ([_]bool{ false, true }) |overlay| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        for ([_][]const u8{ "lower/etc", "lower/dev", "upper", "work", "merged" }) |path|
            try tmp.dir.createDirPath(std.testing.io, path);
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "lower/etc/hosts", .data = "original image hosts" });
        try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "lower/dev/startup-gpu", .data = "hidden by essential /dev mount" });
        var path_buf: [4096]u8 = undefined;
        const root_len = try tmp.dir.realPathFile(std.testing.io, ".", &path_buf);
        const base = path_buf[0..root_len];
        const alloc = std.testing.allocator;
        const lower = try std.fmt.allocPrint(alloc, "{s}/lower", .{base});
        defer alloc.free(lower);
        const upper = try std.fmt.allocPrint(alloc, "{s}/upper", .{base});
        defer alloc.free(upper);
        const work = try std.fmt.allocPrint(alloc, "{s}/work", .{base});
        defer alloc.free(work);
        const merged = try std.fmt.allocPrint(alloc, "{s}/merged", .{base});
        defer alloc.free(merged);
        const ctx = ChildExecContext{
            .has_overlay = overlay,
            .host_mode = false,
            .fs_config = .{ .lower_dirs = &.{lower}, .upper_dir = upper, .work_dir = work, .merged_dir = merged },
            .rootfs = lower,
            .command = "unused",
            .args = &.{},
            .env = &.{},
            .working_dir = "/",
            .hostname = "startup-test",
            .mounts = &.{},
            .gpu_indices = &.{0},
            .shm_size = 12 * 1024 * 1024,
            .tmpfs_mounts = &.{
                .{ .target = "/cache/sub", .size_bytes = 4 * 1024 * 1024 },
                .{ .target = "/cache", .size_bytes = 8 * 1024 * 1024, .mode = 0o750, .noexec = true },
                .{ .target = "/readonly", .read_only = true },
            },
        };
        const rc = linux.fork();
        if (linux.errno(rc) != .SUCCESS) return error.ForkFailed;
        if (rc == 0) linux.exit_group(Fixture.run(&ctx));
        const result = try @import("../process.zig").wait(@intCast(rc), false);
        try std.testing.expectEqual(@import("../process.zig").ExitStatus{ .exited = 0 }, result.status);
        if (overlay) {
            const original = try tmp.dir.readFileAlloc(std.testing.io, "lower/etc/hosts", alloc, .limited(100));
            defer alloc.free(original);
            try std.testing.expectEqualStrings("original image hosts", original);
            try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "merged/etc/hosts", .{}));
        }
    }
}

pub fn isSafeRoot(root: []const u8) bool {
    if (root.len == 0 or std.mem.indexOfScalar(u8, root, 0) != null) return false;
    var canonical: [4096]u8 = undefined;
    const length = std.Io.Dir.cwd().realPathFile(std.Options.debug_io, root, &canonical) catch return false;
    return !std.mem.eql(u8, canonical[0..length], "/");
}

test "root validation accepts a disposable directory and rejects root symlinks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.symLink(std.testing.io, "/", "root", .{});
    var path: [4096]u8 = undefined;
    const length = try tmp.dir.realPathFile(std.testing.io, ".", &path);
    try std.testing.expect(isSafeRoot(path[0..length]));
    const link = try std.fmt.allocPrint(std.testing.allocator, "{s}/root", .{path[0..length]});
    defer std.testing.allocator.free(link);
    try std.testing.expect(!isSafeRoot(link));
}
