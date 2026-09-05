const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const linux = std.os.linux;

const filesystem = @import("../filesystem.zig");
const security = @import("../security.zig");
const init = @import("../init.zig");
const exec_helpers = @import("../../lib/exec_helpers.zig");
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
};

pub fn childMain(arg: ?*anyopaque) callconv(.c) u8 {
    const ctx: *const ChildExecContext = @ptrCast(@alignCast(arg));

    if (ctx.parent_startup_fd >= 0) linux_platform.posix.close(ctx.parent_startup_fd);
    defer if (ctx.startup_fd >= 0) linux_platform.posix.close(ctx.startup_fd);
    const host_mode = ctx.host_mode;

    if (!host_mode) {
        const result = mountFilesystem(ctx);
        if (result != .success) return @intFromEnum(result);
    }

    // Parent network setup needs the child's PID, while generated files must
    // target mounts visible only in this namespace. Hand off data, not paths.
    startup.notify(ctx.startup_fd, .filesystem_ready) catch return @intFromEnum(ExitCode.general_error);
    const network_files = startup.receiveNetwork(ctx.startup_fd) catch return @intFromEnum(ExitCode.general_error);
    if (!host_mode) {
        const result = completeFilesystem(ctx, network_files, gpu_passthrough.setupGpuPassthrough);
        if (result != .success) return @intFromEnum(result);
    }

    if (host_mode) {
        startup.notify(ctx.startup_fd, .prepared) catch return @intFromEnum(ExitCode.general_error);
        startup.expect(ctx.startup_fd, .execute) catch return @intFromEnum(ExitCode.general_error);
        linux_platform.posix.chdir(ctx.working_dir) catch {
            linux_platform.posix.chdir("/") catch {};
        };
        return execCommandWrapper(@ptrCast(@constCast(ctx)));
    }

    setHostname(ctx.hostname);
    _ = linux.syscall1(.umask, 0o022);

    linux_platform.posix.chdir(ctx.working_dir) catch {
        linux_platform.posix.chdir("/") catch {};
    };

    security.apply() catch return @intFromEnum(ExitCode.security_failed);
    startup.notify(ctx.startup_fd, .prepared) catch return @intFromEnum(ExitCode.general_error);
    startup.expect(ctx.startup_fd, .execute) catch return @intFromEnum(ExitCode.general_error);
    return init.run(execCommandWrapper, @ptrCast(@constCast(ctx)));
}

fn mountFilesystem(ctx: *const ChildExecContext) ExitCode {
    const root = if (ctx.has_overlay) ctx.fs_config.merged_dir else ctx.rootfs;
    if (root.len == 0) return .filesystem_error;
    // Do this before the first mount, not just when pivoting the finished root.
    if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS) return .filesystem_error;
    if (ctx.has_overlay) filesystem.mountOverlay(ctx.fs_config) catch return .filesystem_error;
    for (ctx.mounts) |mount| {
        if (!mount.isSourceAllowed()) return .permission_denied;
        if (!isCanonicalBindSource(mount.source)) return .bind_mount_denied;
        filesystem.bindMount(root, mount.source, mount.target, mount.read_only) catch |err| {
            log.err("container: bind mount failed for {s}: {}", .{ mount.source, err });
            return .filesystem_error;
        };
    }
    filesystem.mountEssentialAt(root) catch return .essential_mount_failed;
    return .success;
}

fn completeFilesystem(ctx: *const ChildExecContext, files: startup.NetworkFiles, comptime setup_gpu: anytype) ExitCode {
    const root = if (ctx.has_overlay) ctx.fs_config.merged_dir else ctx.rootfs;
    // /dev is final now. Mount host GPU libraries before pivot hides them.
    if (ctx.gpu_indices.len > 0) {
        var gpu_env_buf: [4096]u8 = undefined;
        _ = setup_gpu(root, ctx.gpu_indices, &gpu_env_buf) catch return .filesystem_error;
    }
    filesystem.pivotRoot(root) catch return .filesystem_error;
    // Resolve image-provided /etc symlinks only within the container root.
    if (files.enabled) net_setup.writeNetworkFiles("/", files.address, files.gateway, ctx.hostname);
    return .success;
}

fn execCommandWrapper(arg: ?*anyopaque) callconv(.c) u8 {
    const ctx: *const ChildExecContext = @ptrCast(@alignCast(arg));
    return execCommand(ctx.command, ctx.args, ctx.env);
}

fn execCommand(command: []const u8, args: []const []const u8, env: []const []const u8) u8 {
    const str_buf_size = 65536;
    const max_entries = 257;

    comptime std.debug.assert(str_buf_size >= 4096);
    comptime std.debug.assert(max_entries <= 512);

    var str_buf: [str_buf_size]u8 = undefined;
    var str_pos: usize = 0;

    var argv: [max_entries]?[*:0]const u8 = .{null} ** max_entries;
    argv[0] = exec_helpers.packString(&str_buf, &str_pos, command) orelse return 127;

    var argv_idx: usize = 1;
    for (args) |arg| {
        if (argv_idx >= argv.len - 1) break;
        argv[argv_idx] = exec_helpers.packString(&str_buf, &str_pos, arg) orelse return 127;
        argv_idx += 1;
    }

    var envp: [max_entries]?[*:0]const u8 = .{null} ** max_entries;
    for (env, 0..) |e, i| {
        if (i >= envp.len - 1) break;
        envp[i] = exec_helpers.packString(&str_buf, &str_pos, e) orelse return 127;
    }

    _ = linux.syscall3(
        .execve,
        @intFromPtr(argv[0].?),
        @intFromPtr(&argv),
        @intFromPtr(&envp),
    );
    return 127;
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

        fn run(ctx: *const ChildExecContext) u8 {
            if (linux.errno(linux.unshare(linux.CLONE.NEWNS)) != .SUCCESS) return 10;
            const mounted = mountFilesystem(ctx);
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
