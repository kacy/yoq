const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const filesystem = @import("../filesystem.zig");
const security = @import("../security.zig");
const init = @import("../init.zig");
const exec_helpers = @import("../../lib/exec_helpers.zig");
const log = @import("../../lib/log.zig");

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
        if (std.mem.indexOf(u8, self.source, "/.local/share/yoq/")) |pos| {
            if (pos > 0 and std.mem.indexOf(u8, self.source, "..") == null) return true;
        }

        const blocked = [_][]const u8{
            "/etc",
            "/root",
            "/var/lib",
            "/home",
            "/proc",
            "/sys",
            "/dev",
            "/boot",
            "/usr/sbin",
            "/sbin",
        };
        for (blocked) |prefix| {
            if (std.mem.startsWith(u8, self.source, prefix)) {
                if (self.source.len == prefix.len or self.source[prefix.len] == '/') {
                    return false;
                }
            }
        }
        return true;
    }
};

pub const ChildExecContext = struct {
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

    const host_mode = ctx.host_mode;

    if (!host_mode) {
        var setup_failed = false;

        if (ctx.has_overlay) {
            filesystem.mountOverlay(ctx.fs_config) catch {
                setup_failed = true;
            };
            if (!setup_failed) {
                for (ctx.mounts) |m| {
                    if (!m.isSourceAllowed()) return @intFromEnum(ExitCode.permission_denied);
                    if (!isCanonicalBindSource(m.source)) return @intFromEnum(ExitCode.bind_mount_denied);
                    filesystem.bindMount(ctx.fs_config.merged_dir, m.source, m.target, m.read_only) catch |e| {
                        log.err("container: bind mount failed for {s}: {s}", .{ m.source, @errorName(e) });
                        setup_failed = true;
                        break;
                    };
                }
            }
            if (!setup_failed) {
                filesystem.pivotRoot(ctx.fs_config.merged_dir) catch {
                    setup_failed = true;
                };
            }
        } else {
            if (ctx.rootfs.len == 0 and ctx.mounts.len > 0) {
                log.err("container: bind mounts specified but no rootfs configured", .{});
                setup_failed = true;
            }
            for (ctx.mounts) |m| {
                if (setup_failed) break;
                if (!m.isSourceAllowed()) return @intFromEnum(ExitCode.permission_denied);
                if (!isCanonicalBindSource(m.source)) return @intFromEnum(ExitCode.bind_mount_denied);
                filesystem.bindMount(ctx.rootfs, m.source, m.target, m.read_only) catch |e| {
                    log.err("container: bind mount failed for {s}: {s}", .{ m.source, @errorName(e) });
                    setup_failed = true;
                    break;
                };
            }
            if (!setup_failed) {
                filesystem.pivotRoot(ctx.rootfs) catch {
                    setup_failed = true;
                };
            }
        }

        if (!setup_failed) {
            filesystem.mountEssential() catch |err| {
                switch (err) {
                    error.MountPermissionDenied => {
                        setup_failed = true;
                    },
                    else => return @intFromEnum(ExitCode.essential_mount_failed),
                }
            };
        }

        if (shouldRefuseIsolationFallback(ctx.host_mode, setup_failed)) {
            log.err("container: filesystem isolation setup failed; refusing unsafe host-mode fallback", .{});
            return @intFromEnum(ExitCode.filesystem_error);
        }
    }

    if (host_mode) {
        posix.chdir(ctx.working_dir) catch {
            posix.chdir("/") catch {};
        };
        return execCommandWrapper(@ptrCast(@constCast(ctx)));
    }

    setHostname(ctx.hostname);
    _ = linux.syscall1(.umask, 0o022);

    posix.chdir(ctx.working_dir) catch {
        posix.chdir("/") catch {};
    };

    security.apply() catch return @intFromEnum(ExitCode.security_failed);
    return init.run(execCommandWrapper, @ptrCast(@constCast(ctx)));
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
