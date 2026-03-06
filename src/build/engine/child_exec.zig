const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const filesystem = @import("../../runtime/filesystem.zig");
const exec_helpers = @import("../../lib/exec_helpers.zig");

pub const BuildChildContext = struct {
    layer_dirs: []const []const u8,
    upper_dir: []const u8,
    work_dir: []const u8,
    merged_dir: []const u8,
    command: []const u8,
    env: []const []const u8,
    workdir: []const u8,
    shell: ?[]const u8,
};

pub fn buildChildMain(arg: ?*anyopaque) callconv(.c) u8 {
    const ctx: *const BuildChildContext = @ptrCast(@alignCast(arg));

    if (ctx.layer_dirs.len > 0) {
        filesystem.mountOverlay(.{
            .lower_dirs = ctx.layer_dirs,
            .upper_dir = ctx.upper_dir,
            .work_dir = ctx.work_dir,
            .merged_dir = ctx.merged_dir,
        }) catch return 1;

        filesystem.pivotRoot(ctx.merged_dir) catch return 1;
    }

    filesystem.mountEssential() catch return 1;

    posix.chdir(ctx.workdir) catch {
        posix.chdir("/") catch {};
    };

    return execShellCommand(ctx.command, ctx.env, ctx.shell);
}

pub fn execShellCommand(command: []const u8, env: []const []const u8, shell: ?[]const u8) u8 {
    var str_buf: [65536]u8 = undefined;
    var str_pos: usize = 0;

    var argv: [16]?[*:0]const u8 = .{null} ** 16;
    var argv_len: usize = 0;

    if (shell) |sh| {
        const trimmed = std.mem.trim(u8, sh, " \t[]");
        var iter = std.mem.splitScalar(u8, trimmed, ',');
        while (iter.next()) |entry| {
            if (argv_len >= argv.len - 2) break;
            const part = std.mem.trim(u8, entry, " \t\"");
            if (part.len == 0) continue;
            argv[argv_len] = exec_helpers.packString(&str_buf, &str_pos, part) orelse return 127;
            argv_len += 1;
        }
    }

    if (argv_len == 0) {
        argv[0] = exec_helpers.packString(&str_buf, &str_pos, "/bin/sh") orelse return 127;
        argv[1] = exec_helpers.packString(&str_buf, &str_pos, "-c") orelse return 127;
        argv_len = 2;
    }

    argv[argv_len] = exec_helpers.packString(&str_buf, &str_pos, command) orelse return 127;

    var envp: [257]?[*:0]const u8 = .{null} ** 257;
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
