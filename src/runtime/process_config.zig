// Shared, allocation-free command preparation for run and exec children.
const std = @import("std");
const linux = std.os.linux;
const exec_helpers = @import("../lib/exec_helpers.zig");

pub const max_args = 255;
pub const max_env = 256;
const string_capacity = 65536;
const default_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub fn validate(command: []const u8, args: []const []const u8, env: []const []const u8) error{InvalidArguments}!void {
    if (command.len == 0 or args.len > max_args or env.len > max_env) return error.InvalidArguments;
    var remaining: usize = string_capacity;
    try reserveString(command, &remaining);
    for (args) |arg| try reserveString(arg, &remaining);
    for (env) |entry| try reserveString(entry, &remaining);
}

fn reserveString(value: []const u8, remaining: *usize) error{InvalidArguments}!void {
    if (value.len >= remaining.* or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidArguments;
    remaining.* -= value.len + 1;
}

/// Resolve PATH inside the final root and working directory. Return the shell
/// convention of 127 for missing commands and 126 for commands that cannot run.
pub fn execCommand(command: []const u8, args: []const []const u8, env: []const []const u8) u8 {
    validate(command, args, env) catch return 126;
    var strings: [string_capacity]u8 = undefined;
    var position: usize = 0;
    var argv: [max_args + 2]?[*:0]const u8 = .{null} ** (max_args + 2);
    var envp: [max_env + 1]?[*:0]const u8 = .{null} ** (max_env + 1);
    argv[0] = exec_helpers.packString(&strings, &position, command).?;
    for (args, 1..) |arg, i| argv[i] = exec_helpers.packString(&strings, &position, arg).?;
    for (env, 0..) |entry, i| envp[i] = exec_helpers.packString(&strings, &position, entry).?;

    if (std.mem.indexOfScalar(u8, command, '/') != null) {
        return execFailure(linux.errno(linux.execve(argv[0].?, @ptrCast(&argv), @ptrCast(&envp))));
    }
    var path: []const u8 = default_path;
    for (env) |entry| {
        if (std.mem.startsWith(u8, entry, "PATH=")) {
            path = entry[5..];
            break;
        }
    }
    var dirs = std.mem.splitScalar(u8, path, ':');
    var executable: [4096]u8 = undefined;
    var failure: u8 = 127;
    while (dirs.next()) |dir| {
        const candidate = std.fmt.bufPrintZ(&executable, "{s}/{s}", .{ if (dir.len > 0) dir else ".", command }) catch {
            failure = 126;
            continue;
        };
        const err = linux.errno(linux.execve(candidate, @ptrCast(&argv), @ptrCast(&envp)));
        switch (err) {
            .NOENT, .NOTDIR => {},
            .ACCES => failure = 126,
            else => return execFailure(err),
        }
    }
    return failure;
}

fn execFailure(err: linux.E) u8 {
    return switch (err) {
        .NOENT, .NOTDIR => 127,
        else => 126,
    };
}

test "process arguments reject overflow and embedded zero without truncation" {
    try validate("sh", &.{}, &.{});
    const args = [_][]const u8{"x"} ** (max_args + 1);
    try validate("sh", args[0..max_args], &.{});
    try std.testing.expectError(error.InvalidArguments, validate("sh", &args, &.{}));
    const env = [_][]const u8{"K=V"} ** (max_env + 1);
    try validate("sh", &.{}, env[0..max_env]);
    try std.testing.expectError(error.InvalidArguments, validate("sh", &.{}, &env));
    try std.testing.expectError(error.InvalidArguments, validate("sh", &.{"x\x00y"}, &.{}));
    try std.testing.expectError(error.InvalidArguments, validate("", &.{}, &.{}));
    const huge = "x" ** string_capacity;
    try std.testing.expectError(error.InvalidArguments, validate("sh", &.{huge}, &.{}));
}

fn childStatus(command: []const u8, args: []const []const u8, env: []const []const u8, working_dir: ?[:0]const u8) !u8 {
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.ForkFailed;
    if (pid == 0) {
        if (working_dir) |dir| {
            if (linux.errno(linux.chdir(dir)) != .SUCCESS) linux.exit_group(125);
        }
        linux.exit_group(execCommand(command, args, env));
    }
    const result = try @import("process.zig").waitForExit(@intCast(pid));
    return switch (result.status) {
        .exited => |code| code,
        else => error.UnexpectedStatus,
    };
}

test "process execution resolves custom and empty PATH in the working directory" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.symLink(std.testing.io, "/bin/sh", "local-shell", .{});
    var path_buf: [4096]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &path_buf);
    const path = try alloc.dupeZ(u8, path_buf[0..len]);
    defer alloc.free(path);
    const env_path = try std.fmt.allocPrint(alloc, "PATH={s}", .{path});
    defer alloc.free(env_path);
    const script = "test \"$MESSAGE\" = inherited && test -L local-shell";
    try std.testing.expectEqual(@as(u8, 0), try childStatus("local-shell", &.{ "-c", script }, &.{ env_path, "MESSAGE=inherited" }, path));
    try std.testing.expectEqual(@as(u8, 0), try childStatus("local-shell", &.{ "-c", script }, &.{ "PATH=", "MESSAGE=inherited" }, path));
    try std.testing.expectEqual(@as(u8, 127), try childStatus("missing-shell", &.{}, &.{env_path}, path));
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "not-executable", .data = "plain text" });
    try std.testing.expectEqual(@as(u8, 126), try childStatus("not-executable", &.{}, &.{env_path}, path));
}
