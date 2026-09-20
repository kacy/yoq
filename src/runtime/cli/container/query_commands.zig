const std = @import("std");
const cli = @import("../../../lib/cli.zig");
const json_out = @import("../../../lib/json_output.zig");
const store = @import("../../../state/store.zig");
const logs = @import("../../logs.zig");
const exec = @import("../../exec.zig");
const run_state = @import("../../run_state.zig");
const state_support = @import("state_support.zig");
const common = @import("common.zig");
const environment = @import("environment.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const ContainerError = common.ContainerError;

fn psJson(alloc: std.mem.Allocator, ids: []const []const u8) void {
    var w = json_out.JsonWriter{};
    w.beginArray();

    for (ids) |id| {
        const record = store.load(alloc, id) catch continue;
        defer record.deinit(alloc);

        const status = state_support.reconcileLiveness(id, record.status, record.pid);

        w.beginObject();
        w.stringField("id", id);
        w.stringField("name", record.hostname);
        w.stringField("status", status);
        if (record.ip_address) |addr| {
            w.stringField("ip", addr);
        } else {
            w.nullField("ip");
        }
        w.stringField("command", record.command);
        if (record.pid) |pid| {
            w.intField("pid", pid);
        } else {
            w.nullField("pid");
        }
        w.intField("created_at", record.created_at);
        w.endObject();
    }

    w.endArray();
    w.flush();
}

pub fn ps(alloc: std.mem.Allocator) !void {
    var ids = store.listIds(alloc) catch |err| {
        writeErr("failed to list containers: {}\n", .{err});
        return ContainerError.StoreError;
    };
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    if (cli.output_mode == .json) {
        psJson(alloc, ids.items);
        return;
    }

    if (ids.items.len == 0) {
        write("no containers\n", .{});
        return;
    }

    write("{s:<14} {s:<10} {s:<16} {s:<24} {s:<20}\n", .{ "CONTAINER ID", "STATUS", "IP", "NAME", "COMMAND" });
    for (ids.items) |id| {
        const record = store.load(alloc, id) catch |err| {
            write("{s:<14} {s:<10} {s:<16} {s:<24} {s:<20}\n", .{ id, @errorName(err), "-", "-", "-" });
            continue;
        };
        defer record.deinit(alloc);

        const status = state_support.reconcileLiveness(id, record.status, record.pid);
        const ip_display: []const u8 = record.ip_address orelse "-";
        write("{s:<14} {s:<10} {s:<16} {s:<24} {s:<20}\n", .{ id, status, ip_display, record.hostname, record.command });
    }
}

const ExecFlags = struct {
    reference: []const u8 = "",
    command: []const u8 = "",
    args: std.ArrayList([]const u8) = .empty,
    env: std.ArrayList([]const u8) = .empty,
    user: ?[]const u8 = null,
    working_dir: ?[]const u8 = null,
    interactive: bool = false,
    tty: bool = false,

    fn deinit(self: *ExecFlags, alloc: std.mem.Allocator) void {
        self.args.deinit(alloc);
        for (self.env.items) |entry| alloc.free(entry);
        self.env.deinit(alloc);
    }
};

fn execUsage() ContainerError {
    writeErr("usage: yoq exec [-i] [-t] [-e NAME[=VALUE]] [-u USER[:GROUP]] [-w /PATH] <container-id|name> <command> [args...]\n", .{});
    return ContainerError.InvalidArgument;
}

fn execOptionValue(args: anytype, option: []const u8, inline_value: ?[]const u8) ContainerError![]const u8 {
    return inline_value orelse args.next() orelse {
        writeErr("{s} requires a value\n", .{option});
        return ContainerError.InvalidArgument;
    };
}

fn parseExecFlags(args: anytype, alloc: std.mem.Allocator) ContainerError!ExecFlags {
    var flags: ExecFlags = .{};
    errdefer flags.deinit(alloc);
    while (args.next()) |raw| {
        if (std.mem.eql(u8, raw, "--")) {
            flags.reference = args.next() orelse return execUsage();
            break;
        }
        if (!std.mem.startsWith(u8, raw, "-")) {
            flags.reference = raw;
            break;
        }
        const equals = if (std.mem.startsWith(u8, raw, "--")) std.mem.indexOfScalar(u8, raw, '=') else null;
        const option = if (equals) |i| raw[0..i] else raw;
        const inline_value = if (equals) |i| raw[i + 1 ..] else null;
        if (std.mem.eql(u8, option, "-e") or std.mem.eql(u8, option, "--env")) {
            try environment.append(alloc, &flags.env, try execOptionValue(args, option, inline_value));
        } else if (std.mem.eql(u8, option, "-u") or std.mem.eql(u8, option, "--user")) {
            const value = try execOptionValue(args, option, inline_value);
            @import("../../identity.zig").validate(value) catch return ContainerError.InvalidArgument;
            flags.user = value;
        } else if (std.mem.eql(u8, option, "-w") or std.mem.eql(u8, option, "--workdir")) {
            const value = try execOptionValue(args, option, inline_value);
            if (value.len == 0 or value[0] != '/' or std.mem.indexOfScalar(u8, value, 0) != null) {
                writeErr("working directory must be an absolute container path\n", .{});
                return ContainerError.InvalidArgument;
            }
            flags.working_dir = value;
        } else if (std.mem.eql(u8, raw, "-i") or std.mem.eql(u8, raw, "--interactive")) {
            flags.interactive = true;
        } else if (std.mem.eql(u8, raw, "-t") or std.mem.eql(u8, raw, "--tty")) {
            flags.tty = true;
        } else if (std.mem.eql(u8, raw, "-it") or std.mem.eql(u8, raw, "-ti")) {
            flags.interactive = true;
            flags.tty = true;
        } else {
            writeErr("unknown exec option: {s}\n", .{raw});
            return ContainerError.InvalidArgument;
        }
    }
    if (flags.reference.len == 0) return execUsage();
    flags.command = args.next() orelse return execUsage();
    if (flags.command.len == 0) return execUsage();
    // everything after the container reference belongs to the command.
    while (args.next()) |arg| try flags.args.append(alloc, arg);
    return flags;
}

// only env is newly allocated. the remaining settings borrow flags or saved
// configuration, and no per-exec override is written back to the container.
fn buildExecConfig(alloc: std.mem.Allocator, flags: *const ExecFlags, pid: std.posix.pid_t, id: []const u8, saved: ?run_state.SavedRunConfig) !exec.ExecConfig {
    return .{
        .pid = pid,
        .command = flags.command,
        .args = flags.args.items,
        .env = try environment.merge(alloc, if (saved) |config| config.env else &.{}, flags.env.items),
        .working_dir = flags.working_dir orelse if (saved) |config| config.working_dir else "/",
        .user = if (flags.user) |user| user else if (saved) |config| config.user else null,
        .cgroup_id = id,
        .interactive = flags.interactive,
        .tty = flags.tty,
    };
}

pub fn exec_cmd(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var flags = try parseExecFlags(args, alloc);
    defer flags.deinit(alloc);
    const id = flags.reference;

    const record = state_support.resolveContainerRef(alloc, id) catch |e| return e;
    defer record.deinit(alloc);

    if (!std.mem.eql(u8, record.status, "running")) {
        writeErr("container {s} is not running (status: {s})\n", .{ id, record.status });
        return ContainerError.InvalidStatus;
    }

    const pid = state_support.currentOwnedRunningPid(&record) orelse {
        writeErr("container {s} is not running (status: stopped)\n", .{id});
        return ContainerError.ProcessNotFound;
    };

    const saved = loadExecConfig(alloc, &record) catch |err| {
        writeErr("failed to load process configuration for {s}: {}\n", .{ id, err });
        return ContainerError.StoreError;
    };
    defer if (saved) |config| config.deinit(alloc);

    const exec_config = try buildExecConfig(alloc, &flags, pid, record.id, saved);
    defer environment.free(alloc, exec_config.env);
    const exit_code = exec.execInContainer(exec_config) catch |err| {
        writeErr("failed to exec in container {s}: {}\n", .{ id, err });
        return ContainerError.ProcessNotFound;
    };

    std.process.exit(exit_code);
}

fn loadExecConfig(alloc: std.mem.Allocator, record: *const store.ContainerRecord) !?run_state.SavedRunConfig {
    return run_state.loadConfig(alloc, record.id) catch |err| {
        if (err != error.NotFound) return err;
        // managed and legacy owners may have no saved settings. a known
        // standalone container must retain its configured user and environment.
        if (try @import("../../container_lifecycle.zig").isStandalone(alloc, record)) return err;
        return null;
    };
}

pub fn log(args: *std.process.Args.Iterator, io: std.Io, alloc: std.mem.Allocator) !void {
    const ref = cli.requireArg(args, "usage: yoq logs <container-id|name> [--tail N] [-f]\n");
    const record = try state_support.resolveContainerRef(alloc, ref);
    defer record.deinit(alloc);

    var tail_lines: ?usize = null;
    var follow = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--tail")) {
            const n_str = args.next() orelse {
                writeErr("--tail requires a number\n", .{});
                std.process.exit(1);
            };
            tail_lines = std.fmt.parseInt(usize, n_str, 10) catch {
                writeErr("invalid number: {s}\n", .{n_str});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--follow")) {
            follow = true;
        } else {
            writeErr("unknown logs option: {s}\n", .{arg});
            return ContainerError.InvalidArgument;
        }
    }

    if (follow) {
        logs.followLogsWithIo(io, record.id, tail_lines, record.pid) catch |err| {
            writeErr("failed to follow logs for container: {s} ({})\n", .{ record.id, err });
            std.process.exit(1);
        };
        return;
    }

    logs.streamLogsWithIo(io, record.id, tail_lines) catch |err| {
        writeErr("failed to read logs for container: {s} ({})\n", .{ record.id, err });
        return ContainerError.StoreError;
    };
}

pub fn attach_cmd(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var interactive = true;
    var reference = args.next() orelse return ContainerError.InvalidArgument;
    if (std.mem.eql(u8, reference, "--no-stdin")) {
        interactive = false;
        reference = args.next() orelse return ContainerError.InvalidArgument;
    }
    if (args.next() != null) return ContainerError.InvalidArgument;
    const record = try state_support.resolveContainerRef(alloc, reference);
    defer record.deinit(alloc);
    if (!std.mem.eql(u8, record.status, "running") and !std.mem.eql(u8, record.status, "restarting")) return ContainerError.InvalidStatus;
    const code = @import("../../session.zig").attach(record.id, interactive) catch |err| {
        writeErr("failed to attach to {s}: {}\n", .{ reference, err });
        return ContainerError.ProcessNotFound;
    };
    std.process.exit(code);
}

test "exec rejects missing standalone settings and preserves managed defaults" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    const control = @import("../../local_control.zig");
    var id: [12]u8 = undefined;
    try @import("../../container.zig").generateId(&id);
    var record: store.ContainerRecord = .{
        .id = &id,
        .rootfs = "/fixture",
        .command = "serve",
        .hostname = "web",
        .status = "running",
        .pid = 42,
        .exit_code = null,
        .created_at = 0,
    };

    try std.testing.expect((try loadExecConfig(alloc, &record)) == null);
    try control.register(&id, null);
    try std.testing.expectError(error.NotFound, loadExecConfig(alloc, &record));

    // an app owner remains authoritative over older standalone registration.
    record.app_name = "managed-app";
    try std.testing.expect((try loadExecConfig(alloc, &record)) == null);
}

const TestArgs = struct {
    values: []const []const u8,
    index: usize = 0,

    fn next(self: *TestArgs) ?[]const u8 {
        if (self.index == self.values.len) return null;
        defer self.index += 1;
        return self.values[self.index];
    }
};

test "exec parses local overrides and preserves command arguments" {
    const alloc = std.testing.allocator;
    var args: TestArgs = .{ .values = &.{ "-it", "-e", "A=first", "--env=A=last=literal", "-u", "1000:1001", "--user=app:staff", "-w", "/first", "--workdir=/work", "web", "sh", "-c", "printf %s \"$A\"", "--env=command-argument", "--", "" } };
    var flags = try parseExecFlags(&args, alloc);
    defer flags.deinit(alloc);
    try std.testing.expect(flags.interactive and flags.tty);
    try std.testing.expectEqualStrings("web", flags.reference);
    try std.testing.expectEqualStrings("sh", flags.command);
    try std.testing.expectEqualStrings("app:staff", flags.user.?);
    try std.testing.expectEqualStrings("/work", flags.working_dir.?);
    try std.testing.expectEqualStrings("A=first", flags.env.items[0]);
    try std.testing.expectEqualStrings("A=last=literal", flags.env.items[1]);
    try std.testing.expectEqual(@as(usize, 5), flags.args.items.len);
    for (args.values[12..], flags.args.items) |expected, actual| try std.testing.expectEqualStrings(expected, actual);

    var delimited: TestArgs = .{ .values = &.{ "--interactive", "--tty", "--", "web", "--command", "-u", "root" } };
    var explicit = try parseExecFlags(&delimited, alloc);
    defer explicit.deinit(alloc);
    try std.testing.expect(explicit.interactive and explicit.tty);
    try std.testing.expectEqualStrings("web", explicit.reference);
    try std.testing.expectEqualStrings("--command", explicit.command);
    try std.testing.expectEqual(@as(usize, 2), explicit.args.items.len);
    for (delimited.values[5..], explicit.args.items) |expected, actual| try std.testing.expectEqualStrings(expected, actual);
}

test "exec rejects invalid options before resolving a container" {
    for ([_][]const []const u8{
        &.{},
        &.{"web"},
        &.{ "web", "" },
        &.{"--"},
        &.{"-e"},
        &.{"--user"},
        &.{"--workdir"},
        &.{ "-e", "A=allocated", "--unknown", "web", "sh" },
        &.{ "--tty=false", "web", "sh" },
        &.{ "--interactive=true", "web", "sh" },
        &.{ "--env=", "web", "sh" },
        &.{ "--env==value", "web", "sh" },
        &.{ "--env=BAD NAME=value", "web", "sh" },
        &.{ "--user=", "web", "sh" },
        &.{ "--user=app:", "web", "sh" },
        &.{ "--user=app:staff:extra", "web", "sh" },
        &.{ "--workdir=", "web", "sh" },
        &.{ "--workdir=relative", "web", "sh" },
    }) |values| {
        var args: TestArgs = .{ .values = values };
        try std.testing.expectError(ContainerError.InvalidArgument, parseExecFlags(&args, std.testing.allocator));
    }
}

test "exec overrides leave saved process defaults unchanged" {
    const alloc = std.testing.allocator;
    var saved_env = [_][]const u8{ "A=saved", "B=keep" };
    const saved: run_state.SavedRunConfig = .{
        .rootfs = "/fixture",
        .command = "serve",
        .hostname = "web",
        .working_dir = "/original",
        .user = "app:staff",
        .args = &.{},
        .env = &saved_env,
        .lower_dirs = &.{},
        .mounts = &.{},
        .network_enabled = false,
        .port_maps = &.{},
        .limits = .{},
        .restart_policy = .no,
    };
    var args: TestArgs = .{ .values = &.{ "--env=A=override", "--env=EMPTY=", "--user=0:0", "--workdir=/temporary", "web", "sh" } };
    var flags = try parseExecFlags(&args, alloc);
    defer flags.deinit(alloc);
    const overridden = try buildExecConfig(alloc, &flags, 42, "0123456789ab", saved);
    defer environment.free(alloc, overridden.env);
    try std.testing.expectEqualStrings("A=override", overridden.env[0]);
    try std.testing.expectEqualStrings("B=keep", overridden.env[1]);
    try std.testing.expectEqualStrings("EMPTY=", overridden.env[2]);
    try std.testing.expectEqualStrings("0:0", overridden.user.?);
    try std.testing.expectEqualStrings("/temporary", overridden.working_dir);

    const defaults = try buildExecConfig(alloc, &.{ .command = "sh" }, 42, "0123456789ab", saved);
    defer environment.free(alloc, defaults.env);
    try std.testing.expectEqualStrings("A=saved", saved.env[0]);
    try std.testing.expectEqualStrings("A=saved", defaults.env[0]);
    try std.testing.expectEqualStrings("app:staff", defaults.user.?);
    try std.testing.expectEqualStrings("/original", defaults.working_dir);
    try std.testing.expectEqual(@as(usize, 2), defaults.env.len);

    const legacy = try buildExecConfig(alloc, &.{ .command = "sh" }, 42, "0123456789ab", null);
    defer environment.free(alloc, legacy.env);
    try std.testing.expectEqual(@as(usize, 0), legacy.env.len);
    try std.testing.expect(legacy.user == null);
    try std.testing.expectEqualStrings("/", legacy.working_dir);
}

fn checkExecFlagAllocations(alloc: std.mem.Allocator) !void {
    var args: TestArgs = .{ .values = &.{ "-e", "A=one", "-e", "B=two", "web", "sh", "-c", "echo done" } };
    var flags = try parseExecFlags(&args, alloc);
    defer flags.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), flags.env.items.len);
    try std.testing.expectEqual(@as(usize, 2), flags.args.items.len);
}

test "exec option allocation failures release owned environment entries" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkExecFlagAllocations, .{});
}

test "exec environment uses host values and removes unset inherited names" {
    const host_path = std.c.getenv("PATH") orelse return error.SkipZigTest;
    const unset_name = "YOQ_EXEC_TEST_UNSET_6f02ad9ce087";
    if (std.c.getenv(unset_name) != null) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    var args: TestArgs = .{ .values = &.{ "-e", "PATH", "-e", unset_name, "web", "sh" } };
    var flags = try parseExecFlags(&args, alloc);
    defer flags.deinit(alloc);
    const merged = try environment.merge(alloc, &.{ "PATH=/original", unset_name ++ "=inherited" }, flags.env.items);
    defer environment.free(alloc, merged);
    try std.testing.expectEqual(@as(usize, 1), merged.len);
    try std.testing.expect(std.mem.startsWith(u8, merged[0], "PATH="));
    try std.testing.expectEqualStrings(std.mem.span(host_path), merged[0][5..]);
}
