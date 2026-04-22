const std = @import("std");
const container = @import("../../container.zig");
const process = @import("../../process.zig");
const run_state = @import("../../run_state.zig");
const store = @import("../../../state/store.zig");
const cli = @import("../../../lib/cli.zig");
const net_setup = @import("../../../network/setup.zig");
const common = @import("common.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const requireArg = cli.requireArg;
const ContainerError = common.ContainerError;

fn containerFromSaved(id: []const u8, cfg: *const run_state.SavedRunConfig, mirror_output: bool) container.Container {
    const net_config: ?net_setup.NetworkConfig = if (cfg.network_enabled)
        .{ .port_maps = cfg.port_maps }
    else
        null;

    return .{
        .config = .{
            .id = id,
            .rootfs = cfg.rootfs,
            .command = cfg.command,
            .args = cfg.args,
            .env = cfg.env,
            .working_dir = cfg.working_dir,
            .lower_dirs = cfg.lower_dirs,
            .network = net_config,
            .hostname = cfg.hostname,
            .mounts = cfg.mounts,
            .limits = cfg.limits,
            .host_mode = false,
        },
        .status = .created,
        .pid = null,
        .exit_code = null,
        .created_at = @import("compat").timestamp(),
        .runtime = .{ .mirror_output = mirror_output },
    };
}

fn shouldRestart(policy: run_state.RestartPolicy, exit_code: u8) bool {
    return switch (policy) {
        .no => false,
        .always => true,
        .on_failure => exit_code != 0,
    };
}

pub fn superviseSavedRun(id: []const u8, cfg: *const run_state.SavedRunConfig, attach: bool) u8 {
    var backoff_ms: u32 = 1000;
    var first_start = true;
    var last_exit: u8 = 0;

    while (true) {
        store.updateStatus(id, "created", null, null) catch {};

        var c = containerFromSaved(id, cfg, attach);
        c.start() catch |err| {
            store.updateStatus(id, "stopped", null, 255) catch {};
            writeErr("failed to start container: {}\n", .{err});
            return 255;
        };

        if (first_start and attach) {
            write("{s}\n", .{id});
        }

        last_exit = c.wait() catch 255;
        container.cleanupContainerDirs(id);

        if (!shouldRestart(cfg.restart_policy, last_exit)) break;
        if (attach) {
            writeErr("container {s} exited ({d}), restarting in {d}ms...\n", .{ id, last_exit, backoff_ms });
        }
        @import("compat").sleep(@as(u64, backoff_ms) * std.time.ns_per_ms);
        backoff_ms = @min(std.math.mul(u32, backoff_ms, 2) catch 30_000, 30_000);
        first_start = false;
    }

    return last_exit;
}

pub fn spawnSupervisor(alloc: std.mem.Allocator, id: []const u8) ContainerError!void {
    const exe_path = @import("compat").selfExePathAlloc(alloc) catch return ContainerError.OutOfMemory;
    defer alloc.free(exe_path);

    const child = std.process.spawn(@import("compat").io(), .{
        .argv = &.{ exe_path, "__run-supervisor", id },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch |err| {
        writeErr("failed to spawn detached supervisor: {}\n", .{err});
        return ContainerError.ProcessNotFound;
    };

    @import("compat").sleep(100 * std.time.ns_per_ms);

    if (process.sendSignal(child.id orelse return ContainerError.ProcessNotFound, 0)) |_| {
        return;
    } else |_| {
        writeErr("supervisor process exited immediately\n", .{});
        return ContainerError.ProcessNotFound;
    }
}

pub fn stopProcess(pid: i32) ContainerError!void {
    process.terminate(pid) catch |err| {
        writeErr("failed to stop container process: {}\n", .{err});
        return ContainerError.ProcessNotFound;
    };

    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        if (process.sendSignal(pid, 0)) |_| {
            @import("compat").sleep(50 * std.time.ns_per_ms);
        } else |_| {
            return;
        }
    }

    process.kill(pid) catch {};

    attempts = 0;
    while (attempts < 40) : (attempts += 1) {
        if (process.sendSignal(pid, 0)) |_| {
            @import("compat").sleep(50 * std.time.ns_per_ms);
        } else |_| {
            return;
        }
    }

    writeErr("container process {d} did not exit after SIGKILL\n", .{pid});
    return ContainerError.StateUnknown;
}

fn forwardSignal(sig: std.os.linux.SIG) callconv(.c) void {
    const pid = container.active_pid.load(.acquire);
    if (pid > 0) {
        _ = std.os.linux.syscall2(
            .kill,
            @as(usize, @bitCast(@as(isize, pid))),
            @intFromEnum(sig),
        );
    }
}

pub fn installSignalHandlers() void {
    const act = std.posix.Sigaction{
        .handler = .{ .handler = forwardSignal },
        .mask = std.posix.sigemptyset(),
        .flags = @bitCast(@as(u32, 0x10000000)),
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
}

pub fn runSupervisor(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    const id = requireArg(args, "usage: yoq __run-supervisor <container-id>\n");
    var cfg = run_state.loadConfig(alloc, id) catch |err| {
        writeErr("failed to load container config for {s}: {}\n", .{ id, err });
        return ContainerError.ConfigSaveFailed;
    };
    defer cfg.deinit(alloc);

    const exit_code = superviseSavedRun(id, &cfg, false);
    std.process.exit(exit_code);
}
