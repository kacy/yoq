const std = @import("std");
const container = @import("../../container.zig");
const process = @import("../../process.zig");
const run_state = @import("../../run_state.zig");
const store = @import("../../../state/store.zig");
const cli = @import("../../../lib/cli.zig");
const net_setup = @import("../../../network/setup.zig");
const common = @import("common.zig");
const control = @import("../../local_control.zig");
const runtime_wait = @import("../../../lib/runtime_wait.zig");
const session = @import("../../session.zig");

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
            .user = cfg.user,
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
        .created_at = std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
        .runtime = .{ .mirror_output = mirror_output },
    };
}

fn shouldRestart(policy: run_state.RestartPolicy, exit_code: u8) bool {
    return switch (policy) {
        .no => false,
        .always, .unless_stopped => true,
        .on_failure => exit_code != 0,
    };
}

pub fn superviseSavedRun(id: []const u8, cfg: *const run_state.SavedRunConfig, attach: bool) u8 {
    const command_lock = control.lock(id, .command, true) catch return 255;
    control.ensureRegistered(id) catch {
        command_lock.deinit();
        return 255;
    };
    const generation = control.request(id, true) catch {
        command_lock.deinit();
        return 255;
    };
    command_lock.deinit();
    return superviseGeneration(id, cfg, attach, generation);
}

fn acquireOwner(id: []const u8, generation: i64) !control.Lock {
    while (try control.shouldRun(id, generation)) {
        return control.lock(id, .owner, false) catch |err| switch (err) {
            error.Busy => {
                if (!runtime_wait.sleep(.fromMilliseconds(50), "waiting for container owner")) return error.Cancelled;
                continue;
            },
            else => return err,
        };
    }
    return error.StaleGeneration;
}

fn superviseGeneration(id: []const u8, cfg: *const run_state.SavedRunConfig, attach: bool, generation: i64) u8 {
    const owner = acquireOwner(id, generation) catch return 255;
    defer owner.deinit();
    defer control.finish(id, generation) catch {};
    var backoff_ms: u32 = 1000;
    var first_start = true;
    var last_exit: u8 = 255;
    var server = session.Server.init(id, cfg.interactive, cfg.tty) catch return 255;
    defer server.deinit();
    defer server.finish(last_exit);
    server.start() catch return 255;
    if (attach) {
        var attempts: usize = 0;
        while (!server.ever_attached.load(.acquire)) : (attempts += 1) {
            if (attempts == 200 or !(control.shouldRun(id, generation) catch return 255)) return 255;
            if (!runtime_wait.sleep(.fromMilliseconds(50), "waiting for foreground session")) return 255;
        }
    }

    while (true) {
        var channels = session.ProcessIo.init(cfg.interactive, cfg.tty) catch return 255;
        defer channels.deinit();
        var c = containerFromSaved(id, cfg, false);
        c.config.session_io = &channels;
        c.config.session_output = .{ .context = &server, .write = session.Server.output };
        server.prepareChild(&channels);
        defer server.childStarted();
        {
            // stop takes this same lock before changing the requested state.
            // it either cancels this attempt or observes its published pid.
            const transition = control.lock(id, .transition, true) catch return 255;
            defer transition.deinit();
            if (!(control.shouldRun(id, generation) catch return 255)) return last_exit;
            store.updateStatus(id, "created", null, null) catch return 255;
            c.start() catch |err| {
                // startup rollback may have retained resources for cleanup.
                store.setStartupOutcome(id, .failed) catch {};
                writeErr("failed to start container: {}\n", .{err});
                return 255;
            };
            server.childStarted();
            server.setInput(&channels, c.pid.?);
            if (first_start) {
                store.setStartupOutcome(id, .succeeded) catch |err| {
                    c.forceStop() catch {};
                    _ = c.wait() catch 255;
                    writeErr("failed to record container startup: {}\n", .{err});
                    return 255;
                };
            }
        }

        last_exit = c.wait() catch 255;
        server.clearInput();
        // the writable layer belongs to the container, not this process run.
        // failed teardown retains its handles and must never be overwritten.
        if (c.runtime.cgroup != null or c.net_info != null) return last_exit;
        if (!shouldRestart(cfg.restart_policy, last_exit)) break;
        if (!(control.shouldRun(id, generation) catch return 255)) break;
        store.updateStatus(id, "restarting", null, last_exit) catch return 255;
        var elapsed: u32 = 0;
        while (elapsed < backoff_ms) : (elapsed += 50) {
            if (!(control.shouldRun(id, generation) catch return 255)) return last_exit;
            if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(50), "container restart backoff")) return last_exit;
        }
        backoff_ms = @min(backoff_ms * 2, 30_000);
        first_start = false;
    }
    return last_exit;
}

pub fn spawnSupervisor(io: std.Io, alloc: std.mem.Allocator, id: []const u8) ContainerError!void {
    return spawnSupervisorWithAttach(io, alloc, id, false);
}

pub fn spawnAttachedSupervisor(io: std.Io, alloc: std.mem.Allocator, id: []const u8) ContainerError!void {
    return spawnSupervisorWithAttach(io, alloc, id, true);
}

fn spawnSupervisorWithAttach(io: std.Io, alloc: std.mem.Allocator, id: []const u8, attach: bool) ContainerError!void {
    control.ensureRegistered(id) catch return ContainerError.ConfigSaveFailed;
    const generation = control.request(id, true) catch return ContainerError.ConfigSaveFailed;
    errdefer control.finish(id, generation) catch {};
    const exe_path = readSelfExePathAlloc(io, alloc) catch return ContainerError.OutOfMemory;
    defer alloc.free(exe_path);
    var generation_buf: [32]u8 = undefined;
    const generation_text = std.fmt.bufPrint(&generation_buf, "{d}", .{generation}) catch unreachable;
    store.setStartupOutcome(id, .pending) catch return ContainerError.ConfigSaveFailed;
    _ = std.process.spawn(io, .{
        .argv = &.{ exe_path, "__run-supervisor", id, generation_text, if (attach) "attach" else "detached" },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch |err| {
        writeErr("failed to spawn detached supervisor: {}\n", .{err});
        return ContainerError.ProcessNotFound;
    };
}

pub fn stopProcess(pid: i32) ContainerError!void {
    return stopProcessWithOptions(pid, 15, 5);
}

pub fn stopProcessWithOptions(pid: i32, signal: u8, timeout_seconds: u32) ContainerError!void {
    process.sendSignal(pid, signal) catch |err| {
        writeErr("failed to stop container process: {}\n", .{err});
        return ContainerError.ProcessNotFound;
    };

    var attempts: usize = 0;
    while (attempts < @as(u64, timeout_seconds) * 20) : (attempts += 1) {
        if (process.sendSignal(pid, 0)) |_| {
            if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(50), "container process terminate wait")) break;
        } else |_| {
            return;
        }
    }

    process.kill(pid) catch {};

    attempts = 0;
    while (attempts < 40) : (attempts += 1) {
        if (process.sendSignal(pid, 0)) |_| {
            if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(50), "container process kill wait")) break;
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
    const generation_text = requireArg(args, "missing supervisor generation\n");
    const generation = std.fmt.parseInt(i64, generation_text, 10) catch return ContainerError.InvalidArgument;
    var cfg = run_state.loadConfig(alloc, id) catch |err| {
        store.recordStartupFailure(id) catch {};
        writeErr("failed to load container config for {s}: {}\n", .{ id, err });
        return ContainerError.ConfigSaveFailed;
    };
    defer cfg.deinit(alloc);

    const mode = args.next() orelse "detached";
    const exit_code = superviseGeneration(id, &cfg, std.mem.eql(u8, mode, "attach"), generation);
    std.process.exit(exit_code);
}

fn readSelfExePathAlloc(io: std.Io, alloc: std.mem.Allocator) ![:0]u8 {
    var size: usize = 256;
    while (size <= 64 * 1024) : (size *= 2) {
        const buffer = try alloc.alloc(u8, size);
        defer alloc.free(buffer);

        const path_len = std.Io.Dir.readLinkAbsolute(io, "/proc/self/exe", buffer) catch |err| switch (err) {
            error.FileNotFound => return error.FileNotFound,
            error.AccessDenied => return error.AccessDenied,
            error.NameTooLong => continue,
            else => return error.Unexpected,
        };
        if (path_len < buffer.len) {
            return alloc.dupeZ(u8, buffer[0..path_len]);
        }
    }
    return error.NameTooLong;
}
