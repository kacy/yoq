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

fn containerFromSaved(id: []const u8, cfg: *const run_state.SavedRunConfig, mirror_output: bool, local_name: ?[]const u8) container.Container {
    const net_config: ?net_setup.NetworkConfig = if (cfg.network_enabled)
        .{ .port_maps = cfg.port_maps, .network_name = cfg.network_name, .dns_name = local_name orelse id }
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
            .shm_size = cfg.shm_size,
            .tmpfs_mounts = cfg.tmpfs_mounts,
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

const StartupConfig = struct {
    value: run_state.SavedRunConfig,
    transition: ?control.Lock,
    alloc: std.mem.Allocator,

    fn load(alloc: std.mem.Allocator, id: []const u8) !StartupConfig {
        const transition = try control.lock(id, .transition, true);
        errdefer transition.deinit();
        return .{ .value = try run_state.loadConfig(alloc, id), .transition = transition, .alloc = alloc };
    }

    fn releaseTransition(self: *StartupConfig) void {
        if (self.transition) |lock| lock.deinit();
        self.transition = null;
    }

    fn deinit(self: *StartupConfig) void {
        self.releaseTransition();
        self.value.deinit(self.alloc);
    }
};

fn superviseGeneration(id: []const u8, cfg: *const run_state.SavedRunConfig, attach: bool, generation: i64) u8 {
    const owner = acquireOwner(id, generation) catch return 255;
    defer owner.deinit();
    defer control.finish(id, generation) catch {};
    var startup_acknowledged = false;
    defer if (!startup_acknowledged) {
        // setup can fail before an execution attempt exists (session socket,
        // channels, or orphan cleanup). do not leave its caller waiting on a
        // pending outcome, and do not overwrite a newer generation's launch.
        if ((control.currentGeneration(id) catch null) == generation)
            store.recordStartupFailure(id) catch {};
    };
    @import("../../local_health.zig").cleanupOrphans(id) catch return 255;
    var backoff_ms: u32 = 1000;
    var first_start = true;
    var restart_count: u32 = 0;
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
        // update and stop use this lock too. read the effective configuration
        // after acquiring it and retain the lock through PID publication.
        var startup_config = StartupConfig.load(std.heap.page_allocator, id) catch return 255;
        defer startup_config.deinit();
        const current_cfg = &startup_config.value;
        var ports = @import("../../../network/port_allocator.zig").hold(current_cfg.port_maps) catch |err| {
            store.recordStartupFailure(id) catch {};
            var error_buf: [192]u8 = undefined;
            const message = std.fmt.bufPrint(&error_buf, "published port is unavailable: {}\n", .{err}) catch "published port unavailable\n";
            session.Server.output(&server, "stderr", message);
            return 255;
        };
        defer ports.deinit();
        var channels = session.ProcessIo.init(current_cfg.interactive, current_cfg.tty) catch return 255;
        defer channels.deinit();
        var monitor: ?*@import("../../local_health.zig").Monitor = null;
        const local_name = control.nameForId(std.heap.page_allocator, id) catch return 255;
        defer if (local_name) |name| std.heap.page_allocator.free(name);
        var c = containerFromSaved(id, current_cfg, false, local_name);
        c.config.session_io = &channels;
        c.config.session_output = .{ .context = &server, .write = session.Server.output };
        server.prepareChild(&channels);
        defer server.childStarted();
        {
            // stop takes this same lock before changing the requested state.
            // it either cancels this attempt or observes its published pid.
            if (!(control.shouldRun(id, generation) catch return 255)) return last_exit;
            store.updateStatus(id, "created", null, null) catch return 255;
            c.start() catch |err| {
                // startup rollback may have retained resources for cleanup.
                store.recordStartupFailure(id) catch {};
                var error_buf: [256]u8 = undefined;
                const message = std.fmt.bufPrint(&error_buf, "failed to start container: {}\n", .{err}) catch "failed to start container\n";
                session.Server.output(&server, "stderr", message);
                return 255;
            };
            if (!first_start) {
                restart_count +|= 1;
                control.countRestart(id, generation) catch {};
            }
            server.childStarted();
            server.setInput(&channels, c.pid.?);
            monitor = @import("../../local_health.zig").Monitor.start(id, c.pid.?, generation, current_cfg) catch |err| {
                c.forceStop() catch {};
                _ = c.wait() catch 255;
                store.recordStartupFailure(id) catch {};
                writeErr("failed to start container healthcheck: {}\n", .{err});
                return 255;
            };
            if (first_start) {
                store.setStartupOutcome(id, .succeeded) catch |err| {
                    c.forceStop() catch {};
                    _ = c.wait() catch 255;
                    if (monitor) |worker| worker.stop() catch {};
                    writeErr("failed to record container startup: {}\n", .{err});
                    return 255;
                };
                startup_acknowledged = true;
            }
        }
        startup_config.releaseTransition();

        last_exit = c.wait() catch 255;
        if (monitor) |worker| worker.stop() catch |err| {
            store.updateStatus(id, "cleanup_failed", null, last_exit) catch {};
            writeErr("failed to stop container healthcheck: {}\n", .{err});
            return last_exit;
        };
        server.clearInput();
        // attached callers observe this attempt's exit, even if policy restarts it.
        server.finish(last_exit);
        // the writable layer belongs to the container, not this process run.
        // failed teardown retains its handles and must never be overwritten.
        if (c.runtime.cgroup != null or c.net_info != null) return last_exit;
        const policy_cfg = run_state.loadConfig(std.heap.page_allocator, id) catch return 255;
        defer policy_cfg.deinit(std.heap.page_allocator);
        if (!shouldRestart(policy_cfg.restart_policy, last_exit)) break;
        if (policy_cfg.restart_policy == .on_failure) {
            if (policy_cfg.restart_max_retries) |limit| if (restart_count >= limit) break;
        }
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
    _ = try spawnSupervisorWithAttach(io, alloc, id, false);
}

pub fn spawnAttachedSupervisor(io: std.Io, alloc: std.mem.Allocator, id: []const u8) ContainerError!i64 {
    return spawnSupervisorWithAttach(io, alloc, id, true);
}

fn spawnSupervisorWithAttach(io: std.Io, alloc: std.mem.Allocator, id: []const u8, attach: bool) ContainerError!i64 {
    control.ensureRegistered(id) catch return ContainerError.ConfigSaveFailed;
    const generation = control.request(id, true) catch return ContainerError.ConfigSaveFailed;
    errdefer control.finish(id, generation) catch {};
    const exe_path = readSelfExePathAlloc(io, alloc) catch return ContainerError.OutOfMemory;
    defer alloc.free(exe_path);
    var generation_buf: [32]u8 = undefined;
    const generation_text = std.fmt.bufPrint(&generation_buf, "{d}", .{generation}) catch return ContainerError.ConfigSaveFailed;
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
    return generation;
}

pub fn stopProcess(pid: i32) ContainerError!void {
    return stopProcessWithOptions(pid, 15, 5);
}

pub fn stopProcessWithOptions(pid: i32, signal: u8, timeout_seconds: u32) ContainerError!void {
    if (process.hasExited(pid)) return;
    process.sendSignal(pid, signal) catch |err| {
        if (process.hasExited(pid)) return;
        writeErr("failed to stop container process: {}\n", .{err});
        return ContainerError.ProcessNotFound;
    };

    var attempts: usize = 0;
    while (attempts < @as(u64, timeout_seconds) * 20) : (attempts += 1) {
        if (process.hasExited(pid)) return;
        if (process.sendSignal(pid, 0)) |_| {
            if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(50), "container process terminate wait")) break;
        } else |_| {
            return;
        }
    }

    process.kill(pid) catch {};

    attempts = 0;
    while (attempts < 40) : (attempts += 1) {
        if (process.hasExited(pid)) return;
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
    if (cfg.auto_remove) {
        @import("../../local_lifecycle.zig").removeAutomatic(id, alloc, generation) catch |err| {
            writeErr("automatic removal failed for {s}: {}\n", .{ id, err });
        };
    }
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

test "standalone DNS uses saved names and IDs independently of the UTS hostname" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    try control.register("0123456789ab", "web");
    try control.register("abcdef012345", null);
    const cfg: run_state.SavedRunConfig = .{ .rootfs = "/", .command = "/bin/sh", .hostname = "custom-hostname", .working_dir = "/", .args = &.{}, .env = &.{}, .lower_dirs = &.{}, .mounts = &.{}, .network_enabled = true, .port_maps = &.{}, .limits = .{}, .restart_policy = .no };
    for ([_][]const u8{ "0123456789ab", "abcdef012345" }, [_][]const u8{ "web", "abcdef012345" }) |id, expected| {
        const local_name = try control.nameForId(alloc, id);
        defer if (local_name) |name| alloc.free(name);
        const instance = containerFromSaved(id, &cfg, false, local_name);
        try std.testing.expectEqualStrings(expected, instance.config.network.?.dns_name.?);
        try std.testing.expectEqualStrings("custom-hostname", instance.config.hostname);
    }
}

test "startup reads resource updates after acquiring the transition lock" {
    var random: [6]u8 = undefined;
    @import("linux_platform").randomBytes(&random);
    const id = std.fmt.bytesToHex(random, .lower);
    var config: run_state.SavedRunConfig = .{
        .rootfs = "/fixture",
        .command = "/bin/sh",
        .hostname = "update-test",
        .working_dir = "/",
        .args = &.{},
        .env = &.{},
        .lower_dirs = &.{},
        .mounts = &.{},
        .network_enabled = false,
        .port_maps = &.{},
        .limits = .{ .memory_max = 64 * 1024 * 1024 },
        .restart_policy = .no,
    };
    try run_state.saveConfig(&id, config);
    defer run_state.removeConfig(&id);
    const Loader = struct {
        id: []const u8,
        started: std.atomic.Value(bool) = .init(false),
        finished: std.atomic.Value(bool) = .init(false),
        memory_max: ?u64 = null,
        retries: ?u32 = null,
        failed: bool = false,

        fn run(self: *@This()) void {
            self.started.store(true, .release);
            var startup = StartupConfig.load(std.heap.page_allocator, self.id) catch {
                self.failed = true;
                self.finished.store(true, .release);
                return;
            };
            defer startup.deinit();
            self.memory_max = startup.value.limits.memory_max;
            self.retries = startup.value.restart_max_retries;
            self.finished.store(true, .release);
        }
    };
    var loader: Loader = .{ .id = &id };
    var transition: ?control.Lock = try control.lock(&id, .transition, true);
    var worker: ?std.Thread = null;
    defer {
        if (transition) |lock| lock.deinit();
        if (worker) |thread| thread.join();
    }
    worker = try std.Thread.spawn(.{}, Loader.run, .{&loader});
    while (!loader.started.load(.acquire)) try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
    try std.Io.sleep(std.testing.io, .fromMilliseconds(25), .awake);
    try std.testing.expect(!loader.finished.load(.acquire));
    config.limits.memory_max = 128 * 1024 * 1024;
    config.restart_policy = .on_failure;
    config.restart_max_retries = 2;
    try run_state.saveConfig(&id, config);
    transition.?.deinit();
    transition = null;
    worker.?.join();
    worker = null;
    try std.testing.expect(!loader.failed);
    try std.testing.expectEqual(@as(?u64, 128 * 1024 * 1024), loader.memory_max);
    try std.testing.expectEqual(@as(?u32, 2), loader.retries);
}
