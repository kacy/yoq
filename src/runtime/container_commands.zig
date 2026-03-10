// container_commands — CLI handlers for container lifecycle operations
//
// run, ps, stop, exec, rm, logs. extracted from main.zig for
// readability — no logic changes.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const cli = @import("../lib/cli.zig");
const json_out = @import("../lib/json_output.zig");
const store = @import("../state/store.zig");
const container = @import("container.zig");
const process = @import("process.zig");
const logs = @import("logs.zig");
const run_state = @import("run_state.zig");
const net_setup = @import("../network/setup.zig");
const ip = @import("../network/ip.zig");
const exec = @import("exec.zig");
const oci = @import("../image/oci.zig");
const image_cmds = @import("../image/commands.zig");
const cgroups = @import("cgroups.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const parsePortMap = cli.parsePortMap;
const parseEnvVar = cli.parseEnvVar;
const parseVolumeMount = cli.parseVolumeMount;
const parseMemorySize = cli.parseMemorySize;
const isValidContainerName = cli.isValidContainerName;
const requireArg = cli.requireArg;

const ContainerError = error{
    InvalidArgument,
    NotSupported,
    ContainerNotFound,
    OutOfMemory,
    ProcessNotFound,
    ContainerRunning,
    InvalidStatus,
    PullFailed,
    CommandResolveFailed,
    ConfigSaveFailed,
    InvalidLimits,
    StoreError,
};

// -- types --

const RunFlags = struct {
    port_maps: std.ArrayList(net_setup.PortMap),
    env: std.ArrayList([]const u8),
    volume_specs: std.ArrayList(cli.VolumeMountSpec),
    networking_enabled: bool,
    container_name: ?[]const u8,
    detach: bool,
    limits: cgroups.ResourceLimits,
    restart_policy: run_state.RestartPolicy,
    target: []const u8,
    user_argv: std.ArrayList([]const u8),
};

// -- helpers --

fn isFilesystemTarget(target: []const u8) bool {
    return std.mem.startsWith(u8, target, "/") or
        std.mem.startsWith(u8, target, "./") or
        std.mem.startsWith(u8, target, "../") or
        std.mem.eql(u8, target, ".") or
        std.mem.eql(u8, target, "..");
}

fn persistStoppedState(record: *const store.ContainerRecord, exit_code: ?u8) void {
    store.updateStatus(record.id, "stopped", null, exit_code) catch {};
}

fn waitForStoppedState(alloc: std.mem.Allocator, id: []const u8) bool {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        const record = store.load(alloc, id) catch {
            std.Thread.sleep(50 * std.time.ns_per_ms);
            continue;
        };
        defer record.deinit(alloc);

        if (std.mem.eql(u8, record.status, "stopped") and record.pid == null) return true;
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }

    return false;
}

/// parse CLI flags for `yoq run`. consumes args up to and including the target,
/// then collects remaining args as user command.
fn parseRunFlags(args: *std.process.ArgIterator, alloc: std.mem.Allocator) ContainerError!RunFlags {
    var port_maps: std.ArrayList(net_setup.PortMap) = .empty;
    var env: std.ArrayList([]const u8) = .empty;
    var volume_specs: std.ArrayList(cli.VolumeMountSpec) = .empty;
    var networking_enabled = true;
    var container_name: ?[]const u8 = null;
    var detach = false;
    var limits: cgroups.ResourceLimits = .{};
    var restart_policy: run_state.RestartPolicy = .no;
    var target: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--name")) {
            const name_val = args.next() orelse {
                writeErr("--name requires a container name\n", .{});
                return ContainerError.InvalidArgument;
            };
            if (!isValidContainerName(name_val)) {
                writeErr("invalid container name: {s}\n", .{name_val});
                writeErr("names must be 1-63 chars, alphanumeric or hyphens, no leading/trailing hyphen\n", .{});
                return ContainerError.InvalidArgument;
            }
            container_name = name_val;
        } else if (std.mem.eql(u8, arg, "-p")) {
            const port_str = args.next() orelse {
                writeErr("-p requires host_port:container_port\n", .{});
                return ContainerError.InvalidArgument;
            };
            const pm = parsePortMap(port_str) orelse {
                writeErr("invalid port mapping: {s}\n", .{port_str});
                return ContainerError.InvalidArgument;
            };
            port_maps.append(alloc, pm) catch return ContainerError.OutOfMemory;
        } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--env")) {
            const env_str = args.next() orelse {
                writeErr("{s} requires KEY=VALUE\n", .{arg});
                return ContainerError.InvalidArgument;
            };
            if (parseEnvVar(env_str) == null) {
                writeErr("invalid env var: {s}\n", .{env_str});
                return ContainerError.InvalidArgument;
            }
            env.append(alloc, env_str) catch return ContainerError.OutOfMemory;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--volume")) {
            const mount_str = args.next() orelse {
                writeErr("{s} requires source:target[:ro]\n", .{arg});
                return ContainerError.InvalidArgument;
            };
            const mount = parseVolumeMount(mount_str) orelse {
                writeErr("invalid volume mount: {s}\n", .{mount_str});
                return ContainerError.InvalidArgument;
            };
            volume_specs.append(alloc, mount) catch return ContainerError.OutOfMemory;
        } else if (std.mem.eql(u8, arg, "--no-net")) {
            networking_enabled = false;
        } else if (std.mem.eql(u8, arg, "--net")) {
            networking_enabled = true;
        } else if (std.mem.eql(u8, arg, "--memory")) {
            const mem_str = args.next() orelse {
                writeErr("--memory requires a size like 256m\n", .{});
                return ContainerError.InvalidArgument;
            };
            limits.memory_max = parseMemorySize(mem_str) orelse {
                writeErr("invalid memory size: {s}\n", .{mem_str});
                return ContainerError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--cpus")) {
            const cpu_str = args.next() orelse {
                writeErr("--cpus requires a number like 2 or 0.5\n", .{});
                return ContainerError.InvalidArgument;
            };
            const cpu_count = std.fmt.parseFloat(f64, cpu_str) catch {
                writeErr("invalid CPU value: {s}\n", .{cpu_str});
                return ContainerError.InvalidArgument;
            };
            if (cpu_count <= 0) {
                writeErr("--cpus must be greater than 0\n", .{});
                return ContainerError.InvalidArgument;
            }
            // add reasonable upper bound to prevent overflow
            if (cpu_count > 1024) {
                writeErr("--cpus exceeds maximum of 1024\n", .{});
                return ContainerError.InvalidArgument;
            }
            limits.cpu_max_usec = @intFromFloat(cpu_count * @as(f64, @floatFromInt(limits.cpu_max_period)));
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--detach")) {
            detach = true;
        } else if (std.mem.eql(u8, arg, "--restart")) {
            const policy_str = args.next() orelse {
                writeErr("--restart requires one of: no, always, on-failure\n", .{});
                return ContainerError.InvalidArgument;
            };
            restart_policy = run_state.RestartPolicy.parse(policy_str) orelse {
                writeErr("invalid restart policy: {s}\n", .{policy_str});
                return ContainerError.InvalidArgument;
            };
        } else {
            target = arg;
            break;
        }
    }

    const run_target = target orelse {
        writeErr("usage: yoq run [--name <name>] [-e KEY=VALUE] [-v source:target[:ro]] [-p host:container] [--memory SIZE] [--cpus N] [-d] [--restart POLICY] [--no-net] <image|rootfs> [command]\n", .{});
        return ContainerError.InvalidArgument;
    };

    // collect user-provided command + args
    var user_argv: std.ArrayList([]const u8) = .empty;
    while (args.next()) |arg| {
        user_argv.append(alloc, arg) catch return ContainerError.OutOfMemory;
    }

    return .{
        .port_maps = port_maps,
        .env = env,
        .volume_specs = volume_specs,
        .networking_enabled = networking_enabled,
        .container_name = container_name,
        .detach = detach,
        .limits = limits,
        .restart_policy = restart_policy,
        .target = run_target,
        .user_argv = user_argv,
    };
}

fn resolveContainerRef(alloc: std.mem.Allocator, ref: []const u8) ContainerError!store.ContainerRecord {
    return store.load(alloc, ref) catch {
        const record = store.findByHostname(alloc, ref) catch |err| {
            writeErr("container not found: {s} ({})", .{ ref, err });
            return ContainerError.ContainerNotFound;
        };
        return record orelse {
            writeErr("container not found: {s}\n", .{ref});
            return ContainerError.ContainerNotFound;
        };
    };
}

fn dupStringList(alloc: std.mem.Allocator, values: []const []const u8) ContainerError![][]const u8 {
    const result = alloc.alloc([]const u8, values.len) catch return ContainerError.OutOfMemory;
    var idx: usize = 0;
    errdefer {
        for (result[0..idx]) |value| alloc.free(value);
        alloc.free(result);
    }
    for (values, 0..) |value, i| {
        result[i] = alloc.dupe(u8, value) catch return ContainerError.OutOfMemory;
        idx += 1;
    }
    return result;
}

fn mergeEnv(alloc: std.mem.Allocator, base_env: []const []const u8, override_env: []const []const u8) ContainerError![][]const u8 {
    var merged: std.ArrayList([]const u8) = .empty;
    defer merged.deinit(alloc);

    for (base_env) |value| {
        merged.append(alloc, value) catch return ContainerError.OutOfMemory;
    }

    for (override_env) |value| {
        const eq = std.mem.indexOfScalar(u8, value, '=') orelse continue;
        const key = value[0..eq];
        var replaced = false;
        for (merged.items) |*existing| {
            const existing_eq = std.mem.indexOfScalar(u8, existing.*, '=') orelse continue;
            if (std.mem.eql(u8, existing.*[0..existing_eq], key)) {
                existing.* = value;
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            merged.append(alloc, value) catch return ContainerError.OutOfMemory;
        }
    }

    return dupStringList(alloc, merged.items);
}

fn buildMounts(alloc: std.mem.Allocator, volume_specs: []const cli.VolumeMountSpec) ContainerError![]container.BindMount {
    if (volume_specs.len == 0) {
        return alloc.alloc(container.BindMount, 0) catch return ContainerError.OutOfMemory;
    }

    const cwd = std.fs.cwd().realpathAlloc(alloc, ".") catch {
        writeErr("failed to resolve current working directory\n", .{});
        return ContainerError.OutOfMemory;
    };
    defer alloc.free(cwd);

    const mounts = alloc.alloc(container.BindMount, volume_specs.len) catch return ContainerError.OutOfMemory;
    var idx: usize = 0;
    errdefer {
        for (mounts[0..idx]) |mount| {
            alloc.free(mount.source);
            alloc.free(mount.target);
        }
        alloc.free(mounts);
    }

    for (volume_specs, 0..) |spec, i| {
        const is_host_path = std.mem.startsWith(u8, spec.source, "/") or
            std.mem.startsWith(u8, spec.source, "./") or
            std.mem.startsWith(u8, spec.source, "../");
        if (!is_host_path) {
            writeErr("volume sources must be host paths: {s}\n", .{spec.source});
            return ContainerError.InvalidArgument;
        }
        if (!std.mem.startsWith(u8, spec.target, "/")) {
            writeErr("volume target must be an absolute container path: {s}\n", .{spec.target});
            return ContainerError.InvalidArgument;
        }

        const source_input = if (std.mem.startsWith(u8, spec.source, "/"))
            alloc.dupe(u8, spec.source) catch return error.OutOfMemory
        else
            std.fs.path.resolve(alloc, &.{ cwd, spec.source }) catch return error.OutOfMemory;
        defer alloc.free(source_input);

        const source = std.fs.cwd().realpathAlloc(alloc, source_input) catch {
            writeErr("volume source must exist and be canonicalizable: {s}\n", .{spec.source});
            return ContainerError.InvalidArgument;
        };

        mounts[i] = .{
            .source = source,
            .target = alloc.dupe(u8, spec.target) catch return error.OutOfMemory,
            .read_only = spec.read_only,
        };
        if (!mounts[i].isSourceAllowed()) {
            writeErr("volume source is not allowed: {s}\n", .{mounts[i].source});
            return ContainerError.InvalidArgument;
        }
        idx += 1;
    }

    return mounts;
}

fn buildSavedRunConfig(
    alloc: std.mem.Allocator,
    flags: *const RunFlags,
    img: *const image_cmds.ImageResolution,
    resolved: *const oci.ResolvedCommand,
) ContainerError!run_state.SavedRunConfig {
    const merged_env = mergeEnv(alloc, img.image_env, flags.env.items) catch |e| return e;
    errdefer {
        for (merged_env) |value| alloc.free(value);
        alloc.free(merged_env);
    }

    return .{
        .rootfs = alloc.dupe(u8, img.rootfs) catch return ContainerError.OutOfMemory,
        .command = alloc.dupe(u8, resolved.command) catch return ContainerError.OutOfMemory,
        .hostname = alloc.dupe(u8, flags.container_name orelse "container") catch return ContainerError.OutOfMemory,
        .working_dir = alloc.dupe(u8, img.working_dir) catch return ContainerError.OutOfMemory,
        .args = dupStringList(alloc, resolved.args.items) catch |e| return e,
        .env = merged_env,
        .lower_dirs = dupStringList(alloc, img.layer_paths) catch |e| return e,
        .mounts = buildMounts(alloc, flags.volume_specs.items) catch |e| return e,
        .network_enabled = flags.networking_enabled,
        .port_maps = alloc.dupe(net_setup.PortMap, flags.port_maps.items) catch return ContainerError.OutOfMemory,
        .limits = flags.limits,
        .restart_policy = flags.restart_policy,
    };
}

fn saveCreatedRecord(id: []const u8, cfg: *const run_state.SavedRunConfig) ContainerError!void {
    store.save(.{
        .id = id,
        .rootfs = cfg.rootfs,
        .command = cfg.command,
        .hostname = cfg.hostname,
        .status = "created",
        .pid = null,
        .exit_code = null,
        .created_at = std.time.timestamp(),
    }) catch |err| {
        writeErr("failed to save container state: {}\n", .{err});
        return ContainerError.ConfigSaveFailed;
    };
}

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
            .host_mode = false, // auto-detected at runtime based on capability restrictions
        },
        .status = .created,
        .pid = null,
        .exit_code = null,
        .created_at = std.time.timestamp(),
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

fn superviseSavedRun(id: []const u8, cfg: *const run_state.SavedRunConfig, attach: bool) u8 {
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
        std.Thread.sleep(@as(u64, backoff_ms) * std.time.ns_per_ms);
        // use saturating multiplication to prevent overflow
        backoff_ms = @min(std.math.mul(u32, backoff_ms, 2) catch 30_000, 30_000);
        first_start = false;
    }

    return last_exit;
}

fn spawnSupervisor(alloc: std.mem.Allocator, id: []const u8) ContainerError!void {
    const exe_path = std.fs.selfExePathAlloc(alloc) catch return ContainerError.OutOfMemory;
    defer alloc.free(exe_path);

    var child = std.process.Child.init(&.{ exe_path, "__run-supervisor", id }, alloc);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    child.spawn() catch |err| {
        writeErr("failed to spawn detached supervisor: {}\n", .{err});
        return ContainerError.ProcessNotFound;
    };

    // don't wait for the supervisor - it should daemonize itself
    // but we do need to ensure it didn't immediately fail
    std.Thread.sleep(100 * std.time.ns_per_ms);

    // check if process is still running (signal 0 is no-op check)
    if (process.sendSignal(child.id, 0)) |_| {
        // process exists, detach from it so it continues running
        _ = child.wait() catch {};
    } else |_| {
        // process already exited - something went wrong
        writeErr("supervisor process exited immediately\n", .{});
        return ContainerError.ProcessNotFound;
    }
}

fn waitForContainerStart(alloc: std.mem.Allocator, id: []const u8) ContainerError!void {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        const record = store.load(alloc, id) catch {
            std.Thread.sleep(50 * std.time.ns_per_ms);
            continue;
        };
        defer record.deinit(alloc);

        if (std.mem.eql(u8, record.status, "running") and record.pid != null) return;
        if (std.mem.eql(u8, record.status, "stopped")) {
            writeErr("failed to start detached container\n", .{});
            return ContainerError.ProcessNotFound;
        }

        std.Thread.sleep(50 * std.time.ns_per_ms);
    }

    writeErr("timed out waiting for container start\n", .{});
    return ContainerError.ProcessNotFound;
}

fn stopProcess(pid: i32) ContainerError!void {
    process.terminate(pid) catch |err| {
        writeErr("failed to stop container process: {}\n", .{err});
        return ContainerError.ProcessNotFound;
    };

    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        if (process.sendSignal(pid, 0)) |_| {
            std.Thread.sleep(50 * std.time.ns_per_ms);
        } else |_| {
            return;
        }
    }

    process.kill(pid) catch {};
}

/// signal handler that forwards SIGINT/SIGTERM to the active container process.
/// only async-signal-safe operations: atomic load + kill syscall.
fn forwardSignal(sig: c_int) callconv(.c) void {
    const pid = container.active_pid.load(.acquire);
    if (pid > 0) {
        _ = std.os.linux.syscall2(
            .kill,
            @as(usize, @bitCast(@as(isize, pid))),
            @intCast(sig),
        );
    }
}

/// install SIGINT and SIGTERM handlers that forward to the container.
fn installSignalHandlers() void {
    const act = std.posix.Sigaction{
        .handler = .{ .handler = forwardSignal },
        .mask = std.posix.sigemptyset(),
        .flags = @bitCast(@as(u32, 0x10000000)), // SA_RESTART
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
}

/// full cleanup for a stopped container: network, logs, dirs, then DB record.
/// DB record is removed last so we can still find orphaned resources if
/// an earlier cleanup step fails.
pub fn cleanupStoppedContainer(id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    cleanupNetwork(id, ip_address, veth_host);
    logs.deleteLogFile(id);
    container.cleanupContainerDirs(id);
    run_state.removeConfig(id);
    store.remove(id) catch |e| {
        writeErr("warning: failed to remove container record {s}: {}\n", .{ id, e });
    };
}

/// clean up network resources for a container (veth pair + IP allocation).
/// called from stop and rm. non-fatal — logs warnings on failure
/// to help debug network resource leaks.
pub fn cleanupNetwork(container_id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    const bridge = @import("../network/bridge.zig");

    // delete veth pair
    if (veth_host) |veth| {
        var name_buf: [32]u8 = undefined;
        const len = @min(veth.len, name_buf.len);
        @memcpy(name_buf[0..len], veth[0..len]);
        bridge.deleteVeth(name_buf[0..len]) catch |e| {
            writeErr("warning: failed to delete veth {s} for {s}: {}\n", .{ veth, container_id, e });
        };
    }

    // release IP allocation
    if (ip_address != null) {
        var db = store.openDb() catch return;
        defer db.deinit();
        ip.release(&db, container_id) catch |e| {
            writeErr("warning: failed to release IP for {s}: {}\n", .{ container_id, e });
        };
    }
}

// -- commands --

pub fn run(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    if (builtin.os.tag != .linux) {
        writeErr("yoq run is only supported on linux (kernel 6.1+)\n", .{});
        return ContainerError.NotSupported;
    }

    // warn if not running as root (required for cgroups and networking)
    if (posix.getuid() != 0) {
        writeErr("warning: yoq run requires root privileges for cgroups and networking\n", .{});
    }

    var flags = parseRunFlags(args, alloc) catch |e| return e;
    defer flags.port_maps.deinit(alloc);
    defer flags.env.deinit(alloc);
    defer flags.volume_specs.deinit(alloc);
    defer flags.user_argv.deinit(alloc);

    // detect if target is an image reference or a local rootfs path
    const is_image = !isFilesystemTarget(flags.target);

    // resolve image config or use local rootfs
    var img = if (is_image)
        try image_cmds.pullAndResolveImage(alloc, flags.target)
    else
        image_cmds.ImageResolution{ .rootfs = flags.target };
    defer img.deinit();

    // resolve effective command per OCI spec
    var resolved = oci.resolveCommand(alloc, img.entrypoint, img.default_cmd, flags.user_argv.items) catch |err| {
        writeErr("failed to resolve command: {}\n", .{err});
        return ContainerError.CommandResolveFailed;
    };
    defer resolved.args.deinit(alloc);

    var saved = buildSavedRunConfig(alloc, &flags, &img, &resolved) catch |e| return e;
    defer saved.deinit(alloc);
    saved.limits.validate() catch |err| {
        writeErr("invalid resource limits: {}\n", .{err});
        return ContainerError.InvalidLimits;
    };

    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf) catch {
        writeErr("failed to generate unique container ID\n", .{});
        return error.IdGenerationFailed;
    };
    const id = id_buf[0..];

    saveCreatedRecord(id, &saved) catch |e| return e;
    run_state.saveConfig(id, saved) catch |err| {
        store.remove(id) catch {};
        writeErr("failed to save container config: {}\n", .{err});
        return ContainerError.ConfigSaveFailed;
    };

    if (flags.detach) {
        spawnSupervisor(alloc, id) catch |e| return e;
        waitForContainerStart(alloc, id) catch |e| return e;
        write("{s}\n", .{id});
        return;
    }

    installSignalHandlers();
    const exit_code = superviseSavedRun(id, &saved, true);
    std.process.exit(exit_code);
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

    write("{s:<14} {s:<10} {s:<16} {s:<20}\n", .{ "CONTAINER ID", "STATUS", "IP", "COMMAND" });
    for (ids.items) |id| {
        const record = store.load(alloc, id) catch |err| {
            write("{s:<14} {s:<10} {s:<16} {s:<20}\n", .{ id, @errorName(err), "-", "-" });
            continue;
        };
        defer record.deinit(alloc);

        // check liveness: if DB says "running" but process is gone, update to "stopped"
        var status = record.status;
        if (std.mem.eql(u8, status, "running")) {
            if (record.pid) |pid| {
                process.sendSignal(pid, 0) catch {
                    // process is dead — update DB
                    store.updateStatus(id, "stopped", null, null) catch {};
                    status = "stopped";
                };
            }
        }

        const ip_display: []const u8 = record.ip_address orelse "-";
        write("{s:<14} {s:<10} {s:<16} {s:<20}\n", .{ id, status, ip_display, record.command });
    }
}

fn psJson(alloc: std.mem.Allocator, ids: []const []const u8) void {
    var w = json_out.JsonWriter{};
    w.beginArray();

    for (ids) |id| {
        const record = store.load(alloc, id) catch continue;
        defer record.deinit(alloc);

        var status = record.status;
        if (std.mem.eql(u8, status, "running")) {
            if (record.pid) |pid| {
                process.sendSignal(pid, 0) catch {
                    store.updateStatus(id, "stopped", null, null) catch {};
                    status = "stopped";
                };
            }
        }

        w.beginObject();
        w.stringField("id", id);
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

pub fn stop(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const id = requireArg(args, "usage: yoq stop <container-id|name>\n");

    const record = resolveContainerRef(alloc, id) catch |e| return e;
    defer record.deinit(alloc);

    if (!std.mem.eql(u8, record.status, "running")) {
        writeErr("container {s} is not running (status: {s})\n", .{ id, record.status });
        return ContainerError.InvalidStatus;
    }

    const pid = record.pid orelse {
        writeErr("container {s} has no pid\n", .{id});
        return ContainerError.ProcessNotFound;
    };

    // check if the process is actually still alive before sending SIGTERM
    process.sendSignal(pid, 0) catch {
        // already dead — just update the record
        persistStoppedState(&record, null);
        write("{s} (already stopped)\n", .{id});
        return;
    };

    stopProcess(pid) catch |e| return e;
    if (!waitForStoppedState(alloc, record.id)) {
        persistStoppedState(&record, null);
    }
    write("{s}\n", .{record.id});
}

pub fn exec_cmd(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const id = args.next() orelse {
        writeErr("usage: yoq exec <container-id|name> <command> [args...]\n", .{});
        return ContainerError.InvalidArgument;
    };

    const record = resolveContainerRef(alloc, id) catch |e| return e;
    defer record.deinit(alloc);

    if (!std.mem.eql(u8, record.status, "running")) {
        writeErr("container {s} is not running (status: {s})\n", .{ id, record.status });
        return ContainerError.InvalidStatus;
    }

    const pid = record.pid orelse {
        writeErr("container {s} has no pid\n", .{id});
        return ContainerError.ProcessNotFound;
    };

    const command = args.next() orelse {
        writeErr("usage: yoq exec <container-id|name> <command> [args...]\n", .{});
        return ContainerError.InvalidArgument;
    };

    // collect remaining args
    var exec_args: std.ArrayList([]const u8) = .empty;
    defer exec_args.deinit(alloc);
    while (args.next()) |arg| {
        exec_args.append(alloc, arg) catch return ContainerError.OutOfMemory;
    }

    const exit_code = exec.execInContainer(.{
        .pid = pid,
        .command = command,
        .args = exec_args.items,
        .env = &.{},
        .working_dir = "/",
    }) catch |err| {
        writeErr("failed to exec in container {s}: {}\n", .{ id, err });
        return ContainerError.ProcessNotFound;
    };

    std.process.exit(exit_code);
}

pub fn rm(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const id = requireArg(args, "usage: yoq rm <container-id|name>\n");

    const record = resolveContainerRef(alloc, id) catch |e| return e;

    if (std.mem.eql(u8, record.status, "running")) {
        writeErr("cannot remove running container {s} — stop it first\n", .{record.id});
        record.deinit(alloc);
        return ContainerError.ContainerRunning;
    }

    cleanupStoppedContainer(record.id, record.ip_address, record.veth_host);
    record.deinit(alloc);

    write("{s}\n", .{id});
}

pub fn log(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const ref = requireArg(args, "usage: yoq logs <container-id|name> [--tail N] [-f]\n");
    const record = try resolveContainerRef(alloc, ref);
    defer record.deinit(alloc);

    var tail_lines: usize = 0;
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
        }
    }

    if (follow) {
        logs.followLogs(record.id, tail_lines, record.pid) catch |err| {
            writeErr("failed to follow logs for container: {s} ({})\n", .{ record.id, err });
            std.process.exit(1);
        };
        return;
    }

    const content = if (tail_lines > 0)
        logs.readTail(alloc, record.id, tail_lines)
    else
        logs.readLogs(alloc, record.id);

    const data = content catch |err| {
        writeErr("no logs found for container: {s} ({})\n", .{ record.id, err });
        std.process.exit(1);
    };
    defer alloc.free(data);

    if (data.len == 0) {
        write("(no output)\n", .{});
        return;
    }

    write("{s}", .{data});
}

pub fn restart(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const ref = requireArg(args, "usage: yoq restart <container-id|name>\n");
    const record = resolveContainerRef(alloc, ref) catch |e| return e;
    defer record.deinit(alloc);

    if (std.mem.eql(u8, record.status, "running")) {
        const pid = record.pid orelse {
            writeErr("container {s} has no pid\n", .{record.id});
            return ContainerError.ProcessNotFound;
        };
        stopProcess(pid) catch |e| return e;
    }

    store.updateStatus(record.id, "created", null, null) catch {};
    spawnSupervisor(alloc, record.id) catch |e| return e;
    waitForContainerStart(alloc, record.id) catch |e| return e;
    write("{s}\n", .{record.id});
}

pub fn runSupervisor(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const id = requireArg(args, "usage: yoq __run-supervisor <container-id>\n");
    var cfg = run_state.loadConfig(alloc, id) catch |err| {
        writeErr("failed to load container config for {s}: {}\n", .{ id, err });
        return ContainerError.ConfigSaveFailed;
    };
    defer cfg.deinit(alloc);

    const exit_code = superviseSavedRun(id, &cfg, false);
    std.process.exit(exit_code);
}

test "filesystem target detection matches supported rootfs shapes" {
    try std.testing.expect(isFilesystemTarget("/tmp/rootfs"));
    try std.testing.expect(isFilesystemTarget("./rootfs"));
    try std.testing.expect(isFilesystemTarget("../rootfs"));
    try std.testing.expect(isFilesystemTarget("."));
    try std.testing.expect(isFilesystemTarget(".."));
    try std.testing.expect(!isFilesystemTarget("nginx:latest"));
    try std.testing.expect(!isFilesystemTarget("library/nginx"));
}
