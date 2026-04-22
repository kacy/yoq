const std = @import("std");
const platform = @import("platform");
const builtin = @import("builtin");
const posix = std.posix;
const cli = @import("../../../lib/cli.zig");
const container = @import("../../container.zig");
const run_state = @import("../../run_state.zig");
const net_setup = @import("../../../network/setup.zig");
const oci = @import("../../../image/oci.zig");
const image_cmds = @import("../../../image/commands.zig");
const common = @import("common.zig");
const state_support = @import("state_support.zig");
const supervisor_runtime = @import("supervisor_runtime.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const parsePortMap = cli.parsePortMap;
const parseEnvVar = cli.parseEnvVar;
const parseVolumeMount = cli.parseVolumeMount;
const parseMemorySize = cli.parseMemorySize;
const isValidContainerName = cli.isValidContainerName;
const ContainerError = common.ContainerError;
const RunFlags = common.RunFlags;

fn isFilesystemTarget(target: []const u8) bool {
    return std.mem.startsWith(u8, target, "/") or
        std.mem.startsWith(u8, target, "./") or
        std.mem.startsWith(u8, target, "../") or
        std.mem.eql(u8, target, ".") or
        std.mem.eql(u8, target, "..");
}

fn parseRunFlags(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) ContainerError!RunFlags {
    var port_maps: std.ArrayList(net_setup.PortMap) = .empty;
    var env: std.ArrayList([]const u8) = .empty;
    var volume_specs: std.ArrayList(cli.VolumeMountSpec) = .empty;
    var networking_enabled = true;
    var container_name: ?[]const u8 = null;
    var detach = false;
    var limits: @import("../../cgroups.zig").ResourceLimits = .{};
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
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--volume") or std.mem.eql(u8, arg, "--mount")) {
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
        } else if (std.mem.eql(u8, arg, "--pids")) {
            const pids_str = args.next() orelse {
                writeErr("--pids requires a numeric limit\n", .{});
                return ContainerError.InvalidArgument;
            };
            limits.pids_max = std.fmt.parseUnsigned(u32, pids_str, 10) catch {
                writeErr("invalid pids limit: {s}\n", .{pids_str});
                return ContainerError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--cpu-weight")) {
            const weight_str = args.next() orelse {
                writeErr("--cpu-weight requires a value between 1 and 10000\n", .{});
                return ContainerError.InvalidArgument;
            };
            limits.cpu_weight = std.fmt.parseUnsigned(u16, weight_str, 10) catch {
                writeErr("invalid cpu weight: {s}\n", .{weight_str});
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
        writeErr("usage: yoq run [--name <name>] [-e KEY=VALUE] [-v source:target[:ro]] [--mount source:target[:ro]] [-p host:container] [--memory SIZE] [--pids N] [--cpu-weight N] [--cpus N] [-d] [--restart POLICY] [--no-net] <image|rootfs> [command]\n", .{});
        return ContainerError.InvalidArgument;
    };

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

fn freeOwnedStringList(alloc: std.mem.Allocator, values: []const []const u8) void {
    for (values) |value| alloc.free(value);
    alloc.free(values);
}

fn freeOwnedMounts(alloc: std.mem.Allocator, mounts: []const container.BindMount) void {
    for (mounts) |mount| {
        alloc.free(mount.source);
        alloc.free(mount.target);
    }
    alloc.free(mounts);
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

    const cwd = platform.cwd().realpathAlloc(alloc, ".") catch {
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

    for (volume_specs) |spec| {
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

        const source = platform.cwd().realpathAlloc(alloc, source_input) catch {
            writeErr("volume source must exist and be canonicalizable: {s}\n", .{spec.source});
            return ContainerError.InvalidArgument;
        };
        errdefer alloc.free(source);

        const target = alloc.dupe(u8, spec.target) catch return error.OutOfMemory;
        errdefer alloc.free(target);

        const mount: container.BindMount = .{
            .source = source,
            .target = target,
            .read_only = spec.read_only,
        };
        if (!mount.isSourceAllowed()) {
            writeErr("volume source is not allowed: {s}\n", .{mount.source});
            return ContainerError.InvalidArgument;
        }

        mounts[idx] = mount;
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
    errdefer freeOwnedStringList(alloc, merged_env);

    const rootfs = alloc.dupe(u8, img.rootfs) catch return ContainerError.OutOfMemory;
    errdefer alloc.free(rootfs);

    const command = alloc.dupe(u8, resolved.command) catch return ContainerError.OutOfMemory;
    errdefer alloc.free(command);

    const hostname = alloc.dupe(u8, flags.container_name orelse "container") catch return ContainerError.OutOfMemory;
    errdefer alloc.free(hostname);

    const working_dir = alloc.dupe(u8, img.working_dir) catch return ContainerError.OutOfMemory;
    errdefer alloc.free(working_dir);

    const args = dupStringList(alloc, resolved.args.items) catch |e| return e;
    errdefer freeOwnedStringList(alloc, args);

    const lower_dirs = dupStringList(alloc, img.layer_paths) catch |e| return e;
    errdefer freeOwnedStringList(alloc, lower_dirs);

    const mounts = buildMounts(alloc, flags.volume_specs.items) catch |e| return e;
    errdefer freeOwnedMounts(alloc, mounts);

    const port_maps = alloc.dupe(net_setup.PortMap, flags.port_maps.items) catch return ContainerError.OutOfMemory;
    errdefer alloc.free(port_maps);

    return .{
        .rootfs = rootfs,
        .command = command,
        .hostname = hostname,
        .working_dir = working_dir,
        .args = args,
        .env = merged_env,
        .lower_dirs = lower_dirs,
        .mounts = mounts,
        .network_enabled = flags.networking_enabled,
        .port_maps = port_maps,
        .limits = flags.limits,
        .restart_policy = flags.restart_policy,
    };
}

fn saveCreatedRecord(id: []const u8, cfg: *const run_state.SavedRunConfig) ContainerError!void {
    @import("../../../state/store.zig").save(.{
        .id = id,
        .rootfs = cfg.rootfs,
        .command = cfg.command,
        .hostname = cfg.hostname,
        .status = "created",
        .pid = null,
        .exit_code = null,
        .created_at = platform.timestamp(),
    }) catch |err| {
        writeErr("failed to save container state: {}\n", .{err});
        return ContainerError.ConfigSaveFailed;
    };
}

pub fn run(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    if (builtin.os.tag != .linux) {
        writeErr("yoq run is only supported on linux (kernel 6.1+)\n", .{});
        return ContainerError.NotSupported;
    }

    if (platform.posix.getuid() != 0) {
        writeErr("warning: yoq run requires root privileges for cgroups and networking\n", .{});
    }

    var flags = parseRunFlags(args, alloc) catch |e| return e;
    defer flags.deinit(alloc);

    const is_image = !isFilesystemTarget(flags.target);

    var img = if (is_image)
        try image_cmds.pullAndResolveImage(alloc, flags.target)
    else
        image_cmds.ImageResolution{ .rootfs = flags.target };
    defer img.deinit();

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
        @import("../../../state/store.zig").remove(id) catch {};
        writeErr("failed to save container config: {}\n", .{err});
        return ContainerError.ConfigSaveFailed;
    };

    if (flags.detach) {
        supervisor_runtime.spawnSupervisor(alloc, id) catch |e| return e;
        state_support.waitForContainerStart(alloc, id) catch |e| return e;
        write("{s}\n", .{id});
        return;
    }

    supervisor_runtime.installSignalHandlers();
    const exit_code = supervisor_runtime.superviseSavedRun(id, &saved, true);
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

test "buildMounts rejects disallowed canonical source without leaking" {
    const alloc = std.testing.allocator;
    const specs = [_]cli.VolumeMountSpec{
        .{ .source = "/etc", .target = "/data", .read_only = true },
    };

    try std.testing.expectError(ContainerError.InvalidArgument, buildMounts(alloc, &specs));
}
