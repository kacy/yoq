const std = @import("std");
const linux_platform = @import("linux_platform");
const builtin = @import("builtin");
const posix = std.posix;
const cli = @import("../../../lib/cli.zig");
const AppContext = @import("../../../lib/app_context.zig").AppContext;
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

fn optionValue(args: anytype, option: []const u8, inline_value: ?[]const u8) ContainerError![]const u8 {
    return inline_value orelse args.next() orelse {
        writeErr("{s} requires a value\n", .{option});
        return ContainerError.InvalidArgument;
    };
}

fn appendEnv(alloc: std.mem.Allocator, env: *std.ArrayList([]const u8), value: []const u8) ContainerError!void {
    const eq = std.mem.indexOfScalar(u8, value, '=');
    const name = if (eq) |i| value[0..i] else value;
    if (name.len == 0 or std.mem.indexOfAny(u8, name, " \t\r\n") != null or std.mem.indexOfScalar(u8, value, 0) != null) {
        writeErr("invalid environment variable name\n", .{});
        return ContainerError.InvalidArgument;
    }
    const owned = if (eq != null)
        alloc.dupe(u8, value) catch return ContainerError.OutOfMemory
    else blk: {
        const key = alloc.dupeZ(u8, name) catch return ContainerError.OutOfMemory;
        defer alloc.free(key);
        if (std.c.getenv(key)) |host_value| {
            break :blk std.fmt.allocPrint(alloc, "{s}={s}", .{ name, std.mem.span(host_value) }) catch return ContainerError.OutOfMemory;
        }
        // Keep an unset name so it also removes a value inherited from the image.
        break :blk alloc.dupe(u8, name) catch return ContainerError.OutOfMemory;
    };
    errdefer alloc.free(owned);
    env.append(alloc, owned) catch return ContainerError.OutOfMemory;
}

fn appendEnvFile(alloc: std.mem.Allocator, env: *std.ArrayList([]const u8), contents: []const u8) ContainerError!void {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimStart(u8, std.mem.trimEnd(u8, raw, "\r"), " \t");
        if (line.len == 0 or line[0] == '#') continue;
        try appendEnv(alloc, env, line);
    }
}

fn parseRunFlags(args: anytype, alloc: std.mem.Allocator, io: std.Io) ContainerError!RunFlags {
    var flags: RunFlags = .{};
    errdefer flags.deinit(alloc);
    var file_env: std.ArrayList([]const u8) = .empty;
    defer {
        for (file_env.items) |value| alloc.free(value);
        file_env.deinit(alloc);
    }

    while (args.next()) |raw_arg| {
        const eq = if (std.mem.startsWith(u8, raw_arg, "--")) std.mem.indexOfScalar(u8, raw_arg, '=') else null;
        const option = if (eq) |i| raw_arg[0..i] else raw_arg;
        const inline_value = if (eq) |i| raw_arg[i + 1 ..] else null;
        // Flags without a value must reject forms such as --detach=false.
        const takes_no_value = std.mem.eql(u8, option, "--detach") or std.mem.eql(u8, option, "--net") or
            std.mem.eql(u8, option, "--no-net") or std.mem.eql(u8, option, "--rm") or
            std.mem.eql(u8, option, "--interactive") or std.mem.eql(u8, option, "--tty") or
            std.mem.eql(u8, option, "--no-healthcheck") or std.mem.eql(u8, option, "--");
        const arg = if (inline_value != null and takes_no_value) raw_arg else option;
        if (std.mem.eql(u8, arg, "--")) {
            flags.target = try optionValue(args, "--", null);
            break;
        } else if (std.mem.eql(u8, arg, "--name") or std.mem.eql(u8, arg, "--hostname")) {
            const value = try optionValue(args, arg, inline_value);
            if (!isValidContainerName(value)) {
                writeErr("invalid {s}: {s} (use 1-63 letters, digits, or hyphens)\n", .{ arg, value });
                return ContainerError.InvalidArgument;
            }
            if (std.mem.eql(u8, arg, "--name")) flags.container_name = value else flags.hostname = value;
        } else if (std.mem.eql(u8, arg, "--entrypoint")) {
            flags.entrypoint = try optionValue(args, arg, inline_value);
        } else if (std.mem.eql(u8, arg, "--workdir") or std.mem.eql(u8, arg, "-w")) {
            const value = try optionValue(args, arg, inline_value);
            if (value.len == 0 or value[0] != '/') {
                writeErr("working directory must be an absolute container path\n", .{});
                return ContainerError.InvalidArgument;
            }
            flags.working_dir = value;
        } else if (std.mem.eql(u8, arg, "--user") or std.mem.eql(u8, arg, "-u")) {
            const value = try optionValue(args, arg, inline_value);
            if (value.len == 0) return ContainerError.InvalidArgument;
            flags.user = value;
        } else if (std.mem.eql(u8, arg, "--rm")) {
            flags.auto_remove = true;
        } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--interactive")) {
            flags.interactive = true;
        } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--tty")) {
            flags.tty = true;
        } else if (std.mem.eql(u8, arg, "-it") or std.mem.eql(u8, arg, "-ti")) {
            flags.interactive = true;
            flags.tty = true;
        } else if (std.mem.eql(u8, arg, "--no-healthcheck")) {
            flags.no_healthcheck = true;
        } else if (std.mem.eql(u8, arg, "--health-cmd")) {
            flags.health_command = try optionValue(args, arg, inline_value);
        } else if (std.mem.eql(u8, arg, "--health-retries")) {
            flags.health_retries = std.fmt.parseInt(i64, try optionValue(args, arg, inline_value), 10) catch return ContainerError.InvalidArgument;
        } else if (std.mem.eql(u8, arg, "--health-interval") or std.mem.eql(u8, arg, "--health-timeout") or
            std.mem.eql(u8, arg, "--health-start-period") or std.mem.eql(u8, arg, "--health-start-interval"))
        {
            const value = try optionValue(args, arg, inline_value);
            const duration = if (std.mem.eql(u8, value, "0") and std.mem.eql(u8, arg, "--health-start-period")) 0 else @import("../../../lib/duration.zig").nanoseconds(value) catch return ContainerError.InvalidArgument;
            if (std.mem.eql(u8, arg, "--health-interval")) flags.health_interval = duration;
            if (std.mem.eql(u8, arg, "--health-timeout")) flags.health_timeout = duration;
            if (std.mem.eql(u8, arg, "--health-start-period")) flags.health_start_period = duration;
            if (std.mem.eql(u8, arg, "--health-start-interval")) flags.health_start_interval = duration;
        } else if (std.mem.eql(u8, arg, "--network-alias")) {
            const value = try optionValue(args, arg, inline_value);
            if (!isValidContainerName(value)) return ContainerError.InvalidArgument;
            flags.network_aliases.append(alloc, value) catch return ContainerError.OutOfMemory;
        } else if (std.mem.eql(u8, arg, "--network")) {
            const value = try optionValue(args, arg, inline_value);
            if (std.mem.eql(u8, value, "none")) {
                flags.networking_enabled = false;
                flags.network_name = null;
            } else {
                flags.networking_enabled = true;
                flags.network_name = if (std.mem.eql(u8, value, "default")) null else value;
            }
        } else if (std.mem.eql(u8, arg, "--stop-signal")) {
            flags.stop_signal = @import("../../signals.zig").parse(try optionValue(args, arg, inline_value)) orelse return ContainerError.InvalidArgument;
        } else if (std.mem.eql(u8, arg, "--stop-timeout")) {
            flags.stop_timeout_seconds = std.fmt.parseInt(u32, try optionValue(args, arg, inline_value), 10) catch return ContainerError.InvalidArgument;
        } else if (std.mem.eql(u8, arg, "--pull")) {
            const value = try optionValue(args, arg, inline_value);
            flags.pull_policy = std.meta.stringToEnum(image_cmds.PullPolicy, value) orelse {
                writeErr("--pull requires missing, always, or never\n", .{});
                return ContainerError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--publish")) {
            const value = try optionValue(args, arg, inline_value);
            const mapping = parsePortMap(value) orelse {
                writeErr("invalid port mapping: {s}; expected host:container[/tcp|udp]\n", .{value});
                return ContainerError.InvalidArgument;
            };
            flags.port_maps.append(alloc, mapping) catch return ContainerError.OutOfMemory;
        } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--env")) {
            try appendEnv(alloc, &flags.env, try optionValue(args, arg, inline_value));
        } else if (std.mem.eql(u8, arg, "--env-file")) {
            const path = try optionValue(args, arg, inline_value);
            const contents = std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(1024 * 1024)) catch |err| {
                writeErr("cannot read environment file {s}: {}\n", .{ path, err });
                return ContainerError.InvalidArgument;
            };
            defer alloc.free(contents);
            try appendEnvFile(alloc, &file_env, contents);
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--volume") or std.mem.eql(u8, arg, "--mount")) {
            const value = try optionValue(args, arg, inline_value);
            const structured = std.mem.eql(u8, arg, "--mount") and std.mem.indexOfScalar(u8, value, '=') != null;
            const mount = (if (structured) cli.parseStructuredMount(value) else parseVolumeMount(value)) orelse {
                writeErr("invalid mount: {s}; use --mount type=bind,src=PATH,dst=/PATH[,readonly] or -v PATH:/PATH[:ro|rw]\n", .{value});
                return ContainerError.InvalidArgument;
            };
            if (std.mem.eql(u8, arg, "--mount") and !structured) {
                writeErr("warning: --mount colon syntax is deprecated and defaults to read-only; use -v or structured --mount\n", .{});
            }
            flags.volume_specs.append(alloc, mount) catch return ContainerError.OutOfMemory;
        } else if (std.mem.eql(u8, arg, "--no-net")) {
            flags.networking_enabled = false;
            flags.network_name = null;
        } else if (std.mem.eql(u8, arg, "--net")) {
            flags.networking_enabled = true;
        } else if (std.mem.eql(u8, arg, "--cpuset-cpus")) {
            const value = try optionValue(args, arg, inline_value);
            flags.limits.cpuset_cpus = @import("../../cgroups.zig").CpuSet.parse(value) catch return ContainerError.InvalidArgument;
        } else if (std.mem.eql(u8, arg, "--shm-size")) {
            const value = try optionValue(args, arg, inline_value);
            flags.shm_size = parseMemorySize(value) orelse return ContainerError.InvalidArgument;
            if (flags.shm_size == 0 or flags.shm_size > std.math.maxInt(i64)) return ContainerError.InvalidArgument;
        } else if (std.mem.eql(u8, arg, "--tmpfs")) {
            const value = try optionValue(args, arg, inline_value);
            if (flags.tmpfs_mounts.items.len >= 256) return ContainerError.InvalidArgument;
            const mount = @import("../../filesystem.zig").TmpfsMount.parse(value) catch return ContainerError.InvalidArgument;
            flags.tmpfs_mounts.append(alloc, mount) catch return ContainerError.OutOfMemory;
        } else if (std.mem.eql(u8, arg, "--memory")) {
            const value = try optionValue(args, arg, inline_value);
            flags.limits.memory_max = if (std.mem.eql(u8, value, "unlimited")) null else parseMemorySize(value) orelse {
                writeErr("--memory requires a size such as 256m, or unlimited\n", .{});
                return ContainerError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--pids")) {
            const value = try optionValue(args, arg, inline_value);
            flags.limits.pids_max = if (std.mem.eql(u8, value, "unlimited")) null else std.fmt.parseUnsigned(u32, value, 10) catch {
                writeErr("--pids requires a positive integer, or unlimited\n", .{});
                return ContainerError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--cpu-weight")) {
            const value = try optionValue(args, arg, inline_value);
            const weight = std.fmt.parseUnsigned(u16, value, 10) catch 0;
            if (weight < 1 or weight > 10000) {
                writeErr("--cpu-weight requires an integer between 1 and 10000\n", .{});
                return ContainerError.InvalidArgument;
            }
            flags.limits.cpu_weight = weight;
        } else if (std.mem.eql(u8, arg, "--cpus")) {
            const value = try optionValue(args, arg, inline_value);
            flags.limits.cpu_max_usec = if (std.mem.eql(u8, value, "unlimited")) null else cli.parseCpuQuota(value, flags.limits.cpu_max_period) orelse {
                writeErr("--cpus requires a finite positive number up to 1024, with a quota of at least one microsecond, or unlimited\n", .{});
                return ContainerError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--detach")) {
            flags.detach = true;
        } else if (std.mem.eql(u8, arg, "--restart")) {
            const value = try optionValue(args, arg, inline_value);
            const restart = run_state.RestartPolicy.parseWithRetries(value) catch {
                writeErr("invalid restart policy: {s}\n", .{value});
                return ContainerError.InvalidArgument;
            };
            flags.restart_policy = restart.policy;
            flags.restart_max_retries = restart.max_retries;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            writeErr("unknown run option: {s}\n", .{arg});
            return ContainerError.InvalidArgument;
        } else {
            flags.target = arg;
            break;
        }
    }
    if (flags.target.len == 0) {
        writeErr("usage: yoq run [options] <image|rootfs> [command [args...]]\n", .{});
        return ContainerError.InvalidArgument;
    }
    for (flags.tmpfs_mounts.items, 0..) |mount, index| {
        for (flags.tmpfs_mounts.items[0..index]) |other| {
            if (std.mem.eql(u8, mount.target, other.target)) return ContainerError.InvalidArgument;
        }
        for (flags.volume_specs.items) |other| {
            if (std.mem.eql(u8, mount.target, other.target)) return ContainerError.InvalidArgument;
        }
    }
    flags.limits.validate() catch |err| {
        writeErr("invalid resource limits: {}\n", .{err});
        return ContainerError.InvalidLimits;
    };
    while (args.next()) |arg| flags.user_argv.append(alloc, arg) catch return ContainerError.OutOfMemory;

    // File values precede explicit -e values regardless of option order.
    file_env.appendSlice(alloc, flags.env.items) catch return ContainerError.OutOfMemory;
    flags.env.clearRetainingCapacity();
    std.mem.swap(std.ArrayList([]const u8), &file_env, &flags.env);
    return flags;
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
        const eq = std.mem.indexOfScalar(u8, value, '=');
        const key = if (eq) |i| value[0..i] else value;
        var replaced = false;
        for (merged.items, 0..) |*existing, i| {
            const existing_eq = std.mem.indexOfScalar(u8, existing.*, '=') orelse continue;
            if (std.mem.eql(u8, existing.*[0..existing_eq], key)) {
                if (eq != null) existing.* = value else _ = merged.orderedRemove(i);
                replaced = true;
                break;
            }
        }
        if (!replaced and eq != null) {
            merged.append(alloc, value) catch return ContainerError.OutOfMemory;
        }
    }

    return dupStringList(alloc, merged.items);
}

fn buildMounts(alloc: std.mem.Allocator, volume_specs: []const cli.VolumeMountSpec, id: ?[]const u8) ContainerError![]container.BindMount {
    if (volume_specs.len == 0) {
        return alloc.alloc(container.BindMount, 0) catch return ContainerError.OutOfMemory;
    }

    const cwd = std.Io.Dir.cwd().realPathFileAlloc(std.Options.debug_io, ".", alloc) catch {
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
        if (spec.kind == .volume) {
            mounts[idx] = @import("../../local_volumes.zig").resolveMount(alloc, id orelse return ContainerError.InvalidArgument, spec) catch |err| {
                writeErr("cannot attach volume: {}\n", .{err});
                return ContainerError.ConfigSaveFailed;
            };
            idx += 1;
            continue;
        }
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

        const canonical_source = std.Io.Dir.cwd().realPathFileAlloc(std.Options.debug_io, source_input, alloc) catch {
            writeErr("volume source must exist and be canonicalizable: {s}\n", .{spec.source});
            return ContainerError.InvalidArgument;
        };
        defer alloc.free(canonical_source);
        const source = alloc.dupe(u8, canonical_source) catch return error.OutOfMemory;
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
    id: ?[]const u8,
) ContainerError!run_state.SavedRunConfig {
    const merged_env = mergeEnv(alloc, img.image_env, flags.env.items) catch |e| return e;
    errdefer freeOwnedStringList(alloc, merged_env);

    const rootfs = alloc.dupe(u8, img.rootfs) catch return ContainerError.OutOfMemory;
    errdefer alloc.free(rootfs);

    const command = alloc.dupe(u8, resolved.command) catch return ContainerError.OutOfMemory;
    errdefer alloc.free(command);

    const hostname = alloc.dupe(u8, flags.hostname orelse "container") catch return ContainerError.OutOfMemory;
    errdefer alloc.free(hostname);

    const working_dir = alloc.dupe(u8, flags.working_dir orelse img.working_dir) catch return ContainerError.OutOfMemory;
    errdefer alloc.free(working_dir);

    const effective_user = flags.user orelse img.user;
    const user = if (effective_user) |value| alloc.dupe(u8, value) catch return ContainerError.OutOfMemory else null;
    errdefer if (user) |value| alloc.free(value);

    const args = dupStringList(alloc, resolved.args.items) catch |e| return e;
    errdefer freeOwnedStringList(alloc, args);

    const lower_dirs = dupStringList(alloc, img.layer_paths) catch |e| return e;
    errdefer freeOwnedStringList(alloc, lower_dirs);

    const mounts = buildMounts(alloc, flags.volume_specs.items, id) catch |e| return e;
    errdefer freeOwnedMounts(alloc, mounts);

    const tmpfs_mounts = alloc.alloc(@import("../../filesystem.zig").TmpfsMount, flags.tmpfs_mounts.items.len) catch return ContainerError.OutOfMemory;
    var tmpfs_loaded: usize = 0;
    errdefer {
        for (tmpfs_mounts[0..tmpfs_loaded]) |mount| alloc.free(mount.target);
        alloc.free(tmpfs_mounts);
    }
    for (tmpfs_mounts, flags.tmpfs_mounts.items) |*mount, original| {
        mount.* = original;
        mount.target = alloc.dupe(u8, original.target) catch return ContainerError.OutOfMemory;
        tmpfs_loaded += 1;
    }
    const port_maps = alloc.dupe(net_setup.PortMap, flags.port_maps.items) catch return ContainerError.OutOfMemory;
    errdefer alloc.free(port_maps);

    return .{
        .rootfs = rootfs,
        .command = command,
        .hostname = hostname,
        .working_dir = working_dir,
        .user = user,
        .args = args,
        .env = merged_env,
        .lower_dirs = lower_dirs,
        .mounts = mounts,
        .shm_size = flags.shm_size,
        .tmpfs_mounts = tmpfs_mounts,
        .network_enabled = flags.networking_enabled,
        .port_maps = port_maps,
        .limits = flags.limits,
        .restart_policy = flags.restart_policy,
        .restart_max_retries = flags.restart_max_retries,
    };
}

fn resolveRunCommand(alloc: std.mem.Allocator, flags: *const RunFlags, img: *const image_cmds.ImageResolution) ContainerError!oci.ResolvedCommand {
    var entrypoint_buffer: [1][]const u8 = undefined;
    const entrypoint: []const []const u8 = if (flags.entrypoint) |value| blk: {
        if (value.len == 0) break :blk &.{};
        entrypoint_buffer[0] = value;
        break :blk &entrypoint_buffer;
    } else img.entrypoint;
    // An explicit entrypoint also clears the image's default arguments.
    const default_cmd: []const []const u8 = if (flags.entrypoint != null) &.{} else img.default_cmd;
    return oci.resolveCommand(alloc, entrypoint, default_cmd, flags.user_argv.items) catch |err| {
        writeErr("failed to resolve command: {}\n", .{err});
        return ContainerError.CommandResolveFailed;
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
        .created_at = std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
    }) catch |err| {
        writeErr("failed to save container state: {}\n", .{err});
        return ContainerError.ConfigSaveFailed;
    };
}

pub fn run(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return createAndRun(args, ctx, false);
}

pub fn create(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return createAndRun(args, ctx, true);
}

fn createAndRun(args: *std.process.Args.Iterator, ctx: AppContext, create_only: bool) !void {
    const alloc = ctx.alloc;

    if (builtin.os.tag != .linux) {
        writeErr("yoq run is only supported on linux (kernel 6.1+)\n", .{});
        return ContainerError.NotSupported;
    }

    if (linux_platform.posix.getuid() != 0) {
        writeErr("warning: yoq run requires root privileges for cgroups and networking\n", .{});
    }

    var flags = parseRunFlags(args, alloc, ctx.io) catch |e| return e;
    defer flags.deinit(alloc);

    const is_image = !isFilesystemTarget(flags.target);

    // Keep resolved layers alive until the saved configuration pins them.
    var image_lease = try @import("../../../image/store_lock.zig").Lock.acquire(.shared);
    defer image_lease.deinit();

    var img = if (is_image)
        try image_cmds.resolveImage(ctx.io, alloc, flags.target, flags.pull_policy)
    else
        image_cmds.ImageResolution{ .rootfs = flags.target };
    defer img.deinit();

    var resolved = try resolveRunCommand(alloc, &flags, &img);
    defer resolved.args.deinit(alloc);

    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf) catch {
        writeErr("failed to generate unique container ID\n", .{});
        return error.IdGenerationFailed;
    };
    const id = id_buf[0..];

    var created = false;
    errdefer if (!created) @import("../../local_volumes.zig").releaseContainer(id, true) catch {};
    errdefer if (!created) @import("../../../network/port_allocator.zig").release(id) catch {};
    errdefer if (!created) @import("../../../network/local_networks.zig").release(id) catch {};
    if (img.volumes) |volumes| {
        if (volumes == .object) {
            var it = volumes.object.iterator();
            while (it.next()) |entry| {
                var overridden = false;
                for (flags.volume_specs.items) |mount| {
                    if (std.mem.eql(u8, mount.target, entry.key_ptr.*)) overridden = true;
                }
                for (flags.tmpfs_mounts.items) |mount| {
                    if (std.mem.eql(u8, mount.target, entry.key_ptr.*)) overridden = true;
                }
                if (!overridden) try flags.volume_specs.append(alloc, .{ .kind = .volume, .source = "", .target = entry.key_ptr.*, .read_only = false });
            }
        }
    }

    var saved = buildSavedRunConfig(alloc, &flags, &img, &resolved, id) catch |e| return e;
    defer saved.deinit(alloc);
    try @import("../../../network/port_allocator.zig").reserve(id, saved.port_maps);
    saved.healthcheck_json = try effectiveHealthcheck(alloc, &flags, img.healthcheck);
    if (flags.network_aliases.items.len > 0 and flags.network_name == null) return error.NamedNetworkRequired;
    if (!flags.networking_enabled and saved.port_maps.len > 0) return error.NetworkRequired;
    if (flags.network_name) |name| saved.network_name = try alloc.dupe(u8, name);
    saved.network_aliases = try duplicateStrings(alloc, flags.network_aliases.items);
    if (saved.network_name) |name| {
        try @import("../../../network/local_networks.zig").reserve(name, id, flags.container_name orelse saved.hostname);
        try @import("../../../network/local_networks.zig").reserveAliases(id, saved.network_aliases);
    }
    saved.auto_remove = flags.auto_remove;
    saved.interactive = flags.interactive;
    saved.tty = flags.tty;
    saved.stop_timeout_seconds = flags.stop_timeout_seconds;
    saved.stop_signal = flags.stop_signal orelse if (img.stop_signal) |value| @import("../../signals.zig").parse(value) orelse return ContainerError.InvalidArgument else 15;
    if (img.manifest_digest.len > 0) saved.image_reference = try alloc.dupe(u8, img.manifest_digest);
    if (saved.auto_remove and saved.restart_policy != .no) {
        writeErr("--rm cannot be combined with a restart policy\n", .{});
        return ContainerError.InvalidArgument;
    }
    saved.limits.validate() catch |err| {
        writeErr("invalid resource limits: {}\n", .{err});
        return ContainerError.InvalidLimits;
    };

    {
        const control = @import("../../local_control.zig");
        const creation_lock = try control.lock(id, .command, true);
        defer creation_lock.deinit();
        control.register(id, flags.container_name) catch |err| {
            writeErr("cannot reserve container name: {}\n", .{err});
            return ContainerError.ConfigSaveFailed;
        };
        errdefer control.remove(id) catch {};
        saveCreatedRecord(id, &saved) catch |e| return e;
        run_state.saveConfig(id, saved) catch |err| {
            @import("../../../state/store.zig").remove(id) catch {};
            writeErr("failed to save container config: {}\n", .{err});
            return ContainerError.ConfigSaveFailed;
        };
    }

    created = true;
    image_lease.deinit();
    if (create_only) {
        write("{s}\n", .{id});
        return;
    }
    if (flags.detach) {
        try @import("../../local_lifecycle.zig").start(ctx.io, alloc, id);
        write("{s}\n", .{id});
        return;
    }

    const generation = blk: {
        const lock = try @import("../../local_control.zig").lock(id, .command, true);
        defer lock.deinit();
        break :blk try supervisor_runtime.spawnAttachedSupervisor(ctx.io, alloc, id);
    };
    const outcome = try @import("../../session.zig").attachOutcome(id, saved.interactive);
    const exit_code: u8 = switch (outcome) {
        .detached => 0,
        .exited => |code| blk: {
            if (saved.auto_remove) {
                // Either caller can finish removal; command locking makes it
                // idempotent. A detached session must leave its workload alive.
                @import("../../local_lifecycle.zig").removeAutomatic(id, alloc, generation) catch |err| {
                    if (err != error.NotFound) return err;
                };
            }
            break :blk code;
        },
    };
    std.process.exit(exit_code);
}

fn duplicateStrings(alloc: std.mem.Allocator, source: []const []const u8) ![][]const u8 {
    const result = try alloc.alloc([]const u8, source.len);
    errdefer alloc.free(result);
    var count: usize = 0;
    errdefer for (result[0..count]) |value| alloc.free(value);
    for (source, 0..) |value, i| {
        result[i] = try alloc.dupe(u8, value);
        count += 1;
    }
    return result;
}

fn effectiveHealthcheck(alloc: std.mem.Allocator, flags: *const RunFlags, image: ?@import("../../../image/spec.zig").Healthcheck) !?[]const u8 {
    const overrides = flags.health_command != null or flags.health_interval != null or flags.health_timeout != null or
        flags.health_start_period != null or flags.health_start_interval != null or flags.health_retries != null;
    if (flags.no_healthcheck) {
        if (overrides) return error.ConflictingHealthOptions;
        return null;
    }
    if (image == null and !overrides) return null;
    var health = image orelse @import("../../../image/spec.zig").Healthcheck{};
    var command: [2][]const u8 = undefined;
    if (flags.health_command) |value| {
        if (value.len == 0) return error.InvalidHealthcheck;
        command = .{ "CMD-SHELL", value };
        health.Test = &command;
    }
    if (flags.health_interval) |value| health.Interval = value;
    if (flags.health_timeout) |value| health.Timeout = value;
    if (flags.health_start_period) |value| health.StartPeriod = value;
    if (flags.health_start_interval) |value| health.StartInterval = value;
    if (flags.health_retries) |value| health.Retries = value;
    if ((try @import("../../local_health.zig").Settings.fromImage(health)) == null and overrides) return error.MissingHealthCommand;
    return try std.json.Stringify.valueAlloc(alloc, health, .{});
}

test "health overrides require a command and reject conflicting disable" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.ConflictingHealthOptions, effectiveHealthcheck(alloc, &.{ .no_healthcheck = true, .health_command = "true" }, null));
    try std.testing.expectError(error.MissingHealthCommand, effectiveHealthcheck(alloc, &.{ .health_interval = std.time.ns_per_s }, null));
    const result = (try effectiveHealthcheck(alloc, &.{ .health_command = "exit 0", .health_interval = std.time.ns_per_s }, null)).?;
    defer alloc.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "CMD-SHELL") != null);
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

    try std.testing.expectError(ContainerError.InvalidArgument, buildMounts(alloc, &specs, null));
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

test "run options keep process overrides separate from container names" {
    var args: TestArgs = .{ .values = &.{ "--name", "web", "--hostname", "inside", "--entrypoint", "/bin/sh", "-w", "/app", "-u", "1000:1000", "--pull", "never", "--memory", "unlimited", "--pids", "unlimited", "--cpus", "unlimited", "image", "-c", "echo hello" } };
    var flags = try parseRunFlags(&args, std.testing.allocator, std.testing.io);
    defer flags.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("web", flags.container_name.?);
    try std.testing.expectEqualStrings("inside", flags.hostname.?);
    try std.testing.expectEqualStrings("/app", flags.working_dir.?);
    try std.testing.expectEqualStrings("1000:1000", flags.user.?);
    try std.testing.expectEqual(image_cmds.PullPolicy.never, flags.pull_policy);
    try std.testing.expect(flags.limits.memory_max == null and flags.limits.pids_max == null and flags.limits.cpu_max_usec == null);
    try std.testing.expectEqualStrings("-c", flags.user_argv.items[0]);

    const img: image_cmds.ImageResolution = .{ .rootfs = "/tmp/rootfs", .entrypoint = &.{"/original"}, .default_cmd = &.{"default"}, .user = "old", .working_dir = "/old" };
    var resolved = try resolveRunCommand(std.testing.allocator, &flags, &img);
    defer resolved.args.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("/bin/sh", resolved.command);
    var saved = try buildSavedRunConfig(std.testing.allocator, &flags, &img, &resolved, null);
    defer saved.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("1000:1000", saved.user.?);
    try std.testing.expectEqualStrings("/app", saved.working_dir);
    try std.testing.expectEqualStrings("inside", saved.hostname);
}

test "run rejects unknown options and invalid resource values without leaking" {
    const cases = [_][]const []const u8{
        &.{ "-e", "A=B", "--unknown", "image" },
        &.{ "--cpu-weight", "0", "image" },
        &.{ "--cpu-weight", "10001", "image" },
        &.{ "--cpus", "nan", "image" },
        &.{ "--cpus", "0.000001", "image" },
        &.{ "--workdir", "relative", "image" },
        &.{ "--pull", "sometimes", "image" },
        &.{ "-e", "A=B", "--name" },
    };
    for (cases) |values| {
        var args: TestArgs = .{ .values = values };
        try std.testing.expectError(ContainerError.InvalidArgument, parseRunFlags(&args, std.testing.allocator, std.testing.io));
    }
}

test "entrypoint override clears image arguments including empty entrypoint" {
    var flags: RunFlags = .{ .entrypoint = "/new" };
    defer flags.deinit(std.testing.allocator);
    const img: image_cmds.ImageResolution = .{ .rootfs = "/rootfs", .entrypoint = &.{ "/old", "old-argument" }, .default_cmd = &.{"default"} };
    var resolved = try resolveRunCommand(std.testing.allocator, &flags, &img);
    defer resolved.args.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("/new", resolved.command);
    try std.testing.expectEqual(@as(usize, 0), resolved.args.items.len);
    flags.entrypoint = "";
    try flags.user_argv.append(std.testing.allocator, "echo");
    var cleared = try resolveRunCommand(std.testing.allocator, &flags, &img);
    defer cleared.args.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("echo", cleared.command);
}

test "env files preserve literal values and later overrides remove unset names" {
    const alloc = std.testing.allocator;
    var env: std.ArrayList([]const u8) = .empty;
    defer {
        for (env.items) |value| alloc.free(value);
        env.deinit(alloc);
    }
    try appendEnvFile(alloc, &env, "# comment\r\n\n A=one\r\nB=literal # value\nA=two\n");
    const merged = try mergeEnv(alloc, &.{ "A=image", "C=keep" }, env.items);
    defer freeOwnedStringList(alloc, merged);
    try std.testing.expectEqualStrings("A=two", merged[0]);
    try std.testing.expectEqualStrings("C=keep", merged[1]);
    try std.testing.expectEqualStrings("B=literal # value", merged[2]);
    const removed = try mergeEnv(alloc, merged, &.{ "A", "B=cli" });
    defer freeOwnedStringList(alloc, removed);
    try std.testing.expectEqual(@as(usize, 2), removed.len);
    try std.testing.expectEqualStrings("C=keep", removed[0]);
    try std.testing.expectEqualStrings("B=cli", removed[1]);
}

test "run environment file values precede explicit environment options" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "env", .data = "VALUE=file\nSECOND=two\n" });
    const path = try tmp.dir.realPathFileAlloc(std.testing.io, "env", alloc);
    defer alloc.free(path);
    var args: TestArgs = .{ .values = &.{ "-e", "VALUE=cli", "--env-file", path, "image" } };
    var flags = try parseRunFlags(&args, alloc, std.testing.io);
    defer flags.deinit(alloc);
    const env = try mergeEnv(alloc, &.{"VALUE=image"}, flags.env.items);
    defer freeOwnedStringList(alloc, env);
    try std.testing.expectEqualStrings("VALUE=cli", env[0]);
    try std.testing.expectEqualStrings("SECOND=two", env[1]);
}

test "run accepts equals values and rejects values on switches" {
    var args: TestArgs = .{ .values = &.{ "--entrypoint=", "--pull=never", "--env=VALUE=a=b", "--hostname=inside", "image", "echo" } };
    var flags = try parseRunFlags(&args, std.testing.allocator, std.testing.io);
    defer flags.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("", flags.entrypoint.?);
    try std.testing.expectEqualStrings("VALUE=a=b", flags.env.items[0]);
    try std.testing.expectEqualStrings("inside", flags.hostname.?);
    var invalid: TestArgs = .{ .values = &.{ "--detach=false", "image" } };
    try std.testing.expectError(ContainerError.InvalidArgument, parseRunFlags(&invalid, std.testing.allocator, std.testing.io));
}

test "saved run configuration inherits the image user and working directory" {
    const alloc = std.testing.allocator;
    var flags: RunFlags = .{ .container_name = "named-container" };
    defer flags.deinit(alloc);
    const img: image_cmds.ImageResolution = .{ .rootfs = "/rootfs", .user = "app:staff", .working_dir = "/work", .default_cmd = &.{ "echo", "hello" } };
    var resolved = try resolveRunCommand(alloc, &flags, &img);
    defer resolved.args.deinit(alloc);
    const saved = try buildSavedRunConfig(alloc, &flags, &img, &resolved, null);
    defer saved.deinit(alloc);
    try std.testing.expectEqualStrings("app:staff", saved.user.?);
    try std.testing.expectEqualStrings("/work", saved.working_dir);
    try std.testing.expectEqualStrings("container", saved.hostname);
}

test "environment passthrough copies the current host value" {
    const value = std.c.getenv("PATH") orelse return error.SkipZigTest;
    const alloc = std.testing.allocator;
    var env: std.ArrayList([]const u8) = .empty;
    defer {
        for (env.items) |entry| alloc.free(entry);
        env.deinit(alloc);
    }
    try appendEnv(alloc, &env, "PATH");
    try std.testing.expect(std.mem.startsWith(u8, env.items[0], "PATH="));
    try std.testing.expectEqualStrings(std.mem.span(value), env.items[0][5..]);
}

test "run flags parse cpu affinity shared memory and typed tmpfs" {
    const alloc = std.testing.allocator;
    var args: TestArgs = .{ .values = &.{ "--restart", "on-failure:2", "--cpuset-cpus=1-3,5", "--shm-size", "128m", "--tmpfs", "/cache:size=16m,mode=750,noexec", "image" } };
    var flags = try parseRunFlags(&args, alloc, std.testing.io);
    defer flags.deinit(alloc);
    try std.testing.expectEqualStrings("1-3,5", flags.limits.cpuset_cpus.?.text());
    try std.testing.expectEqual(@as(?u32, 2), flags.restart_max_retries);
    try std.testing.expectEqual(@as(u64, 128 * 1024 * 1024), flags.shm_size);
    try std.testing.expectEqual(@as(usize, 1), flags.tmpfs_mounts.items.len);
    try std.testing.expectEqual(@as(u16, 0o750), flags.tmpfs_mounts.items[0].mode);
    try std.testing.expect(flags.tmpfs_mounts.items[0].noexec);
    for ([_][]const []const u8{
        &.{ "--cpuset-cpus", "3-1", "image" },
        &.{ "--shm-size", "0", "image" },
        &.{ "--tmpfs", "/cache:mode=888", "image" },
        &.{ "--tmpfs", "/cache", "--tmpfs", "/cache:ro", "image" },
        &.{ "--tmpfs", "/cache", "-v", "data:/cache", "image" },
    }) |values| {
        var invalid: TestArgs = .{ .values = values };
        try std.testing.expectError(ContainerError.InvalidArgument, parseRunFlags(&invalid, alloc, std.testing.io));
    }
}
