const std = @import("std");
const cli = @import("lib/cli.zig");
const store = @import("state/store.zig");
const container = @import("runtime/container.zig");
const process = @import("runtime/process.zig");
const logs = @import("runtime/logs.zig");
const spec = @import("image/spec.zig");
const oci = @import("image/oci.zig");
const image_cmds = @import("image/commands.zig");
const net_setup = @import("network/setup.zig");
const ip = @import("network/ip.zig");
const exec = @import("runtime/exec.zig");
const dockerfile = @import("build/dockerfile.zig");
const build_engine = @import("build/engine.zig");
const build_manifest = @import("build/manifest.zig");
const manifest_loader = @import("manifest/loader.zig");
const orchestrator = @import("manifest/orchestrator.zig");
const watcher_mod = @import("dev/watcher.zig");
const manifest_spec = @import("manifest/spec.zig");
const health = @import("manifest/health.zig");
const update = @import("manifest/update.zig");
const http_client = @import("cluster/http_client.zig");
const cluster_cmds = @import("cluster/commands.zig");
const json_helpers = @import("lib/json_helpers.zig");
const sqlite = @import("sqlite");
const state_cmds = @import("state/commands.zig");
const monitor = @import("runtime/monitor.zig");
const cgroups = @import("runtime/cgroups.zig");
const ebpf = @import("network/ebpf.zig");
const net_policy = @import("network/policy.zig");
const net_cmds = @import("network/commands.zig");
const runtime_cmds = @import("runtime/commands.zig");
const tls_cmds = @import("tls/commands.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const parsePortMap = cli.parsePortMap;
const isValidContainerName = cli.isValidContainerName;
const requireArg = cli.requireArg;
const formatTimestamp = cli.formatTimestamp;
const formatCount = cli.formatCount;
const truncate = cli.truncate;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    // skip program name
    _ = args.next();

    const command = args.next() orelse {
        printUsage();
        return;
    };

    if (std.mem.eql(u8, command, "version")) {
        write("yoq 0.0.1\n", .{});
    } else if (std.mem.eql(u8, command, "help")) {
        printUsage();
    } else if (std.mem.eql(u8, command, "run")) {
        cmdRun(&args, alloc);
    } else if (std.mem.eql(u8, command, "ps")) {
        cmdPs(alloc);
    } else if (std.mem.eql(u8, command, "stop")) {
        cmdStop(&args, alloc);
    } else if (std.mem.eql(u8, command, "rm")) {
        cmdRm(&args, alloc);
    } else if (std.mem.eql(u8, command, "logs")) {
        cmdLogs(&args, alloc);
    } else if (std.mem.eql(u8, command, "pull")) {
        image_cmds.pull(&args, alloc);
    } else if (std.mem.eql(u8, command, "push")) {
        image_cmds.push(&args, alloc);
    } else if (std.mem.eql(u8, command, "images")) {
        image_cmds.images(alloc);
    } else if (std.mem.eql(u8, command, "rmi")) {
        image_cmds.rmi(&args, alloc);
    } else if (std.mem.eql(u8, command, "prune")) {
        image_cmds.prune(alloc);
    } else if (std.mem.eql(u8, command, "inspect")) {
        image_cmds.inspect(&args, alloc);
    } else if (std.mem.eql(u8, command, "exec")) {
        cmdExec(&args, alloc);
    } else if (std.mem.eql(u8, command, "build")) {
        cmdBuild(&args, alloc);
    } else if (std.mem.eql(u8, command, "up")) {
        cmdUp(&args, alloc);
    } else if (std.mem.eql(u8, command, "down")) {
        cmdDown(&args, alloc);
    } else if (std.mem.eql(u8, command, "serve")) {
        cluster_cmds.serve(&args, alloc);
    } else if (std.mem.eql(u8, command, "init-server")) {
        cluster_cmds.initServer(&args, alloc);
    } else if (std.mem.eql(u8, command, "join")) {
        cluster_cmds.join(&args, alloc);
    } else if (std.mem.eql(u8, command, "cluster")) {
        cluster_cmds.cluster(&args, alloc);
    } else if (std.mem.eql(u8, command, "nodes")) {
        cluster_cmds.nodes(&args, alloc);
    } else if (std.mem.eql(u8, command, "drain")) {
        cluster_cmds.drain(&args, alloc);
    } else if (std.mem.eql(u8, command, "rollback")) {
        cmdRollback(&args, alloc);
    } else if (std.mem.eql(u8, command, "history")) {
        cmdHistory(&args, alloc);
    } else if (std.mem.eql(u8, command, "secret")) {
        state_cmds.secret(&args, alloc);
    } else if (std.mem.eql(u8, command, "status")) {
        runtime_cmds.status(&args, alloc);
    } else if (std.mem.eql(u8, command, "metrics")) {
        runtime_cmds.metrics(&args, alloc);
    } else if (std.mem.eql(u8, command, "policy")) {
        net_cmds.policy(&args, alloc);
    } else if (std.mem.eql(u8, command, "cert")) {
        tls_cmds.cert(&args, alloc);
    } else {
        writeErr("unknown command: {s}\n", .{command});
        printUsage();
        std.process.exit(1);
    }
}

const RunFlags = struct {
    port_maps: std.ArrayList(net_setup.PortMap),
    networking_enabled: bool,
    container_name: ?[]const u8,
    target: []const u8,
    user_argv: std.ArrayList([]const u8),
};

/// parse CLI flags for `yoq run`. consumes args up to and including the target,
/// then collects remaining args as user command.
fn parseRunFlags(args: *std.process.ArgIterator, alloc: std.mem.Allocator) RunFlags {
    var port_maps: std.ArrayList(net_setup.PortMap) = .empty;
    var networking_enabled = true;
    var container_name: ?[]const u8 = null;
    var target: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--name")) {
            const name_val = args.next() orelse {
                writeErr("--name requires a container name\n", .{});
                std.process.exit(1);
            };
            if (!isValidContainerName(name_val)) {
                writeErr("invalid container name: {s}\n", .{name_val});
                writeErr("names must be 1-63 chars, alphanumeric or hyphens, no leading/trailing hyphen\n", .{});
                std.process.exit(1);
            }
            container_name = name_val;
        } else if (std.mem.eql(u8, arg, "-p")) {
            const port_str = args.next() orelse {
                writeErr("-p requires host_port:container_port\n", .{});
                std.process.exit(1);
            };
            const pm = parsePortMap(port_str) orelse {
                writeErr("invalid port mapping: {s}\n", .{port_str});
                std.process.exit(1);
            };
            port_maps.append(alloc, pm) catch |e| {
                writeErr("failed to add port mapping: {}\n", .{e});
            };
        } else if (std.mem.eql(u8, arg, "--no-net")) {
            networking_enabled = false;
        } else if (std.mem.eql(u8, arg, "--net")) {
            networking_enabled = true;
        } else {
            target = arg;
            break;
        }
    }

    const run_target = target orelse {
        writeErr("usage: yoq run [--name <name>] [-p host:container] [--no-net] <image|rootfs> [command]\n", .{});
        std.process.exit(1);
    };

    // collect user-provided command + args
    var user_argv: std.ArrayList([]const u8) = .empty;
    while (args.next()) |arg| {
        user_argv.append(alloc, arg) catch |e| {
            writeErr("failed to add command argument: {}\n", .{e});
        };
    }

    return .{
        .port_maps = port_maps,
        .networking_enabled = networking_enabled,
        .container_name = container_name,
        .target = run_target,
        .user_argv = user_argv,
    };
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
        .mask = std.posix.empty_sigset,
        .flags = @bitCast(@as(u32, 0x10000000)), // SA_RESTART
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
}

fn cmdRun(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var flags = parseRunFlags(args, alloc);
    defer flags.port_maps.deinit(alloc);
    defer flags.user_argv.deinit(alloc);

    // detect if target is an image reference or a local rootfs path
    const is_image = !std.mem.startsWith(u8, flags.target, "/") and
        !std.mem.startsWith(u8, flags.target, "./");

    // resolve image config or use local rootfs
    var img = if (is_image)
        image_cmds.pullAndResolveImage(alloc, flags.target)
    else
        image_cmds.ImageResolution{ .rootfs = flags.target };
    defer img.deinit();

    // resolve effective command per OCI spec
    var resolved = oci.resolveCommand(alloc, img.entrypoint, img.default_cmd, flags.user_argv.items) catch {
        writeErr("failed to resolve command: out of memory\n", .{});
        std.process.exit(1);
    };
    defer resolved.args.deinit(alloc);

    // generate container id
    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf);
    const id = id_buf[0..];

    // save container record
    store.save(.{
        .id = id,
        .rootfs = img.rootfs,
        .command = resolved.command,
        .hostname = flags.container_name orelse "container",
        .status = "created",
        .pid = null,
        .exit_code = null,
        .created_at = std.time.timestamp(),
    }) catch {
        writeErr("failed to save container state\n", .{});
        std.process.exit(1);
    };

    // build network config
    const net_config: ?net_setup.NetworkConfig = if (flags.networking_enabled)
        .{ .port_maps = flags.port_maps.items }
    else
        null;

    // build container config and start execution
    var c = container.Container{
        .config = .{
            .id = id,
            .rootfs = img.rootfs,
            .command = resolved.command,
            .args = resolved.args.items,
            .env = img.image_env,
            .working_dir = img.working_dir,
            .lower_dirs = img.layer_paths,
            .network = net_config,
        },
        .status = .created,
        .pid = null,
        .exit_code = null,
        .created_at = std.time.timestamp(),
    };

    // forward SIGINT/SIGTERM to the container so Ctrl+C stops it
    installSignalHandlers();

    c.start() catch {
        // clean up the DB record and dirs so yoq ps doesn't show a ghost
        store.remove(id) catch {};
        container.cleanupContainerDirs(id);
        writeErr("failed to start container\n", .{});
        std.process.exit(1);
    };

    // only print the ID after successful start
    write("{s}\n", .{id});

    // exit with the container's exit code
    std.process.exit(c.exit_code orelse 0);
}

fn cmdPs(alloc: std.mem.Allocator) void {
    var ids = store.listIds(alloc) catch {
        writeErr("failed to list containers\n", .{});
        std.process.exit(1);
    };
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    if (ids.items.len == 0) {
        write("no containers\n", .{});
        return;
    }

    write("{s:<14} {s:<10} {s:<16} {s:<20}\n", .{ "CONTAINER ID", "STATUS", "IP", "COMMAND" });
    for (ids.items) |id| {
        const record = store.load(alloc, id) catch {
            write("{s:<14} {s:<10} {s:<16} {s:<20}\n", .{ id, "unknown", "-", "-" });
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

fn cmdStop(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const id = requireArg(args, "usage: yoq stop <container-id>\n");

    // load container record to get the pid
    const record = store.load(alloc, id) catch {
        writeErr("container not found: {s}\n", .{id});
        std.process.exit(1);
    };
    defer record.deinit(alloc);

    if (!std.mem.eql(u8, record.status, "running")) {
        writeErr("container {s} is not running (status: {s})\n", .{ id, record.status });
        std.process.exit(1);
    }

    const pid = record.pid orelse {
        writeErr("container {s} has no pid\n", .{id});
        std.process.exit(1);
    };

    // check if the process is actually still alive before sending SIGTERM
    process.sendSignal(pid, 0) catch {
        // already dead — just update the record
        store.updateStatus(id, "stopped", null, null) catch {};
        write("{s} (already stopped)\n", .{id});
        return;
    };

    process.terminate(pid) catch {
        writeErr("failed to stop container {s}\n", .{id});
        std.process.exit(1);
    };

    // clean up network resources
    cleanupNetwork(id, record.ip_address, record.veth_host);

    store.updateStatus(id, "stopped", null, null) catch |e| {
        writeErr("warning: failed to update container status: {}\n", .{e});
    };

    write("{s}\n", .{id});
}

fn cmdExec(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const id = args.next() orelse {
        writeErr("usage: yoq exec <container-id> <command> [args...]\n", .{});
        std.process.exit(1);
    };

    const record = store.load(alloc, id) catch {
        writeErr("container not found: {s}\n", .{id});
        std.process.exit(1);
    };
    defer record.deinit(alloc);

    if (!std.mem.eql(u8, record.status, "running")) {
        writeErr("container {s} is not running (status: {s})\n", .{ id, record.status });
        std.process.exit(1);
    }

    const pid = record.pid orelse {
        writeErr("container {s} has no pid\n", .{id});
        std.process.exit(1);
    };

    const command = args.next() orelse {
        writeErr("usage: yoq exec <container-id> <command> [args...]\n", .{});
        std.process.exit(1);
    };

    // collect remaining args
    var exec_args: std.ArrayList([]const u8) = .empty;
    defer exec_args.deinit(alloc);
    while (args.next()) |arg| {
        exec_args.append(alloc, arg) catch |e| {
            writeErr("failed to add exec argument: {}\n", .{e});
        };
    }

    const exit_code = exec.execInContainer(.{
        .pid = pid,
        .command = command,
        .args = exec_args.items,
        .env = &.{},
        .working_dir = "/",
    }) catch {
        writeErr("failed to exec in container {s}\n", .{id});
        std.process.exit(1);
    };

    std.process.exit(exit_code);
}

fn cmdRm(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const id = requireArg(args, "usage: yoq rm <container-id>\n");

    // load record to check status and get network info
    const record = store.load(alloc, id) catch {
        writeErr("container not found: {s}\n", .{id});
        std.process.exit(1);
    };

    if (std.mem.eql(u8, record.status, "running")) {
        record.deinit(alloc);
        writeErr("cannot remove running container {s} — stop it first\n", .{id});
        std.process.exit(1);
    }

    cleanupStoppedContainer(id, record.ip_address, record.veth_host);
    record.deinit(alloc);

    write("{s}\n", .{id});
}

fn cmdLogs(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const id = requireArg(args, "usage: yoq logs <container-id> [--tail N]\n");

    // check for --tail flag
    var tail_lines: usize = 0;
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
        }
    }

    const content = if (tail_lines > 0)
        logs.readTail(alloc, id, tail_lines)
    else
        logs.readLogs(alloc, id);

    const data = content catch {
        writeErr("no logs found for container: {s}\n", .{id});
        std.process.exit(1);
    };
    defer alloc.free(data);

    if (data.len == 0) {
        write("(no output)\n", .{});
        return;
    }

    write("{s}", .{data});
}



/// validate an image tag per OCI distribution spec constraints.
/// tags must be alphanumeric with '.', '-', '_' separators, max 128 chars.
fn isValidTag(tag: []const u8) bool {
    if (tag.len == 0 or tag.len > 128) return false;
    for (tag) |c| {
        if (std.ascii.isAlphanumeric(c)) continue;
        if (c == '.' or c == '-' or c == '_') continue;
        return false;
    }
    return true;
}

fn cmdBuild(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var tag: ?[]const u8 = null;
    var dockerfile_path: []const u8 = "Dockerfile";
    var context_path: ?[]const u8 = null;
    var format: enum { dockerfile, toml } = .dockerfile;
    var build_args_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer build_args_list.deinit(alloc);

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-t")) {
            tag = args.next() orelse {
                writeErr("-t requires an image tag\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "-f")) {
            dockerfile_path = args.next() orelse {
                writeErr("-f requires a Dockerfile path\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--format")) {
            const fmt = args.next() orelse {
                writeErr("--format requires 'dockerfile' or 'toml'\n", .{});
                std.process.exit(1);
            };
            if (std.mem.eql(u8, fmt, "toml")) {
                format = .toml;
            } else if (std.mem.eql(u8, fmt, "dockerfile")) {
                format = .dockerfile;
            } else {
                writeErr("unknown format '{s}', expected 'dockerfile' or 'toml'\n", .{fmt});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--build-arg")) {
            const ba = args.next() orelse {
                writeErr("--build-arg requires KEY=VALUE\n", .{});
                std.process.exit(1);
            };
            build_args_list.append(alloc, ba) catch {
                writeErr("out of memory\n", .{});
                std.process.exit(1);
            };
        } else {
            context_path = arg;
        }
    }

    const ctx_dir = context_path orelse ".";

    // validate tag format
    if (tag) |t| {
        const ref = spec.parseImageRef(t);
        if (!isValidTag(ref.reference)) {
            writeErr("invalid tag: must be alphanumeric with '.', '-', '_' (max 128 chars)\n", .{});
            std.process.exit(1);
        }
    }

    // determine the build file path and default filename based on format
    const default_filename: []const u8 = switch (format) {
        .dockerfile => "Dockerfile",
        .toml => "build.toml",
    };
    const using_default = std.mem.eql(u8, dockerfile_path, "Dockerfile");

    var df_path_buf: [4096]u8 = undefined;
    const effective_path = if (using_default)
        std.fmt.bufPrint(&df_path_buf, "{s}/{s}", .{ ctx_dir, default_filename }) catch {
            writeErr("path too long\n", .{});
            std.process.exit(1);
        }
    else
        dockerfile_path;

    // parse instructions — both formats produce []Instruction
    var instructions: []const dockerfile.Instruction = undefined;

    // we need to track which deinit to call
    var df_parsed: ?dockerfile.ParseResult = null;
    var toml_parsed: ?build_manifest.LoadResult = null;

    switch (format) {
        .dockerfile => {
            const content = std.fs.cwd().readFileAlloc(alloc, effective_path, 1024 * 1024) catch {
                writeErr("cannot read {s}\n", .{effective_path});
                std.process.exit(1);
            };
            defer alloc.free(content);

            const parsed = dockerfile.parse(alloc, content) catch |err| {
                switch (err) {
                    dockerfile.ParseError.UnknownInstruction => writeErr("unknown instruction in Dockerfile\n", .{}),
                    dockerfile.ParseError.EmptyInstruction => writeErr("empty instruction in Dockerfile\n", .{}),
                    dockerfile.ParseError.OutOfMemory => writeErr("out of memory\n", .{}),
                }
                std.process.exit(1);
            };
            df_parsed = parsed;
            instructions = parsed.instructions;
        },
        .toml => {
            const parsed = build_manifest.load(alloc, effective_path) catch |err| {
                switch (err) {
                    build_manifest.LoadError.FileNotFound => writeErr("cannot find {s}\n", .{effective_path}),
                    build_manifest.LoadError.ReadFailed => writeErr("cannot read {s}\n", .{effective_path}),
                    build_manifest.LoadError.ParseFailed => writeErr("invalid TOML in {s}\n", .{effective_path}),
                    build_manifest.LoadError.MissingFrom => writeErr("stage missing required 'from' field\n", .{}),
                    build_manifest.LoadError.InvalidStep => writeErr("invalid step in build manifest\n", .{}),
                    build_manifest.LoadError.EmptyManifest => writeErr("no stages found in build manifest\n", .{}),
                    build_manifest.LoadError.CyclicDependency => writeErr("circular dependency between stages\n", .{}),
                    build_manifest.LoadError.OutOfMemory => writeErr("out of memory\n", .{}),
                }
                std.process.exit(1);
            };
            toml_parsed = parsed;
            instructions = parsed.instructions;
        },
    }
    defer {
        if (df_parsed) |*p| p.deinit();
        if (toml_parsed) |*p| p.deinit();
    }

    writeErr("building from {s} ({d} instructions)...\n", .{
        effective_path, instructions.len,
    });

    // resolve context directory to absolute path
    var abs_ctx_buf: [4096]u8 = undefined;
    const abs_ctx = std.fs.cwd().realpath(ctx_dir, &abs_ctx_buf) catch {
        writeErr("cannot resolve context directory: {s}\n", .{ctx_dir});
        std.process.exit(1);
    };

    // build
    const cli_args: ?[]const []const u8 = if (build_args_list.items.len > 0)
        build_args_list.items
    else
        null;
    var result = build_engine.build(alloc, instructions, abs_ctx, tag, cli_args) catch |err| {
        switch (err) {
            build_engine.BuildError.NoFromInstruction => writeErr("build must start with FROM\n", .{}),
            build_engine.BuildError.PullFailed => writeErr("failed to pull base image\n", .{}),
            build_engine.BuildError.RunStepFailed => writeErr("RUN step failed\n", .{}),
            build_engine.BuildError.CopyStepFailed => writeErr("COPY step failed\n", .{}),
            build_engine.BuildError.LayerFailed => writeErr("failed to create layer\n", .{}),
            build_engine.BuildError.ImageStoreFailed => writeErr("failed to store image\n", .{}),
            build_engine.BuildError.ParseFailed => writeErr("failed to parse build instructions\n", .{}),
            build_engine.BuildError.CacheFailed => writeErr("cache error\n", .{}),
        }
        std.process.exit(1);
    };
    defer result.deinit();

    const size_mb = result.total_size / (1024 * 1024);

    if (tag) |t| {
        write("built {s} ({d} layers, {d} MB)\n", .{ t, result.layer_count, size_mb });
    } else {
        // show short digest
        const short_id = if (result.manifest_digest.len > 19)
            result.manifest_digest[7..19]
        else
            result.manifest_digest;
        write("built {s} ({d} layers, {d} MB)\n", .{ short_id, result.layer_count, size_mb });
    }
}

fn cmdUp(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var manifest_path: []const u8 = manifest_loader.default_filename;
    var dev_mode = false;
    var server_addr: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--dev")) {
            dev_mode = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                std.process.exit(1);
            };
        }
    }

    // load and validate manifest
    var manifest = manifest_loader.load(alloc, manifest_path) catch {
        writeErr("failed to load manifest: {s}\n", .{manifest_path});
        std.process.exit(1);
    };
    defer manifest.deinit();

    // if --server is set, deploy to cluster instead of running locally
    if (server_addr) |addr| {
        deployToCluster(alloc, addr, &manifest);
        return;
    }

    // derive app name from cwd basename
    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.fs.cwd().realpath(".", &cwd_buf) catch {
        writeErr("failed to resolve working directory\n", .{});
        std.process.exit(1);
    };
    const app_name = std.fs.path.basename(cwd);

    if (dev_mode) {
        writeErr("starting {s} in dev mode ({d} services)...\n", .{ app_name, manifest.services.len });
    } else {
        writeErr("starting {s} ({d} services)...\n", .{ app_name, manifest.services.len });
    }

    // install signal handlers for graceful shutdown
    orchestrator.installSignalHandlers();

    // create and run orchestrator
    var orch = orchestrator.Orchestrator.init(alloc, &manifest, app_name) catch {
        writeErr("failed to initialize orchestrator\n", .{});
        std.process.exit(1);
    };
    defer orch.deinit();
    orch.dev_mode = dev_mode;

    orch.startAll() catch {
        writeErr("failed to start services\n", .{});
        std.process.exit(1);
    };

    // in dev mode, set up file watcher for bind-mounted volumes
    var w: ?watcher_mod.Watcher = null;
    var watcher_thread: ?std.Thread = null;

    if (dev_mode) {
        w = watcher_mod.Watcher.init() catch |e| blk: {
            writeErr("warning: file watcher unavailable: {}\n", .{e});
            break :blk null;
        };

        if (w != null) {
            // add watches for each service's bind-mounted volumes
            for (manifest.services, 0..) |svc, i| {
                for (svc.volumes) |vol| {
                    if (vol.kind != .bind) continue;

                    // resolve relative source path to absolute
                    var resolve_buf: [4096]u8 = undefined;
                    const abs_source = std.fs.cwd().realpath(vol.source, &resolve_buf) catch continue;

                    w.?.addRecursive(abs_source, i) catch |e| {
                        writeErr("warning: failed to watch {s}: {}\n", .{ vol.source, e });
                    };
                }
            }

            // spawn watcher thread
            watcher_thread = std.Thread.spawn(.{}, orchestrator.watcherThread, .{
                &orch, &w.?,
            }) catch |e| blk: {
                writeErr("warning: failed to start watcher thread: {}\n", .{e});
                break :blk null;
            };
        }

        writeErr("all services running. watching for changes...\n", .{});
    } else {
        writeErr("all services running. press ctrl-c to stop.\n", .{});
    }

    // block until shutdown signal or all services exit
    orch.waitForShutdown();

    writeErr("\nshutting down...\n", .{});

    // clean up watcher before stopping services (closes fd, unblocks watcher thread)
    if (w) |*watcher| watcher.deinit();
    if (watcher_thread) |t| t.join();

    orch.stopAll();
    writeErr("stopped\n", .{});
}

/// deploy manifest services to a cluster server via POST /deploy.
fn deployToCluster(alloc: std.mem.Allocator, addr_str: []const u8, manifest: *const manifest_spec.Manifest) void {
    const server = cli.parseServerAddr(addr_str);
    const server_ip = server.ip;
    const server_port = server.port;

    // build JSON body: {"services":[{"image":"...","command":"...","cpu_limit":N,"memory_limit_mb":N},...]}
    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeAll("{\"services\":[") catch {
        writeErr("failed to build deploy request\n", .{});
        std.process.exit(1);
    };

    for (manifest.services, 0..) |svc, i| {
        if (i > 0) writer.writeByte(',') catch break;

        // join command args into a single string
        var cmd_buf: [1024]u8 = undefined;
        var cmd_len: usize = 0;
        for (svc.command, 0..) |arg, j| {
            if (j > 0) {
                if (cmd_len < cmd_buf.len) {
                    cmd_buf[cmd_len] = ' ';
                    cmd_len += 1;
                }
            }
            const copy_len = @min(arg.len, cmd_buf.len - cmd_len);
            @memcpy(cmd_buf[cmd_len..][0..copy_len], arg[0..copy_len]);
            cmd_len += copy_len;
        }

        // use JSON escaping for image and command values — they could contain
        // quotes or special characters that would produce malformed JSON
        writer.writeAll("{\"image\":\"") catch break;
        json_helpers.writeJsonEscaped(writer, svc.image) catch break;
        writer.writeAll("\",\"command\":\"") catch break;
        json_helpers.writeJsonEscaped(writer, cmd_buf[0..cmd_len]) catch break;
        writer.writeAll("\",\"cpu_limit\":1000,\"memory_limit_mb\":256}") catch break;
    }

    writer.writeAll("]}") catch {
        writeErr("failed to build deploy request\n", .{});
        std.process.exit(1);
    };

    writeErr("deploying {d} services to cluster {s}...\n", .{ manifest.services.len, addr_str });

    // POST to /deploy with auth token if available
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.postWithAuth(alloc, server_ip, server_port, "/deploy", json_buf.items, token) catch {
        writeErr("failed to connect to cluster server\n", .{});
        std.process.exit(1);
    };
    defer resp.deinit(alloc);

    if (resp.status_code == 200) {
        write("{s}\n", .{resp.body});
    } else {
        writeErr("deploy failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        std.process.exit(1);
    }
}

fn cmdDown(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var manifest_path: []const u8 = manifest_loader.default_filename;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                std.process.exit(1);
            };
        }
    }

    // load manifest to get service names and ordering
    var manifest = manifest_loader.load(alloc, manifest_path) catch {
        writeErr("failed to load manifest: {s}\n", .{manifest_path});
        std.process.exit(1);
    };
    defer manifest.deinit();

    // derive app name from cwd basename
    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.fs.cwd().realpath(".", &cwd_buf) catch {
        writeErr("failed to resolve working directory\n", .{});
        std.process.exit(1);
    };
    const app_name = std.fs.path.basename(cwd);

    // find all containers belonging to this app
    var ids = store.listAppContainerIds(alloc, app_name) catch {
        writeErr("failed to query app containers\n", .{});
        std.process.exit(1);
    };
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    if (ids.items.len == 0) {
        writeErr("no running services found for {s}\n", .{app_name});
        return;
    }

    // stop containers in reverse dependency order.
    // iterate services in reverse (manifest is topo-sorted, so reverse = dependents first)
    var i: usize = manifest.services.len;
    while (i > 0) {
        i -= 1;
        const svc = manifest.services[i];

        // find this service's container by app_name + hostname
        const record = store.findAppContainer(alloc, app_name, svc.name) catch continue;
        const rec = record orelse continue;
        defer rec.deinit(alloc);

        writeErr("stopping {s}...", .{svc.name});

        if (std.mem.eql(u8, rec.status, "running")) {
            if (rec.pid) |pid| {
                process.terminate(pid) catch {
                    process.kill(pid) catch {};
                };

                // wait briefly for process to exit
                var waited: u32 = 0;
                while (waited < 100) : (waited += 1) {
                    const result = process.wait(pid, true) catch break;
                    switch (result.status) {
                        .running => std.Thread.sleep(100 * std.time.ns_per_ms),
                        else => break,
                    }
                }
            }
        }

        // update status and clean up
        store.updateStatus(rec.id, "stopped", null, null) catch |e| {
            writeErr("warning: failed to update status for {s}: {}\n", .{ svc.name, e });
        };
        cleanupStoppedContainer(rec.id, rec.ip_address, rec.veth_host);

        writeErr(" stopped\n", .{});
    }

    writeErr("all services stopped\n", .{});
}

// cluster commands moved to cluster/commands.zig

// -- deployment commands --

fn cmdRollback(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const service_name = args.next() orelse {
        writeErr("usage: yoq rollback <service>\n", .{});
        std.process.exit(1);
    };

    // look up the previous successful deployment
    const config = update.rollback(alloc, service_name) catch |err| {
        switch (err) {
            update.UpdateError.NoPreviousDeployment => {
                writeErr("no previous deployment found for {s}\n", .{service_name});
            },
            update.UpdateError.StoreFailed => {
                writeErr("failed to read deployment history\n", .{});
            },
            else => {
                writeErr("rollback failed\n", .{});
            },
        }
        std.process.exit(1);
    };
    defer alloc.free(config);

    write("rollback config for {s}:\n{s}\n", .{ service_name, config });
    write("\nto apply this rollback, redeploy with this config using 'yoq up'\n", .{});
}

fn cmdHistory(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const service_name = args.next() orelse {
        writeErr("usage: yoq history <service>\n", .{});
        std.process.exit(1);
    };

    var deployments = store.listDeployments(alloc, service_name) catch {
        writeErr("failed to read deployment history\n", .{});
        std.process.exit(1);
    };
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    if (deployments.items.len == 0) {
        write("no deployments found for {s}\n", .{service_name});
        return;
    }

    write("{s:<14} {s:<14} {s:<14} {s:<20} {s}\n", .{ "ID", "STATUS", "HASH", "TIMESTAMP", "MESSAGE" });

    for (deployments.items) |dep| {
        // format timestamp as a simple unix time string.
        // full date formatting is deferred until we have a time library.
        var ts_buf: [20]u8 = undefined;
        const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{dep.created_at}) catch "?";
        const msg = dep.message orelse "";

        write("{s:<14} {s:<14} {s:<14} {s:<20} {s}\n", .{
            truncate(dep.id, 12),
            dep.status,
            truncate(dep.manifest_hash, 12),
            ts_str,
            truncate(msg, 40),
        });
    }
}

fn printUsage() void {
    write(
        \\yoq — container runtime and orchestrator
        \\
        \\usage: yoq <command> [options]
        \\
        \\commands:
        \\  run [opts] <image|rootfs> [cmd]  create and run a container
        \\  up [-f manifest.toml] [--dev]     start services (--dev: watch + restart)
        \\     [--server host:port]           deploy to cluster instead of locally
        \\  down [-f manifest.toml]          stop all services from manifest
        \\  serve [--port PORT]             start the API server (default: 7700)
        \\  init-server [opts]              start a cluster server node
        \\  join <host> --token <token>     join a cluster as an agent node
        \\  cluster status                  show cluster node status
        \\  nodes [--server host:port]       list cluster agent nodes
        \\  drain <id> [--server host:port]  drain an agent node
        \\  secret set <name> [--value val] store a secret (reads stdin if no --value)
        \\  secret get <name>               print decrypted value
        \\  secret rm <name>                remove a secret
        \\  secret list                     list secret names
        \\  secret rotate <name>            re-encrypt with current key
        \\  build [opts] <path>              build an image from a Dockerfile
        \\  exec <id> <cmd> [args...]         run a command in a running container
        \\  status [--verbose] [--server h:p]  show service status and resources
        \\  metrics [service] [--server h:p]  show per-service network metrics
        \\  metrics --pairs [--server h:p]    show service-to-service pair metrics
        \\  cert install <domain> --cert <p> --key <p>  store a TLS certificate
        \\  cert list                        list certificates with expiry
        \\  cert rm <domain>                 remove a certificate
        \\  cert provision <domain> --email <e>  provision via ACME (Let's Encrypt)
        \\  cert renew <domain>              check/trigger certificate renewal
        \\  policy deny <src> <tgt>          block traffic from source to target
        \\  policy allow <src> <tgt>         allow only this destination for source
        \\  policy rm <src> <tgt>            remove a policy rule
        \\  policy list                      list all policy rules
        \\  ps                               list containers
        \\  logs <id>                        show container output
        \\  stop <id>                        stop a running container
        \\  rm <id>                          remove a stopped container
        \\  pull <image>                     pull an image from a registry
        \\  push <source> [target]           push an image to a registry
        \\  images                           list pulled images
        \\  rollback <service>               rollback to previous deployment
        \\  history <service>                show deployment history
        \\  rmi <image>                      remove a pulled image
        \\  prune                            remove unused blobs and layers
        \\  inspect <image>                  show image details
        \\  version                          print version
        \\  help                             show this help
        \\
        \\run options:
        \\  --name <name>             assign a name (used for DNS service discovery)
        \\  -p host:container         map host port to container port
        \\  --no-net                  disable networking
        \\
        \\build options:
        \\  -t <tag>                  image tag (e.g. myapp:latest)
        \\  -f <path>                 Dockerfile path (default: Dockerfile)
        \\
        \\cluster options:
        \\  --id <id>                 node ID (default: 1)
        \\  --port <port>             raft port (default: 9700)
        \\  --api-port <port>         API port (default: 7700)
        \\  --peers <peers>           peers (e.g. 2@10.0.0.2:9700,3@10.0.0.3:9700)
        \\  --token <token>           join token for agent authentication
        \\
        \\other options:
        \\  logs --tail N             show last N lines only
        \\
    , .{});
}

/// full cleanup for a stopped container: network, logs, dirs, then DB record.
/// DB record is removed last so we can still find orphaned resources if
/// an earlier cleanup step fails.
fn cleanupStoppedContainer(id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    cleanupNetwork(id, ip_address, veth_host);
    logs.deleteLogFile(id);
    container.cleanupContainerDirs(id);
    store.remove(id) catch |e| {
        writeErr("warning: failed to remove container record {s}: {}\n", .{ id, e });
    };
}

/// clean up network resources for a container (veth pair + IP allocation).
/// called from cmdStop and cmdRm. non-fatal — logs warnings on failure
/// to help debug network resource leaks.
fn cleanupNetwork(container_id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    const bridge = @import("network/bridge.zig");

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

// use shared JSON extraction helpers
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;
const extractJsonFloat = json_helpers.extractJsonFloat;

test "smoke test" {
    try std.testing.expect(true);
}

// pull in tests from all modules
comptime {
    _ = @import("runtime/container.zig");
    _ = @import("runtime/cgroups.zig");
    _ = @import("runtime/namespaces.zig");
    _ = @import("runtime/filesystem.zig");
    _ = @import("runtime/security.zig");
    _ = @import("runtime/process.zig");
    _ = @import("runtime/exec.zig");
    _ = @import("runtime/logs.zig");
    _ = @import("runtime/commands.zig");
    _ = @import("state/store.zig");
    _ = @import("state/schema.zig");
    _ = @import("state/commands.zig");
    _ = @import("lib/cli.zig");
    _ = @import("lib/exec_helpers.zig");
    _ = @import("lib/log.zig");
    _ = @import("lib/paths.zig");
    _ = @import("lib/toml.zig");
    _ = @import("lib/json_helpers.zig");
    _ = @import("lib/sql.zig");
    _ = @import("image/spec.zig");
    _ = @import("image/store.zig");
    _ = @import("image/registry.zig");
    _ = @import("image/layer.zig");
    _ = @import("image/oci.zig");
    _ = @import("image/commands.zig");
    _ = @import("network/netlink.zig");
    _ = @import("network/bridge.zig");
    _ = @import("network/dns.zig");
    _ = @import("network/ip.zig");
    _ = @import("network/nat.zig");
    _ = @import("network/setup.zig");
    _ = @import("network/wireguard.zig");
    _ = @import("network/ebpf.zig");
    _ = @import("network/commands.zig");
    _ = @import("build/dockerfile.zig");
    _ = @import("build/context.zig");
    _ = @import("build/engine.zig");
    _ = @import("build/manifest.zig");
    _ = @import("manifest/spec.zig");
    _ = @import("manifest/loader.zig");
    _ = @import("manifest/orchestrator.zig");
    _ = @import("manifest/health.zig");
    _ = @import("manifest/update.zig");
    _ = @import("dev/log_mux.zig");
    _ = @import("dev/watcher.zig");
    _ = @import("api/http.zig");
    _ = @import("api/routes.zig");
    _ = @import("api/server.zig");
    _ = @import("cluster/raft_types.zig");
    _ = @import("cluster/log.zig");
    _ = @import("cluster/raft.zig");
    _ = @import("cluster/transport.zig");
    _ = @import("cluster/state_machine.zig");
    _ = @import("cluster/node.zig");
    _ = @import("cluster/config.zig");
    _ = @import("cluster/agent_types.zig");
    _ = @import("cluster/registry.zig");
    _ = @import("cluster/http_client.zig");
    _ = @import("cluster/agent.zig");
    _ = @import("cluster/scheduler.zig");
    _ = @import("cluster/commands.zig");
    _ = @import("tls/commands.zig");
}
