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
const api_server = @import("api/server.zig");
const routes = @import("api/routes.zig");
const cluster_node = @import("cluster/node.zig");
const cluster_config = @import("cluster/config.zig");
const cluster_agent = @import("cluster/agent.zig");
const http_client = @import("cluster/http_client.zig");
const json_helpers = @import("lib/json_helpers.zig");
const paths = @import("lib/paths.zig");
const sqlite = @import("sqlite");
const secrets = @import("state/secrets.zig");
const dns = @import("network/dns.zig");
const monitor = @import("runtime/monitor.zig");
const cgroups = @import("runtime/cgroups.zig");
const ebpf = @import("network/ebpf.zig");
const net_policy = @import("network/policy.zig");
const cert_store = @import("tls/cert_store.zig");
const acme = @import("tls/acme.zig");

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
        cmdServe(&args, alloc);
    } else if (std.mem.eql(u8, command, "init-server")) {
        cmdInitServer(&args, alloc);
    } else if (std.mem.eql(u8, command, "join")) {
        cmdJoin(&args, alloc);
    } else if (std.mem.eql(u8, command, "cluster")) {
        cmdCluster(&args, alloc);
    } else if (std.mem.eql(u8, command, "nodes")) {
        cmdNodes(&args, alloc);
    } else if (std.mem.eql(u8, command, "drain")) {
        cmdDrain(&args, alloc);
    } else if (std.mem.eql(u8, command, "rollback")) {
        cmdRollback(&args, alloc);
    } else if (std.mem.eql(u8, command, "history")) {
        cmdHistory(&args, alloc);
    } else if (std.mem.eql(u8, command, "secret")) {
        cmdSecret(&args, alloc);
    } else if (std.mem.eql(u8, command, "status")) {
        cmdStatus(&args, alloc);
    } else if (std.mem.eql(u8, command, "metrics")) {
        cmdMetrics(&args, alloc);
    } else if (std.mem.eql(u8, command, "policy")) {
        cmdPolicy(&args, alloc);
    } else if (std.mem.eql(u8, command, "cert")) {
        cmdCert(&args, alloc);
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
    const token = readApiToken(&token_buf);

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

fn cmdServe(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var port: u16 = 7700;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            const port_str = args.next() orelse {
                writeErr("--port requires a port number\n", .{});
                std.process.exit(1);
            };
            port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid port: {s}\n", .{port_str});
                std.process.exit(1);
            };
        }
    }

    // generate or load API token for authentication.
    // even in single-node mode (localhost-only), require auth so that
    // any process on the machine can't silently manage containers.
    var token_buf: [64]u8 = undefined;
    const token: ?[]const u8 = readApiToken(&token_buf) orelse generateAndSaveToken(&token_buf);

    if (token) |t| {
        routes.api_token = t;

        var path_buf: [paths.max_path]u8 = undefined;
        const token_path = paths.dataPath(&path_buf, "api_token") catch "~/.local/share/yoq/api_token";
        writeErr("API token: {s}\n", .{token_path});
    } else {
        writeErr("warning: failed to set up API token, running without auth\n", .{});
    }
    defer routes.api_token = null;

    var server = api_server.Server.init(alloc, port, .{ 127, 0, 0, 1 }) catch {
        writeErr("failed to start server on port {d}\n", .{port});
        std.process.exit(1);
    };
    defer server.deinit();

    orchestrator.installSignalHandlers();
    server.run();
}

/// read the API token from ~/.local/share/yoq/api_token.
/// returns a 64-char hex string in the provided buffer, or null if the file
/// doesn't exist or can't be read.
fn readApiToken(buf: *[64]u8) ?[]const u8 {
    var path_buf: [paths.max_path]u8 = undefined;
    const token_path = paths.dataPath(&path_buf, "api_token") catch return null;

    const file = std.fs.cwd().openFile(token_path, .{}) catch return null;
    defer file.close();

    const n = file.readAll(buf) catch return null;
    if (n != 64) return null;

    // validate it's all hex
    for (buf) |c| {
        switch (c) {
            '0'...'9', 'a'...'f' => {},
            else => return null,
        }
    }
    return buf;
}

/// generate 32 random bytes, hex-encode to 64 chars, write to
/// ~/.local/share/yoq/api_token with 0o600 permissions.
/// returns the hex string in the provided buffer, or null on failure.
fn generateAndSaveToken(buf: *[64]u8) ?[]const u8 {
    var raw: [32]u8 = undefined;
    std.crypto.random.bytes(&raw);

    const hex = std.fmt.bytesToHex(raw, .lower);
    buf.* = hex;

    // ensure data directory exists
    paths.ensureDataDir("") catch return null;

    var path_buf: [paths.max_path]u8 = undefined;
    const token_path = paths.dataPath(&path_buf, "api_token") catch return null;

    const file = std.fs.cwd().createFile(token_path, .{ .mode = 0o600 }) catch return null;
    defer file.close();

    file.writeAll(buf) catch return null;
    return buf;
}

fn cmdInitServer(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var node_id: u64 = 1;
    var raft_port: u16 = 9700;
    var api_port: u16 = 7700;
    var peers_str: []const u8 = "";
    var token: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--id")) {
            const id_str = args.next() orelse {
                writeErr("--id requires a node ID\n", .{});
                std.process.exit(1);
            };
            node_id = std.fmt.parseInt(u64, id_str, 10) catch {
                writeErr("invalid node id: {s}\n", .{id_str});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--port")) {
            const port_str = args.next() orelse {
                writeErr("--port requires a port number\n", .{});
                std.process.exit(1);
            };
            raft_port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid port: {s}\n", .{port_str});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--api-port")) {
            const port_str = args.next() orelse {
                writeErr("--api-port requires a port number\n", .{});
                std.process.exit(1);
            };
            api_port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid port: {s}\n", .{port_str});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--peers")) {
            peers_str = args.next() orelse {
                writeErr("--peers requires peer list\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--token")) {
            token = args.next() orelse {
                writeErr("--token requires a join token\n", .{});
                std.process.exit(1);
            };
        }
    }

    // resolve data directory
    var data_dir_buf: [512]u8 = undefined;
    const data_dir = cluster_config.defaultDataDir(&data_dir_buf) catch {
        writeErr("failed to create cluster data directory\n", .{});
        std.process.exit(1);
    };

    // parse peers
    const peers = cluster_config.parsePeers(alloc, peers_str) catch {
        writeErr("invalid peers format. use: id@host:port,id@host:port\n", .{});
        std.process.exit(1);
    };
    defer alloc.free(peers);

    // derive a shared key from the join token for raft transport authentication.
    // uses HMAC-SHA256 as a simple KDF: HMAC(key=token, data="yoq-raft-transport-key").
    // this ensures cluster comms are always authenticated when a token is set.
    var shared_key: ?[32]u8 = null;
    if (token) |t| {
        const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
        var derived: [32]u8 = undefined;
        HmacSha256.create(&derived, "yoq-raft-transport-key", t);
        shared_key = derived;
    }

    writeErr("starting server node {d} on :{d} (api :{d}) with {d} peers\n", .{
        node_id, raft_port, api_port, peers.len,
    });

    // initialize raft node
    var node = cluster_node.Node.init(alloc, .{
        .id = node_id,
        .port = raft_port,
        .peers = peers,
        .data_dir = data_dir,
    }) catch {
        writeErr("failed to initialize raft node\n", .{});
        std.process.exit(1);
    };
    defer node.deinit();

    // set transport authentication key derived from join token
    if (shared_key) |key| {
        node.transport.shared_key = key;
    }

    node.start() catch {
        writeErr("failed to start raft node\n", .{});
        std.process.exit(1);
    };

    // set cluster node and join token for API routes
    routes.cluster = &node;
    routes.join_token = token;
    defer {
        routes.cluster = null;
        routes.join_token = null;
    }

    // enable cluster-wide DNS resolution. the server's DNS resolver
    // will fall through to the replicated service_names table for
    // names not found in the local in-memory registry. this lets
    // containers on any node resolve service names cluster-wide.
    dns.setClusterDb(node.stateMachineDb());
    defer dns.setClusterDb(null);

    // start API server — cluster mode binds to all interfaces since
    // agents on other nodes need to reach this server.
    // set api_token so all endpoints (except health/version) require auth.
    routes.api_token = token;
    defer routes.api_token = null;

    var server = api_server.Server.init(alloc, api_port, .{ 0, 0, 0, 0 }) catch {
        writeErr("failed to start API server on port {d}\n", .{api_port});
        std.process.exit(1);
    };
    defer server.deinit();

    orchestrator.installSignalHandlers();
    server.run();

    node.stop();
}

fn cmdJoin(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var server_host: ?[]const u8 = null;
    var token: ?[]const u8 = null;
    var api_port: u16 = 7700;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--token")) {
            token = args.next() orelse {
                writeErr("--token requires a join token\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--port")) {
            const port_str = args.next() orelse {
                writeErr("--port requires a port number\n", .{});
                std.process.exit(1);
            };
            api_port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid port: {s}\n", .{port_str});
                std.process.exit(1);
            };
        } else {
            server_host = arg;
        }
    }

    const host = server_host orelse {
        writeErr("usage: yoq join <server-host> --token <token> [--port <api-port>]\n", .{});
        std.process.exit(1);
    };

    const join_token = token orelse {
        writeErr("--token is required\n", .{});
        std.process.exit(1);
    };

    // parse server address
    const server_addr = ip.parseIp(host) orelse {
        writeErr("invalid server address: {s}\n", .{host});
        std.process.exit(1);
    };

    writeErr("joining cluster at {s}:{d}...\n", .{ host, api_port });

    var agent = cluster_agent.Agent.init(alloc, server_addr, api_port, join_token);

    // register with server
    agent.register() catch {
        writeErr("failed to register with server\n", .{});
        std.process.exit(1);
    };

    writeErr("joined cluster as agent {s}\n", .{agent.id});

    // set up wireguard mesh networking if the server assigned a node_id.
    // this creates the wg-yoq interface, assigns our overlay IP, and adds
    // any existing peers so cross-node container traffic can flow immediately.
    if (agent.node_id != null and agent.wg_keypair != null and agent.overlay_ip != null) {
        setupAgentWireguard(&agent, alloc);
    }
    defer {
        // tear down wireguard on exit — the kernel cleans up peers and routes
        // when the interface is deleted, so this is a single operation.
        if (agent.node_id != null) {
            net_setup.teardownClusterNetworking();
        }
    }

    // start heartbeat loop
    agent.start() catch {
        writeErr("failed to start agent loop\n", .{});
        std.process.exit(1);
    };

    // install signal handlers for graceful shutdown
    orchestrator.installSignalHandlers();

    // block until shutdown signal
    agent.wait();

    writeErr("agent stopped\n", .{});
}

/// fetch the peer list from the server and set up the wireguard mesh.
/// called once during cmdJoin after the agent has registered and received
/// its node_id, overlay IP, and wireguard keypair. any failure here is
/// non-fatal — the agent will still function, and the reconcilePeers loop
/// in the heartbeat cycle will retry peer setup.
fn setupAgentWireguard(agent: *cluster_agent.Agent, alloc: std.mem.Allocator) void {
    const node_id = agent.node_id orelse return;
    const kp = agent.wg_keypair orelse return;
    const overlay_ip = agent.overlay_ip orelse return;

    // fetch the current peer list from the server
    var peers_buf: [16]net_setup.PeerInfo = undefined;
    var peer_count: usize = 0;

    var resp = http_client.getWithAuth(
        alloc,
        agent.server_addr,
        agent.server_port,
        "/wireguard/peers",
        agent.token,
    ) catch {
        writeErr("warning: failed to fetch wireguard peers, will retry on heartbeat\n", .{});
        // still set up the interface with no peers — they'll be added
        // on the first heartbeat cycle via reconcilePeers
        net_setup.setupClusterNetworking(.{
            .node_id = node_id,
            .private_key = &kp.private_key,
            .listen_port = agent.wg_listen_port,
            .overlay_ip = overlay_ip,
            .peers = &.{},
        }) catch {
            writeErr("warning: failed to set up wireguard interface\n", .{});
        };
        return;
    };
    defer resp.deinit(alloc);

    // parse peer objects from the response
    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        if (peer_count >= peers_buf.len) break;

        const pub_key = json_helpers.extractJsonString(obj, "public_key") orelse continue;
        const overlay_str = json_helpers.extractJsonString(obj, "overlay_ip") orelse continue;
        const node_id_val = json_helpers.extractJsonInt(obj, "node_id") orelse continue;
        const endpoint = json_helpers.extractJsonString(obj, "endpoint") orelse "";

        // skip ourselves
        if (node_id_val == node_id) continue;

        const peer_node: u8 = if (node_id_val >= 1 and node_id_val <= 254)
            @intCast(node_id_val)
        else
            continue;

        peers_buf[peer_count] = .{
            .public_key = pub_key,
            .endpoint = endpoint,
            .overlay_ip = .{ 10, 40, 0, peer_node },
            .container_subnet_node = peer_node,
        };

        // also parse the actual overlay IP from the string
        if (parseIpv4Bytes(overlay_str)) |ip_bytes| {
            peers_buf[peer_count].overlay_ip = ip_bytes;
        }

        peer_count += 1;
    }

    net_setup.setupClusterNetworking(.{
        .node_id = node_id,
        .private_key = &kp.private_key,
        .listen_port = agent.wg_listen_port,
        .overlay_ip = overlay_ip,
        .peers = peers_buf[0..peer_count],
    }) catch {
        writeErr("warning: failed to set up wireguard interface\n", .{});
        return;
    };

    writeErr("wireguard mesh active (node_id={d}, {d} peers)\n", .{ node_id, peer_count });
}

/// parse a dotted-quad IPv4 string into 4 bytes. returns null on failure.
fn parseIpv4Bytes(str: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var start: usize = 0;

    for (str, 0..) |c, i| {
        if (c == '.') {
            if (octet_idx >= 3) return null;
            result[octet_idx] = std.fmt.parseInt(u8, str[start..i], 10) catch return null;
            octet_idx += 1;
            start = i + 1;
        }
    }

    if (octet_idx != 3) return null;
    result[3] = std.fmt.parseInt(u8, str[start..], 10) catch return null;
    return result;
}

fn cmdCluster(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const subcommand = args.next() orelse {
        writeErr("usage: yoq cluster <status>\n", .{});
        std.process.exit(1);
    };

    if (std.mem.eql(u8, subcommand, "status")) {
        cmdClusterStatus(alloc);
    } else {
        writeErr("unknown cluster subcommand: {s}\n", .{subcommand});
        std.process.exit(1);
    }
}

fn cmdClusterStatus(alloc: std.mem.Allocator) void {
    // query the local API server for cluster status
    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch {
        writeErr("failed to create socket\n", .{});
        return;
    };
    defer std.posix.close(fd);

    const timeout = std.posix.timeval{ .sec = 2, .usec = 0 };
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 7700);
    std.posix.connect(fd, &addr.any, addr.getOsSockLen()) catch {
        writeErr("cannot connect to API server at localhost:7700\n", .{});
        return;
    };

    const request = "GET /cluster/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    _ = std.posix.write(fd, request) catch {
        writeErr("failed to send request\n", .{});
        return;
    };

    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }

    // find body (after \r\n\r\n)
    const response = buf[0..total];
    if (std.mem.indexOf(u8, response, "\r\n\r\n")) |body_start| {
        write("{s}\n", .{response[body_start + 4 ..]});
    } else {
        writeErr("invalid response from server\n", .{});
    }

    _ = alloc;
}

fn cmdNodes(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var server: cli.ServerAddr = .{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                std.process.exit(1);
            };
            server = cli.parseServerAddr(addr_str);
        }
    }
    const server_addr = server.ip;
    const server_port = server.port;

    var token_buf: [64]u8 = undefined;
    const token = readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, server_addr, server_port, "/agents", token) catch {
        writeErr("failed to connect to server\n", .{});
        std.process.exit(1);
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        std.process.exit(1);
    }

    // parse and display agent list as a table
    // response is a JSON array: [{"id":"...","status":"...","cpu_cores":N,...},...]
    write("{s:<14} {s:<10} {s:<12} {s:<16} {s}\n", .{ "ID", "STATUS", "CPU", "MEMORY", "CONTAINERS" });
    write("{s:->14} {s:->10} {s:->12} {s:->16} {s:->10}\n", .{ "", "", "", "", "" });

    // simple parser: walk through JSON array finding each object
    var pos: usize = 0;
    while (pos < resp.body.len) {
        const obj_start = std.mem.indexOfPos(u8, resp.body, pos, "{\"id\":\"") orelse break;
        const obj_end = std.mem.indexOfPos(u8, resp.body, obj_start + 1, "}") orelse break;
        const obj = resp.body[obj_start .. obj_end + 1];

        const id = extractJsonString(obj, "id") orelse "?";
        const status = extractJsonString(obj, "status") orelse "?";
        const cpu_cores = extractJsonInt(obj, "cpu_cores") orelse 0;
        const cpu_used = extractJsonInt(obj, "cpu_used") orelse 0;
        const memory_mb = extractJsonInt(obj, "memory_mb") orelse 0;
        const memory_used = extractJsonInt(obj, "memory_used_mb") orelse 0;
        const containers = extractJsonInt(obj, "containers") orelse 0;

        // format CPU as "used/total" in millicores
        var cpu_buf: [24]u8 = undefined;
        const cpu_str = std.fmt.bufPrint(&cpu_buf, "{d}/{d}", .{ cpu_used, cpu_cores * 1000 }) catch "?";

        var mem_buf: [24]u8 = undefined;
        const mem_str = std.fmt.bufPrint(&mem_buf, "{d}/{d}MB", .{ memory_used, memory_mb }) catch "?";

        var cnt_buf: [12]u8 = undefined;
        const cnt_str = std.fmt.bufPrint(&cnt_buf, "{d}", .{containers}) catch "?";

        write("{s:<14} {s:<10} {s:<12} {s:<16} {s}\n", .{ id, status, cpu_str, mem_str, cnt_str });

        pos = obj_end + 1;
    }
}

fn cmdDrain(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var node_id: ?[]const u8 = null;
    var server: cli.ServerAddr = .{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                std.process.exit(1);
            };
            server = cli.parseServerAddr(addr_str);
        } else {
            node_id = arg;
        }
    }
    const server_addr = server.ip;
    const server_port = server.port;

    const id = node_id orelse {
        writeErr("usage: yoq drain <node-id> [--server host:port]\n", .{});
        std.process.exit(1);
    };

    // POST /agents/{id}/drain
    var path_buf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/drain", .{id}) catch {
        writeErr("node ID too long\n", .{});
        std.process.exit(1);
    };

    var token_buf: [64]u8 = undefined;
    const token = readApiToken(&token_buf);

    var resp = http_client.postWithAuth(alloc, server_addr, server_port, path, "", token) catch {
        writeErr("failed to connect to server\n", .{});
        std.process.exit(1);
    };
    defer resp.deinit(alloc);

    if (resp.status_code == 200) {
        write("node {s} marked for draining\n", .{id});
    } else {
        writeErr("drain failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        std.process.exit(1);
    }
}

// -- status command --

fn cmdStatus(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var verbose = false;
    var server: ?cli.ServerAddr = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                std.process.exit(1);
            };
            server = cli.parseServerAddr(addr_str);
        }
    }

    // cluster mode: query API endpoint
    if (server) |s| {
        cmdStatusRemote(alloc, s.ip, s.port, verbose);
        return;
    }

    // local mode: read directly from store and cgroups
    cmdStatusLocal(alloc, verbose);
}

fn cmdStatusLocal(alloc: std.mem.Allocator, verbose: bool) void {
    var records = store.listAll(alloc) catch {
        writeErr("failed to list containers\n", .{});
        std.process.exit(1);
    };
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
    }

    if (records.items.len == 0) {
        write("no services running\n", .{});
        return;
    }

    var snapshots = monitor.collectSnapshots(alloc, &records) catch {
        writeErr("failed to collect service snapshots\n", .{});
        std.process.exit(1);
    };
    defer snapshots.deinit(alloc);

    printStatusTable(snapshots.items, verbose);
}

fn cmdStatusRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16, verbose: bool) void {
    var token_buf: [64]u8 = undefined;
    const token = readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, "/v1/status", token) catch {
        writeErr("failed to connect to server\n", .{});
        std.process.exit(1);
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        std.process.exit(1);
    }

    // parse JSON response into snapshots for display
    var snapshots: std.ArrayList(monitor.ServiceSnapshot) = .empty;
    defer snapshots.deinit(alloc);

    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        const name = extractJsonString(obj, "name") orelse "?";
        const status_str = extractJsonString(obj, "status") orelse "unknown";
        const health_str = extractJsonString(obj, "health");

        const status: monitor.ServiceStatus = if (std.mem.eql(u8, status_str, "running"))
            .running
        else if (std.mem.eql(u8, status_str, "stopped"))
            .stopped
        else
            .mixed;

        const health_status: ?health.HealthStatus = if (health_str) |h| blk: {
            if (std.mem.eql(u8, h, "healthy")) break :blk .healthy;
            if (std.mem.eql(u8, h, "unhealthy")) break :blk .unhealthy;
            if (std.mem.eql(u8, h, "starting")) break :blk .starting;
            break :blk null;
        } else null;

        // parse PSI metrics if present in the response
        const psi_cpu = parsePsiFromJson(obj, "psi_cpu_some", "psi_cpu_full");
        const psi_mem = parsePsiFromJson(obj, "psi_mem_some", "psi_mem_full");

        snapshots.append(alloc, .{
            .name = name,
            .status = status,
            .health_status = health_status,
            .cpu_pct = extractJsonFloat(obj, "cpu_pct") orelse 0.0,
            .memory_bytes = @intCast(extractJsonInt(obj, "memory_bytes") orelse 0),
            .psi_cpu = psi_cpu,
            .psi_memory = psi_mem,
            .running_count = @intCast(extractJsonInt(obj, "running") orelse 0),
            .desired_count = @intCast(extractJsonInt(obj, "desired") orelse 0),
            .uptime_secs = extractJsonInt(obj, "uptime_secs") orelse 0,
        }) catch {
            writeErr("failed to parse status response\n", .{});
            std.process.exit(1);
        };
    }

    if (snapshots.items.len == 0) {
        write("no services running\n", .{});
        return;
    }

    printStatusTable(snapshots.items, verbose);
}

fn printStatusTable(snapshots: []const monitor.ServiceSnapshot, verbose: bool) void {
    write("{s:<12} {s:<10} {s:<11} {s:<10} {s:<11} {s:<13} {s}\n", .{
        "SERVICE", "STATUS", "HEALTH", "CPU", "MEMORY", "CONTAINERS", "UPTIME",
    });

    for (snapshots) |snap| {
        var cpu_buf: [16]u8 = undefined;
        const cpu_str = if (snap.cpu_pct > 0.0)
            std.fmt.bufPrint(&cpu_buf, "{d:.1}%", .{snap.cpu_pct}) catch "-"
        else
            @as([]const u8, "-");

        var mem_buf: [16]u8 = undefined;
        const mem_str = monitor.formatBytes(&mem_buf, snap.memory_bytes);

        var uptime_buf: [16]u8 = undefined;
        const uptime_str = monitor.formatUptime(&uptime_buf, snap.uptime_secs);

        var count_buf: [12]u8 = undefined;
        const count_str = std.fmt.bufPrint(&count_buf, "{d}/{d}", .{
            snap.running_count, snap.desired_count,
        }) catch "-";

        write("{s:<12} {s:<10} {s:<11} {s:<10} {s:<11} {s:<13} {s}\n", .{
            snap.name,
            monitor.formatStatus(snap.status),
            monitor.formatHealth(snap.health_status),
            cpu_str,
            mem_str,
            count_str,
            uptime_str,
        });

        if (verbose) {
            printVerboseDetails(snap);
        }
    }
}

fn printVerboseDetails(snap: monitor.ServiceSnapshot) void {
    // PSI pressure metrics
    if (snap.psi_cpu) |psi| {
        write("  cpu pressure:    some={d:.1}%  full={d:.1}%\n", .{ psi.some_avg10, psi.full_avg10 });
    }
    if (snap.psi_memory) |psi| {
        write("  memory pressure: some={d:.1}%  full={d:.1}%\n", .{ psi.some_avg10, psi.full_avg10 });
    }

    // auto-tuning suggestions based on PSI
    if (snap.psi_memory) |psi| {
        if (psi.some_avg10 > 25.0) {
            write("  \xe2\x9a\xa0 memory pressure high \xe2\x80\x94 consider increasing memory limit\n", .{});
        }
    }
    if (snap.psi_cpu) |psi| {
        if (psi.some_avg10 > 50.0) {
            write("  \xe2\x9a\xa0 cpu pressure high \xe2\x80\x94 consider increasing cpu allocation\n", .{});
        }
    }
}

/// parse PSI metrics from a JSON object's some/full fields.
/// returns null if neither field is present.
fn parsePsiFromJson(json: []const u8, some_key: []const u8, full_key: []const u8) ?cgroups.PsiMetrics {
    const some = extractJsonFloat(json, some_key) orelse return null;
    const full = extractJsonFloat(json, full_key) orelse return null;
    return .{ .some_avg10 = some, .full_avg10 = full };
}

// -- metrics command --

fn cmdMetrics(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var service_filter: ?[]const u8 = null;
    var server: ?cli.ServerAddr = null;
    var pairs_mode = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                std.process.exit(1);
            };
            server = cli.parseServerAddr(addr_str);
        } else if (std.mem.eql(u8, arg, "--pairs")) {
            pairs_mode = true;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            service_filter = arg;
        }
    }

    if (pairs_mode) {
        if (server) |s| {
            cmdMetricsPairsRemote(alloc, s.ip, s.port);
        } else {
            cmdMetricsPairs(alloc);
        }
        return;
    }

    if (server) |s| {
        cmdMetricsRemote(alloc, s.ip, s.port, service_filter);
        return;
    }

    cmdMetricsLocal(alloc, service_filter);
}

fn cmdMetricsLocal(alloc: std.mem.Allocator, service_filter: ?[]const u8) void {
    var records = store.listAll(alloc) catch {
        writeErr("failed to list containers\n", .{});
        std.process.exit(1);
    };
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
    }

    if (records.items.len == 0) {
        write("no services running\n", .{});
        return;
    }

    const mc = ebpf.getMetricsCollector();

    write("{s:<12} {s:<10} {s:<16} {s:<12} {s}\n", .{
        "SERVICE", "CONTAINER", "IP", "PACKETS", "BYTES",
    });

    var found = false;
    for (records.items) |rec| {
        if (!std.mem.eql(u8, rec.status, "running")) continue;

        if (service_filter) |svc| {
            if (!std.mem.eql(u8, rec.hostname, svc)) continue;
        }

        const ip_str = rec.ip_address orelse continue;
        const short_id = if (rec.id.len >= 6) rec.id[0..6] else rec.id;

        var packets: u64 = 0;
        var bytes: u64 = 0;
        if (mc) |collector| {
            if (ip.parseIp(ip_str)) |addr| {
                const ip_net = ebpf.ipToNetworkOrder(addr);
                if (collector.readMetrics(ip_net)) |m| {
                    packets = m.packets;
                    bytes = m.bytes;
                }
            }
        }

        var bytes_buf: [16]u8 = undefined;
        const bytes_str = monitor.formatBytes(&bytes_buf, bytes);

        var pkt_buf: [16]u8 = undefined;
        const pkt_str = formatCount(&pkt_buf, packets);

        write("{s:<12} {s:<10} {s:<16} {s:<12} {s}\n", .{
            rec.hostname, short_id, ip_str, pkt_str, bytes_str,
        });
        found = true;
    }

    if (!found) {
        if (service_filter) |svc| {
            write("no running containers for service '{s}'\n", .{svc});
        } else {
            write("no running containers with network\n", .{});
        }
    }
}

fn cmdMetricsRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16, service_filter: ?[]const u8) void {
    // build path with optional query param
    var path_buf: [128]u8 = undefined;
    const path = if (service_filter) |svc|
        std.fmt.bufPrint(&path_buf, "/v1/metrics?service={s}", .{svc}) catch "/v1/metrics"
    else
        @as([]const u8, "/v1/metrics");

    var token_buf: [64]u8 = undefined;
    const token = readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, path, token) catch {
        writeErr("failed to connect to server\n", .{});
        std.process.exit(1);
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        std.process.exit(1);
    }

    write("{s:<12} {s:<10} {s:<16} {s:<12} {s}\n", .{
        "SERVICE", "CONTAINER", "IP", "PACKETS", "BYTES",
    });

    var found = false;
    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        const service = extractJsonString(obj, "service") orelse "?";
        const container_id = extractJsonString(obj, "container") orelse "?";
        const ip_str = extractJsonString(obj, "ip") orelse "?";
        const packets: u64 = @intCast(extractJsonInt(obj, "packets") orelse 0);
        const bytes: u64 = @intCast(extractJsonInt(obj, "bytes") orelse 0);

        var bytes_buf: [16]u8 = undefined;
        const bytes_str = monitor.formatBytes(&bytes_buf, bytes);

        var pkt_buf: [16]u8 = undefined;
        const pkt_str = formatCount(&pkt_buf, packets);

        write("{s:<12} {s:<10} {s:<16} {s:<12} {s}\n", .{
            service, container_id, ip_str, pkt_str, bytes_str,
        });
        found = true;
    }

    if (!found) {
        write("no metrics available\n", .{});
    }
}

fn cmdMetricsPairs(alloc: std.mem.Allocator) void {
    const mc = ebpf.getMetricsCollector() orelse {
        write("metrics collector not loaded (requires root)\n", .{});
        return;
    };

    var records = store.listAll(alloc) catch {
        writeErr("failed to list containers\n", .{});
        std.process.exit(1);
    };
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
    }

    var entries: [1024]ebpf.PairEntry = undefined;
    const count = mc.readPairMetrics(&entries);

    if (count == 0) {
        write("no pair metrics available\n", .{});
        return;
    }

    write("{s:<14} {s:<14} {s:<8} {s:<12} {s:<12} {s:<10} {s}\n", .{
        "FROM", "TO", "PORT", "CONNECTIONS", "PACKETS", "BYTES", "ERRORS",
    });

    for (entries[0..count]) |entry| {
        const src_name = resolveIpName(entry.key.src_ip, records.items);
        const dst_name = resolveIpName(entry.key.dst_ip, records.items);
        const port = std.mem.nativeTo(u16, entry.key.dst_port, .big);

        var conn_buf: [16]u8 = undefined;
        const conn_str = formatCount(&conn_buf, entry.value.connections);
        var pkt_buf: [16]u8 = undefined;
        const pkt_str = formatCount(&pkt_buf, entry.value.packets);
        var bytes_buf: [16]u8 = undefined;
        const bytes_str = monitor.formatBytes(&bytes_buf, entry.value.bytes);
        var err_buf: [16]u8 = undefined;
        const err_str = formatCount(&err_buf, entry.value.errors);

        write("{s:<14} {s:<14} {d:<8} {s:<12} {s:<12} {s:<10} {s}\n", .{
            src_name, dst_name, port, conn_str, pkt_str, bytes_str, err_str,
        });
    }
}

fn cmdMetricsPairsRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16) void {
    var token_buf: [64]u8 = undefined;
    const token = readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, "/v1/metrics?mode=pairs", token) catch {
        writeErr("failed to connect to server\n", .{});
        std.process.exit(1);
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        std.process.exit(1);
    }

    write("{s:<14} {s:<14} {s:<8} {s:<12} {s:<12} {s:<10} {s}\n", .{
        "FROM", "TO", "PORT", "CONNECTIONS", "PACKETS", "BYTES", "ERRORS",
    });

    var found = false;
    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        const from = extractJsonString(obj, "from") orelse "?";
        const to = extractJsonString(obj, "to") orelse "?";
        const obj_port: u64 = @intCast(extractJsonInt(obj, "port") orelse 0);
        const connections: u64 = @intCast(extractJsonInt(obj, "connections") orelse 0);
        const packets: u64 = @intCast(extractJsonInt(obj, "packets") orelse 0);
        const bytes: u64 = @intCast(extractJsonInt(obj, "bytes") orelse 0);
        const errors: u64 = @intCast(extractJsonInt(obj, "errors") orelse 0);

        var conn_buf: [16]u8 = undefined;
        const conn_str = formatCount(&conn_buf, connections);
        var pkt_buf: [16]u8 = undefined;
        const pkt_str = formatCount(&pkt_buf, packets);
        var bytes_buf: [16]u8 = undefined;
        const bytes_str = monitor.formatBytes(&bytes_buf, bytes);
        var err_buf: [16]u8 = undefined;
        const err_str = formatCount(&err_buf, errors);

        write("{s:<14} {s:<14} {d:<8} {s:<12} {s:<12} {s:<10} {s}\n", .{
            from, to, obj_port, conn_str, pkt_str, bytes_str, err_str,
        });
        found = true;
    }

    if (!found) {
        write("no pair metrics available\n", .{});
    }
}

/// resolve a network-order IP (u32) to a service hostname.
fn resolveIpName(ip_net: u32, records: []const store.ContainerRecord) []const u8 {
    const ip_bytes = std.mem.asBytes(&ip_net);
    for (records) |rec| {
        if (!std.mem.eql(u8, rec.status, "running")) continue;
        const rec_ip_str = rec.ip_address orelse continue;
        if (ip.parseIp(rec_ip_str)) |addr| {
            if (std.mem.eql(u8, &addr, ip_bytes[0..4])) return rec.hostname;
        }
    }
    return "unknown";
}

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

// -- secret commands --

fn cmdSecret(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const subcmd = args.next() orelse {
        writeErr(
            \\usage: yoq secret <command> [options]
            \\
            \\commands:
            \\  set <name> [--value <val>]  store a secret (reads stdin if no --value)
            \\  get <name>                  print decrypted value
            \\  rm <name>                   remove a secret
            \\  list                        list secret names
            \\  rotate <name>               re-encrypt with current key
            \\
        , .{});
        std.process.exit(1);
    };

    if (std.mem.eql(u8, subcmd, "set")) {
        cmdSecretSet(args, alloc);
    } else if (std.mem.eql(u8, subcmd, "get")) {
        cmdSecretGet(args, alloc);
    } else if (std.mem.eql(u8, subcmd, "rm")) {
        cmdSecretRm(args, alloc);
    } else if (std.mem.eql(u8, subcmd, "list")) {
        cmdSecretList(alloc);
    } else if (std.mem.eql(u8, subcmd, "rotate")) {
        cmdSecretRotate(args, alloc);
    } else {
        writeErr("unknown secret command: {s}\n", .{subcmd});
        std.process.exit(1);
    }
}

fn cmdSecretSet(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var name: ?[]const u8 = null;
    var value_flag: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--value")) {
            value_flag = args.next() orelse {
                writeErr("--value requires a value\n", .{});
                std.process.exit(1);
            };
        } else if (name == null) {
            name = arg;
        }
    }

    const secret_name = name orelse {
        writeErr("usage: yoq secret set <name> [--value <val>]\n", .{});
        std.process.exit(1);
    };

    // get value from --value flag or stdin
    const value = if (value_flag) |v|
        v
    else blk: {
        // read from stdin
        const stdin_file: std.fs.File = .{ .handle = std.posix.STDIN_FILENO };
        const stdin_data = stdin_file.readToEndAlloc(alloc, 1024 * 1024) catch {
            writeErr("failed to read from stdin\n", .{});
            std.process.exit(1);
        };
        // trim trailing newline — users typically pipe from echo or here-string
        break :blk std.mem.trimRight(u8, stdin_data, "\n\r");
    };

    var sec_store = openSecretsStore(alloc);
    defer closeSecretsStore(alloc, &sec_store);

    sec_store.set(secret_name, value) catch {
        writeErr("failed to store secret\n", .{});
        std.process.exit(1);
    };

    write("{s}\n", .{secret_name});
}

fn cmdSecretGet(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const name = requireArg(args, "usage: yoq secret get <name>\n");

    var sec_store = openSecretsStore(alloc);
    defer closeSecretsStore(alloc, &sec_store);

    const value = sec_store.get(name) catch |err| {
        if (err == secrets.SecretsError.NotFound) {
            writeErr("secret not found: {s}\n", .{name});
        } else {
            writeErr("failed to read secret\n", .{});
        }
        std.process.exit(1);
    };
    defer {
        // zero before freeing — don't leave secrets in freed memory
        std.crypto.secureZero(u8, value);
        alloc.free(value);
    }

    write("{s}\n", .{value});
}

fn cmdSecretRm(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const name = requireArg(args, "usage: yoq secret rm <name>\n");

    var sec_store = openSecretsStore(alloc);
    defer closeSecretsStore(alloc, &sec_store);

    sec_store.remove(name) catch |err| {
        if (err == secrets.SecretsError.NotFound) {
            writeErr("secret not found: {s}\n", .{name});
        } else {
            writeErr("failed to remove secret\n", .{});
        }
        std.process.exit(1);
    };

    write("{s}\n", .{name});
}

fn cmdSecretList(alloc: std.mem.Allocator) void {
    var sec_store = openSecretsStore(alloc);
    defer closeSecretsStore(alloc, &sec_store);

    var names = sec_store.list() catch {
        writeErr("failed to list secrets\n", .{});
        std.process.exit(1);
    };
    defer {
        for (names.items) |n| alloc.free(n);
        names.deinit(alloc);
    }

    if (names.items.len == 0) {
        write("no secrets\n", .{});
        return;
    }

    for (names.items) |name| {
        write("{s}\n", .{name});
    }
}

fn cmdSecretRotate(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const name = requireArg(args, "usage: yoq secret rotate <name>\n");

    var sec_store = openSecretsStore(alloc);
    defer closeSecretsStore(alloc, &sec_store);

    sec_store.rotate(name) catch |err| {
        if (err == secrets.SecretsError.NotFound) {
            writeErr("secret not found: {s}\n", .{name});
        } else {
            writeErr("failed to rotate secret\n", .{});
        }
        std.process.exit(1);
    };

    write("{s}\n", .{name});
}

/// open a SecretsStore with a heap-allocated database connection.
/// exits on failure — used by CLI commands where there's nothing to recover from.
/// caller must call closeSecretsStore() when done.
fn openSecretsStore(alloc: std.mem.Allocator) secrets.SecretsStore {
    const db_ptr = alloc.create(sqlite.Db) catch {
        writeErr("failed to allocate database\n", .{});
        std.process.exit(1);
    };
    db_ptr.* = store.openDb() catch {
        alloc.destroy(db_ptr);
        writeErr("failed to open database\n", .{});
        std.process.exit(1);
    };

    return secrets.SecretsStore.init(db_ptr, alloc) catch |err| {
        db_ptr.deinit();
        alloc.destroy(db_ptr);
        if (err == secrets.SecretsError.HomeDirNotFound) {
            writeErr("HOME directory not found\n", .{});
        } else {
            writeErr("failed to initialize secrets store\n", .{});
        }
        std.process.exit(1);
    };
}

/// close a secrets store opened with openSecretsStore.
fn closeSecretsStore(alloc: std.mem.Allocator, sec: *secrets.SecretsStore) void {
    sec.db.deinit();
    alloc.destroy(sec.db);
}

// -- network policy commands --

fn cmdPolicy(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const subcmd = args.next() orelse {
        writeErr(
            \\usage: yoq policy <command> [options]
            \\
            \\commands:
            \\  deny <source> <target>   block traffic from source to target
            \\  allow <source> <target>  allow only this destination for source
            \\  rm <source> <target>     remove a policy rule
            \\  list                     list all policy rules
            \\
        , .{});
        std.process.exit(1);
    };

    if (std.mem.eql(u8, subcmd, "deny")) {
        cmdPolicyDeny(args, alloc);
    } else if (std.mem.eql(u8, subcmd, "allow")) {
        cmdPolicyAllow(args, alloc);
    } else if (std.mem.eql(u8, subcmd, "rm")) {
        cmdPolicyRm(args, alloc);
    } else if (std.mem.eql(u8, subcmd, "list")) {
        cmdPolicyList(alloc);
    } else {
        writeErr("unknown policy command: {s}\n", .{subcmd});
        std.process.exit(1);
    }
}

fn cmdPolicyDeny(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const source = args.next() orelse {
        writeErr("usage: yoq policy deny <source> <target>\n", .{});
        std.process.exit(1);
    };
    const target = args.next() orelse {
        writeErr("usage: yoq policy deny <source> <target>\n", .{});
        std.process.exit(1);
    };

    store.addNetworkPolicy(source, target, "deny") catch {
        writeErr("failed to add deny rule\n", .{});
        std.process.exit(1);
    };

    // sync BPF maps with updated rules
    net_policy.syncPolicies(alloc);

    write("{s} -> {s}: deny\n", .{ source, target });
}

fn cmdPolicyAllow(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const source = args.next() orelse {
        writeErr("usage: yoq policy allow <source> <target>\n", .{});
        std.process.exit(1);
    };
    const target = args.next() orelse {
        writeErr("usage: yoq policy allow <source> <target>\n", .{});
        std.process.exit(1);
    };

    store.addNetworkPolicy(source, target, "allow") catch {
        writeErr("failed to add allow rule\n", .{});
        std.process.exit(1);
    };

    // sync BPF maps with updated rules
    net_policy.syncPolicies(alloc);

    write("{s} -> {s}: allow\n", .{ source, target });
}

fn cmdPolicyRm(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const source = args.next() orelse {
        writeErr("usage: yoq policy rm <source> <target>\n", .{});
        std.process.exit(1);
    };
    const target = args.next() orelse {
        writeErr("usage: yoq policy rm <source> <target>\n", .{});
        std.process.exit(1);
    };

    store.removeNetworkPolicy(source, target) catch {
        writeErr("failed to remove policy rule\n", .{});
        std.process.exit(1);
    };

    // sync BPF maps with updated rules
    net_policy.syncPolicies(alloc);

    write("{s} -> {s}: removed\n", .{ source, target });
}

fn cmdPolicyList(alloc: std.mem.Allocator) void {
    var policies = store.listNetworkPolicies(alloc) catch {
        writeErr("failed to list policies\n", .{});
        std.process.exit(1);
    };
    defer {
        for (policies.items) |p| p.deinit(alloc);
        policies.deinit(alloc);
    }

    if (policies.items.len == 0) {
        write("no network policies\n", .{});
        return;
    }

    write("{s:<16} {s:<16} {s:<8} {s}\n", .{
        "SOURCE", "TARGET", "ACTION", "CREATED",
    });

    for (policies.items) |pol| {
        // format timestamp as simple date
        var time_buf: [20]u8 = undefined;
        const time_str = formatTimestamp(&time_buf, pol.created_at);

        write("{s:<16} {s:<16} {s:<8} {s}\n", .{
            pol.source_service, pol.target_service, pol.action, time_str,
        });
    }
}

// -- certificate commands --

fn cmdCert(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const subcmd = args.next() orelse {
        writeErr(
            \\usage: yoq cert <command> [options]
            \\
            \\commands:
            \\  install <domain> --cert <path> --key <path>   store a certificate
            \\  provision <domain> --email <email> [--staging] obtain via ACME
            \\  renew <domain>                                 renew via ACME
            \\  list                                           list certificates
            \\  rm <domain>                                    remove a certificate
            \\
        , .{});
        std.process.exit(1);
    };

    if (std.mem.eql(u8, subcmd, "install")) {
        cmdCertInstall(args, alloc);
    } else if (std.mem.eql(u8, subcmd, "provision")) {
        cmdCertProvision(args, alloc);
    } else if (std.mem.eql(u8, subcmd, "renew")) {
        cmdCertRenew(args, alloc);
    } else if (std.mem.eql(u8, subcmd, "list")) {
        cmdCertList(alloc);
    } else if (std.mem.eql(u8, subcmd, "rm")) {
        cmdCertRm(args, alloc);
    } else {
        writeErr("unknown cert command: {s}\n", .{subcmd});
        std.process.exit(1);
    }
}

fn cmdCertInstall(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var domain: ?[]const u8 = null;
    var cert_path: ?[]const u8 = null;
    var key_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--cert")) {
            cert_path = args.next() orelse {
                writeErr("--cert requires a file path\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--key")) {
            key_path = args.next() orelse {
                writeErr("--key requires a file path\n", .{});
                std.process.exit(1);
            };
        } else if (domain == null) {
            domain = arg;
        }
    }

    const dom = domain orelse {
        writeErr("usage: yoq cert install <domain> --cert <path> --key <path>\n", .{});
        std.process.exit(1);
    };
    const cp = cert_path orelse {
        writeErr("--cert is required\n", .{});
        std.process.exit(1);
    };
    const kp = key_path orelse {
        writeErr("--key is required\n", .{});
        std.process.exit(1);
    };

    // read cert file
    const cert_pem = std.fs.cwd().readFileAlloc(alloc, cp, 1024 * 1024) catch {
        writeErr("failed to read certificate file: {s}\n", .{cp});
        std.process.exit(1);
    };
    defer alloc.free(cert_pem);

    // read key file
    const key_pem = std.fs.cwd().readFileAlloc(alloc, kp, 1024 * 1024) catch {
        writeErr("failed to read key file: {s}\n", .{kp});
        std.process.exit(1);
    };
    defer {
        std.crypto.secureZero(u8, key_pem);
        alloc.free(key_pem);
    }

    var cs = openCertStore(alloc);
    defer closeCertStore(alloc, &cs);

    cs.install(dom, cert_pem, key_pem, "manual") catch |err| {
        if (err == cert_store.CertError.InvalidCert) {
            writeErr("failed to parse certificate (invalid PEM or X.509)\n", .{});
        } else {
            writeErr("failed to store certificate\n", .{});
        }
        std.process.exit(1);
    };

    write("{s}\n", .{dom});
}

fn cmdCertList(alloc: std.mem.Allocator) void {
    var cs = openCertStore(alloc);
    defer closeCertStore(alloc, &cs);

    var certs = cs.list() catch {
        writeErr("failed to list certificates\n", .{});
        std.process.exit(1);
    };
    defer {
        for (certs.items) |c| c.deinit(alloc);
        certs.deinit(alloc);
    }

    if (certs.items.len == 0) {
        write("no certificates\n", .{});
        return;
    }

    for (certs.items) |cert| {
        var ts_buf: [20]u8 = undefined;
        const expires = formatTimestamp(&ts_buf, cert.not_after);
        write("{s}  expires={s}  source={s}\n", .{ cert.domain, expires, cert.source });
    }
}

fn cmdCertRm(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const domain = requireArg(args, "usage: yoq cert rm <domain>\n");

    var cs = openCertStore(alloc);
    defer closeCertStore(alloc, &cs);

    cs.remove(domain) catch |err| {
        if (err == cert_store.CertError.NotFound) {
            writeErr("certificate not found: {s}\n", .{domain});
        } else {
            writeErr("failed to remove certificate\n", .{});
        }
        std.process.exit(1);
    };

    write("{s}\n", .{domain});
}

fn cmdCertProvision(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var domain: ?[]const u8 = null;
    var email: ?[]const u8 = null;
    var use_staging = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--email")) {
            email = args.next() orelse {
                writeErr("--email requires an address\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--staging")) {
            use_staging = true;
        } else if (arg[0] != '-') {
            domain = arg;
        } else {
            writeErr("unknown option: {s}\n", .{arg});
            std.process.exit(1);
        }
    }

    const dom = domain orelse {
        writeErr("usage: yoq cert provision <domain> --email <email> [--staging]\n", .{});
        std.process.exit(1);
    };
    const em = email orelse {
        writeErr("--email is required for ACME provisioning\n", .{});
        std.process.exit(1);
    };

    const directory_url = if (use_staging)
        acme.letsencrypt_staging
    else
        acme.letsencrypt_production;

    writeErr("provisioning certificate for {s}...\n", .{dom});
    if (use_staging) writeErr("  using staging environment\n", .{});

    var client = acme.AcmeClient.init(alloc, directory_url);
    defer client.deinit();

    // step 1: discover endpoints
    client.fetchDirectory() catch {
        writeErr("failed to fetch ACME directory\n", .{});
        std.process.exit(1);
    };

    // step 2: create account
    client.createAccount(em) catch {
        writeErr("failed to create ACME account\n", .{});
        std.process.exit(1);
    };
    writeErr("  account registered\n", .{});

    // step 3: create order
    var order = client.createOrder(dom) catch {
        writeErr("failed to create certificate order\n", .{});
        std.process.exit(1);
    };
    defer order.deinit();

    // step 4: handle HTTP-01 challenge
    if (order.authorization_urls.len > 0) {
        var challenge = client.getHttpChallenge(order.authorization_urls[0]) catch {
            writeErr("failed to get HTTP-01 challenge\n", .{});
            std.process.exit(1);
        };
        defer challenge.deinit();

        writeErr("  challenge token: {s}\n", .{challenge.token});
        writeErr("  place at: /.well-known/acme-challenge/{s}\n", .{challenge.token});

        client.respondToChallenge(challenge.url) catch {
            writeErr("failed to respond to challenge\n", .{});
            std.process.exit(1);
        };
    }

    // step 5: finalize, export as PEM, and store
    var exported = client.finalizeAndExport(order.finalize_url, dom) catch {
        writeErr("failed to finalize certificate order\n", .{});
        std.process.exit(1);
    };
    defer exported.deinit();

    var cs = openCertStore(alloc);
    defer closeCertStore(alloc, &cs);

    cs.install(dom, exported.cert_pem, exported.key_pem, "acme") catch {
        writeErr("failed to store certificate\n", .{});
        std.process.exit(1);
    };

    writeErr("certificate provisioned for {s}\n", .{dom});
}

fn cmdCertRenew(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const domain = requireArg(args, "usage: yoq cert renew <domain>\n");

    // check if cert exists and get its source
    var cs = openCertStore(alloc);
    defer closeCertStore(alloc, &cs);

    // verify the domain has an existing certificate
    const needs = cs.needsRenewal(domain, 90) catch |err| {
        if (err == cert_store.CertError.NotFound) {
            writeErr("no certificate found for {s}\n", .{domain});
        } else {
            writeErr("failed to check certificate for {s}\n", .{domain});
        }
        std.process.exit(1);
    };

    if (!needs) {
        writeErr("certificate for {s} does not need renewal yet\n", .{domain});
        return;
    }

    writeErr("certificate for {s} needs renewal\n", .{domain});
    writeErr("run: yoq cert provision {s} --email <email>\n", .{domain});
    writeErr("automatic renewal via the orchestrator is available in the next release\n", .{});
}

/// open a CertStore with a heap-allocated database connection.
/// exits on failure — used by CLI commands.
/// caller must call closeCertStore() when done.
fn openCertStore(alloc: std.mem.Allocator) cert_store.CertStore {
    const db_ptr = alloc.create(sqlite.Db) catch {
        writeErr("failed to allocate database\n", .{});
        std.process.exit(1);
    };
    db_ptr.* = store.openDb() catch {
        alloc.destroy(db_ptr);
        writeErr("failed to open database\n", .{});
        std.process.exit(1);
    };

    return cert_store.CertStore.init(db_ptr, alloc) catch |err| {
        db_ptr.deinit();
        alloc.destroy(db_ptr);
        if (err == cert_store.CertError.HomeDirNotFound) {
            writeErr("HOME directory not found\n", .{});
        } else {
            writeErr("failed to initialize certificate store\n", .{});
        }
        std.process.exit(1);
    };
}

/// close a cert store opened with openCertStore.
fn closeCertStore(alloc: std.mem.Allocator, cs: *cert_store.CertStore) void {
    cs.db.deinit();
    alloc.destroy(cs.db);
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

test "generateAndSaveToken produces valid 64-char hex string" {
    var buf: [64]u8 = undefined;
    const token = generateAndSaveToken(&buf);
    try std.testing.expect(token != null);
    try std.testing.expectEqual(@as(usize, 64), token.?.len);
    for (token.?) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "readApiToken round-trip with generateAndSaveToken" {
    // generate a token
    var gen_buf: [64]u8 = undefined;
    const generated = generateAndSaveToken(&gen_buf).?;

    // read it back
    var read_buf: [64]u8 = undefined;
    const read_back = readApiToken(&read_buf).?;
    try std.testing.expectEqualSlices(u8, generated, read_back);
}

test "readApiToken returns null for missing file" {
    // temporarily rename token file if it exists, test, restore
    var path_buf: [paths.max_path]u8 = undefined;
    const token_path = paths.dataPath(&path_buf, "api_token") catch return;

    var backup_buf: [paths.max_path]u8 = undefined;
    const backup_path = paths.dataPath(&backup_buf, "api_token.test_backup") catch return;

    // move existing file out of the way
    std.fs.cwd().rename(token_path, backup_path) catch {};
    defer std.fs.cwd().rename(backup_path, token_path) catch {};

    var buf: [64]u8 = undefined;
    try std.testing.expect(readApiToken(&buf) == null);
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
    _ = @import("state/store.zig");
    _ = @import("state/schema.zig");
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
}
