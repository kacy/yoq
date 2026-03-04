const std = @import("std");
const cli = @import("lib/cli.zig");
const store = @import("state/store.zig");
const container = @import("runtime/container.zig");
const process = @import("runtime/process.zig");
const logs = @import("runtime/logs.zig");
const spec = @import("image/spec.zig");
const registry = @import("image/registry.zig");
const layer = @import("image/layer.zig");
const oci = @import("image/oci.zig");
const net_setup = @import("network/setup.zig");
const ip = @import("network/ip.zig");
const exec = @import("runtime/exec.zig");
const dockerfile = @import("build/dockerfile.zig");
const build_engine = @import("build/engine.zig");
const manifest_loader = @import("manifest/loader.zig");
const orchestrator = @import("manifest/orchestrator.zig");
const watcher_mod = @import("dev/watcher.zig");
const manifest_spec = @import("manifest/spec.zig");
const api_server = @import("api/server.zig");

const write = cli.write;
const writeErr = cli.writeErr;

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
        cmdPull(&args, alloc);
    } else if (std.mem.eql(u8, command, "images")) {
        cmdImages(alloc);
    } else if (std.mem.eql(u8, command, "rmi")) {
        cmdRmi(&args, alloc);
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
            port_maps.append(alloc, pm) catch {};
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
        user_argv.append(alloc, arg) catch {};
    }

    return .{
        .port_maps = port_maps,
        .networking_enabled = networking_enabled,
        .container_name = container_name,
        .target = run_target,
        .user_argv = user_argv,
    };
}

const ImageResolution = struct {
    rootfs: []const u8,
    entrypoint: []const []const u8 = &.{},
    default_cmd: []const []const u8 = &.{},
    image_env: []const []const u8 = &.{},
    working_dir: []const u8 = "/",
    layer_paths: []const []const u8 = &.{},
    pull_result: ?registry.PullResult = null,
    config_parsed: ?spec.ParseResult(spec.ImageConfig) = null,

    fn deinit(self: *ImageResolution) void {
        if (self.pull_result) |*r| r.deinit();
        if (self.config_parsed) |*c| c.deinit();
    }
};

/// pull an image and extract its config. returns the rootfs path,
/// image defaults, and layer paths for overlayfs.
fn pullAndResolveImage(alloc: std.mem.Allocator, target: []const u8) ImageResolution {
    const ref = spec.parseImageRef(target);

    writeErr("pulling {s}...\n", .{target});

    var result = ImageResolution{ .rootfs = target };

    result.pull_result = registry.pull(alloc, ref) catch {
        writeErr("failed to pull image: {s}\n", .{target});
        std.process.exit(1);
    };

    result.config_parsed = spec.parseImageConfig(alloc, result.pull_result.?.config_bytes) catch {
        writeErr("failed to parse image config\n", .{});
        std.process.exit(1);
    };

    // extract defaults from image config
    if (result.config_parsed.?.value.config) |cc| {
        if (cc.Entrypoint) |ep| result.entrypoint = ep;
        if (cc.Cmd) |cmd| result.default_cmd = cmd;
        if (cc.Env) |env| result.image_env = env;
        if (cc.WorkingDir) |wd| {
            if (wd.len > 0) result.working_dir = wd;
        }
    }

    // extract layers for overlayfs
    result.layer_paths = layer.assembleRootfs(alloc, result.pull_result.?.layer_digests) catch {
        writeErr("failed to extract image layers\n", .{});
        std.process.exit(1);
    };

    if (result.layer_paths.len > 0) {
        result.rootfs = result.layer_paths[result.layer_paths.len - 1];
    }

    // save image record
    oci.saveImageFromPull(ref, result.pull_result.?.manifest_digest, result.pull_result.?.total_size) catch {};

    writeErr("image pulled and extracted\n", .{});
    return result;
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
        pullAndResolveImage(alloc, flags.target)
    else
        ImageResolution{ .rootfs = flags.target };
    defer img.deinit();

    // resolve effective command per OCI spec
    var resolved = oci.resolveCommand(alloc, img.entrypoint, img.default_cmd, flags.user_argv.items);
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

    write("{s}\n", .{id});

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

    c.start() catch {
        writeErr("failed to start container\n", .{});
        std.process.exit(1);
    };

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

        const ip_display: []const u8 = record.ip_address orelse "-";
        write("{s:<14} {s:<10} {s:<16} {s:<20}\n", .{ id, record.status, ip_display, record.command });
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

    process.terminate(pid) catch {
        writeErr("failed to stop container {s}\n", .{id});
        std.process.exit(1);
    };

    // clean up network resources
    cleanupNetwork(id, record.ip_address, record.veth_host);

    store.updateStatus(id, "stopped", null, null) catch {};

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
        exec_args.append(alloc, arg) catch {};
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

fn cmdPull(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const image_str = requireArg(args, "usage: yoq pull <image>\n");

    const ref = spec.parseImageRef(image_str);

    writeErr("pulling {s}...\n", .{image_str});

    var result = registry.pull(alloc, ref) catch {
        writeErr("failed to pull image: {s}\n", .{image_str});
        std.process.exit(1);
    };
    defer result.deinit();

    // extract layers so they're cached for future runs
    const layer_paths = layer.assembleRootfs(alloc, result.layer_digests) catch {
        writeErr("failed to extract image layers\n", .{});
        std.process.exit(1);
    };
    defer {
        for (layer_paths) |p| alloc.free(p);
        alloc.free(layer_paths);
    }

    // save image record
    oci.saveImageFromPull(ref, result.manifest_digest, result.total_size) catch {
        writeErr("failed to save image record\n", .{});
        std.process.exit(1);
    };

    // format size for display
    const size_mb = result.total_size / (1024 * 1024);
    write("{s}: pulled ({d} layers, {d} MB)\n", .{
        image_str,
        result.layer_digests.len,
        size_mb,
    });
}

fn cmdImages(alloc: std.mem.Allocator) void {
    var images = store.listImages(alloc) catch {
        writeErr("failed to list images\n", .{});
        std.process.exit(1);
    };
    defer {
        for (images.items) |img| img.deinit(alloc);
        images.deinit(alloc);
    }

    if (images.items.len == 0) {
        write("no images\n", .{});
        return;
    }

    write("{s:<30} {s:<15} {s:<14} {s:<10}\n", .{ "REPOSITORY", "TAG", "IMAGE ID", "SIZE" });
    for (images.items) |img| {
        // truncate the digest for display (first 12 chars after "sha256:")
        const short_id = if (img.id.len > 19) img.id[7..19] else img.id;
        const size_mb = @divTrunc(img.total_size, 1024 * 1024);

        write("{s:<30} {s:<15} {s:<14} {d} MB\n", .{
            img.repository,
            img.tag,
            short_id,
            size_mb,
        });
    }
}

fn cmdRmi(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const image_str = requireArg(args, "usage: yoq rmi <image>\n");

    // try to find the image by repository:tag
    const ref = spec.parseImageRef(image_str);
    const image = store.findImage(alloc, ref.repository, ref.reference) catch {
        writeErr("image not found: {s}\n", .{image_str});
        std.process.exit(1);
    };
    defer image.deinit(alloc);

    // remove the image record from the database
    store.removeImage(image.id) catch {
        writeErr("failed to remove image record\n", .{});
        std.process.exit(1);
    };

    // note: we don't delete the blobs or extracted layers here.
    // a future `yoq prune` command can handle garbage collection
    // of unreferenced blobs. this matches docker's behavior —
    // rmi removes the tag, prune cleans up storage.

    write("untagged: {s}:{s}\n", .{ image.repository, image.tag });
}

fn cmdBuild(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var tag: ?[]const u8 = null;
    var dockerfile_path: []const u8 = "Dockerfile";
    var context_path: ?[]const u8 = null;

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
        } else {
            context_path = arg;
        }
    }

    const ctx_dir = context_path orelse ".";

    // resolve Dockerfile path relative to context directory
    var df_path_buf: [4096]u8 = undefined;
    const effective_df_path = if (std.mem.eql(u8, dockerfile_path, "Dockerfile"))
        std.fmt.bufPrint(&df_path_buf, "{s}/Dockerfile", .{ctx_dir}) catch {
            writeErr("path too long\n", .{});
            std.process.exit(1);
        }
    else
        dockerfile_path;

    // read the Dockerfile
    const content = std.fs.cwd().readFileAlloc(alloc, effective_df_path, 1024 * 1024) catch {
        writeErr("cannot read {s}\n", .{effective_df_path});
        std.process.exit(1);
    };
    defer alloc.free(content);

    // parse
    var parsed = dockerfile.parse(alloc, content) catch |err| {
        switch (err) {
            dockerfile.ParseError.UnknownInstruction => writeErr("unknown instruction in Dockerfile\n", .{}),
            dockerfile.ParseError.EmptyInstruction => writeErr("empty instruction in Dockerfile\n", .{}),
            dockerfile.ParseError.OutOfMemory => writeErr("out of memory\n", .{}),
        }
        std.process.exit(1);
    };
    defer parsed.deinit();

    writeErr("building from {s} ({d} instructions)...\n", .{
        effective_df_path, parsed.instructions.len,
    });

    // resolve context directory to absolute path
    var abs_ctx_buf: [4096]u8 = undefined;
    const abs_ctx = std.fs.cwd().realpath(ctx_dir, &abs_ctx_buf) catch {
        writeErr("cannot resolve context directory: {s}\n", .{ctx_dir});
        std.process.exit(1);
    };

    // build
    var result = build_engine.build(alloc, parsed.instructions, abs_ctx, tag) catch |err| {
        switch (err) {
            build_engine.BuildError.NoFromInstruction => writeErr("Dockerfile must start with FROM\n", .{}),
            build_engine.BuildError.PullFailed => writeErr("failed to pull base image\n", .{}),
            build_engine.BuildError.RunStepFailed => writeErr("RUN step failed\n", .{}),
            build_engine.BuildError.CopyStepFailed => writeErr("COPY step failed\n", .{}),
            build_engine.BuildError.LayerFailed => writeErr("failed to create layer\n", .{}),
            build_engine.BuildError.ImageStoreFailed => writeErr("failed to store image\n", .{}),
            build_engine.BuildError.ParseFailed => writeErr("failed to parse Dockerfile\n", .{}),
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

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--dev")) {
            dev_mode = true;
        }
    }

    // load and validate manifest
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
        w = watcher_mod.Watcher.init() catch null;

        if (w != null) {
            // add watches for each service's bind-mounted volumes
            for (manifest.services, 0..) |svc, i| {
                for (svc.volumes) |vol| {
                    if (vol.kind != .bind) continue;

                    // resolve relative source path to absolute
                    var resolve_buf: [4096]u8 = undefined;
                    const abs_source = std.fs.cwd().realpath(vol.source, &resolve_buf) catch continue;

                    w.?.addRecursive(abs_source, i) catch {};
                }
            }

            // spawn watcher thread
            watcher_thread = std.Thread.spawn(.{}, orchestrator.watcherThread, .{
                &orch, &w.?,
            }) catch null;
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
        store.updateStatus(rec.id, "stopped", null, null) catch {};
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

    var server = api_server.Server.init(alloc, port) catch {
        writeErr("failed to start server on port {d}\n", .{port});
        std.process.exit(1);
    };
    defer server.deinit();

    orchestrator.installSignalHandlers();
    server.run();
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
        \\  down [-f manifest.toml]          stop all services from manifest
        \\  serve [--port PORT]             start the API server (default: 7700)
        \\  build [opts] <path>              build an image from a Dockerfile
        \\  exec <id> <cmd> [args...]         run a command in a running container
        \\  ps                               list containers
        \\  logs <id>                        show container output
        \\  stop <id>                        stop a running container
        \\  rm <id>                          remove a stopped container
        \\  pull <image>                     pull an image from a registry
        \\  images                           list pulled images
        \\  rmi <image>                      remove a pulled image
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
        \\other options:
        \\  logs --tail N             show last N lines only
        \\
    , .{});
}

/// validate a container name as an RFC 1123 DNS label.
/// must be 1-63 chars, alphanumeric or hyphens, no leading/trailing hyphen.
fn isValidContainerName(name: []const u8) bool {
    if (name.len == 0 or name.len > 63) return false;
    if (name[0] == '-' or name[name.len - 1] == '-') return false;
    for (name) |c| {
        const ok = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '-';
        if (!ok) return false;
    }
    return true;
}

/// parse a port mapping string "host_port:container_port" into a PortMap
fn parsePortMap(str: []const u8) ?net_setup.PortMap {
    // find the colon separator
    const colon_pos = std.mem.indexOf(u8, str, ":") orelse return null;
    if (colon_pos == 0 or colon_pos >= str.len - 1) return null;

    const host_port = std.fmt.parseInt(u16, str[0..colon_pos], 10) catch return null;
    const container_port = std.fmt.parseInt(u16, str[colon_pos + 1 ..], 10) catch return null;

    return .{ .host_port = host_port, .container_port = container_port };
}

/// require the next CLI argument, or print usage and exit.
/// used by commands that take a single required positional argument.
fn requireArg(args: *std.process.ArgIterator, comptime usage: []const u8) []const u8 {
    return args.next() orelse {
        writeErr(usage, .{});
        std.process.exit(1);
    };
}

/// full cleanup for a stopped container: network, store record, logs, dirs.
/// used by cmdRm and the per-service cleanup loop in cmdDown.
fn cleanupStoppedContainer(id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    cleanupNetwork(id, ip_address, veth_host);
    store.remove(id) catch {};
    logs.deleteLogFile(id);
    container.cleanupContainerDirs(id);
}

/// clean up network resources for a container (veth pair + IP allocation).
/// called from cmdStop and cmdRm. non-fatal — ignores errors.
fn cleanupNetwork(container_id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    const bridge = @import("network/bridge.zig");

    // delete veth pair
    if (veth_host) |veth| {
        var name_buf: [32]u8 = undefined;
        const len = @min(veth.len, name_buf.len);
        @memcpy(name_buf[0..len], veth[0..len]);
        bridge.deleteVeth(name_buf[0..len]) catch {};
    }

    // release IP allocation
    if (ip_address != null) {
        var db = store.openDb() catch return;
        defer db.deinit();
        ip.release(&db, container_id) catch {};
    }
}

test "smoke test" {
    try std.testing.expect(true);
}

test "parse port map" {
    const pm = parsePortMap("8080:80").?;
    try std.testing.expectEqual(@as(u16, 8080), pm.host_port);
    try std.testing.expectEqual(@as(u16, 80), pm.container_port);
}

test "parse port map invalid" {
    try std.testing.expect(parsePortMap("invalid") == null);
    try std.testing.expect(parsePortMap(":80") == null);
    try std.testing.expect(parsePortMap("8080:") == null);
    try std.testing.expect(parsePortMap("99999:80") == null);
}

test "valid container names" {
    try std.testing.expect(isValidContainerName("db"));
    try std.testing.expect(isValidContainerName("web-api"));
    try std.testing.expect(isValidContainerName("my-service-1"));
    try std.testing.expect(isValidContainerName("A"));
    try std.testing.expect(isValidContainerName("abc123"));
}

test "invalid container names" {
    try std.testing.expect(!isValidContainerName(""));
    try std.testing.expect(!isValidContainerName("-db"));
    try std.testing.expect(!isValidContainerName("db-"));
    try std.testing.expect(!isValidContainerName("my db"));
    try std.testing.expect(!isValidContainerName("../../etc/passwd"));
    try std.testing.expect(!isValidContainerName("a" ** 64));
    try std.testing.expect(!isValidContainerName("hello_world"));
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
    _ = @import("image/spec.zig");
    _ = @import("image/store.zig");
    _ = @import("image/registry.zig");
    _ = @import("image/layer.zig");
    _ = @import("image/oci.zig");
    _ = @import("network/netlink.zig");
    _ = @import("network/bridge.zig");
    _ = @import("network/dns.zig");
    _ = @import("network/ip.zig");
    _ = @import("network/nat.zig");
    _ = @import("network/setup.zig");
    _ = @import("build/dockerfile.zig");
    _ = @import("build/context.zig");
    _ = @import("build/engine.zig");
    _ = @import("manifest/spec.zig");
    _ = @import("manifest/loader.zig");
    _ = @import("manifest/orchestrator.zig");
    _ = @import("dev/log_mux.zig");
    _ = @import("dev/watcher.zig");
    _ = @import("api/http.zig");
    _ = @import("api/routes.zig");
    _ = @import("api/server.zig");
}
