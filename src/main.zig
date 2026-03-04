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
const blob_store = @import("image/store.zig");
const net_setup = @import("network/setup.zig");
const ip = @import("network/ip.zig");
const exec = @import("runtime/exec.zig");
const dockerfile = @import("build/dockerfile.zig");
const build_engine = @import("build/engine.zig");
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
const sqlite = @import("sqlite");
const secrets = @import("state/secrets.zig");
const dns = @import("network/dns.zig");

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
    } else if (std.mem.eql(u8, command, "push")) {
        cmdPush(&args, alloc);
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

    // compute config digest from config bytes
    const pr = result.pull_result.?;
    const cfg_computed = blob_store.computeDigest(pr.config_bytes);
    var cfg_digest_buf: [71]u8 = undefined;
    const cfg_digest_str = cfg_computed.string(&cfg_digest_buf);

    // save image record (stores manifest/config blobs and metadata)
    oci.saveImageFromPull(
        ref,
        pr.manifest_digest,
        pr.manifest_bytes,
        pr.config_bytes,
        cfg_digest_str,
        pr.total_size,
    ) catch |e| {
        writeErr("warning: failed to save image record: {}\n", .{e});
    };

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

    // compute config digest from config bytes
    const config_computed = blob_store.computeDigest(result.config_bytes);
    var config_digest_buf: [71]u8 = undefined;
    const config_digest_str = config_computed.string(&config_digest_buf);

    // save image record (stores manifest/config blobs and metadata)
    oci.saveImageFromPull(
        ref,
        result.manifest_digest,
        result.manifest_bytes,
        result.config_bytes,
        config_digest_str,
        result.total_size,
    ) catch {
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

fn cmdPush(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const source_str = requireArg(args, "usage: yoq push <source> [target]\n");

    // optional target — if not given, push to the same ref
    const target_str = args.next() orelse source_str;

    // look up the source image in the local store
    const source_ref = spec.parseImageRef(source_str);
    const image_record = store.findImage(alloc, source_ref.repository, source_ref.reference) catch {
        writeErr("image not found: {s}\n", .{source_str});
        writeErr("pull or build the image first, then push\n", .{});
        std.process.exit(1);
    };
    defer image_record.deinit(alloc);

    // read manifest bytes from the blob store
    const manifest_parsed_digest = blob_store.Digest.parse(image_record.manifest_digest) orelse {
        writeErr("invalid manifest digest in image record\n", .{});
        std.process.exit(1);
    };
    const manifest_bytes = blob_store.getBlob(alloc, manifest_parsed_digest) catch {
        writeErr("failed to read manifest from blob store\n", .{});
        writeErr("the image may be corrupted — try pulling again\n", .{});
        std.process.exit(1);
    };
    defer alloc.free(manifest_bytes);

    // read config bytes from the blob store
    const config_parsed_digest = blob_store.Digest.parse(image_record.config_digest) orelse {
        writeErr("invalid config digest in image record\n", .{});
        std.process.exit(1);
    };
    const config_bytes = blob_store.getBlob(alloc, config_parsed_digest) catch {
        writeErr("failed to read config from blob store\n", .{});
        writeErr("the image may be corrupted — try pulling again\n", .{});
        std.process.exit(1);
    };
    defer alloc.free(config_bytes);

    // parse manifest to get layer digests
    var parsed_manifest = spec.parseManifest(alloc, manifest_bytes) catch {
        writeErr("failed to parse image manifest\n", .{});
        std.process.exit(1);
    };
    defer parsed_manifest.deinit();

    // collect layer digests
    var layer_digest_strs: std.ArrayListUnmanaged([]const u8) = .empty;
    defer layer_digest_strs.deinit(alloc);
    for (parsed_manifest.value.layers) |l| {
        layer_digest_strs.append(alloc, l.digest) catch {
            writeErr("out of memory\n", .{});
            std.process.exit(1);
        };
    }

    // parse the target reference for pushing
    const target_ref = spec.parseImageRef(target_str);

    writeErr("pushing {s}...\n", .{target_str});

    var result = registry.push(alloc, target_ref, manifest_bytes, config_bytes, layer_digest_strs.items) catch |e| {
        writeErr("failed to push image: {}\n", .{e});
        std.process.exit(1);
    };
    defer result.deinit();

    write("{s}: pushed ({d} layers uploaded, {d} skipped)\n", .{
        target_str,
        result.layers_uploaded,
        result.layers_skipped,
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
    const cli_args: ?[]const []const u8 = if (build_args_list.items.len > 0)
        build_args_list.items
    else
        null;
    var result = build_engine.build(alloc, parsed.instructions, abs_ctx, tag, cli_args) catch |err| {
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
    // parse host:port
    var server_ip: [4]u8 = .{ 127, 0, 0, 1 };
    var server_port: u16 = 7700;

    if (std.mem.indexOf(u8, addr_str, ":")) |colon| {
        server_ip = parseIpv4(addr_str[0..colon]) orelse {
            writeErr("invalid server address: {s}\n", .{addr_str});
            std.process.exit(1);
        };
        server_port = std.fmt.parseInt(u16, addr_str[colon + 1 ..], 10) catch {
            writeErr("invalid port in server address: {s}\n", .{addr_str});
            std.process.exit(1);
        };
    } else {
        server_ip = parseIpv4(addr_str) orelse {
            writeErr("invalid server address: {s}\n", .{addr_str});
            std.process.exit(1);
        };
    }

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

    // POST to /deploy
    var resp = http_client.post(alloc, server_ip, server_port, "/deploy", json_buf.items) catch {
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

    // single-node mode: bind to localhost only — no auth needed
    var server = api_server.Server.init(alloc, port, .{ 127, 0, 0, 1 }) catch {
        writeErr("failed to start server on port {d}\n", .{port});
        std.process.exit(1);
    };
    defer server.deinit();

    orchestrator.installSignalHandlers();
    server.run();
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
    const server_addr = parseIpv4(host) orelse {
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
            .private_key = kp.privateKeySlice(),
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
        .private_key = kp.privateKeySlice(),
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
    var server_addr: [4]u8 = .{ 127, 0, 0, 1 };
    var server_port: u16 = 7700;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                std.process.exit(1);
            };
            if (std.mem.indexOf(u8, addr_str, ":")) |colon| {
                server_addr = parseIpv4(addr_str[0..colon]) orelse {
                    writeErr("invalid server address: {s}\n", .{addr_str});
                    std.process.exit(1);
                };
                server_port = std.fmt.parseInt(u16, addr_str[colon + 1 ..], 10) catch {
                    writeErr("invalid port: {s}\n", .{addr_str});
                    std.process.exit(1);
                };
            } else {
                server_addr = parseIpv4(addr_str) orelse {
                    writeErr("invalid server address: {s}\n", .{addr_str});
                    std.process.exit(1);
                };
            }
        }
    }

    var resp = http_client.get(alloc, server_addr, server_port, "/agents") catch {
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
    var server_addr: [4]u8 = .{ 127, 0, 0, 1 };
    var server_port: u16 = 7700;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                std.process.exit(1);
            };
            if (std.mem.indexOf(u8, addr_str, ":")) |colon| {
                server_addr = parseIpv4(addr_str[0..colon]) orelse {
                    writeErr("invalid server address: {s}\n", .{addr_str});
                    std.process.exit(1);
                };
                server_port = std.fmt.parseInt(u16, addr_str[colon + 1 ..], 10) catch {
                    writeErr("invalid port: {s}\n", .{addr_str});
                    std.process.exit(1);
                };
            } else {
                server_addr = parseIpv4(addr_str) orelse {
                    writeErr("invalid server address: {s}\n", .{addr_str});
                    std.process.exit(1);
                };
            }
        } else {
            node_id = arg;
        }
    }

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

    var resp = http_client.post(alloc, server_addr, server_port, path, "") catch {
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

/// truncate a string to max_len, adding "..." if truncated
fn truncate(s: []const u8, max_len: usize) []const u8 {
    if (s.len <= max_len) return s;
    return s[0..max_len];
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
        const stdin_data = std.io.getStdIn().readToEndAlloc(alloc, 1024 * 1024) catch {
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
    store.remove(id) catch |e| {
        writeErr("warning: failed to remove container record {s}: {}\n", .{ id, e });
    };
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

/// parse a dotted IPv4 address string into 4 bytes.
// use shared JSON extraction helpers
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

fn parseIpv4(s: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var part: u8 = 0;
    var idx: usize = 0;

    for (s) |c| {
        if (c == '.') {
            if (idx >= 3) return null;
            result[idx] = part;
            idx += 1;
            part = 0;
        } else if (c >= '0' and c <= '9') {
            const digit = c - '0';
            const next = @as(u16, part) * 10 + digit;
            if (next > 255) return null;
            part = @intCast(next);
        } else {
            return null;
        }
    }

    if (idx != 3) return null;
    result[3] = part;
    return result;
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

test "parse ipv4 valid" {
    const addr = parseIpv4("10.0.0.1").?;
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, addr);
}

test "parse ipv4 localhost" {
    const addr = parseIpv4("127.0.0.1").?;
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, addr);
}

test "parse ipv4 invalid" {
    try std.testing.expect(parseIpv4("not.an.ip") == null);
    try std.testing.expect(parseIpv4("256.0.0.1") == null);
    try std.testing.expect(parseIpv4("1.2.3") == null);
    try std.testing.expect(parseIpv4("") == null);
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
    _ = @import("lib/sql.zig");
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
    _ = @import("network/wireguard.zig");
    _ = @import("build/dockerfile.zig");
    _ = @import("build/context.zig");
    _ = @import("build/engine.zig");
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
