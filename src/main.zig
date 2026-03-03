const std = @import("std");
const store = @import("state/store.zig");
const container = @import("runtime/container.zig");
const logs = @import("runtime/logs.zig");
const spec = @import("image/spec.zig");
const registry = @import("image/registry.zig");
const layer = @import("image/layer.zig");

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
        cmdStop(&args);
    } else if (std.mem.eql(u8, command, "rm")) {
        cmdRm(&args);
    } else if (std.mem.eql(u8, command, "logs")) {
        cmdLogs(&args, alloc);
    } else if (std.mem.eql(u8, command, "pull")) {
        cmdPull(&args, alloc);
    } else if (std.mem.eql(u8, command, "images")) {
        cmdImages(alloc);
    } else if (std.mem.eql(u8, command, "rmi")) {
        cmdRmi(&args, alloc);
    } else {
        writeErr("unknown command: {s}\n", .{command});
        printUsage();
        std.process.exit(1);
    }
}

fn cmdRun(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const target = args.next() orelse {
        writeErr("usage: yoq run <image|rootfs> [command]\n", .{});
        std.process.exit(1);
    };

    // detect if target is an image reference or a local rootfs path.
    // image references don't start with '/' or './'
    const is_image = !std.mem.startsWith(u8, target, "/") and
        !std.mem.startsWith(u8, target, "./");

    // collect user-provided command + args from CLI
    var user_argv: std.ArrayList([]const u8) = .empty;
    defer user_argv.deinit(alloc);
    while (args.next()) |arg| {
        user_argv.append(alloc, arg) catch {};
    }

    // these will be populated from the image config or defaults
    var entrypoint: []const []const u8 = &.{};
    var default_cmd: []const []const u8 = &.{};
    var image_env: []const []const u8 = &.{};
    var working_dir: []const u8 = "/";
    var layer_paths: []const []const u8 = &.{};
    var rootfs_str: []const u8 = target;

    // image pull state (deferred cleanup)
    var pull_result: ?registry.PullResult = null;
    defer if (pull_result) |*r| r.deinit();
    var config_parsed: ?spec.ParseResult(spec.ImageConfig) = null;
    defer if (config_parsed) |*c| c.deinit();

    if (is_image) {
        const ref = spec.parseImageRef(target);

        writeErr("pulling {s}...\n", .{target});

        pull_result = registry.pull(alloc, ref) catch {
            writeErr("failed to pull image: {s}\n", .{target});
            std.process.exit(1);
        };

        config_parsed = spec.parseImageConfig(alloc, pull_result.?.config_bytes) catch {
            writeErr("failed to parse image config\n", .{});
            std.process.exit(1);
        };

        // extract defaults from image config
        if (config_parsed.?.value.config) |cc| {
            if (cc.Entrypoint) |ep| entrypoint = ep;
            if (cc.Cmd) |cmd| default_cmd = cmd;
            if (cc.Env) |env| image_env = env;
            if (cc.WorkingDir) |wd| {
                if (wd.len > 0) working_dir = wd;
            }
        }

        // extract layers for overlayfs
        layer_paths = layer.assembleRootfs(alloc, pull_result.?.layer_digests) catch {
            writeErr("failed to extract image layers\n", .{});
            std.process.exit(1);
        };

        if (layer_paths.len > 0) {
            rootfs_str = layer_paths[layer_paths.len - 1];
        }

        // save image record
        store.saveImage(.{
            .id = pull_result.?.manifest_digest,
            .repository = ref.repository,
            .tag = ref.reference,
            .manifest_digest = pull_result.?.manifest_digest,
            .config_digest = "sha256:config",
            .total_size = @intCast(pull_result.?.total_size),
            .created_at = std.time.timestamp(),
        }) catch {};

        writeErr("image pulled and extracted\n", .{});
    }

    // resolve the effective command per OCI spec:
    //   effective_argv = entrypoint ++ (user_override or default_cmd)
    // if nothing specified, fall back to /bin/sh
    const effective_args: []const []const u8 = if (user_argv.items.len > 0)
        user_argv.items
    else
        default_cmd;

    const effective_cmd: []const u8 = if (entrypoint.len > 0)
        entrypoint[0]
    else if (effective_args.len > 0)
        effective_args[0]
    else
        "/bin/sh";

    // build the full args list: entrypoint[1..] ++ effective_args
    // (or effective_args[1..] if no entrypoint)
    var full_args: std.ArrayList([]const u8) = .empty;
    defer full_args.deinit(alloc);

    if (entrypoint.len > 1) {
        for (entrypoint[1..]) |ep_arg| {
            full_args.append(alloc, ep_arg) catch {};
        }
    }

    if (entrypoint.len > 0) {
        // entrypoint is set — append all of effective_args
        for (effective_args) |arg| {
            full_args.append(alloc, arg) catch {};
        }
    } else if (effective_args.len > 1) {
        // no entrypoint — effective_args[0] is the command, rest are args
        for (effective_args[1..]) |arg| {
            full_args.append(alloc, arg) catch {};
        }
    }

    // generate container id
    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf);
    const id = id_buf[0..];

    // save container record
    store.save(.{
        .id = id,
        .rootfs = rootfs_str,
        .command = effective_cmd,
        .hostname = "container",
        .status = "created",
        .pid = null,
        .exit_code = null,
        .created_at = std.time.timestamp(),
    }) catch {
        writeErr("failed to save container state\n", .{});
        std.process.exit(1);
    };

    write("{s}\n", .{id});

    // build container config and start execution
    var c = container.Container{
        .config = .{
            .id = id,
            .rootfs = rootfs_str,
            .command = effective_cmd,
            .args = full_args.items,
            .env = image_env,
            .working_dir = working_dir,
            .lower_dirs = layer_paths,
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

    write("{s:<14} {s:<10} {s:<20}\n", .{ "CONTAINER ID", "STATUS", "COMMAND" });
    for (ids.items) |id| {
        const record = store.load(alloc, id) catch {
            write("{s:<14} {s:<10} {s:<20}\n", .{ id, "unknown", "-" });
            continue;
        };
        defer {
            alloc.free(record.rootfs);
            alloc.free(record.command);
            alloc.free(record.hostname);
            alloc.free(record.status);
        }
        // don't double-free — load() allocates its own copy of id,
        // but we already have one from listIds(). free load's copy.
        alloc.free(record.id);

        write("{s:<14} {s:<10} {s:<20}\n", .{ id, record.status, record.command });
    }
}

fn cmdStop(args: *std.process.ArgIterator) void {
    const id = args.next() orelse {
        writeErr("usage: yoq stop <container-id>\n", .{});
        std.process.exit(1);
    };
    write("stopping {s}...\n", .{id});
    // on Linux: look up pid from state, send SIGTERM
    writeErr("stop requires Linux\n", .{});
}

fn cmdRm(args: *std.process.ArgIterator) void {
    const id = args.next() orelse {
        writeErr("usage: yoq rm <container-id>\n", .{});
        std.process.exit(1);
    };

    store.remove(id) catch {
        writeErr("container not found: {s}\n", .{id});
        std.process.exit(1);
    };

    // clean up log file too
    logs.deleteLogFile(id);

    write("{s}\n", .{id});
}

fn cmdLogs(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const id = args.next() orelse {
        writeErr("usage: yoq logs <container-id> [--tail N]\n", .{});
        std.process.exit(1);
    };

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
    const image_str = args.next() orelse {
        writeErr("usage: yoq pull <image>\n", .{});
        std.process.exit(1);
    };

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
    store.saveImage(.{
        .id = result.manifest_digest,
        .repository = ref.repository,
        .tag = ref.reference,
        .manifest_digest = result.manifest_digest,
        .config_digest = "sha256:config",
        .total_size = @intCast(result.total_size),
        .created_at = std.time.timestamp(),
    }) catch {
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
        for (images.items) |img| {
            alloc.free(img.id);
            alloc.free(img.repository);
            alloc.free(img.tag);
            alloc.free(img.manifest_digest);
            alloc.free(img.config_digest);
        }
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
    const image_str = args.next() orelse {
        writeErr("usage: yoq rmi <image>\n", .{});
        std.process.exit(1);
    };

    // try to find the image by repository:tag
    const ref = spec.parseImageRef(image_str);
    const image = store.findImage(alloc, ref.repository, ref.reference) catch {
        writeErr("image not found: {s}\n", .{image_str});
        std.process.exit(1);
    };
    defer {
        alloc.free(image.id);
        alloc.free(image.repository);
        alloc.free(image.tag);
        alloc.free(image.manifest_digest);
        alloc.free(image.config_digest);
    }

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

fn printUsage() void {
    write(
        \\yoq — container runtime and orchestrator
        \\
        \\usage: yoq <command> [options]
        \\
        \\commands:
        \\  run <image|rootfs> [cmd]  create and run a container
        \\  ps                        list containers
        \\  logs <id>                 show container output
        \\  stop <id>                 stop a running container
        \\  rm <id>                   remove a stopped container
        \\  pull <image>              pull an image from a registry
        \\  images                    list pulled images
        \\  rmi <image>               remove a pulled image
        \\  version                   print version
        \\  help                      show this help
        \\
        \\options:
        \\  logs --tail N             show last N lines only
        \\
    , .{});
}

fn write(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = std.fs.File.stdout().writer(&buf);
    const out = &w.interface;
    out.print(fmt, args) catch {};
    out.flush() catch {};
}

fn writeErr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = std.fs.File.stderr().writer(&buf);
    const out = &w.interface;
    out.print(fmt, args) catch {};
    out.flush() catch {};
}

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
    _ = @import("runtime/logs.zig");
    _ = @import("state/store.zig");
    _ = @import("state/schema.zig");
    _ = @import("lib/log.zig");
    _ = @import("image/spec.zig");
    _ = @import("image/store.zig");
    _ = @import("image/registry.zig");
    _ = @import("image/layer.zig");
}
