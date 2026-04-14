const std = @import("std");
const cli = @import("cli.zig");
const image_cmds = @import("../image/commands.zig");
const cluster_cmds = @import("../cluster/commands.zig");
const state_cmds = @import("../state/commands.zig");
const net_cmds = @import("../network/commands.zig");
const runtime_cmds = @import("../runtime/commands.zig");
const tls_cmds = @import("../tls/commands.zig");
const container_cmds = @import("../runtime/container_commands.zig");
const build_cmds = @import("../build/commands.zig");
const manifest_cmds = @import("../manifest/commands.zig");
const gpu_cmds = @import("../gpu/commands.zig");
const doctor_cmds = @import("doctor_commands.zig");
const completion = @import("completion.zig");

const write = cli.write;

pub const CommandHandler = *const fn (*std.process.ArgIterator, std.mem.Allocator) anyerror!void;

pub const CommandGroup = enum {
    runtime,
    image,
    build_manifest,
    cluster,
    state_security,
    misc,
};

pub const CommandSpec = struct {
    name: []const u8,
    group: CommandGroup,
    usage: []const u8,
    description: []const u8,
    handler: CommandHandler,
    hidden: bool = false,
};

pub const command_specs = [_]CommandSpec{
    .{ .name = "run", .group = .runtime, .usage = "run [opts] <image|rootfs> [cmd]", .description = "create and run a container", .handler = container_cmds.run },
    .{ .name = "ps", .group = .runtime, .usage = "ps", .description = "list containers", .handler = psHandler },
    .{ .name = "logs", .group = .runtime, .usage = "logs <id|name>", .description = "show container output", .handler = container_cmds.log },
    .{ .name = "stop", .group = .runtime, .usage = "stop <id|name>", .description = "stop a running container", .handler = container_cmds.stop },
    .{ .name = "rm", .group = .runtime, .usage = "rm <id|name>", .description = "remove a stopped container", .handler = container_cmds.rm },
    .{ .name = "restart", .group = .runtime, .usage = "restart <id|name>", .description = "restart a container", .handler = container_cmds.restart },
    .{ .name = "exec", .group = .runtime, .usage = "exec <id|name> <cmd> [args...]", .description = "run a command in a running container", .handler = container_cmds.exec_cmd },
    .{ .name = "status", .group = .runtime, .usage = "status [--app [name]] [--verbose] [--server h:p]", .description = "show service or app status", .handler = runtime_cmds.status },
    .{ .name = "apps", .group = .runtime, .usage = "apps [--server h:p] [--json] [--status s|--failed|--in-progress]", .description = "list app release summaries", .handler = runtime_cmds.apps },
    .{ .name = "metrics", .group = .runtime, .usage = "metrics [service] [--server h:p]", .description = "show per-service network metrics", .handler = runtime_cmds.metrics },
    .{ .name = "gpu", .group = .runtime, .usage = "gpu <topo|bench> [--json]", .description = "GPU topology, diagnostics, and benchmarking", .handler = gpu_cmds.gpu },

    .{ .name = "pull", .group = .image, .usage = "pull <image>", .description = "pull an image from a registry", .handler = image_cmds.pull },
    .{ .name = "push", .group = .image, .usage = "push <source> [target]", .description = "push an image to a registry", .handler = image_cmds.push },
    .{ .name = "images", .group = .image, .usage = "images", .description = "list pulled images", .handler = imagesHandler },
    .{ .name = "rmi", .group = .image, .usage = "rmi <image>", .description = "remove a pulled image", .handler = image_cmds.rmi },
    .{ .name = "prune", .group = .image, .usage = "prune", .description = "remove unused blobs and layers", .handler = pruneHandler },
    .{ .name = "inspect", .group = .image, .usage = "inspect <image>", .description = "show image details", .handler = image_cmds.inspect },

    .{ .name = "build", .group = .build_manifest, .usage = "build [opts] <path>", .description = "build an image from a Dockerfile", .handler = build_cmds.build_cmd },
    .{ .name = "init", .group = .build_manifest, .usage = "init [-f path]", .description = "create a manifest.toml interactively", .handler = manifest_cmds.init },
    .{ .name = "validate", .group = .build_manifest, .usage = "validate [-f manifest.toml] [-q]", .description = "validate a manifest file", .handler = manifest_cmds.validate },
    .{ .name = "up", .group = .build_manifest, .usage = "up [-f manifest.toml] [--dev] [--server host:port] [service...]", .description = "start services from a manifest", .handler = manifest_cmds.up },
    .{ .name = "down", .group = .build_manifest, .usage = "down [-f manifest.toml]", .description = "stop all services from manifest", .handler = manifest_cmds.down },
    .{ .name = "run-worker", .group = .build_manifest, .usage = "run-worker [-f manifest.toml] [--server host:port] <name>", .description = "run a one-shot worker task", .handler = manifest_cmds.runWorker },
    .{ .name = "rollback", .group = .build_manifest, .usage = "rollback <service> | --app [name] [--server h:p] [--release id] [--print]", .description = "rollback a service or app release", .handler = manifest_cmds.rollback },
    .{ .name = "history", .group = .build_manifest, .usage = "history <service> | --app [name] [--server h:p] [--json]", .description = "show service or app release history", .handler = manifest_cmds.history },
    .{ .name = "rollout", .group = .build_manifest, .usage = "rollout <pause|resume|cancel> --app [name] [--server h:p]", .description = "control an active app rollout", .handler = manifest_cmds.rollout },
    .{ .name = "train", .group = .build_manifest, .usage = "train <start|status|stop|pause|resume|scale|logs> [--server host:port] <name>", .description = "manage training jobs", .handler = manifest_cmds.train },

    .{ .name = "serve", .group = .cluster, .usage = "serve [--port PORT] [--http-proxy-bind ADDR] [--http-proxy-port PORT]", .description = "start the API server (default: 7700)", .handler = cluster_cmds.serve },
    .{ .name = "init-server", .group = .cluster, .usage = "init-server [opts]", .description = "start a cluster server node", .handler = cluster_cmds.initServer },
    .{ .name = "join", .group = .cluster, .usage = "join <host> --token <token>", .description = "join a cluster as an agent node", .handler = cluster_cmds.join },
    .{ .name = "cluster", .group = .cluster, .usage = "cluster status", .description = "show cluster node status", .handler = cluster_cmds.cluster },
    .{ .name = "nodes", .group = .cluster, .usage = "nodes [--server host:port]", .description = "list cluster agent nodes", .handler = cluster_cmds.nodes },
    .{ .name = "drain", .group = .cluster, .usage = "drain <id> [--server host:port]", .description = "drain an agent node", .handler = cluster_cmds.drain },

    .{ .name = "secret", .group = .state_security, .usage = "secret <set|get|rm|list|rotate> ...", .description = "manage encrypted secrets", .handler = state_cmds.secret },
    .{ .name = "policy", .group = .state_security, .usage = "policy <deny|allow|rm|list> ...", .description = "manage network policy rules", .handler = net_cmds.policy },
    .{ .name = "cert", .group = .state_security, .usage = "cert <install|list|rm|provision|renew> ...", .description = "manage TLS certificates", .handler = tls_cmds.cert },
    .{ .name = "backup", .group = .state_security, .usage = "backup [--output path]", .description = "backup database state", .handler = state_cmds.backupCmd },
    .{ .name = "restore", .group = .state_security, .usage = "restore <path>", .description = "restore database from backup", .handler = state_cmds.restoreCmd },

    .{ .name = "doctor", .group = .misc, .usage = "doctor [--json]", .description = "check system readiness", .handler = doctor_cmds.doctorCmd },
    .{ .name = "version", .group = .misc, .usage = "version", .description = "print version", .handler = versionHandler },
    .{ .name = "help", .group = .misc, .usage = "help", .description = "show this help", .handler = helpHandler },
    .{ .name = "completion", .group = .misc, .usage = "completion <bash|zsh|fish>", .description = "output shell completion script", .handler = completion.handler },
    .{ .name = "__run-supervisor", .group = .misc, .usage = "__run-supervisor <id>", .description = "internal detached run supervisor", .handler = container_cmds.runSupervisor, .hidden = true },
};

const group_order = [_]struct {
    group: CommandGroup,
    title: []const u8,
}{
    .{ .group = .runtime, .title = "runtime commands" },
    .{ .group = .image, .title = "image commands" },
    .{ .group = .build_manifest, .title = "build and manifest commands" },
    .{ .group = .cluster, .title = "cluster commands" },
    .{ .group = .state_security, .title = "state and security commands" },
    .{ .group = .misc, .title = "misc commands" },
};

pub fn findCommand(name: []const u8) ?*const CommandSpec {
    for (command_specs, 0..) |spec, i| {
        if (std.mem.eql(u8, spec.name, name)) return &command_specs[i];
    }
    return null;
}

pub fn printUsage() void {
    write(
        \\yoq — container runtime and orchestrator
        \\
        \\usage: yoq <command> [options]
        \\
    , .{});

    for (group_order) |group| {
        printGroup(group.group, group.title);
    }

    write(
        \\
        \\run options:
        \\  --name <name>             assign a name (used for DNS service discovery)
        \\  -e, --env KEY=VALUE       set an environment variable
        \\  -v, --volume src:dst[:ro] bind mount a host path
        \\  -p host:container         map host port to container port
        \\  --memory <size>           set memory limit (e.g. 256m)
        \\  --cpus <n>                set CPU quota in cores
        \\  -d, --detach              run in the background
        \\  --restart <policy>        restart policy: no, always, on-failure
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
        \\  --http-proxy-bind <addr>  HTTP routing listener bind address
        \\  --http-proxy-port <port>  HTTP routing listener port (default: 17080)
        \\  --peers <peers>           peers (e.g. 2@10.0.0.2:9700,3@10.0.0.3:9700)
        \\  --token <token>           join token for agent authentication
        \\
        \\other options:
        \\  logs --tail N             show last N lines only
        \\  logs -f, --follow         stream logs until the container exits
        \\
    , .{});
}

fn printGroup(group: CommandGroup, title: []const u8) void {
    var has_commands = false;
    for (command_specs) |spec| {
        if (spec.group == group) {
            if (spec.hidden) continue;
            has_commands = true;
            break;
        }
    }
    if (!has_commands) return;

    write("{s}:\n", .{title});
    for (command_specs) |spec| {
        if (spec.group != group or spec.hidden) continue;
        write("  {s:<44} {s}\n", .{ spec.usage, spec.description });
    }
    write("\n", .{});
}

fn versionHandler(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    _ = alloc;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) cli.output_mode = .json;
    }
    if (cli.output_mode == .json) {
        const json_out = @import("json_output.zig");
        var w = json_out.JsonWriter{};
        w.beginObject();
        w.stringField("version", "0.1.8");
        w.endObject();
        w.flush();
    } else {
        write("yoq 0.1.8\n", .{});
    }
}

fn helpHandler(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    _ = args;
    _ = alloc;
    printUsage();
}

fn psHandler(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) cli.output_mode = .json;
    }
    try container_cmds.ps(alloc);
}

fn imagesHandler(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) cli.output_mode = .json;
    }
    try image_cmds.images(alloc);
}

fn pruneHandler(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) cli.output_mode = .json;
    }
    try image_cmds.prune(alloc);
}

test "every command name is unique" {
    for (command_specs, 0..) |left, i| {
        for (command_specs[i + 1 ..]) |right| {
            try std.testing.expect(!std.mem.eql(u8, left.name, right.name));
        }
    }
}

test "lookup finds all registered commands" {
    for (command_specs) |spec| {
        const found = findCommand(spec.name);
        try std.testing.expect(found != null);
        try std.testing.expectEqualStrings(spec.name, found.?.name);
    }
}
