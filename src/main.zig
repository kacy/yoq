const std = @import("std");
const cli = @import("lib/cli.zig");
const image_cmds = @import("image/commands.zig");
const cluster_cmds = @import("cluster/commands.zig");
const json_helpers = @import("lib/json_helpers.zig");
const state_cmds = @import("state/commands.zig");
const net_cmds = @import("network/commands.zig");
const runtime_cmds = @import("runtime/commands.zig");
const tls_cmds = @import("tls/commands.zig");
const container_cmds = @import("runtime/container_commands.zig");
const build_cmds = @import("build/commands.zig");
const manifest_cmds = @import("manifest/commands.zig");

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
        container_cmds.run(&args, alloc);
    } else if (std.mem.eql(u8, command, "ps")) {
        container_cmds.ps(alloc);
    } else if (std.mem.eql(u8, command, "stop")) {
        container_cmds.stop(&args, alloc);
    } else if (std.mem.eql(u8, command, "rm")) {
        container_cmds.rm(&args, alloc);
    } else if (std.mem.eql(u8, command, "logs")) {
        container_cmds.log(&args, alloc);
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
        container_cmds.exec_cmd(&args, alloc);
    } else if (std.mem.eql(u8, command, "build")) {
        build_cmds.build_cmd(&args, alloc);
    } else if (std.mem.eql(u8, command, "up")) {
        manifest_cmds.up(&args, alloc);
    } else if (std.mem.eql(u8, command, "down")) {
        manifest_cmds.down(&args, alloc);
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
        manifest_cmds.rollback(&args, alloc);
    } else if (std.mem.eql(u8, command, "history")) {
        manifest_cmds.history(&args, alloc);
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
        \\     [service...]                   start only named services + deps
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
    _ = @import("runtime/container_commands.zig");
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
    _ = @import("build/commands.zig");
    _ = @import("manifest/spec.zig");
    _ = @import("manifest/loader.zig");
    _ = @import("manifest/orchestrator.zig");
    _ = @import("manifest/health.zig");
    _ = @import("manifest/update.zig");
    _ = @import("manifest/commands.zig");
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
