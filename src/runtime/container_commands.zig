// container_commands — CLI handlers for container lifecycle operations
//
// run, ps, stop, exec, rm, logs. extracted from main.zig for
// readability — no logic changes.

const std = @import("std");
const cli = @import("../lib/cli.zig");
const store = @import("../state/store.zig");
const container = @import("container.zig");
const process = @import("process.zig");
const logs = @import("logs.zig");
const net_setup = @import("../network/setup.zig");
const ip = @import("../network/ip.zig");
const exec = @import("exec.zig");
const oci = @import("../image/oci.zig");
const image_cmds = @import("../image/commands.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const parsePortMap = cli.parsePortMap;
const isValidContainerName = cli.isValidContainerName;
const requireArg = cli.requireArg;

// -- types --

const RunFlags = struct {
    port_maps: std.ArrayList(net_setup.PortMap),
    networking_enabled: bool,
    container_name: ?[]const u8,
    target: []const u8,
    user_argv: std.ArrayList([]const u8),
};

// -- helpers --

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

/// full cleanup for a stopped container: network, logs, dirs, then DB record.
/// DB record is removed last so we can still find orphaned resources if
/// an earlier cleanup step fails.
pub fn cleanupStoppedContainer(id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    cleanupNetwork(id, ip_address, veth_host);
    logs.deleteLogFile(id);
    container.cleanupContainerDirs(id);
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

pub fn run(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
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

pub fn ps(alloc: std.mem.Allocator) void {
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

pub fn stop(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
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

pub fn exec_cmd(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
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

pub fn rm(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
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

pub fn log(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
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
