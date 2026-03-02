const std = @import("std");
const store = @import("state/store.zig");
const container = @import("runtime/container.zig");
const logs = @import("runtime/logs.zig");

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
        cmdRun(&args);
    } else if (std.mem.eql(u8, command, "ps")) {
        cmdPs(alloc);
    } else if (std.mem.eql(u8, command, "stop")) {
        cmdStop(&args);
    } else if (std.mem.eql(u8, command, "rm")) {
        cmdRm(&args);
    } else if (std.mem.eql(u8, command, "logs")) {
        cmdLogs(&args, alloc);
    } else {
        writeErr("unknown command: {s}\n", .{command});
        printUsage();
        std.process.exit(1);
    }
}

fn cmdRun(args: *std.process.ArgIterator) void {
    const rootfs = args.next() orelse {
        writeErr("usage: yoq run <rootfs> <command>\n", .{});
        std.process.exit(1);
    };

    const cmd = args.next() orelse {
        writeErr("usage: yoq run <rootfs> <command>\n", .{});
        std.process.exit(1);
    };

    // generate container id
    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf);
    const id = id_buf[0..];

    // create the log file for this container.
    // on Linux, this stays open for capture threads to write to.
    // for now (no execution), we just create it and close it.
    if (logs.createLogFile(id)) |log_file| {
        log_file.close();
    } else |_| {}

    // save container record
    const record = store.ContainerRecord{
        .id = id,
        .rootfs = rootfs,
        .command = cmd,
        .hostname = "container",
        .status = "created",
        .pid = null,
        .exit_code = null,
        .created_at = std.time.timestamp(),
    };

    store.save(record) catch {
        writeErr("failed to save container state\n", .{});
        std.process.exit(1);
    };

    write("{s}\n", .{id});

    // note: actual container execution (clone3, namespace setup, etc.)
    // requires Linux. the CLI and state management work on any platform.
    // on Linux, this would:
    //   1. call namespaces.spawn() to create the isolated process
    //   2. spawn threads to call logs.captureStream() on stdout_fd/stderr_fd
    //   3. update store status to "running" with the child pid
    //   4. wait for exit, update status to "stopped"
    writeErr("container created (execution requires Linux)\n", .{});
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

fn printUsage() void {
    write(
        \\yoq — container runtime and orchestrator
        \\
        \\usage: yoq <command> [options]
        \\
        \\commands:
        \\  run <rootfs> <cmd>   create and run a container
        \\  ps                   list containers
        \\  logs <id>            show container output
        \\  stop <id>            stop a running container
        \\  rm <id>              remove a stopped container
        \\  version              print version
        \\  help                 show this help
        \\
        \\options:
        \\  logs --tail N        show last N lines only
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
}
