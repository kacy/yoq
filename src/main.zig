const std = @import("std");
const store = @import("state/store.zig");
const container = @import("runtime/container.zig");

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
        cmdRm(&args, alloc);
    } else {
        writeErr("unknown command: {s}\n", .{command});
        printUsage();
        std.process.exit(1);
    }
}

fn cmdRun(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
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

    store.save(alloc, record) catch {
        writeErr("failed to save container state\n", .{});
        std.process.exit(1);
    };

    write("{s}\n", .{id});

    // note: actual container execution (clone3, namespace setup, etc.)
    // requires Linux. the CLI and state management work on any platform.
    // on Linux, this would call namespaces.spawn() with the child
    // function setting up filesystem, security, and exec'ing the command.
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

    write("{s:<14} {s:<10}\n", .{ "CONTAINER ID", "STATUS" });
    for (ids.items) |id| {
        write("{s:<14} {s:<10}\n", .{ id, "created" });
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

fn cmdRm(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const id = args.next() orelse {
        writeErr("usage: yoq rm <container-id>\n", .{});
        std.process.exit(1);
    };

    store.remove(alloc, id) catch {
        writeErr("container not found: {s}\n", .{id});
        std.process.exit(1);
    };

    write("{s}\n", .{id});
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
        \\  stop <id>            stop a running container
        \\  rm <id>              remove a stopped container
        \\  version              print version
        \\  help                 show this help
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
    _ = @import("state/store.zig");
    _ = @import("state/db.zig");
    _ = @import("state/schema.zig");
    _ = @import("lib/log.zig");
}
