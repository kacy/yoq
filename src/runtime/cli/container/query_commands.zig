const std = @import("std");
const cli = @import("../../../lib/cli.zig");
const json_out = @import("../../../lib/json_output.zig");
const store = @import("../../../state/store.zig");
const logs = @import("../../logs.zig");
const exec = @import("../../exec.zig");
const state_support = @import("state_support.zig");
const common = @import("common.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const ContainerError = common.ContainerError;

fn psJson(alloc: std.mem.Allocator, ids: []const []const u8) void {
    var w = json_out.JsonWriter{};
    w.beginArray();

    for (ids) |id| {
        const record = store.load(alloc, id) catch continue;
        defer record.deinit(alloc);

        const status = state_support.reconcileLiveness(id, record.status, record.pid);

        w.beginObject();
        w.stringField("id", id);
        w.stringField("name", record.hostname);
        w.stringField("status", status);
        if (record.ip_address) |addr| {
            w.stringField("ip", addr);
        } else {
            w.nullField("ip");
        }
        w.stringField("command", record.command);
        if (record.pid) |pid| {
            w.intField("pid", pid);
        } else {
            w.nullField("pid");
        }
        w.intField("created_at", record.created_at);
        w.endObject();
    }

    w.endArray();
    w.flush();
}

pub fn ps(alloc: std.mem.Allocator) !void {
    var ids = store.listIds(alloc) catch |err| {
        writeErr("failed to list containers: {}\n", .{err});
        return ContainerError.StoreError;
    };
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    if (cli.output_mode == .json) {
        psJson(alloc, ids.items);
        return;
    }

    if (ids.items.len == 0) {
        write("no containers\n", .{});
        return;
    }

    write("{s:<14} {s:<10} {s:<16} {s:<24} {s:<20}\n", .{ "CONTAINER ID", "STATUS", "IP", "NAME", "COMMAND" });
    for (ids.items) |id| {
        const record = store.load(alloc, id) catch |err| {
            write("{s:<14} {s:<10} {s:<16} {s:<24} {s:<20}\n", .{ id, @errorName(err), "-", "-", "-" });
            continue;
        };
        defer record.deinit(alloc);

        const status = state_support.reconcileLiveness(id, record.status, record.pid);
        const ip_display: []const u8 = record.ip_address orelse "-";
        write("{s:<14} {s:<10} {s:<16} {s:<24} {s:<20}\n", .{ id, status, ip_display, record.hostname, record.command });
    }
}

pub fn exec_cmd(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const id = args.next() orelse {
        writeErr("usage: yoq exec <container-id|name> <command> [args...]\n", .{});
        return ContainerError.InvalidArgument;
    };

    const record = state_support.resolveContainerRef(alloc, id) catch |e| return e;
    defer record.deinit(alloc);

    if (!std.mem.eql(u8, record.status, "running")) {
        writeErr("container {s} is not running (status: {s})\n", .{ id, record.status });
        return ContainerError.InvalidStatus;
    }

    const pid = state_support.currentOwnedRunningPid(&record) orelse {
        writeErr("container {s} is not running (status: stopped)\n", .{id});
        return ContainerError.ProcessNotFound;
    };

    const command = args.next() orelse {
        writeErr("usage: yoq exec <container-id|name> <command> [args...]\n", .{});
        return ContainerError.InvalidArgument;
    };

    var exec_args: std.ArrayList([]const u8) = .empty;
    defer exec_args.deinit(alloc);
    while (args.next()) |arg| {
        exec_args.append(alloc, arg) catch return ContainerError.OutOfMemory;
    }

    const exit_code = exec.execInContainer(.{
        .pid = pid,
        .command = command,
        .args = exec_args.items,
        .env = &.{},
        .working_dir = "/",
    }) catch |err| {
        writeErr("failed to exec in container {s}: {}\n", .{ id, err });
        return ContainerError.ProcessNotFound;
    };

    std.process.exit(exit_code);
}

pub fn log(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const ref = cli.requireArg(args, "usage: yoq logs <container-id|name> [--tail N] [-f]\n");
    const record = try state_support.resolveContainerRef(alloc, ref);
    defer record.deinit(alloc);

    var tail_lines: usize = 0;
    var follow = false;
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
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--follow")) {
            follow = true;
        }
    }

    if (follow) {
        logs.followLogs(record.id, tail_lines, record.pid) catch |err| {
            writeErr("failed to follow logs for container: {s} ({})\n", .{ record.id, err });
            std.process.exit(1);
        };
        return;
    }

    const content = if (tail_lines > 0)
        logs.readTail(alloc, record.id, tail_lines)
    else
        logs.readLogs(alloc, record.id);

    const data = content catch |err| {
        writeErr("no logs found for container: {s} ({})\n", .{ record.id, err });
        std.process.exit(1);
    };
    defer alloc.free(data);

    if (data.len == 0) {
        write("(no output)\n", .{});
        return;
    }

    write("{s}", .{data});
}
