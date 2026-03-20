const std = @import("std");
const container = @import("../../container.zig");
const logs = @import("../../logs.zig");
const run_state = @import("../../run_state.zig");
const store = @import("../../../state/store.zig");
const ip = @import("../../../network/ip.zig");
const cli = @import("../../../lib/cli.zig");
const state_support = @import("state_support.zig");
const supervisor_runtime = @import("supervisor_runtime.zig");
const common = @import("common.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const requireArg = cli.requireArg;
const ContainerError = common.ContainerError;

pub fn cleanupStoppedContainer(id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    cleanupNetwork(id, ip_address, veth_host);
    logs.deleteLogFile(id);
    container.cleanupContainerDirs(id);
    run_state.removeConfig(id);
    store.remove(id) catch |e| {
        writeErr("warning: failed to remove container record {s}: {}\n", .{ id, e });
    };
}

pub fn cleanupNetwork(container_id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    const bridge = @import("../../../network/bridge.zig");

    if (veth_host) |veth| {
        var name_buf: [32]u8 = undefined;
        const len = @min(veth.len, name_buf.len);
        @memcpy(name_buf[0..len], veth[0..len]);
        bridge.deleteVeth(name_buf[0..len]) catch |e| {
            writeErr("warning: failed to delete veth {s} for {s}: {}\n", .{ veth, container_id, e });
        };
    }

    if (ip_address != null) {
        var db = store.openDb() catch return;
        defer db.deinit();
        ip.release(&db, container_id) catch |e| {
            writeErr("warning: failed to release IP for {s}: {}\n", .{ container_id, e });
        };
    }
}

pub fn stop(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const id = requireArg(args, "usage: yoq stop <container-id|name>\n");

    const record = state_support.resolveContainerRef(alloc, id) catch |e| return e;
    defer record.deinit(alloc);

    if (!std.mem.eql(u8, record.status, "running")) {
        writeErr("container {s} is not running (status: {s})\n", .{ id, record.status });
        return ContainerError.InvalidStatus;
    }

    const pid = state_support.currentOwnedRunningPid(&record) orelse {
        writeErr("container {s} has no pid\n", .{id});
        return ContainerError.ProcessNotFound;
    };

    supervisor_runtime.stopProcess(pid) catch |e| return e;
    if (!state_support.waitForStoppedState(alloc, record.id)) {
        writeErr("timed out waiting for container {s} to reach stopped state\n", .{record.id});
        return ContainerError.StateUnknown;
    }
    write("{s}\n", .{record.id});
}

pub fn rm(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const id = requireArg(args, "usage: yoq rm <container-id|name>\n");

    const record = state_support.resolveContainerRef(alloc, id) catch |e| return e;

    if (std.mem.eql(u8, record.status, "running")) {
        writeErr("cannot remove running container {s} — stop it first\n", .{record.id});
        record.deinit(alloc);
        return ContainerError.ContainerRunning;
    }

    cleanupStoppedContainer(record.id, record.ip_address, record.veth_host);
    record.deinit(alloc);

    write("{s}\n", .{id});
}

pub fn restart(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const ref = requireArg(args, "usage: yoq restart <container-id|name>\n");
    const record = state_support.resolveContainerRef(alloc, ref) catch |e| return e;
    defer record.deinit(alloc);

    if (std.mem.eql(u8, record.status, "running")) {
        if (state_support.currentOwnedRunningPid(&record)) |pid| {
            supervisor_runtime.stopProcess(pid) catch |e| return e;
        }
    }

    store.updateStatus(record.id, "created", null, null) catch {};
    supervisor_runtime.spawnSupervisor(alloc, record.id) catch |e| return e;
    state_support.waitForContainerStart(alloc, record.id) catch |e| return e;
    write("{s}\n", .{record.id});
}
