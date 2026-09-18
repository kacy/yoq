const std = @import("std");
const container = @import("container.zig");
const logs = @import("logs.zig");
const run_state = @import("run_state.zig");
const store = @import("../state/store.zig");
const ip = @import("../network/ip.zig");
const cli = @import("../lib/cli.zig");
const control = @import("local_control.zig");
const state_support = @import("cli/container/state_support.zig");
const supervisor = @import("cli/container/supervisor_runtime.zig");
const runtime_wait = @import("../lib/runtime_wait.zig");
const writeErr = cli.writeErr;

pub fn cleanupStoppedContainer(id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    cleanupNetwork(id, ip_address, veth_host);
    logs.deleteLogFile(id);
    container.cleanupContainerDirs(id);
    run_state.removeConfig(id);
    control.remove(id) catch {};
    store.remove(id) catch |e| {
        writeErr("warning: failed to remove container record {s}: {}\n", .{ id, e });
    };
}

pub fn cleanupNetwork(container_id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) void {
    const bridge = @import("../network/bridge.zig");

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

// callers hold the command lock through startup acknowledgement or final cleanup.
// a delayed supervisor carries an old generation and cannot revive a stopped run.
pub fn stop(id: []const u8, alloc: std.mem.Allocator) !void {
    const command_lock = try control.lock(id, .command, true);
    defer command_lock.deinit();
    try stopLocked(id, alloc);
}

fn stopLocked(id: []const u8, alloc: std.mem.Allocator) !void {
    stopping: {
        const transition = try control.lock(id, .transition, true);
        defer transition.deinit();
        var record = try store.load(alloc, id);
        defer record.deinit(alloc);
        try control.ensureRegistered(id);
        _ = try control.request(id, false);
        if (record.pid != null) {
            const pid = state_support.currentOwnedRunningPid(&record) orelse {
                const latest = try store.load(alloc, id);
                defer latest.deinit(alloc);
                if (latest.pid != null) return error.StateUnknown;
                break :stopping;
            };
            const cfg = run_state.loadConfig(alloc, id) catch null;
            defer if (cfg) |value| value.deinit(alloc);
            try supervisor.stopProcessWithOptions(pid, if (cfg) |value| value.stop_signal else 15, if (cfg) |value| value.stop_timeout_seconds else 5);
        }
    }
    try waitForOwner(id);
    const record = try store.load(alloc, id);
    defer record.deinit(alloc);
    if (std.mem.eql(u8, record.status, "cleanup_failed")) return error.CleanupFailed;
    try store.updateStatus(id, "stopped", null, record.exit_code);
}

fn waitForOwner(id: []const u8) !void {
    var attempts: usize = 0;
    while (attempts < 240) : (attempts += 1) {
        const owner = control.lock(id, .owner, false) catch |err| {
            if (err != error.Busy) return err;
            if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(50), "container owner shutdown")) return error.StateUnknown;
            continue;
        };
        owner.deinit();
        return;
    }
    return error.StateUnknown;
}

pub fn start(io: std.Io, alloc: std.mem.Allocator, id: []const u8) !void {
    const command_lock = try control.lock(id, .command, true);
    defer command_lock.deinit();
    try startLocked(io, alloc, id);
}

fn startLocked(io: std.Io, alloc: std.mem.Allocator, id: []const u8) !void {
    const record = try store.load(alloc, id);
    defer record.deinit(alloc);
    if (std.mem.eql(u8, record.status, "cleanup_failed")) return error.CleanupFailed;
    if (record.pid != null or std.mem.eql(u8, record.status, "running")) return error.ContainerRunning;
    const cfg = try run_state.loadConfig(alloc, id);
    defer cfg.deinit(alloc);
    try waitForOwner(id);
    try supervisor.spawnSupervisor(io, alloc, id);
    try state_support.waitForContainerStart(alloc, id);
}

pub fn restart(io: std.Io, alloc: std.mem.Allocator, id: []const u8) !void {
    const command_lock = try control.lock(id, .command, true);
    defer command_lock.deinit();
    try stopLocked(id, alloc);
    try startLocked(io, alloc, id);
}

pub fn remove(id: []const u8, alloc: std.mem.Allocator) !void {
    const command_lock = try control.lock(id, .command, true);
    defer command_lock.deinit();
    const record = try store.load(alloc, id);
    defer record.deinit(alloc);
    if (record.pid != null or std.mem.eql(u8, record.status, "running")) return error.ContainerRunning;
    try stopLocked(id, alloc);
    cleanupStoppedContainer(id, record.ip_address, record.veth_host);
}
