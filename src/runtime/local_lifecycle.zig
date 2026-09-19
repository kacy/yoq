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
            if (std.mem.eql(u8, record.status, "paused")) {
                const cg = try @import("cgroups.zig").Cgroup.open(id);
                try cg.setFrozen(false);
            }
            try supervisor.stopProcessWithOptions(pid, if (cfg) |value| value.stop_signal else 15, if (cfg) |value| value.stop_timeout_seconds else 5);
        }
    }
    try waitForOwner(id);
    const record = try store.load(alloc, id);
    defer record.deinit(alloc);
    const owner = try control.lock(id, .owner, true);
    defer owner.deinit();
    cleanupRuntime(alloc, &record) catch |err| {
        store.updateStatus(id, "cleanup_failed", null, record.exit_code) catch {};
        return err;
    };
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
    if (std.mem.eql(u8, record.status, "removing")) return error.InvalidStatus;
    if (std.mem.eql(u8, record.status, "cleanup_failed")) try stopLocked(id, alloc);
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
    return removeWithVolumes(id, alloc, false);
}

pub fn removeWithVolumes(id: []const u8, alloc: std.mem.Allocator, remove_anonymous: bool) !void {
    const command_lock = try control.lock(id, .command, true);
    defer command_lock.deinit();
    return removeLocked(id, alloc, remove_anonymous);
}

pub fn removeAutomatic(id: []const u8, alloc: std.mem.Allocator, generation: i64) !void {
    const command_lock = try control.lock(id, .command, true);
    defer command_lock.deinit();
    const current = (try control.currentGeneration(id)) orelse return;
    if (current < generation) return;
    // explicit stop advances the generation to cancel restarts. it still
    // permits --rm, but a newer requested run must retain its container.
    if (current != generation and !try control.finishedGeneration(id, null)) return;
    // the exit packet is sent before the supervisor releases ownership.
    // holding the command lock prevents a new start while cleanup finishes.
    try waitForOwner(id);
    if (!try control.finishedGeneration(id, current)) return;
    try removeLocked(id, alloc, true);
}

fn removeLocked(id: []const u8, alloc: std.mem.Allocator, remove_anonymous: bool) !void {
    const record = try store.load(alloc, id);
    defer record.deinit(alloc);
    if (record.pid != null or std.mem.eql(u8, record.status, "running")) return error.ContainerRunning;
    try stopLocked(id, alloc);
    try store.updateStatus(id, "removing", null, record.exit_code);
    try removeArtifacts(id);
    try @import("local_volumes.zig").releaseContainer(id, remove_anonymous);
    try @import("../network/port_allocator.zig").release(id);
    try @import("../network/local_networks.zig").release(id);
    try @import("local_health.zig").remove(id);
    try removeSavedConfig(id);
    try control.removeRecord(id);
}

fn removeArtifacts(id: []const u8) !void {
    const paths = @import("../lib/paths.zig");
    const io = std.Options.debug_io;
    var path_buf: [paths.max_path]u8 = undefined;
    const directory = try paths.dataPathFmt(&path_buf, "containers/{s}", .{id});
    try std.Io.Dir.cwd().deleteTree(io, directory);
    inline for (.{ "logs/{s}.log", "logs/{s}.log.1", "sessions/{s}.sock" }) |pattern| {
        const path = try paths.dataPathFmt(&path_buf, pattern, .{id});
        std.Io.Dir.cwd().deleteFile(io, path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
}

// reconstruct teardown after a supervisor exit using the saved run spec and
// resource handles recorded before launch. this also retries cleanup_failed.
fn cleanupRuntime(alloc: std.mem.Allocator, record: *const store.ContainerRecord) !void {
    try @import("local_health.zig").cleanupOrphans(record.id);
    const cg = try @import("cgroups.zig").Cgroup.open(record.id);
    const io = std.Options.debug_io;
    if (std.Io.Dir.cwd().access(io, cg.path(), .{})) |_| {
        try cg.destroy();
    } else |err| if (err != error.FileNotFound) return err;
    var db = try store.openDb();
    defer db.deinit();
    // an allocation can outlive its container-record update. conversely, a
    // released address may already belong to another container. only the
    // allocation table establishes ownership for recovery teardown.
    const address = ip.lookupChecked(&db, alloc, record.id) catch |err| switch (err) {
        error.NotFound => {
            try store.updateNetwork(record.id, null, null);
            return;
        },
        else => return err,
    };
    const cfg = try run_state.loadConfig(alloc, record.id);
    defer cfg.deinit(alloc);
    const setup = @import("../network/setup.zig");
    var info: setup.NetworkInfo = .{ .ip = address, .veth_host = undefined, .veth_host_len = 0 };
    var name_buffer: [32]u8 = undefined;
    const name = record.veth_host orelse @import("../network/bridge.zig").vethName(record.id, &name_buffer);
    if (name.len > info.veth_host.len) return error.InvalidAddress;
    @memcpy(info.veth_host[0..name.len], name);
    info.veth_host_len = name.len;
    try setup.teardownContainerChecked(record.id, &info, .{ .port_maps = cfg.port_maps, .network_name = cfg.network_name }, &db);
    try store.updateNetwork(record.id, null, null);
}

fn removeSavedConfig(id: []const u8) !void {
    const paths = @import("../lib/paths.zig");
    var buf: [paths.max_path]u8 = undefined;
    const path = try paths.dataPathFmt(&buf, "run_configs/{s}.bin", .{id});
    std.Io.Dir.cwd().deleteFile(std.Options.debug_io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

// recovery is an explicit boot operation. repeating it periodically would
// undo a manual stop of an always-restart container.
pub fn recover(io: std.Io, alloc: std.mem.Allocator, id: []const u8) !bool {
    const command_lock = try control.lock(id, .command, true);
    defer command_lock.deinit();
    const cfg = try run_state.loadConfig(alloc, id);
    defer cfg.deinit(alloc);
    if (!recoverPolicy(cfg.restart_policy, try control.wantsRunning(id))) return false;
    {
        const owner = control.lock(id, .owner, false) catch |err| {
            if (err == error.Busy) return false;
            return err;
        };
        defer owner.deinit();
        const record = try store.load(alloc, id);
        defer record.deinit(alloc);
        if (std.mem.eql(u8, record.status, "removing")) return false;
        if (record.pid) |pid| {
            if (state_support.isOwnedContainerPid(id, pid)) return false;
            const cg = try @import("cgroups.zig").Cgroup.open(id);
            if (std.Io.Dir.cwd().access(io, cg.path(), .{})) |_| {
                // an unreadable existing group is not evidence of an exit.
                if (try cg.containsProcessChecked(pid)) return false;
            } else |err| if (err != error.FileNotFound) return err;
        }
        try cleanupRuntime(alloc, &record);
        try store.updateStatus(id, "stopped", null, record.exit_code);
    }
    try startLocked(io, alloc, id);
    return true;
}

fn recoverPolicy(policy: run_state.RestartPolicy, desired_running: bool) bool {
    return switch (policy) {
        .always => true,
        .unless_stopped => desired_running,
        .no, .on_failure => false,
    };
}

test "host recovery respects manual stop and failure-only policies" {
    try std.testing.expect(recoverPolicy(.always, false));
    try std.testing.expect(recoverPolicy(.unless_stopped, true));
    try std.testing.expect(!recoverPolicy(.unless_stopped, false));
    try std.testing.expect(!recoverPolicy(.on_failure, true));
    try std.testing.expect(!recoverPolicy(.no, true));
}

test "delayed automatic removal leaves a newer created container intact" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const id = "a1b2c3d4e5f6";
    try store.save(.{ .id = id, .rootfs = "/fixture", .command = "sh", .hostname = "new-run", .status = "created", .pid = null, .exit_code = null, .created_at = 1 });
    try control.register(id, null);
    const old = try control.request(id, true);
    try control.finish(id, old);
    const current = try control.request(id, true);
    try removeAutomatic(id, std.testing.allocator, old);
    try std.testing.expect(try control.shouldRun(id, current));
    const record = try store.load(std.testing.allocator, id);
    defer record.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("created", record.status);
}
