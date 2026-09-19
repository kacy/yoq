// native api and cli operations share owner selection. standalone containers
// use durable lifecycle recovery; manifest and assignment owners finalize their
// own runtime resources when their container exits.
const std = @import("std");
const store = @import("../state/store.zig");
const standalone = @import("local_lifecycle.zig");
const control = @import("local_control.zig");
const run_state = @import("run_state.zig");
const process = @import("process.zig");
const cgroups = @import("cgroups.zig");
const runtime_wait = @import("../lib/runtime_wait.zig");
const state_support = @import("cli/container/state_support.zig");
const supervisor = @import("cli/container/supervisor_runtime.zig");

pub const StopWait = enum { brief, complete };
pub const StopResult = enum { stopped, stopping };

fn isStandalone(alloc: std.mem.Allocator, record: *const store.ContainerRecord) !bool {
    if (record.app_name != null) return false;
    if (try control.currentGeneration(record.id) != null) return true;
    const config = run_state.loadConfig(alloc, record.id) catch |err| switch (err) {
        error.NotFound, error.InvalidId => return false,
        else => return err,
    };
    config.deinit(alloc);
    return true;
}

pub fn stop(alloc: std.mem.Allocator, id: []const u8, wait: StopWait) !StopResult {
    const record = try store.load(alloc, id);
    defer record.deinit(alloc);
    if (try isStandalone(alloc, &record)) {
        try standalone.stop(id, alloc);
        return .stopped;
    }
    return stopManaged(alloc, &record, wait);
}

fn stopManaged(alloc: std.mem.Allocator, record: *const store.ContainerRecord, wait: StopWait) !StopResult {
    const id = record.id;
    if (!std.mem.eql(u8, record.status, "running")) return error.InvalidStatus;
    if (wait == .complete) {
        const pid = state_support.currentOwnedRunningPid(record) orelse return error.NotRunning;
        try supervisor.stopProcess(pid);
        if (!state_support.waitForStoppedState(alloc, id)) return error.StateUnknown;
        return .stopped;
    }
    const pid = record.pid orelse return error.NotRunning;
    const cg = cgroups.Cgroup.open(id) catch return error.NotRunning;
    if (!cg.containsProcess(pid)) {
        store.updateStatus(id, "stopped", null, null) catch {};
        return error.NotRunning;
    }
    try process.terminate(pid);
    if (!waitForProcessExit(id, pid)) return .stopping;
    store.updateStatus(id, "stopped", null, null) catch {};
    return .stopped;
}

pub fn waitForProcessExit(id: []const u8, pid: i32) bool {
    for (0..10) |_| {
        const cg = cgroups.Cgroup.open(id) catch return true;
        if (!cg.containsProcess(pid)) return true;
        process.sendSignal(pid, 0) catch return true;
        if (!runtime_wait.sleep(.fromMilliseconds(50), "container stop wait")) return false;
    }
    return false;
}

pub fn remove(alloc: std.mem.Allocator, id: []const u8, remove_anonymous: bool) !void {
    const record = try store.load(alloc, id);
    defer record.deinit(alloc);
    if (try isStandalone(alloc, &record)) return standalone.removeWithVolumes(id, alloc, remove_anonymous);
    if (record.pid != null or std.mem.eql(u8, record.status, "running")) return error.ContainerRunning;
    try store.remove(id);
    @import("logs.zig").deleteLogFile(id);
    @import("container.zig").cleanupContainerDirs(id);
}

test "container stop does not claim manifest lifecycle ownership" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const id = "edca01234567";
    try store.save(.{ .id = id, .rootfs = "/fixture", .command = "serve", .hostname = "web", .app_name = "managed-app", .status = "running", .pid = 999999, .exit_code = null, .created_at = 0 });
    try std.testing.expectError(error.NotRunning, stop(std.testing.allocator, id, .brief));
    try std.testing.expect((try control.currentGeneration(id)) == null);
    const record = try store.load(std.testing.allocator, id);
    defer record.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("stopped", record.status);
}

test "container owner selection recognizes standalone metadata and managed apps" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const id = "edca12345678";
    var record: store.ContainerRecord = .{ .id = id, .rootfs = "/fixture", .command = "serve", .hostname = "web", .status = "created", .pid = null, .exit_code = null, .created_at = 0 };
    try std.testing.expect(!try isStandalone(std.testing.allocator, &record));
    try control.register(id, null);
    try std.testing.expect(try isStandalone(std.testing.allocator, &record));
    // an app owner remains authoritative even if an older api call previously
    // registered this container in the standalone control table.
    record.app_name = "managed-app";
    try std.testing.expect(!try isStandalone(std.testing.allocator, &record));
}

test "managed container removal does not require standalone recovery state" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const id = "edca23456789";
    try store.save(.{ .id = id, .rootfs = "/fixture", .command = "serve", .hostname = "web", .app_name = "managed-app", .status = "stopped", .pid = null, .exit_code = 0, .created_at = 0 });
    try remove(std.testing.allocator, id, false);
    try std.testing.expectError(error.NotFound, store.load(std.testing.allocator, id));
    try std.testing.expect((try control.currentGeneration(id)) == null);
}
