const std = @import("std");
const store = @import("../../../state/store.zig");
const process = @import("../../process.zig");
const cgroups = @import("../../cgroups.zig");
const cli = @import("../../../lib/cli.zig");
const common = @import("common.zig");
const runtime_wait = @import("../../../lib/runtime_wait.zig");

const writeErr = cli.writeErr;
const ContainerError = common.ContainerError;

const LivenessState = enum {
    running,
    gone,
    unknown,
};

pub fn resolveContainerRef(alloc: std.mem.Allocator, ref: []const u8) ContainerError!store.ContainerRecord {
    return store.load(alloc, ref) catch {
        const record = store.findByHostname(alloc, ref) catch |err| {
            writeErr("container not found: {s} ({})", .{ ref, err });
            return ContainerError.ContainerNotFound;
        };
        return record orelse {
            writeErr("container not found: {s}\n", .{ref});
            return ContainerError.ContainerNotFound;
        };
    };
}

pub fn persistStoppedState(record: *const store.ContainerRecord, exit_code: ?u8) void {
    store.updateStatus(record.id, "stopped", null, exit_code) catch {};
}

pub fn isOwnedContainerPid(id: []const u8, pid: i32) bool {
    return ownedPidState(id, pid) == .running;
}

fn ownedPidState(id: []const u8, pid: i32) LivenessState {
    const cg = cgroups.Cgroup.open(id) catch return .unknown;
    const contains = cg.containsProcessChecked(pid) catch return .unknown;
    if (!contains) return .gone;
    process.sendSignal(pid, 0) catch return .gone;
    return .running;
}

pub fn currentOwnedRunningPid(record: *const store.ContainerRecord) ?i32 {
    const pid = record.pid orelse return null;
    return switch (ownedPidState(record.id, pid)) {
        .running => pid,
        .gone => blk: {
            persistStoppedState(record, null);
            break :blk null;
        },
        .unknown => null,
    };
}

pub fn waitForStoppedState(alloc: std.mem.Allocator, id: []const u8) bool {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        const record = store.load(alloc, id) catch |err| {
            // The process has already exited. An assignment owner may remove
            // its completed record before the stop command observes it.
            if (err == error.NotFound) return true;
            if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(50), "container stopped-state load wait")) return false;
            continue;
        };
        defer record.deinit(alloc);

        if (std.mem.eql(u8, record.status, "stopped") and record.pid == null) return true;
        if (record.pid) |pid| {
            switch (ownedPidState(record.id, pid)) {
                .gone => {
                    persistStoppedState(&record, record.exit_code);
                    return true;
                },
                .unknown => {},
                .running => {},
            }
        }
        if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(50), "container stopped-state wait")) return false;
    }

    return false;
}

pub fn waitForContainerStart(alloc: std.mem.Allocator, id: []const u8) ContainerError!void {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        const record = store.load(alloc, id) catch {
            if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(50), "container start load wait")) break;
            continue;
        };
        defer record.deinit(alloc);

        switch (record.startup_outcome) {
            .succeeded => return,
            .failed => {
                writeErr("failed to start detached container\n", .{});
                return ContainerError.ProcessNotFound;
            },
            .pending => {},
        }

        if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(50), "container start wait")) break;
    }

    writeErr("timed out waiting for container start\n", .{});
    return ContainerError.ProcessNotFound;
}

pub fn reconcileLiveness(id: []const u8, status: []const u8, pid: ?i32) []const u8 {
    if (!std.mem.eql(u8, status, "running")) return status;
    if (pid) |p| {
        switch (ownedPidState(id, p)) {
            .gone => {
                store.updateStatus(id, "stopped", null, null) catch {};
                return "stopped";
            },
            .unknown => return status,
            .running => {},
        }
    }
    return status;
}

test "reconcileLiveness preserves running state when cgroup ownership is unknown" {
    store.initTestDb() catch return error.SkipZigTest;
    defer store.deinitTestDb();

    try store.save(.{
        .id = "deadbeefcafe",
        .hostname = "test",
        .rootfs = "/tmp/rootfs",
        .status = "running",
        .command = "sleep 1",
        .created_at = 1,
        .pid = 999999,
        .exit_code = null,
    });

    try std.testing.expectEqualStrings("running", reconcileLiveness("deadbeefcafe", "running", 999999));

    const record = try store.load(std.testing.allocator, "deadbeefcafe");
    defer record.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("running", record.status);
    try std.testing.expectEqual(@as(?i32, 999999), record.pid);
}

test "currentOwnedRunningPid preserves running state when cgroup ownership is unknown" {
    store.initTestDb() catch return error.SkipZigTest;
    defer store.deinitTestDb();

    try store.save(.{
        .id = "cafebabefeed",
        .hostname = "test",
        .rootfs = "/tmp/rootfs",
        .status = "running",
        .command = "sleep 1",
        .created_at = 1,
        .pid = 999999,
        .exit_code = null,
    });

    const record = try store.load(std.testing.allocator, "cafebabefeed");
    defer record.deinit(std.testing.allocator);

    try std.testing.expect(currentOwnedRunningPid(&record) == null);

    const updated = try store.load(std.testing.allocator, "cafebabefeed");
    defer updated.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("running", updated.status);
    try std.testing.expectEqual(@as(?i32, 999999), updated.pid);
}

test "reconcileLiveness preserves running status when ownership cannot be verified" {
    store.initTestDb() catch return error.SkipZigTest;
    defer store.deinitTestDb();

    try store.save(.{
        .id = "invalid-owner",
        .hostname = "test",
        .rootfs = "/tmp/rootfs",
        .status = "running",
        .command = "sleep 1",
        .created_at = 1,
        .pid = 12345,
        .exit_code = null,
    });

    try std.testing.expectEqualStrings("running", reconcileLiveness("invalid-owner", "running", 12345));

    const record = try store.load(std.testing.allocator, "invalid-owner");
    defer record.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("running", record.status);
    try std.testing.expectEqual(@as(?i32, 12345), record.pid);
}

test "currentOwnedRunningPid preserves running state when ownership cannot be verified" {
    store.initTestDb() catch return error.SkipZigTest;
    defer store.deinitTestDb();

    try store.save(.{
        .id = "invalid-owner",
        .hostname = "test",
        .rootfs = "/tmp/rootfs",
        .status = "running",
        .command = "sleep 1",
        .created_at = 1,
        .pid = 12345,
        .exit_code = null,
    });

    const record = try store.load(std.testing.allocator, "invalid-owner");
    defer record.deinit(std.testing.allocator);

    try std.testing.expect(currentOwnedRunningPid(&record) == null);

    const updated = try store.load(std.testing.allocator, "invalid-owner");
    defer updated.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("running", updated.status);
    try std.testing.expectEqual(@as(?i32, 12345), updated.pid);
}

test "stopped state accepts a record already removed by its owner" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const id = "cleaned-stop";
    try store.save(.{
        .id = id,
        .hostname = "completed",
        .rootfs = "/fixture",
        .command = "/bin/sh",
        .status = "stopped",
        .created_at = 1,
        .pid = null,
        .exit_code = 0,
    });
    try std.testing.expect(waitForStoppedState(std.testing.allocator, id));
    try store.remove(id);
    try std.testing.expect(waitForStoppedState(std.testing.allocator, id));
}

test "detached startup outcome survives immediate process exit and rejects real failures" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const id = "fast-started";
    for ([_]u8{ 0, 1, 255 }) |exit_code| {
        try store.save(.{
            .id = id,
            .rootfs = "/fixture",
            .hostname = "fast",
            .command = "/bin/sh",
            .status = "created",
            .pid = null,
            .exit_code = null,
            .created_at = 1,
        });
        try store.setStartupOutcome(id, .succeeded);
        try store.updateStatus(id, "stopped", null, exit_code);
        try waitForContainerStart(std.testing.allocator, id);
    }

    // A later automatic restart failure does not erase the first launch result.
    try store.recordStartupFailure(id);
    try waitForContainerStart(std.testing.allocator, id);

    // An explicit launch starts a new pending outcome and preserves failed cleanup.
    try store.setStartupOutcome(id, .pending);
    try store.updateStatus(id, "cleanup_failed", null, null);
    try store.recordStartupFailure(id);
    const failed = try store.load(std.testing.allocator, id);
    defer failed.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("cleanup_failed", failed.status);
    try std.testing.expectEqual(@as(?u8, null), failed.exit_code);
    try std.testing.expectEqual(store.StartupOutcome.failed, failed.startup_outcome);
    try std.testing.expectError(ContainerError.ProcessNotFound, waitForContainerStart(std.testing.allocator, id));
}
