const std = @import("std");
const store = @import("../../../state/store.zig");
const process = @import("../../process.zig");
const cgroups = @import("../../cgroups.zig");
const cli = @import("../../../lib/cli.zig");
const common = @import("common.zig");

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
        const record = store.load(alloc, id) catch {
            std.Thread.sleep(50 * std.time.ns_per_ms);
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
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }

    return false;
}

pub fn waitForContainerStart(alloc: std.mem.Allocator, id: []const u8) ContainerError!void {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        const record = store.load(alloc, id) catch {
            std.Thread.sleep(50 * std.time.ns_per_ms);
            continue;
        };
        defer record.deinit(alloc);

        if (std.mem.eql(u8, record.status, "running") and record.pid != null) return;
        if (std.mem.eql(u8, record.status, "stopped")) {
            writeErr("failed to start detached container\n", .{});
            return ContainerError.ProcessNotFound;
        }

        std.Thread.sleep(50 * std.time.ns_per_ms);
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
