const std = @import("std");
const ResourceLimits = @import("common.zig").ResourceLimits;
const runtime_wait = @import("../../lib/runtime_wait.zig");

pub const Field = enum {
    cpu_weight,
    cpu_max,
    memory_max,
    memory_high,
    pids_max,

    pub fn file(self: Field) []const u8 {
        return switch (self) {
            .cpu_weight => "cpu.weight",
            .cpu_max => "cpu.max",
            .memory_max => "memory.max",
            .memory_high => "memory.high",
            .pids_max => "pids.max",
        };
    }
};

pub const Change = struct {
    field: Field,
    old: [64]u8 = undefined,
    old_len: usize = 0,
    new: [64]u8 = undefined,
    new_len: usize = 0,
};

/// Capture actual kernel values before changing any controller. The caller keeps
/// this snapshot until its saved configuration has also been committed.
pub const Update = struct {
    changes: [5]Change = undefined,
    count: usize = 0,
    applied: usize = 0,

    pub fn prepare(cgroup: anytype, limits: ResourceLimits, fields: []const Field) !Update {
        try limits.validate();
        if (fields.len > 5) return error.InvalidLimit;
        var result: Update = .{};
        for (fields, 0..) |field, i| {
            result.changes[i] = .{ .field = field };
            const change = &result.changes[i];
            change.old_len = (try cgroup.readFile(field.file(), &change.old)).len;
            const value = switch (field) {
                .cpu_weight => try std.fmt.bufPrint(&change.new, "{d}", .{limits.cpu_weight orelse 100}),
                .cpu_max => if (limits.cpu_max_usec) |quota|
                    try std.fmt.bufPrint(&change.new, "{d} {d}", .{ quota, limits.cpu_max_period })
                else
                    try std.fmt.bufPrint(&change.new, "max {d}", .{limits.cpu_max_period}),
                .memory_max => try formatLimit(&change.new, limits.memory_max),
                .memory_high => try formatLimit(&change.new, limits.memory_high),
                .pids_max => try formatLimit(&change.new, if (limits.pids_max) |max| @as(u64, max) else null),
            };
            change.new_len = value.len;
            result.count += 1;
        }
        return result;
    }

    pub fn apply(self: *Update, cgroup: anytype) !void {
        for (self.changes[0..self.count], 0..) |*change, index| {
            // Include the current write in rollback: a short/failed write may
            // already have reached the kernel.
            self.applied = index + 1;
            cgroup.writeFile(change.field.file(), change.new[0..change.new_len]) catch |err| {
                self.rollback(cgroup) catch return error.PartialUpdate;
                return err;
            };
        }
    }

    pub fn rollback(self: *Update, cgroup: anytype) !void {
        var failed = false;
        var remaining = self.applied;
        while (remaining > 0) {
            remaining -= 1;
            const change = &self.changes[remaining];
            cgroup.writeFile(change.field.file(), change.old[0..change.old_len]) catch {
                failed = true;
            };
        }
        if (failed) return error.PartialUpdate;
        self.applied = 0;
    }
};

fn formatLimit(buffer: []u8, value: ?u64) ![]const u8 {
    return if (value) |number| std.fmt.bufPrint(buffer, "{d}", .{number}) else std.fmt.bufPrint(buffer, "max", .{});
}

pub fn isFrozen(cgroup: anytype) !bool {
    var buffer: [1024]u8 = undefined;
    const events = try cgroup.readFile("cgroup.events", &buffer);
    var lines = std.mem.tokenizeScalar(u8, events, '\n');
    while (lines.next()) |line| {
        if (std.mem.eql(u8, line, "frozen 1")) return true;
        if (std.mem.eql(u8, line, "frozen 0")) return false;
    }
    return error.ReadFailed;
}

pub fn setFrozen(cgroup: anytype, frozen: bool) !void {
    try cgroup.writeFile("cgroup.freeze", if (frozen) "1" else "0");
    for (0..100) |_| {
        if (try isFrozen(cgroup) == frozen) return;
        if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(10), "container freezer transition")) return error.FreezeFailed;
    }
    return error.FreezeFailed;
}

test "container resource update writes unlimited and restores actual prior kernel settings" {
    const Fake = struct {
        writes: [8][]const u8 = undefined,
        storage: [8][64]u8 = undefined,
        count: usize = 0,
        fail_at: ?usize = null,
        fail_rollback: bool = false,

        fn readFile(_: *@This(), name: []const u8, buffer: []u8) ![]const u8 {
            return std.fmt.bufPrint(buffer, "{s}", .{if (std.mem.eql(u8, name, "cpu.max")) "50000 100000" else "123"});
        }
        fn writeFile(self: *@This(), _: []const u8, value: []const u8) !void {
            const index = self.count;
            self.count += 1;
            self.writes[index] = try std.fmt.bufPrint(&self.storage[index], "{s}", .{value});
            if (self.fail_at == index or (self.fail_rollback and index >= 2)) return error.WriteFailed;
        }
    };
    var fake: Fake = .{};
    var update = try Update.prepare(&fake, ResourceLimits.unlimited, &.{ .cpu_max, .memory_max });
    try update.apply(&fake);
    try std.testing.expectEqualStrings("max 100000", fake.writes[0]);
    try std.testing.expectEqualStrings("max", fake.writes[1]);
    try update.rollback(&fake);
    try std.testing.expectEqualStrings("123", fake.writes[2]);
    try std.testing.expectEqualStrings("50000 100000", fake.writes[3]);
    fake = .{ .fail_at = 1 };
    update = try Update.prepare(&fake, ResourceLimits.unlimited, &.{ .cpu_max, .memory_max });
    try std.testing.expectError(error.WriteFailed, update.apply(&fake));
    try std.testing.expectEqualStrings("50000 100000", fake.writes[3]);
    fake = .{ .fail_at = 1, .fail_rollback = true };
    update = try Update.prepare(&fake, ResourceLimits.unlimited, &.{ .cpu_max, .memory_max });
    try std.testing.expectError(error.PartialUpdate, update.apply(&fake));
}
