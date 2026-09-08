const std = @import("std");

pub const max_rules = 4096;
pub const max_isolated = 1024;
pub const Action = enum(u8) { deny = 0, allow = 1 };
pub const Key = extern struct { src_ip: u32, dst_ip: u32 };
pub const Rule = struct { key: Key, action: Action };

/// An owned, sorted policy generation prepared before changing live filters.
pub const Snapshot = struct {
    rules: []Rule,
    isolated: []u32,

    pub fn deinit(self: Snapshot, alloc: std.mem.Allocator) void {
        alloc.free(self.rules);
        alloc.free(self.isolated);
    }

    pub fn clone(self: Snapshot, alloc: std.mem.Allocator) !Snapshot {
        const rules = try alloc.dupe(Rule, self.rules);
        errdefer alloc.free(rules);
        return .{ .rules = rules, .isolated = try alloc.dupe(u32, self.isolated) };
    }

    pub fn eql(self: Snapshot, other: Snapshot) bool {
        if (!std.mem.eql(u32, self.isolated, other.isolated) or self.rules.len != other.rules.len) return false;
        for (self.rules, other.rules) |left, right| {
            if (left.key.src_ip != right.key.src_ip or left.key.dst_ip != right.key.dst_ip or left.action != right.action) return false;
        }
        return true;
    }
};

pub const Builder = struct {
    rules: std.AutoHashMapUnmanaged(Key, Action) = .empty,
    isolated: std.AutoHashMapUnmanaged(u32, void) = .empty,

    pub fn deinit(self: *Builder, alloc: std.mem.Allocator) void {
        self.rules.deinit(alloc);
        self.isolated.deinit(alloc);
    }

    pub fn add(self: *Builder, alloc: std.mem.Allocator, key: Key, action: Action) !void {
        if (self.rules.getPtr(key)) |existing| {
            // An explicit deny wins when service aliases resolve to one pair.
            if (action == .deny) existing.* = .deny;
            return;
        }
        if (self.rules.count() >= max_rules) return error.PolicyCapacityExceeded;
        try self.rules.put(alloc, key, action);
    }

    pub fn isolate(self: *Builder, alloc: std.mem.Allocator, source: u32) !void {
        if (self.isolated.contains(source)) return;
        if (self.isolated.count() >= max_isolated) return error.PolicyCapacityExceeded;
        try self.isolated.put(alloc, source, {});
    }

    pub fn finish(self: *Builder, alloc: std.mem.Allocator) !Snapshot {
        const rules = try alloc.alloc(Rule, self.rules.count());
        errdefer alloc.free(rules);
        const isolated = try alloc.alloc(u32, self.isolated.count());
        var rule_iter = self.rules.iterator();
        var index: usize = 0;
        while (rule_iter.next()) |entry| : (index += 1) {
            rules[index] = .{ .key = entry.key_ptr.*, .action = entry.value_ptr.* };
        }
        var source_iter = self.isolated.keyIterator();
        index = 0;
        while (source_iter.next()) |entry| : (index += 1) isolated[index] = entry.*;
        std.mem.sort(Rule, rules, {}, lessThan);
        std.mem.sort(u32, isolated, {}, std.sort.asc(u32));
        return .{ .rules = rules, .isolated = isolated };
    }
};

fn lessThan(_: void, left: Rule, right: Rule) bool {
    if (left.key.src_ip != right.key.src_ip) return left.key.src_ip < right.key.src_ip;
    return left.key.dst_ip < right.key.dst_ip;
}

test "policy snapshots normalize aliases and preserve explicit deny" {
    var builder: Builder = .{};
    defer builder.deinit(std.testing.allocator);
    try builder.add(std.testing.allocator, .{ .src_ip = 2, .dst_ip = 4 }, .allow);
    try builder.add(std.testing.allocator, .{ .src_ip = 1, .dst_ip = 3 }, .deny);
    try builder.add(std.testing.allocator, .{ .src_ip = 2, .dst_ip = 4 }, .deny);
    try builder.add(std.testing.allocator, .{ .src_ip = 2, .dst_ip = 4 }, .allow);
    try builder.isolate(std.testing.allocator, 2);
    try builder.isolate(std.testing.allocator, 2);
    const snapshot = try builder.finish(std.testing.allocator);
    defer snapshot.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), snapshot.rules.len);
    try std.testing.expectEqual(@as(u32, 1), snapshot.rules[0].key.src_ip);
    try std.testing.expectEqual(Action.deny, snapshot.rules[1].action);
    try std.testing.expectEqualSlices(u32, &.{2}, snapshot.isolated);
    const copied = try snapshot.clone(std.testing.allocator);
    defer copied.deinit(std.testing.allocator);
    try std.testing.expect(snapshot.eql(copied));
}

test "policy snapshots reject excess kernel map capacity before publication" {
    var builder: Builder = .{};
    defer builder.deinit(std.testing.allocator);
    for (0..max_rules) |index| try builder.add(std.testing.allocator, .{ .src_ip = 1, .dst_ip = @intCast(index) }, .deny);
    try std.testing.expectError(error.PolicyCapacityExceeded, builder.add(std.testing.allocator, .{ .src_ip = 2, .dst_ip = 0 }, .deny));
    for (0..max_isolated) |index| try builder.isolate(std.testing.allocator, @intCast(index));
    try std.testing.expectError(error.PolicyCapacityExceeded, builder.isolate(std.testing.allocator, max_isolated));
}
