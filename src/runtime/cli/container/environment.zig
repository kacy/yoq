const std = @import("std");

/// merge inherited values and overrides in order. the last value for each name
/// wins; a bare name removes that variable. the result owns all its strings.
pub fn merge(alloc: std.mem.Allocator, inherited: []const []const u8, overrides: []const []const u8) std.mem.Allocator.Error![][]const u8 {
    var merged: std.ArrayList([]const u8) = .empty;
    defer merged.deinit(alloc);

    // normalize inherited entries too, so an override or unset cannot leave a
    // second value for the same variable in the child's environment.
    for ([_][]const []const u8{ inherited, overrides }) |entries| {
        for (entries) |entry| {
            const equals = std.mem.indexOfScalar(u8, entry, '=');
            const name = if (equals) |i| entry[0..i] else entry;
            var found = false;
            for (merged.items, 0..) |*existing, i| {
                const existing_equals = std.mem.indexOfScalar(u8, existing.*, '=').?;
                if (!std.mem.eql(u8, existing.*[0..existing_equals], name)) continue;
                if (equals != null) existing.* = entry else _ = merged.orderedRemove(i);
                found = true;
                break;
            }
            if (!found and equals != null) try merged.append(alloc, entry);
        }
    }

    const owned = try alloc.alloc([]const u8, merged.items.len);
    var copied: usize = 0;
    errdefer {
        for (owned[0..copied]) |entry| alloc.free(entry);
        alloc.free(owned);
    }
    for (merged.items, 0..) |entry, i| {
        owned[i] = try alloc.dupe(u8, entry);
        copied += 1;
    }
    return owned;
}

pub fn free(alloc: std.mem.Allocator, entries: []const []const u8) void {
    for (entries) |entry| alloc.free(entry);
    alloc.free(entries);
}

test "environment merge keeps the last inherited value and replaces all duplicates" {
    const alloc = std.testing.allocator;
    const inherited = [_][]const u8{ "A=first", "B=keep", "A=second", "A=last" };
    const normalized = try merge(alloc, &inherited, &.{});
    defer free(alloc, normalized);
    try std.testing.expectEqual(@as(usize, 2), normalized.len);
    try std.testing.expectEqualStrings("A=last", normalized[0]);
    try std.testing.expectEqualStrings("B=keep", normalized[1]);

    const replaced = try merge(alloc, &inherited, &.{ "A=override", "A=final" });
    defer free(alloc, replaced);
    try std.testing.expectEqual(@as(usize, 2), replaced.len);
    try std.testing.expectEqualStrings("A=final", replaced[0]);
    try std.testing.expectEqualStrings("B=keep", replaced[1]);
}

test "environment unset removes every inherited value and later values can restore it" {
    const alloc = std.testing.allocator;
    const inherited = [_][]const u8{ "A=first", "B=keep", "A=second" };
    const removed = try merge(alloc, &inherited, &.{"A"});
    defer free(alloc, removed);
    try std.testing.expectEqual(@as(usize, 1), removed.len);
    try std.testing.expectEqualStrings("B=keep", removed[0]);

    const restored = try merge(alloc, &inherited, &.{ "A", "A=", "MISSING" });
    defer free(alloc, restored);
    try std.testing.expectEqual(@as(usize, 2), restored.len);
    try std.testing.expectEqualStrings("B=keep", restored[0]);
    try std.testing.expectEqualStrings("A=", restored[1]);
}

fn checkOwnership(alloc: std.mem.Allocator) !void {
    var inherited = "A=inherited".*;
    var override = "B=override".*;
    const result = try merge(alloc, &.{&inherited}, &.{&override});
    defer free(alloc, result);
    inherited[2] = 'x';
    override[2] = 'x';
    try std.testing.expectEqualStrings("A=inherited", result[0]);
    try std.testing.expectEqualStrings("B=override", result[1]);
}

test "environment merge owns its strings and cleans up failed allocations" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkOwnership, .{});
}
