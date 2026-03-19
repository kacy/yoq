const std = @import("std");

/// Drain an unmanaged action queue into an owned slice without dropping
/// queued work on allocation failure.
pub fn drainOwned(comptime T: type, alloc: std.mem.Allocator, queue: *std.ArrayListUnmanaged(T)) []T {
    if (queue.items.len == 0) {
        return alloc.alloc(T, 0) catch unreachable;
    }

    var pending = queue.*;
    queue.* = .empty;

    return pending.toOwnedSlice(alloc) catch {
        queue.* = pending;
        return alloc.alloc(T, 0) catch unreachable;
    };
}

test "drainOwned returns owned slice on success" {
    const alloc = std.testing.allocator;
    var queue: std.ArrayListUnmanaged(u8) = .empty;
    defer queue.deinit(alloc);

    try queue.append(alloc, 1);
    try queue.append(alloc, 2);

    const drained = drainOwned(u8, alloc, &queue);
    defer alloc.free(drained);

    try std.testing.expectEqualSlices(u8, &.{ 1, 2 }, drained);
    try std.testing.expectEqual(@as(usize, 0), queue.items.len);
}

test "drainOwned preserves queued items on allocation failure" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = 1,
        .resize_fail_index = 0,
    });
    const alloc = failing.allocator();

    var queue: std.ArrayListUnmanaged(u8) = .empty;
    defer queue.deinit(alloc);

    try queue.append(alloc, 7);

    const drained = drainOwned(u8, alloc, &queue);
    defer alloc.free(drained);

    try std.testing.expectEqual(@as(usize, 0), drained.len);
    try std.testing.expectEqual(@as(usize, 1), queue.items.len);
    try std.testing.expectEqual(@as(u8, 7), queue.items[0]);
    try std.testing.expect(failing.has_induced_failure);
}
