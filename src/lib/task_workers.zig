const std = @import("std");

/// Bounded background tasks retain their handles until joined. Each handler
/// receives the group's stop flag before its owned arguments. The owner stops
/// admission and joins before releasing anything those arguments borrow.
pub fn Group(comptime capacity: usize) type {
    return struct {
        const Self = @This();
        const Slot = struct {
            thread: ?std.Thread = null,
            done: bool = false,
        };

        mutex: std.Io.Mutex = .init,
        slots: [capacity]Slot = @splat(.{}),
        stopping: std.atomic.Value(bool) = .init(false),

        /// Arguments transfer to the handler only when spawning succeeds.
        pub fn spawn(self: *Self, comptime handler: anytype, args: anytype) !void {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);
            if (self.stopping.load(.acquire)) return error.Stopping;
            var available: ?usize = null;
            for (&self.slots, 0..) |*slot, index| {
                if (slot.done) {
                    slot.thread.?.join();
                    slot.* = .{};
                }
                if (available == null and slot.thread == null) available = index;
            }
            const index = available orelse return error.TaskLimit;
            const Worker = struct {
                fn run(group: *Self, slot_index: usize, arguments: @TypeOf(args)) void {
                    @call(.auto, handler, .{&group.stopping} ++ arguments);
                    group.mutex.lockUncancelable(std.Options.debug_io);
                    group.slots[slot_index].done = true;
                    group.mutex.unlock(std.Options.debug_io);
                }
            };
            self.slots[index] = .{ .thread = try std.Thread.spawn(.{}, Worker.run, .{ self, index, args }) };
        }

        pub fn cancel(self: *Self) void {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);
            self.stopping.store(true, .release);
        }

        /// Lifecycle calls are serialized by the owner. Handlers cooperate with
        /// cancellation; join never abandons a task that still borrows state.
        pub fn join(self: *Self) void {
            self.cancel();
            for (&self.slots) |*slot| {
                if (slot.thread) |thread| thread.join();
                slot.* = .{};
            }
        }

        pub fn restart(self: *Self) void {
            for (self.slots) |slot| std.debug.assert(slot.thread == null);
            self.stopping.store(false, .release);
        }
    };
}

test "task worker ownership stops admission and joins borrowed state" {
    const Fixture = struct {
        fn run(stopping: *const std.atomic.Value(bool), complete: *bool) void {
            while (!stopping.load(.acquire)) {
                std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake) catch break;
            }
            complete.* = true;
        }
    };
    var group = Group(1){};
    var complete = false;
    defer group.join();
    try group.spawn(Fixture.run, .{&complete});
    try std.testing.expectError(error.TaskLimit, group.spawn(Fixture.run, .{&complete}));
    group.cancel();
    try std.testing.expectError(error.Stopping, group.spawn(Fixture.run, .{&complete}));
    group.join();
    try std.testing.expect(complete);
    complete = false;
    group.restart();
    try group.spawn(Fixture.run, .{&complete});
    group.join();
    try std.testing.expect(complete);
}
