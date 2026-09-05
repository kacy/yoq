const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;

/// Fixed admission slots own worker handles until joined. Handlers own their
/// accepted socket; a duplicate lets stop cancel it without racing fd reuse.
pub fn Group(comptime capacity: usize) type {
    return struct {
        const Self = @This();
        const Slot = struct {
            thread: ?std.Thread = null,
            cancel_fd: posix.fd_t = -1,
            done: bool = false,
        };
        mutex: std.Io.Mutex = .init,
        slots: [capacity]Slot = @splat(.{}),
        stopping: bool = false,
        active: usize = 0,
        limit: usize = capacity,

        /// On failure the caller still owns fd. On success handler owns it.
        pub fn spawn(self: *Self, fd: posix.fd_t, comptime handler: anytype, args: anytype) !void {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);
            if (self.stopping) return error.Stopping;
            if (self.active >= @min(self.limit, capacity)) return error.ConnectionLimit;
            var available: ?usize = null;
            for (&self.slots, 0..) |*slot, index| {
                if (slot.done) {
                    slot.thread.?.join();
                    slot.* = .{};
                }
                if (available == null and slot.thread == null) available = index;
            }
            const index = available orelse return error.ConnectionLimit;
            const duplicate = std.os.linux.fcntl(fd, posix.F.DUPFD_CLOEXEC, 0);
            if (posix.errno(duplicate) != .SUCCESS) return error.DuplicateFailed;
            const cancel_fd: posix.fd_t = @intCast(duplicate);
            errdefer linux_platform.posix.close(cancel_fd);
            const Worker = struct {
                fn run(group: *Self, slot_index: usize, arguments: @TypeOf(args)) void {
                    @call(.auto, handler, arguments);
                    group.mutex.lockUncancelable(std.Options.debug_io);
                    linux_platform.posix.close(group.slots[slot_index].cancel_fd);
                    group.slots[slot_index].cancel_fd = -1;
                    group.slots[slot_index].done = true;
                    group.active -= 1;
                    group.mutex.unlock(std.Options.debug_io);
                }
            };
            const thread = try std.Thread.spawn(.{}, Worker.run, .{ self, index, args });
            self.slots[index] = .{ .thread = thread, .cancel_fd = cancel_fd };
            self.active += 1;
        }

        pub fn count(self: *Self) usize {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);
            return self.active;
        }

        pub fn cancel(self: *Self) void {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);
            self.stopping = true;
            for (self.slots) |slot| if (slot.cancel_fd >= 0) {
                _ = std.os.linux.shutdown(slot.cancel_fd, 2);
            };
        }

        /// The owner serializes lifecycle calls and stops accept loops first.
        pub fn join(self: *Self) void {
            self.cancel();
            for (&self.slots) |*slot| {
                if (slot.thread) |thread| {
                    thread.join();
                    slot.* = .{};
                }
            }
            std.debug.assert(self.active == 0);
        }

        pub fn restart(self: *Self) void {
            self.mutex.lockUncancelable(std.Options.debug_io);
            defer self.mutex.unlock(std.Options.debug_io);
            for (self.slots) |slot| std.debug.assert(slot.thread == null);
            std.debug.assert(self.active == 0);
            self.stopping = false;
        }
    };
}

test "listener lifecycle cancellation does not shut down a reused descriptor" {
    const Fixture = struct {
        closed: std.atomic.Value(bool) = .init(false),
        release: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This(), fd: posix.fd_t) void {
            linux_platform.posix.close(fd);
            self.closed.store(true, .release);
            while (!self.release.load(.acquire)) {
                std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake) catch return;
            }
        }

        fn pair() ![2]posix.fd_t {
            var fds: [2]posix.fd_t = undefined;
            if (posix.errno(std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &fds)) != .SUCCESS)
                return error.SocketFailed;
            return fds;
        }
    };
    var group = Group(1){};
    var fixture = Fixture{};
    defer {
        fixture.release.store(true, .release);
        group.join();
    }
    const original = try Fixture.pair();
    defer linux_platform.posix.close(original[1]);
    group.spawn(original[0], Fixture.run, .{ &fixture, original[0] }) catch |err| {
        linux_platform.posix.close(original[0]);
        return err;
    };
    const deadline = @import("../client_transport.zig").Deadline.afterMilliseconds(2000);
    while (!fixture.closed.load(.acquire)) {
        _ = try deadline.remaining();
        try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
    }
    const unrelated = try Fixture.pair();
    defer linux_platform.posix.close(unrelated[0]);
    defer linux_platform.posix.close(unrelated[1]);
    const needs_alias = unrelated[0] != original[0] and unrelated[1] != original[0];
    if (needs_alias) try linux_platform.posix.dup2(unrelated[0], original[0]);
    defer if (needs_alias) linux_platform.posix.close(original[0]);
    group.cancel();
    try std.testing.expectEqual(@as(usize, 1), try linux_platform.posix.send(unrelated[0], "x", posix.MSG.NOSIGNAL));
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try linux_platform.posix.recv(unrelated[1], &byte, posix.MSG.DONTWAIT));
    try std.testing.expectEqual(@as(u8, 'x'), byte[0]);
}
