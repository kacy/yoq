const std = @import("std");
const membership_support = @import("membership_support.zig");

pub fn collectPiggybackUpdates(self: anytype, BoundedUpdates: type, max_piggyback_updates: usize) BoundedUpdates {
    const PendingUpdate = @TypeOf(self.pending_updates.items[0]);
    if (self.pending_updates.items.len == 0) {
        return .{};
    }

    // send dead updates first, then suspect, then alive. equal states keep
    // their current queue order until expired entries are removed below.
    std.sort.insertion(PendingUpdate, self.pending_updates.items, {}, struct {
        fn lessThan(_: void, lhs: PendingUpdate, rhs: PendingUpdate) bool {
            return @intFromEnum(lhs.update.state) > @intFromEnum(rhs.update.state);
        }
    }.lessThan);

    const count = @min(max_piggyback_updates, self.pending_updates.items.len);
    var result: BoundedUpdates = .{};
    result.len = @intCast(count);

    for (self.pending_updates.items[0..count], 0..) |*pending, i| {
        result.buf[i] = pending.update;
        pending.remaining -= 1;
    }

    var i: usize = 0;
    while (i < self.pending_updates.items.len) {
        if (self.pending_updates.items[i].remaining == 0) {
            _ = self.pending_updates.swapRemove(i);
            // check the entry moved into this slot before advancing.
        } else {
            i += 1;
        }
    }

    return result;
}

pub fn addPendingUpdate(self: anytype, update: anytype) !void {
    const member_count = self.members.count() + 1;
    const transmission_count: u8 = @intCast(membership_support.ceilLog2(member_count) + 1);

    for (self.pending_updates.items) |*pending| {
        if (pending.update.id == update.id) {
            pending.update = update;
            pending.remaining = transmission_count;
            return;
        }
    }

    const max_pending: usize = 1000;
    if (self.pending_updates.items.len >= max_pending) {
        _ = self.pending_updates.swapRemove(evictionIndex(self.pending_updates.items));
    }

    try self.pending_updates.append(self.alloc, .{
        .update = update,
        .remaining = transmission_count,
    });
}

fn evictionIndex(pending_updates: anytype) usize {
    var selected: usize = 0;
    for (pending_updates[1..], 1..) |pending, index| {
        const candidate = pending_updates[selected];
        const priority = @intFromEnum(pending.update.state);
        const selected_priority = @intFromEnum(candidate.update.state);

        // evict the lowest state priority first. within that state, prefer
        // fewer remaining transmissions and keep the first entry on a tie.
        if (priority < selected_priority) {
            selected = index;
        } else if (priority == selected_priority and pending.remaining < candidate.remaining) {
            selected = index;
        }
    }
    return selected;
}
