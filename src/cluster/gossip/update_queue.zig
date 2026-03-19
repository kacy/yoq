const std = @import("std");
const membership_support = @import("membership_support.zig");

pub fn collectPiggybackUpdates(self: anytype, BoundedUpdates: type, max_piggyback_updates: usize) BoundedUpdates {
    const PendingUpdate = @TypeOf(self.pending_updates.items[0]);
    if (self.pending_updates.items.len == 0) {
        return .{};
    }

    std.sort.insertion(PendingUpdate, self.pending_updates.items, {}, struct {
        fn lessThan(_: void, lhs: PendingUpdate, rhs: PendingUpdate) bool {
            return @intFromEnum(lhs.update.state) > @intFromEnum(rhs.update.state);
        }
    }.lessThan);

    const count = @min(max_piggyback_updates, self.pending_updates.items.len);
    var result: BoundedUpdates = .{};
    result.len = @intCast(count);

    for (0..count) |i| {
        result.buf[i] = self.pending_updates.items[i].update;
        self.pending_updates.items[i].remaining -= 1;
    }

    var i: usize = 0;
    while (i < self.pending_updates.items.len) {
        if (self.pending_updates.items[i].remaining == 0) {
            _ = self.pending_updates.swapRemove(i);
        } else {
            i += 1;
        }
    }

    return result;
}

pub fn addPendingUpdate(self: anytype, update: anytype) !void {
    const member_count = self.members.count() + 1;
    const gossip_count: u8 = @intCast(membership_support.ceilLog2(member_count) + 1);

    for (self.pending_updates.items) |*pending| {
        if (pending.update.id == update.id) {
            pending.update = update;
            pending.remaining = gossip_count;
            return;
        }
    }

    const max_pending: usize = 1000;
    if (self.pending_updates.items.len >= max_pending) {
        var worst: usize = 0;
        for (self.pending_updates.items[1..], 1..) |item, idx| {
            const worst_entry = self.pending_updates.items[worst];
            if (@intFromEnum(item.update.state) < @intFromEnum(worst_entry.update.state) or
                (@intFromEnum(item.update.state) == @intFromEnum(worst_entry.update.state) and
                    item.remaining < worst_entry.remaining))
            {
                worst = idx;
            }
        }
        _ = self.pending_updates.swapRemove(worst);
    }

    try self.pending_updates.append(self.alloc, .{
        .update = update,
        .remaining = gossip_count,
    });
}
