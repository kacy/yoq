const std = @import("std");
const membership_support = @import("membership_support.zig");
const state_updates = @import("state_updates.zig");

pub fn tick(self: anytype) !void {
    self.tick_count += 1;

    try checkSuspectTimeouts(self);

    switch (self.probe_phase) {
        .idle => try startProbe(self),
        .direct => {
            self.ticks_in_phase += 1;
            if (self.ticks_in_phase >= self.probe_interval) {
                try escalateToIndirect(self);
            }
        },
        .indirect => {
            self.ticks_in_phase += 1;
            if (self.ticks_in_phase >= self.probe_interval) {
                try suspectProbeTarget(self);
            }
        },
    }
}

pub fn handlePing(self: anytype, msg: anytype) !void {
    for (msg.updates.slice()) |update| {
        try state_updates.applyStateUpdate(self, update);
    }

    const updates = self.collectPiggybackUpdates();
    try self.actions.append(self.alloc, .{ .send_message = .{
        .target = msg.from,
        .addr = self.getMemberAddr(msg.from) orelse return,
        .message = .{ .ping_ack = .{
            .from = self.self_id,
            .sequence = msg.sequence,
            .updates = updates,
        } },
    } });
}

pub fn handlePingAck(self: anytype, msg: anytype) !void {
    for (msg.updates.slice()) |update| {
        try state_updates.applyStateUpdate(self, update);
    }

    if (self.probe_target) |target| {
        if (msg.from == target and msg.sequence == self.probe_sequence) {
            self.probe_phase = .idle;
            self.probe_target = null;
            self.ticks_in_phase = 0;

            if (self.members.getPtr(target)) |member| {
                if (member.state == .suspect) {
                    member.state = .alive;
                    member.state_changed_at = self.tick_count;
                    try self.actions.append(self.alloc, .{ .member_alive = .{ .id = target } });
                    try self.addPendingUpdate(.{
                        .id = target,
                        .addr = member.addr,
                        .state = .alive,
                        .incarnation = member.incarnation,
                    });
                }
            }
        }
    }
}

pub fn handlePingReq(self: anytype, msg: anytype) !void {
    for (msg.updates.slice()) |update| {
        try state_updates.applyStateUpdate(self, update);
    }

    const target_addr = self.getMemberAddr(msg.target) orelse return;
    const updates = self.collectPiggybackUpdates();
    try self.actions.append(self.alloc, .{ .send_message = .{
        .target = msg.target,
        .addr = target_addr,
        .message = .{ .ping = .{
            .from = self.self_id,
            .sequence = msg.sequence,
            .updates = updates,
        } },
    } });
}

pub fn startProbe(self: anytype) !void {
    if (self.probe_order.items.len == 0) {
        try self.rebuildProbeOrder();
        if (self.probe_order.items.len == 0) return;
    }

    var attempts: usize = 0;
    while (attempts < self.probe_order.items.len) : (attempts += 1) {
        const target_id = self.probe_order.items[self.probe_index % self.probe_order.items.len];
        self.probe_index = (self.probe_index + 1) % self.probe_order.items.len;

        if (self.members.get(target_id)) |member| {
            if (member.state == .dead) continue;

            self.probe_target = target_id;
            self.probe_phase = .direct;
            self.probe_sequence += 1;
            self.ticks_in_phase = 0;

            const updates = self.collectPiggybackUpdates();
            try self.actions.append(self.alloc, .{ .send_message = .{
                .target = target_id,
                .addr = member.addr,
                .message = .{ .ping = .{
                    .from = self.self_id,
                    .sequence = self.probe_sequence,
                    .updates = updates,
                } },
            } });
            return;
        }
    }

    if (self.probe_index == 0) {
        try self.rebuildProbeOrder();
    }
}

pub fn escalateToIndirect(self: anytype) !void {
    const target_id = self.probe_target orelse return;

    self.probe_phase = .indirect;
    self.ticks_in_phase = 0;

    var candidates: std.ArrayListUnmanaged(u64) = .{};
    defer candidates.deinit(self.alloc);

    var iter = self.members.iterator();
    while (iter.next()) |entry| {
        const id = entry.key_ptr.*;
        if (id != self.self_id and id != target_id and entry.value_ptr.state != .dead) {
            try candidates.append(self.alloc, id);
        }
    }

    const random = self.prng.random();
    random.shuffle(u64, candidates.items);
    const fanout = self.configured_fanout orelse @max(membership_support.ceilLog2(self.members.count() + 1), 3);
    const relay_count = @min(fanout, candidates.items.len);

    for (candidates.items[0..relay_count]) |relay_id| {
        if (self.members.get(relay_id)) |relay| {
            const updates = self.collectPiggybackUpdates();
            try self.actions.append(self.alloc, .{ .send_message = .{
                .target = relay_id,
                .addr = relay.addr,
                .message = .{ .ping_req = .{
                    .from = self.self_id,
                    .target = target_id,
                    .sequence = self.probe_sequence,
                    .updates = updates,
                } },
            } });
        }
    }
}

pub fn suspectProbeTarget(self: anytype) !void {
    const target_id = self.probe_target orelse return;

    self.probe_phase = .idle;
    self.probe_target = null;
    self.ticks_in_phase = 0;

    if (self.members.getPtr(target_id)) |member| {
        if (member.state == .alive) {
            member.state = .suspect;
            member.state_changed_at = self.tick_count;
            try self.actions.append(self.alloc, .{ .member_suspect = .{ .id = target_id } });
            try self.addPendingUpdate(.{
                .id = target_id,
                .addr = member.addr,
                .state = .suspect,
                .incarnation = member.incarnation,
            });
        }
    }
}

pub fn checkSuspectTimeouts(self: anytype) !void {
    var dead_list: std.ArrayListUnmanaged(u64) = .{};
    defer dead_list.deinit(self.alloc);

    var iter = self.members.iterator();
    while (iter.next()) |entry| {
        const member = entry.value_ptr;
        if (member.state == .suspect and self.tick_count - member.state_changed_at >= self.suspect_timeout) {
            try dead_list.append(self.alloc, member.id);
        }
    }

    for (dead_list.items) |id| {
        if (self.members.getPtr(id)) |member| {
            member.state = .dead;
            member.state_changed_at = self.tick_count;
            try self.actions.append(self.alloc, .{ .member_dead = .{ .id = id } });
            try self.addPendingUpdate(.{
                .id = id,
                .addr = member.addr,
                .state = .dead,
                .incarnation = member.incarnation,
            });
        }
    }
}
