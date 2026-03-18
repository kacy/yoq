pub fn applyStateUpdate(self: anytype, update: anytype) !void {
    if (update.id == self.self_id) {
        if (update.state == .suspect or update.state == .dead) {
            if (update.incarnation >= self.incarnation) {
                self.incarnation = update.incarnation +| 1;
                try self.addPendingUpdate(.{
                    .id = self.self_id,
                    .addr = self.self_addr,
                    .state = .alive,
                    .incarnation = self.incarnation,
                });
            }
        }
        return;
    }

    const member = self.members.getPtr(update.id) orelse {
        if (update.state != .dead) {
            try self.members.put(update.id, .{
                .id = update.id,
                .addr = update.addr,
                .state = update.state,
                .incarnation = update.incarnation,
                .state_changed_at = self.tick_count,
            });
            self.rebuildProbeOrder() catch {};
            if (update.state == .alive) {
                try self.actions.append(self.alloc, .{ .member_alive = .{ .id = update.id } });
            } else {
                try self.actions.append(self.alloc, .{ .member_suspect = .{ .id = update.id } });
            }
        }
        return;
    };

    if (update.incarnation > member.incarnation) {
        const old_state = member.state;
        member.incarnation = update.incarnation;
        member.state = update.state;
        member.addr = update.addr;
        member.state_changed_at = self.tick_count;
        try emitStateChange(self, update.id, old_state, update.state);
    } else if (update.incarnation == member.incarnation) {
        const update_priority = @intFromEnum(update.state);
        const current_priority = @intFromEnum(member.state);
        if (update_priority > current_priority) {
            const old_state = member.state;
            member.state = update.state;
            member.state_changed_at = self.tick_count;
            try emitStateChange(self, update.id, old_state, update.state);
        }
    }
}

pub fn emitStateChange(self: anytype, id: u64, old: anytype, new: anytype) !void {
    _ = old;
    switch (new) {
        .alive => try self.actions.append(self.alloc, .{ .member_alive = .{ .id = id } }),
        .suspect => try self.actions.append(self.alloc, .{ .member_suspect = .{ .id = id } }),
        .dead => try self.actions.append(self.alloc, .{ .member_dead = .{ .id = id } }),
    }
}
