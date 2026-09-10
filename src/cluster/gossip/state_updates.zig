pub fn applyStateUpdate(self: anytype, update: anytype) !void {
    if (update.id == self.self_id) {
        if (update.state == .alive or update.incarnation < self.incarnation) return;
        self.incarnation = update.incarnation +| 1;
        try self.addPendingUpdate(.{
            .id = self.self_id,
            .addr = self.self_addr,
            .state = .alive,
            .incarnation = self.incarnation,
        });
        return;
    }

    const member = self.members.getPtr(update.id) orelse {
        if (update.state == .dead) return;
        try self.members.put(update.id, .{
            .id = update.id,
            .addr = update.addr,
            .state = update.state,
            .incarnation = update.incarnation,
            .state_changed_at = self.tick_count,
        });
        self.rebuildProbeOrder() catch {};
        try emitStateChange(self, update.id, update.state);
        return;
    };

    if (update.incarnation < member.incarnation) return;
    if (update.incarnation == member.incarnation) {
        if (@intFromEnum(update.state) <= @intFromEnum(member.state)) return;
    } else {
        member.incarnation = update.incarnation;
        // refutations may advertise overlay or wildcard addresses. keep registered
        // endpoints for authenticated packet source checks.
        if (!member.endpoint_pinned) member.addr = update.addr;
    }
    member.state = update.state;
    member.state_changed_at = self.tick_count;
    try emitStateChange(self, update.id, update.state);
}

fn emitStateChange(self: anytype, id: u64, state: anytype) !void {
    try self.actions.append(self.alloc, switch (state) {
        .alive => .{ .member_alive = .{ .id = id } },
        .suspect => .{ .member_suspect = .{ .id = id } },
        .dead => .{ .member_dead = .{ .id = id } },
    });
}
