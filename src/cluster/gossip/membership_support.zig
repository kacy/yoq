pub fn ceilLog2(n: usize) u32 {
    if (n <= 2) return 1;

    var log: u32 = 0;
    var val: usize = n - 1;
    while (val > 0) : (val >>= 1) {
        log += 1;
    }
    return log;
}

pub fn recalculateIntervals(
    self: anytype,
    base_probe_interval: u32,
    base_suspect_timeout: u32,
    base_dead_timeout: u32,
    max_interval_multiplier: u32,
) void {
    const member_count = self.members.count() + 1; // +1 for self
    const multiplier = @min(ceilLog2(member_count), max_interval_multiplier);
    const susp_mult = self.configured_suspicion_multiplier orelse 1;
    self.probe_interval = base_probe_interval * multiplier;
    self.suspect_timeout = base_suspect_timeout * multiplier * susp_mult;
    self.dead_timeout = base_dead_timeout * multiplier * susp_mult;
}

pub fn addMember(self: anytype, addr: anytype, id: u64) !void {
    if (id == self.self_id) return;

    const result = try self.members.getOrPut(id);
    if (result.found_existing) return;

    result.value_ptr.* = .{
        .id = id,
        .addr = addr,
        .state = .alive,
        .incarnation = 0,
        .state_changed_at = self.tick_count,
    };
    self.rebuildProbeOrder() catch {};
    self.recalculateIntervals();
}

pub fn getMemberAddr(self: anytype, id: u64) ?@TypeOf(self.self_addr) {
    if (self.members.get(id)) |member| {
        return member.addr;
    }
    return null;
}

pub fn rebuildProbeOrder(self: anytype) !void {
    self.probe_order.clearRetainingCapacity();

    var iter = self.members.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.state != .dead) {
            try self.probe_order.append(self.alloc, entry.key_ptr.*);
        }
    }

    const random = self.prng.random();
    random.shuffle(u64, self.probe_order.items);
    self.probe_index = 0;
}
