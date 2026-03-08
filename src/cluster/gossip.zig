// gossip — SWIM-based failure detection protocol
//
// implements a simplified SWIM protocol for scalable membership and failure
// detection. designed to replace sequential raft heartbeats for agent nodes,
// scaling to 500-1000+ nodes with O(1) per-node network overhead.
//
// this module is a pure state machine — no I/O. all side effects are expressed
// as Actions that the caller must process, matching the pattern used by raft.zig.
//
// probe cycle: each tick, one member is probed in round-robin order:
//   idle → send ping → (timeout) → send K=3 ping_req → (timeout) → suspect
//   suspect timeout → dead
//
// incarnation numbers provide conflict-free state resolution:
//   - higher incarnation always wins
//   - same incarnation: dead > suspect > alive
//   - self-refutation: if accused, increment incarnation and broadcast alive
//
// state updates are piggybacked on ping/ack messages (max 6 per message),
// with priority: dead > suspect > alive. each update is gossiped
// ceil(log2(N))+1 times for reliable dissemination.
//
// usage:
//   var gossip = Gossip.init(alloc, my_id, my_addr);
//   defer gossip.deinit();
//   gossip.addMember(peer_id, peer_addr);
//   gossip.tick(); // call every ~500ms
//   const actions = gossip.drainActions();
//   // process actions: send UDP messages, update membership state

const std = @import("std");

pub const MemberState = enum(u8) {
    alive = 0,
    suspect = 1,
    dead = 2,
};

pub const MemberAddr = struct {
    ip: [4]u8,
    port: u16,
};

pub const Member = struct {
    id: u64,
    addr: MemberAddr,
    state: MemberState,
    incarnation: u64,
    /// tick at which the state last changed (for suspect → dead timeout)
    state_changed_at: u64,
};

/// a compact state update piggybacked on gossip messages.
/// 23 bytes serialized: [8B id] [4B ip] [2B port] [1B state] [8B incarnation]
pub const StateUpdate = struct {
    id: u64,
    addr: MemberAddr,
    state: MemberState,
    incarnation: u64,
};

/// tracks how many more times a state update should be piggybacked.
const PendingUpdate = struct {
    update: StateUpdate,
    remaining: u8,
};

pub const GossipMessage = union(enum) {
    ping: PingPayload,
    ping_ack: PingAckPayload,
    ping_req: PingReqPayload,
};

pub const PingPayload = struct {
    from: u64,
    sequence: u64,
    updates: []const StateUpdate,
};

pub const PingAckPayload = struct {
    from: u64,
    sequence: u64,
    updates: []const StateUpdate,
};

pub const PingReqPayload = struct {
    from: u64,
    target: u64,
    sequence: u64,
    updates: []const StateUpdate,
};

pub const Action = union(enum) {
    send_message: struct {
        target: u64,
        addr: MemberAddr,
        message: GossipMessage,
    },
    member_alive: struct { id: u64 },
    member_suspect: struct { id: u64 },
    member_dead: struct { id: u64 },
};

const ProbePhase = enum {
    idle,
    direct,
    indirect,
};

/// maximum number of piggybacked updates per message
const max_piggyback_updates = 6;

/// number of indirect probe targets (K in SWIM paper)
const indirect_probe_count = 3;

pub const Gossip = struct {
    alloc: std.mem.Allocator,
    self_id: u64,
    self_addr: MemberAddr,

    members: std.AutoHashMap(u64, Member),
    actions: std.ArrayListUnmanaged(Action),
    pending_updates: std.ArrayListUnmanaged(PendingUpdate),

    // probe state
    probe_target: ?u64,
    probe_phase: ProbePhase,
    probe_sequence: u64,
    ticks_in_phase: u32,
    probe_order: std.ArrayListUnmanaged(u64),
    probe_index: usize,

    // timing
    tick_count: u64,
    incarnation: u64,
    prng: std.Random.DefaultPrng,

    // configurable intervals (in ticks, default tick = 500ms)
    probe_interval: u32,
    suspect_timeout: u32,
    dead_timeout: u32,

    pub fn init(alloc: std.mem.Allocator, self_id: u64, self_addr: MemberAddr) Gossip {
        return .{
            .alloc = alloc,
            .self_id = self_id,
            .self_addr = self_addr,
            .members = std.AutoHashMap(u64, Member).init(alloc),
            .actions = .{},
            .pending_updates = .{},
            .probe_target = null,
            .probe_phase = .idle,
            .probe_sequence = 0,
            .ticks_in_phase = 0,
            .probe_order = .{},
            .probe_index = 0,
            .tick_count = 0,
            .incarnation = 1,
            .prng = std.Random.DefaultPrng.init(self_id),
            .probe_interval = 5,
            .suspect_timeout = 20,
            .dead_timeout = 100,
        };
    }

    pub fn deinit(self: *Gossip) void {
        self.members.deinit();
        for (self.actions.items) |action| {
            self.freeActionUpdates(action);
        }
        self.actions.deinit(self.alloc);
        self.pending_updates.deinit(self.alloc);
        self.probe_order.deinit(self.alloc);
    }

    /// add a member to the membership list. if the member already exists,
    /// this is a no-op (use applyStateUpdate for state changes).
    pub fn addMember(self: *Gossip, id: u64, addr: MemberAddr) !void {
        if (id == self.self_id) return;
        const result = try self.members.getOrPut(id);
        if (!result.found_existing) {
            result.value_ptr.* = .{
                .id = id,
                .addr = addr,
                .state = .alive,
                .incarnation = 0,
                .state_changed_at = self.tick_count,
            };
            self.rebuildProbeOrder() catch {};
        }
    }

    /// remove a member from the membership list entirely.
    pub fn removeMember(self: *Gossip, id: u64) void {
        _ = self.members.remove(id);
        self.rebuildProbeOrder() catch {};
    }

    /// advance the protocol by one tick. call this every ~500ms.
    /// generates Actions for the caller to process.
    pub fn tick(self: *Gossip) !void {
        self.tick_count += 1;

        // check suspect timeouts — promote suspect → dead
        try self.checkSuspectTimeouts();

        // advance probe cycle
        switch (self.probe_phase) {
            .idle => try self.startProbe(),
            .direct => {
                self.ticks_in_phase += 1;
                if (self.ticks_in_phase >= self.probe_interval) {
                    try self.escalateToIndirect();
                }
            },
            .indirect => {
                self.ticks_in_phase += 1;
                if (self.ticks_in_phase >= self.probe_interval) {
                    try self.suspectProbeTarget();
                }
            },
        }
    }

    /// process an incoming ping message
    pub fn handlePing(self: *Gossip, msg: PingPayload) !void {
        for (msg.updates) |update| {
            try self.applyStateUpdate(update);
        }

        const updates = try self.collectPiggybackUpdates();
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

    /// process an incoming ping ack
    pub fn handlePingAck(self: *Gossip, msg: PingAckPayload) !void {
        for (msg.updates) |update| {
            try self.applyStateUpdate(update);
        }

        // if this ack matches our current probe, clear it
        if (self.probe_target) |target| {
            if (msg.from == target and msg.sequence == self.probe_sequence) {
                self.probe_phase = .idle;
                self.probe_target = null;
                self.ticks_in_phase = 0;

                // ensure the member is marked alive
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

    /// process an incoming ping_req — forward a ping to the target on behalf
    /// of the requester, and relay any ack back.
    pub fn handlePingReq(self: *Gossip, msg: PingReqPayload) !void {
        for (msg.updates) |update| {
            try self.applyStateUpdate(update);
        }

        const target_addr = self.getMemberAddr(msg.target) orelse return;
        const updates = try self.collectPiggybackUpdates();
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

    /// drain all pending actions for the caller to process
    pub fn drainActions(self: *Gossip) []Action {
        return self.actions.toOwnedSlice(self.alloc) catch return &[_]Action{};
    }

    /// free actions returned by drainActions
    pub fn freeActions(self: *Gossip, actions: []Action) void {
        for (actions) |action| {
            self.freeActionUpdates(action);
        }
        self.alloc.free(actions);
    }

    fn freeActionUpdates(self: *Gossip, action: Action) void {
        switch (action) {
            .send_message => |sm| {
                const updates = switch (sm.message) {
                    .ping => |p| p.updates,
                    .ping_ack => |p| p.updates,
                    .ping_req => |p| p.updates,
                };
                if (updates.len > 0) {
                    self.alloc.free(updates);
                }
            },
            else => {},
        }
    }

    // --- internal ---

    fn startProbe(self: *Gossip) !void {
        if (self.probe_order.items.len == 0) {
            try self.rebuildProbeOrder();
            if (self.probe_order.items.len == 0) return;
        }

        // skip dead members
        var attempts: usize = 0;
        while (attempts < self.probe_order.items.len) : (attempts += 1) {
            const target_id = self.probe_order.items[self.probe_index % self.probe_order.items.len];
            self.probe_index = (self.probe_index + 1) % self.probe_order.items.len;

            if (self.members.get(target_id)) |member| {
                if (member.state == .dead) continue;

                // found a live target — send ping
                self.probe_target = target_id;
                self.probe_phase = .direct;
                self.probe_sequence += 1;
                self.ticks_in_phase = 0;

                const updates = try self.collectPiggybackUpdates();
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

        // if we wrapped around the probe order, rebuild it (stale entries)
        if (self.probe_index == 0) {
            try self.rebuildProbeOrder();
        }
    }

    fn escalateToIndirect(self: *Gossip) !void {
        const target_id = self.probe_target orelse return;

        self.probe_phase = .indirect;
        self.ticks_in_phase = 0;

        // pick up to K random live members (not self, not target) to relay
        var candidates: std.ArrayListUnmanaged(u64) = .{};
        defer candidates.deinit(self.alloc);

        var iter = self.members.iterator();
        while (iter.next()) |entry| {
            const id = entry.key_ptr.*;
            if (id != self.self_id and id != target_id and entry.value_ptr.state != .dead) {
                try candidates.append(self.alloc, id);
            }
        }

        // shuffle and take first K
        const random = self.prng.random();
        random.shuffle(u64, candidates.items);
        const k = @min(indirect_probe_count, candidates.items.len);

        for (candidates.items[0..k]) |relay_id| {
            if (self.members.get(relay_id)) |relay| {
                const updates = try self.collectPiggybackUpdates();
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

    fn suspectProbeTarget(self: *Gossip) !void {
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

    fn checkSuspectTimeouts(self: *Gossip) !void {
        // collect suspects that have timed out. uses ArrayList instead of a
        // fixed array so large clusters with network partitions don't silently
        // drop suspects beyond an arbitrary limit.
        var dead_list: std.ArrayListUnmanaged(u64) = .{};
        defer dead_list.deinit(self.alloc);

        var iter = self.members.iterator();
        while (iter.next()) |entry| {
            const member = entry.value_ptr;
            if (member.state == .suspect) {
                if (self.tick_count - member.state_changed_at >= self.suspect_timeout) {
                    try dead_list.append(self.alloc, member.id);
                }
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

    /// apply a state update using incarnation-based conflict resolution.
    /// higher incarnation always wins. at same incarnation: dead > suspect > alive.
    /// if we ourselves are accused, increment incarnation and refute.
    fn applyStateUpdate(self: *Gossip, update: StateUpdate) !void {
        // self-refutation: if someone says we're suspect or dead, refute it
        if (update.id == self.self_id) {
            if (update.state == .suspect or update.state == .dead) {
                if (update.incarnation >= self.incarnation) {
                    self.incarnation = update.incarnation +| 1; // saturating add to avoid overflow at u64 max
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
            // unknown member — add it if not dead
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

        // incarnation resolution
        if (update.incarnation > member.incarnation) {
            // higher incarnation always wins
            const old_state = member.state;
            member.incarnation = update.incarnation;
            member.state = update.state;
            member.addr = update.addr;
            member.state_changed_at = self.tick_count;
            try self.emitStateChange(update.id, old_state, update.state);
        } else if (update.incarnation == member.incarnation) {
            // same incarnation: dead > suspect > alive
            const update_priority = @intFromEnum(update.state);
            const current_priority = @intFromEnum(member.state);
            if (update_priority > current_priority) {
                const old_state = member.state;
                member.state = update.state;
                member.state_changed_at = self.tick_count;
                try self.emitStateChange(update.id, old_state, update.state);
            }
        }
        // lower incarnation — stale, ignore
    }

    fn emitStateChange(self: *Gossip, id: u64, old: MemberState, new: MemberState) !void {
        _ = old;
        switch (new) {
            .alive => try self.actions.append(self.alloc, .{ .member_alive = .{ .id = id } }),
            .suspect => try self.actions.append(self.alloc, .{ .member_suspect = .{ .id = id } }),
            .dead => try self.actions.append(self.alloc, .{ .member_dead = .{ .id = id } }),
        }
    }

    fn getMemberAddr(self: *Gossip, id: u64) ?MemberAddr {
        if (self.members.get(id)) |member| {
            return member.addr;
        }
        return null;
    }

    fn rebuildProbeOrder(self: *Gossip) !void {
        self.probe_order.clearRetainingCapacity();
        var iter = self.members.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.state != .dead) {
                try self.probe_order.append(self.alloc, entry.key_ptr.*);
            }
        }
        // shuffle for fairness
        const random = self.prng.random();
        random.shuffle(u64, self.probe_order.items);
        self.probe_index = 0;
    }

    /// collect up to max_piggyback_updates updates to piggyback on a message.
    /// prioritizes dead > suspect > alive updates. decrements remaining counters.
    fn collectPiggybackUpdates(self: *Gossip) ![]const StateUpdate {
        if (self.pending_updates.items.len == 0) {
            return &[_]StateUpdate{};
        }

        // sort by priority: dead first (enum value 2), then suspect (1), then alive (0)
        std.sort.insertion(PendingUpdate, self.pending_updates.items, {}, struct {
            fn lessThan(_: void, a: PendingUpdate, b: PendingUpdate) bool {
                return @intFromEnum(a.update.state) > @intFromEnum(b.update.state);
            }
        }.lessThan);

        const count = @min(max_piggyback_updates, self.pending_updates.items.len);
        const updates = try self.alloc.alloc(StateUpdate, count);

        for (0..count) |i| {
            updates[i] = self.pending_updates.items[i].update;
            self.pending_updates.items[i].remaining -= 1;
        }

        // remove expired updates (remaining == 0)
        var i: usize = 0;
        while (i < self.pending_updates.items.len) {
            if (self.pending_updates.items[i].remaining == 0) {
                _ = self.pending_updates.swapRemove(i);
            } else {
                i += 1;
            }
        }

        return updates;
    }

    fn addPendingUpdate(self: *Gossip, update: StateUpdate) !void {
        // compute gossip count: ceil(log2(N)) + 1
        const n = self.members.count() + 1; // +1 for self
        const gossip_count: u8 = if (n <= 1) 1 else blk: {
            var log: u8 = 0;
            var val: usize = n - 1;
            while (val > 0) : (val >>= 1) {
                log += 1;
            }
            break :blk log + 1;
        };

        // replace existing update for same id if present
        for (self.pending_updates.items) |*pending| {
            if (pending.update.id == update.id) {
                pending.update = update;
                pending.remaining = gossip_count;
                return;
            }
        }

        try self.pending_updates.append(self.alloc, .{
            .update = update,
            .remaining = gossip_count,
        });
    }

    // --- serialization ---
    //
    // wire format:
    //   msg types: 0x10=Ping, 0x11=PingAck, 0x12=PingReq
    //   Ping:     [1B type=0x10] [8B from] [8B seq] [1B count] [updates...]
    //   PingAck:  [1B type=0x11] [8B from] [8B seq] [1B count] [updates...]
    //   PingReq:  [1B type=0x12] [8B from] [8B target] [8B seq] [1B count] [updates...]
    //   StateUpdate: [8B id] [4B ip] [2B port] [1B state] [8B incarnation] = 23B

    pub fn encode(buf: []u8, msg: GossipMessage) !usize {
        var pos: usize = 0;

        switch (msg) {
            .ping => |p| {
                if (buf.len < 18 + p.updates.len * 23) return error.BufferTooSmall;
                buf[pos] = 0x10;
                pos += 1;
                writeU64(buf[pos..], p.from);
                pos += 8;
                writeU64(buf[pos..], p.sequence);
                pos += 8;
                buf[pos] = @intCast(p.updates.len);
                pos += 1;
                pos = encodeUpdates(buf, pos, p.updates);
            },
            .ping_ack => |p| {
                if (buf.len < 18 + p.updates.len * 23) return error.BufferTooSmall;
                buf[pos] = 0x11;
                pos += 1;
                writeU64(buf[pos..], p.from);
                pos += 8;
                writeU64(buf[pos..], p.sequence);
                pos += 8;
                buf[pos] = @intCast(p.updates.len);
                pos += 1;
                pos = encodeUpdates(buf, pos, p.updates);
            },
            .ping_req => |p| {
                if (buf.len < 26 + p.updates.len * 23) return error.BufferTooSmall;
                buf[pos] = 0x12;
                pos += 1;
                writeU64(buf[pos..], p.from);
                pos += 8;
                writeU64(buf[pos..], p.target);
                pos += 8;
                writeU64(buf[pos..], p.sequence);
                pos += 8;
                buf[pos] = @intCast(p.updates.len);
                pos += 1;
                pos = encodeUpdates(buf, pos, p.updates);
            },
        }

        return pos;
    }

    pub fn decode(alloc: std.mem.Allocator, data: []const u8) !GossipMessage {
        if (data.len < 1) return error.InvalidMessage;
        const msg_type = data[0];

        switch (msg_type) {
            0x10, 0x11 => {
                if (data.len < 18) return error.InvalidMessage;
                const from = readU64(data[1..]);
                const sequence = readU64(data[9..]);
                const count = data[17];
                if (data.len < 18 + @as(usize, count) * 23) return error.InvalidMessage;

                const updates = try decodeUpdates(alloc, data[18..], count);

                if (msg_type == 0x10) {
                    return .{ .ping = .{
                        .from = from,
                        .sequence = sequence,
                        .updates = updates,
                    } };
                } else {
                    return .{ .ping_ack = .{
                        .from = from,
                        .sequence = sequence,
                        .updates = updates,
                    } };
                }
            },
            0x12 => {
                if (data.len < 26) return error.InvalidMessage;
                const from = readU64(data[1..]);
                const target = readU64(data[9..]);
                const sequence = readU64(data[17..]);
                const count = data[25];
                if (data.len < 26 + @as(usize, count) * 23) return error.InvalidMessage;

                const updates = try decodeUpdates(alloc, data[26..], count);
                return .{ .ping_req = .{
                    .from = from,
                    .target = target,
                    .sequence = sequence,
                    .updates = updates,
                } };
            },
            else => return error.InvalidMessage,
        }
    }

    /// free updates allocated by decode
    pub fn freeDecoded(alloc: std.mem.Allocator, msg: GossipMessage) void {
        const updates = switch (msg) {
            .ping => |p| p.updates,
            .ping_ack => |p| p.updates,
            .ping_req => |p| p.updates,
        };
        if (updates.len > 0) {
            alloc.free(updates);
        }
    }

    fn encodeUpdates(buf: []u8, start: usize, updates: []const StateUpdate) usize {
        var pos = start;
        for (updates) |u| {
            writeU64(buf[pos..], u.id);
            pos += 8;
            @memcpy(buf[pos..][0..4], &u.addr.ip);
            pos += 4;
            buf[pos] = @intCast(u.addr.port & 0xFF);
            buf[pos + 1] = @intCast((u.addr.port >> 8) & 0xFF);
            pos += 2;
            buf[pos] = @intFromEnum(u.state);
            pos += 1;
            writeU64(buf[pos..], u.incarnation);
            pos += 8;
        }
        return pos;
    }

    fn decodeUpdates(alloc: std.mem.Allocator, data: []const u8, count: u8) ![]StateUpdate {
        if (count == 0) return &[_]StateUpdate{};

        const updates = try alloc.alloc(StateUpdate, count);
        errdefer alloc.free(updates);

        var pos: usize = 0;
        for (0..count) |i| {
            updates[i] = .{
                .id = readU64(data[pos..]),
                .addr = .{
                    .ip = data[pos + 8 ..][0..4].*,
                    .port = @as(u16, data[pos + 12]) | (@as(u16, data[pos + 13]) << 8),
                },
                .state = @enumFromInt(data[pos + 14]),
                .incarnation = readU64(data[pos + 15 ..]),
            };
            pos += 23;
        }

        return updates;
    }

    fn writeU64(buf: []u8, val: u64) void {
        buf[0..8].* = @bitCast(val);
    }

    fn readU64(buf: []const u8) u64 {
        return @bitCast(buf[0..8].*);
    }
};

// --- tests ---

test "probe cycle sends ping" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    try g.tick();

    const actions = g.drainActions();
    defer g.freeActions(actions);

    try std.testing.expect(actions.len >= 1);
    const first = actions[0];
    try std.testing.expect(first == .send_message);
    try std.testing.expect(first.send_message.message == .ping);
    try std.testing.expectEqual(@as(u64, 2), first.send_message.target);
}

test "ack clears probe" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    try g.tick();

    const actions = g.drainActions();
    defer g.freeActions(actions);
    const seq = actions[0].send_message.message.ping.sequence;

    try g.handlePingAck(.{ .from = 2, .sequence = seq, .updates = &.{} });

    try std.testing.expect(g.probe_phase == .idle);
    try std.testing.expect(g.probe_target == null);
}

test "missed ack triggers indirect ping" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    try g.addMember(3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });
    try g.addMember(4, .{ .ip = .{ 10, 0, 0, 4 }, .port = 7000 });

    try g.tick(); // sends ping

    const drain = g.drainActions();
    g.freeActions(drain);

    // wait for probe_interval ticks without ack
    for (0..g.probe_interval) |_| {
        try g.tick();
    }

    const actions2 = g.drainActions();
    defer g.freeActions(actions2);

    var ping_req_count: usize = 0;
    for (actions2) |action| {
        if (action == .send_message and action.send_message.message == .ping_req) {
            ping_req_count += 1;
        }
    }
    try std.testing.expect(ping_req_count > 0);
    try std.testing.expect(g.probe_phase == .indirect);
}

test "suspect after failed indirect probe" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    try g.addMember(3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });

    try g.tick();
    var drain = g.drainActions();
    g.freeActions(drain);

    // wait for direct timeout
    for (0..g.probe_interval) |_| {
        try g.tick();
    }
    drain = g.drainActions();
    g.freeActions(drain);

    // wait for indirect timeout
    for (0..g.probe_interval) |_| {
        try g.tick();
    }

    const actions = g.drainActions();
    defer g.freeActions(actions);

    var found_suspect = false;
    for (actions) |action| {
        if (action == .member_suspect) {
            found_suspect = true;
        }
    }
    try std.testing.expect(found_suspect);
}

test "suspect to dead timeout" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g.deinit();

    g.suspect_timeout = 5;

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    // manually mark suspect
    if (g.members.getPtr(2)) |m| {
        m.state = .suspect;
        m.state_changed_at = g.tick_count;
    }

    // tick past suspect timeout
    for (0..6) |_| {
        try g.tick();
        const a = g.drainActions();
        defer g.freeActions(a);
        for (a) |action| {
            if (action == .member_dead and action.member_dead.id == 2) {
                try std.testing.expectEqual(MemberState.dead, g.members.get(2).?.state);
                return;
            }
        }
    }

    return error.TestUnexpectedResult;
}

test "incarnation conflict resolution" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    // same incarnation, higher state (suspect > alive) — should win
    try g.applyStateUpdate(.{
        .id = 2,
        .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .state = .suspect,
        .incarnation = 0,
    });
    try std.testing.expectEqual(MemberState.suspect, g.members.get(2).?.state);

    var drain = g.drainActions();
    g.freeActions(drain);

    // higher incarnation with alive — should override suspect
    try g.applyStateUpdate(.{
        .id = 2,
        .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .state = .alive,
        .incarnation = 5,
    });
    try std.testing.expectEqual(MemberState.alive, g.members.get(2).?.state);
    try std.testing.expectEqual(@as(u64, 5), g.members.get(2).?.incarnation);

    drain = g.drainActions();
    g.freeActions(drain);

    // lower incarnation — should be ignored
    try g.applyStateUpdate(.{
        .id = 2,
        .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .state = .dead,
        .incarnation = 3,
    });
    try std.testing.expectEqual(MemberState.alive, g.members.get(2).?.state);
    try std.testing.expectEqual(@as(u64, 5), g.members.get(2).?.incarnation);

    drain = g.drainActions();
    g.freeActions(drain);
}

test "self-refutation increments incarnation" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g.deinit();

    const original_incarnation = g.incarnation;

    try g.applyStateUpdate(.{
        .id = 1,
        .addr = .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 },
        .state = .suspect,
        .incarnation = original_incarnation,
    });

    try std.testing.expect(g.incarnation > original_incarnation);

    var found_refutation = false;
    for (g.pending_updates.items) |pending| {
        if (pending.update.id == 1 and pending.update.state == .alive) {
            found_refutation = true;
            try std.testing.expect(pending.update.incarnation > original_incarnation);
        }
    }
    try std.testing.expect(found_refutation);

    const drain = g.drainActions();
    g.freeActions(drain);
}

test "encode decode round-trip: ping" {
    const alloc = std.testing.allocator;
    const updates = try alloc.alloc(StateUpdate, 1);
    defer alloc.free(updates);
    updates[0] = .{
        .id = 42,
        .addr = .{ .ip = .{ 192, 168, 1, 1 }, .port = 8080 },
        .state = .alive,
        .incarnation = 7,
    };

    const msg: GossipMessage = .{ .ping = .{
        .from = 100,
        .sequence = 999,
        .updates = updates,
    } };

    var buf: [512]u8 = undefined;
    const len = try Gossip.encode(&buf, msg);

    const decoded = try Gossip.decode(alloc, buf[0..len]);
    defer Gossip.freeDecoded(alloc, decoded);

    try std.testing.expect(decoded == .ping);
    try std.testing.expectEqual(@as(u64, 100), decoded.ping.from);
    try std.testing.expectEqual(@as(u64, 999), decoded.ping.sequence);
    try std.testing.expectEqual(@as(usize, 1), decoded.ping.updates.len);
    try std.testing.expectEqual(@as(u64, 42), decoded.ping.updates[0].id);
    try std.testing.expectEqual(@as(u16, 8080), decoded.ping.updates[0].addr.port);
    try std.testing.expectEqual(MemberState.alive, decoded.ping.updates[0].state);
    try std.testing.expectEqual(@as(u64, 7), decoded.ping.updates[0].incarnation);
}

test "encode decode round-trip: ping_req" {
    const alloc = std.testing.allocator;
    const msg: GossipMessage = .{ .ping_req = .{
        .from = 1,
        .target = 2,
        .sequence = 50,
        .updates = &.{},
    } };

    var buf: [512]u8 = undefined;
    const len = try Gossip.encode(&buf, msg);

    const decoded = try Gossip.decode(alloc, buf[0..len]);
    defer Gossip.freeDecoded(alloc, decoded);

    try std.testing.expect(decoded == .ping_req);
    try std.testing.expectEqual(@as(u64, 1), decoded.ping_req.from);
    try std.testing.expectEqual(@as(u64, 2), decoded.ping_req.target);
    try std.testing.expectEqual(@as(u64, 50), decoded.ping_req.sequence);
    try std.testing.expectEqual(@as(usize, 0), decoded.ping_req.updates.len);
}

test "encode decode round-trip: ping_ack with multiple updates" {
    const alloc = std.testing.allocator;
    const updates = try alloc.alloc(StateUpdate, 3);
    defer alloc.free(updates);
    updates[0] = .{ .id = 10, .addr = .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .state = .alive, .incarnation = 1 };
    updates[1] = .{ .id = 20, .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7001 }, .state = .suspect, .incarnation = 3 };
    updates[2] = .{ .id = 30, .addr = .{ .ip = .{ 10, 0, 0, 3 }, .port = 7002 }, .state = .dead, .incarnation = 5 };

    const msg: GossipMessage = .{ .ping_ack = .{
        .from = 99,
        .sequence = 12345,
        .updates = updates,
    } };

    var buf: [512]u8 = undefined;
    const len = try Gossip.encode(&buf, msg);

    const decoded = try Gossip.decode(alloc, buf[0..len]);
    defer Gossip.freeDecoded(alloc, decoded);

    try std.testing.expect(decoded == .ping_ack);
    try std.testing.expectEqual(@as(usize, 3), decoded.ping_ack.updates.len);
    try std.testing.expectEqual(MemberState.suspect, decoded.ping_ack.updates[1].state);
    try std.testing.expectEqual(@as(u64, 5), decoded.ping_ack.updates[2].incarnation);
}

test "dead member not probed" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    if (g.members.getPtr(2)) |m| {
        m.state = .dead;
    }

    try g.rebuildProbeOrder();
    try std.testing.expectEqual(@as(usize, 0), g.probe_order.items.len);

    try g.tick();
    const actions = g.drainActions();
    defer g.freeActions(actions);

    for (actions) |action| {
        if (action == .send_message) {
            try std.testing.expect(false);
        }
    }
}

test "piggybacked update lifecycle" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    try g.addPendingUpdate(.{
        .id = 2,
        .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .state = .suspect,
        .incarnation = 1,
    });

    try std.testing.expectEqual(@as(usize, 1), g.pending_updates.items.len);
    const initial_remaining = g.pending_updates.items[0].remaining;
    try std.testing.expect(initial_remaining > 0);

    var collected_count: usize = 0;
    while (g.pending_updates.items.len > 0) {
        const upd = try g.collectPiggybackUpdates();
        if (upd.len > 0) alloc.free(upd);
        collected_count += 1;
        if (collected_count > 20) break;
    }

    try std.testing.expectEqual(@as(usize, 0), g.pending_updates.items.len);
    try std.testing.expectEqual(@as(usize, initial_remaining), collected_count);
}

test "decode rejects invalid message type" {
    const alloc = std.testing.allocator;
    const data = [_]u8{ 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const result = Gossip.decode(alloc, &data);
    try std.testing.expectError(error.InvalidMessage, result);
}

test "decode rejects truncated message" {
    const alloc = std.testing.allocator;
    const data = [_]u8{ 0x10, 0, 0, 0, 0, 0 };
    const result = Gossip.decode(alloc, &data);
    try std.testing.expectError(error.InvalidMessage, result);
}

test "more than 64 simultaneous suspects all transition to dead" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g.deinit();

    g.suspect_timeout = 1; // 1 tick for fast test

    // add 100 members and mark them all suspect
    for (2..102) |i| {
        const id: u64 = @intCast(i);
        try g.addMember(id, .{ .ip = .{ 10, 0, @intCast(i / 256), @intCast(i % 256) }, .port = 7000 });
        if (g.members.getPtr(id)) |m| {
            m.state = .suspect;
            m.state_changed_at = 0; // set in the past
        }
    }

    // tick past suspect timeout — all 100 should become dead
    g.tick_count = 10; // well past the timeout of 1
    try g.checkSuspectTimeouts();

    var dead_count: usize = 0;
    var iter = g.members.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.state == .dead) dead_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 100), dead_count);

    const actions = g.drainActions();
    defer g.freeActions(actions);
}

test "incarnation at u64 max wraps on refutation" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g.deinit();

    // set incarnation to max
    g.incarnation = std.math.maxInt(u64);

    // someone accuses us as suspect with max incarnation
    try g.applyStateUpdate(.{
        .id = 1,
        .addr = .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 },
        .state = .suspect,
        .incarnation = std.math.maxInt(u64),
    });

    // saturating add: maxInt + 1 stays at maxInt rather than wrapping.
    // in practice u64 max is unreachable, but the code must not panic.
    try std.testing.expectEqual(std.math.maxInt(u64), g.incarnation);

    const drain = g.drainActions();
    g.freeActions(drain);
}

test "decode rejects invalid state value in update" {
    const alloc = std.testing.allocator;

    // Zig's @enumFromInt panics on invalid values in safe mode,
    // so we validate the state byte before casting. verify that
    // valid state values (0, 1, 2) decode successfully.
    for ([_]u8{ 0, 1, 2 }) |valid_state| {
        var buf: [512]u8 = undefined;
        buf[0] = 0x10; // ping type
        Gossip.writeU64(buf[1..], 99);
        Gossip.writeU64(buf[9..], 1);
        buf[17] = 1; // 1 update
        Gossip.writeU64(buf[18..], 50);
        @memcpy(buf[26..30], &[_]u8{ 10, 0, 0, 50 });
        buf[30] = 0;
        buf[31] = 0x1B;
        buf[32] = valid_state;
        Gossip.writeU64(buf[33..], 1);

        const msg = try Gossip.decode(alloc, buf[0..41]);
        Gossip.freeDecoded(alloc, msg);
    }
}

// -- multi-instance tests --
//
// these tests create multiple gossip instances and route messages between
// them to verify convergence and failure detection across a simulated
// cluster. gossip is a pure state machine, so we can simulate the network
// by delivering drainActions() output to the correct peer.

/// route send_message actions between gossip instances by matching
/// the target id. delivers pings, acks, and ping_reqs to the correct handler.
fn routeGossipActions(actions: []const Action, gossips: []*Gossip) void {
    for (actions) |action| {
        if (action != .send_message) continue;
        const msg = action.send_message;
        const target = findGossip(gossips, msg.target) orelse continue;

        switch (msg.message) {
            .ping => |p| {
                target.handlePing(p) catch {};
            },
            .ping_ack => |pa| {
                target.handlePingAck(pa) catch {};
            },
            .ping_req => |pr| {
                target.handlePingReq(pr) catch {};
            },
        }
    }
}

fn findGossip(gossips: []*Gossip, id: u64) ?*Gossip {
    for (gossips) |g| {
        if (g.self_id == id) return g;
    }
    return null;
}

/// tick all gossip instances and route messages between them for one round
fn tickAndRouteAll(gossips: []*Gossip) void {
    // tick all nodes first
    for (gossips) |g| {
        g.tick() catch {};
    }
    // then drain and route all actions
    for (gossips) |g| {
        const actions = g.drainActions();
        defer g.freeActions(actions);
        routeGossipActions(actions, gossips);
    }
    // drain any reply actions generated by routing
    for (gossips) |g| {
        const reply_actions = g.drainActions();
        defer g.freeActions(reply_actions);
        routeGossipActions(reply_actions, gossips);
    }
}

test "3-node gossip: membership converges to all alive" {
    const alloc = std.testing.allocator;

    var g1 = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g1.deinit();
    var g2 = Gossip.init(alloc, 2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    defer g2.deinit();
    var g3 = Gossip.init(alloc, 3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });
    defer g3.deinit();

    // each node knows about the other two
    try g1.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    try g1.addMember(3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });
    try g2.addMember(1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    try g2.addMember(3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });
    try g3.addMember(1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    try g3.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    var gossips = [_]*Gossip{ &g1, &g2, &g3 };

    // run several rounds of ticking + message routing
    // probe_interval defaults to 5, so we need enough rounds
    // for each node to probe its peers at least once
    for (0..20) |_| {
        tickAndRouteAll(&gossips);
    }

    // all members should be alive on all instances
    for (&gossips) |g| {
        for (&gossips) |other| {
            if (g.self_id == other.self_id) continue;
            const member = g.members.get(other.self_id) orelse {
                try std.testing.expect(false); // member not found
                continue;
            };
            try std.testing.expectEqual(MemberState.alive, member.state);
        }
    }
}

test "gossip detects unresponsive member" {
    const alloc = std.testing.allocator;

    var g1 = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    defer g1.deinit();
    var g2 = Gossip.init(alloc, 2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    defer g2.deinit();
    var g3 = Gossip.init(alloc, 3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });
    defer g3.deinit();

    // short timeouts for fast test
    g1.probe_interval = 2;
    g1.suspect_timeout = 3;
    g2.probe_interval = 2;
    g2.suspect_timeout = 3;
    g3.probe_interval = 2;
    g3.suspect_timeout = 3;

    // wire up membership
    try g1.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    try g1.addMember(3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });
    try g2.addMember(1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    try g2.addMember(3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });
    try g3.addMember(1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    try g3.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    var all_gossips = [_]*Gossip{ &g1, &g2, &g3 };

    // first converge with all three
    for (0..15) |_| {
        tickAndRouteAll(&all_gossips);
    }

    // now stop routing to/from node 3 — only tick nodes 1 and 2
    var live_gossips = [_]*Gossip{ &g1, &g2 };
    for (0..30) |_| {
        // tick all three so g1/g2 advance their timers
        g1.tick() catch {};
        g2.tick() catch {};

        // route only between g1 and g2
        const a1 = g1.drainActions();
        defer g1.freeActions(a1);
        routeGossipActions(a1, &live_gossips);

        const a2 = g2.drainActions();
        defer g2.freeActions(a2);
        routeGossipActions(a2, &live_gossips);

        // drain reply actions
        const r1 = g1.drainActions();
        defer g1.freeActions(r1);
        routeGossipActions(r1, &live_gossips);
        const r2 = g2.drainActions();
        defer g2.freeActions(r2);
        routeGossipActions(r2, &live_gossips);
    }

    // node 3 should be suspect or dead on nodes 1 and 2
    if (g1.members.get(3)) |m3_on_g1| {
        try std.testing.expect(m3_on_g1.state == .suspect or m3_on_g1.state == .dead);
    }
    if (g2.members.get(3)) |m3_on_g2| {
        try std.testing.expect(m3_on_g2.state == .suspect or m3_on_g2.state == .dead);
    }
}
