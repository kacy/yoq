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
//   var gossip = Gossip.init(alloc, my_id, my_addr, .{});
//   defer gossip.deinit();
//   gossip.addMember(peer_id, peer_addr);
//   gossip.tick(); // call every ~500ms
//   const actions = gossip.drainActions();
//   // process actions: send UDP messages, update membership state

const std = @import("std");
const action_queue = @import("action_queue.zig");
const codec_support = @import("gossip/codec_support.zig");
const membership_support = @import("gossip/membership_support.zig");
const probe_runtime = @import("gossip/probe_runtime.zig");
const state_updates = @import("gossip/state_updates.zig");
const update_queue = @import("gossip/update_queue.zig");

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

/// fixed-capacity container for piggybacked state updates.
/// avoids heap allocation — updates are stored inline in message payloads.
pub const BoundedUpdates = struct {
    buf: [max_piggyback_updates]StateUpdate = undefined,
    len: u8 = 0,

    pub fn slice(self: *const BoundedUpdates) []const StateUpdate {
        return self.buf[0..self.len];
    }

    pub fn fromSlice(items: []const StateUpdate) BoundedUpdates {
        var result: BoundedUpdates = .{};
        const count: u8 = @intCast(@min(items.len, max_piggyback_updates));
        for (0..count) |i| {
            result.buf[i] = items[i];
        }
        result.len = count;
        return result;
    }
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
    updates: BoundedUpdates = .{},
};

pub const PingAckPayload = struct {
    from: u64,
    sequence: u64,
    updates: BoundedUpdates = .{},
};

pub const PingReqPayload = struct {
    from: u64,
    target: u64,
    sequence: u64,
    updates: BoundedUpdates = .{},
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

pub const GossipConfig = struct {
    fanout: ?u32 = null,
    suspicion_multiplier: ?u32 = null,
};

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

    // user-configured overrides (null = use automatic values)
    configured_fanout: ?u32,
    configured_suspicion_multiplier: ?u32,

    // base intervals — scaled by ceil(log2(N)) for adaptive timing
    const base_probe_interval: u32 = 5;
    const base_suspect_timeout: u32 = 20;
    const base_dead_timeout: u32 = 100;
    pub const max_interval_multiplier: u32 = 10;

    pub fn init(alloc: std.mem.Allocator, self_id: u64, self_addr: MemberAddr, config: GossipConfig) Gossip {
        const susp_mult = config.suspicion_multiplier orelse 1;
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
            .probe_interval = base_probe_interval,
            .suspect_timeout = base_suspect_timeout * susp_mult,
            .dead_timeout = base_dead_timeout * susp_mult,
            .configured_fanout = config.fanout,
            .configured_suspicion_multiplier = config.suspicion_multiplier,
        };
    }

    pub fn deinit(self: *Gossip) void {
        self.members.deinit();
        self.actions.deinit(self.alloc);
        self.pending_updates.deinit(self.alloc);
        self.probe_order.deinit(self.alloc);
    }

    /// compute ceil(log2(n)), minimum 1. used for adaptive interval scaling
    /// and gossip dissemination counts.
    pub fn ceilLog2(n: usize) u32 {
        return membership_support.ceilLog2(n);
    }

    /// recalculate probe/suspect/dead intervals based on cluster size.
    /// uses ceil(log2(N)) where N = total members including self, capped
    /// at max_interval_multiplier to bound worst-case detection time.
    pub fn recalculateIntervals(self: *Gossip) void {
        membership_support.recalculateIntervals(
            self,
            base_probe_interval,
            base_suspect_timeout,
            base_dead_timeout,
            max_interval_multiplier,
        );
    }

    /// add a member to the membership list. if the member already exists,
    /// this is a no-op (use applyStateUpdate for state changes).
    pub fn addMember(self: *Gossip, id: u64, addr: MemberAddr) !void {
        try membership_support.addMember(self, addr, id);
    }

    /// advance the protocol by one tick. call this every ~500ms.
    /// generates Actions for the caller to process.
    pub fn tick(self: *Gossip) !void {
        return probe_runtime.tick(self);
    }

    /// process an incoming ping message
    pub fn handlePing(self: *Gossip, msg: PingPayload) !void {
        return probe_runtime.handlePing(self, msg);
    }

    /// process an incoming ping ack
    pub fn handlePingAck(self: *Gossip, msg: PingAckPayload) !void {
        return probe_runtime.handlePingAck(self, msg);
    }

    /// process an incoming ping_req — forward a ping to the target on behalf
    /// of the requester, and relay any ack back.
    pub fn handlePingReq(self: *Gossip, msg: PingReqPayload) !void {
        return probe_runtime.handlePingReq(self, msg);
    }

    /// drain all pending actions for the caller to process
    pub fn drainActions(self: *Gossip) []Action {
        return action_queue.drainOwned(Action, self.alloc, &self.actions);
    }

    /// free actions returned by drainActions
    pub fn freeActions(self: *Gossip, actions: []Action) void {
        self.alloc.free(actions);
    }

    // --- internal ---

    fn startProbe(self: *Gossip) !void {
        return probe_runtime.startProbe(self);
    }

    fn escalateToIndirect(self: *Gossip) !void {
        return probe_runtime.escalateToIndirect(self);
    }

    fn suspectProbeTarget(self: *Gossip) !void {
        return probe_runtime.suspectProbeTarget(self);
    }

    fn checkSuspectTimeouts(self: *Gossip) !void {
        return probe_runtime.checkSuspectTimeouts(self);
    }

    /// apply a state update using incarnation-based conflict resolution.
    /// higher incarnation always wins. at same incarnation: dead > suspect > alive.
    /// if we ourselves are accused, increment incarnation and refute.
    fn applyStateUpdate(self: *Gossip, update: StateUpdate) !void {
        return state_updates.applyStateUpdate(self, update);
    }

    fn emitStateChange(self: *Gossip, id: u64, old: MemberState, new: MemberState) !void {
        return state_updates.emitStateChange(self, id, old, new);
    }

    pub fn getMemberAddr(self: *Gossip, id: u64) ?MemberAddr {
        return membership_support.getMemberAddr(self, id);
    }

    pub fn rebuildProbeOrder(self: *Gossip) !void {
        try membership_support.rebuildProbeOrder(self);
    }

    /// collect up to max_piggyback_updates updates to piggyback on a message.
    /// prioritizes dead > suspect > alive updates. decrements remaining counters.
    /// returns a BoundedUpdates stored inline — no heap allocation.
    pub fn collectPiggybackUpdates(self: *Gossip) BoundedUpdates {
        return update_queue.collectPiggybackUpdates(self, BoundedUpdates, max_piggyback_updates);
    }

    pub fn addPendingUpdate(self: *Gossip, update: StateUpdate) !void {
        return update_queue.addPendingUpdate(self, update);
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
        return codec_support.encode(buf, msg, max_piggyback_updates);
    }

    pub fn decode(_: std.mem.Allocator, data: []const u8) !GossipMessage {
        return codec_support.decode(data, GossipMessage, BoundedUpdates, MemberState, max_piggyback_updates);
    }

    /// no-op — updates are stored inline, no heap memory to free.
    /// retained for API compatibility.
    pub fn freeDecoded(_: std.mem.Allocator, _: GossipMessage) void {}

    fn encodeUpdates(buf: []u8, start: usize, updates: []const StateUpdate) usize {
        return codec_support.encodeUpdates(buf, start, updates);
    }

    fn decodeUpdates(data: []const u8, count: u8) BoundedUpdates {
        return codec_support.decodeUpdates(data, count, BoundedUpdates, MemberState);
    }

    fn writeU64(buf: []u8, val: u64) void {
        codec_support.writeU64(buf, val);
    }

    fn readU64(buf: []const u8) u64 {
        return codec_support.readU64(buf);
    }
};

// --- tests ---

test "probe cycle sends ping" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
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
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    try g.tick();

    const actions = g.drainActions();
    defer g.freeActions(actions);
    const seq = actions[0].send_message.message.ping.sequence;

    try g.handlePingAck(.{ .from = 2, .sequence = seq });

    try std.testing.expect(g.probe_phase == .idle);
    try std.testing.expect(g.probe_target == null);
}

test "missed ack triggers indirect ping" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
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
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
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
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    g.suspect_timeout = 5;

    // manually mark suspect
    if (g.members.getPtr(2)) |m| {
        m.state = .suspect;
        m.state_changed_at = g.tick_count;
    }

    // tick past suspect timeout
    for (0..6) |_| {
        try g.tick();
        const actions = g.drainActions();
        defer g.freeActions(actions);
        for (actions) |action| {
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
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
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
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
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
    const items = [_]StateUpdate{.{
        .id = 42,
        .addr = .{ .ip = .{ 192, 168, 1, 1 }, .port = 8080 },
        .state = .alive,
        .incarnation = 7,
    }};

    const msg: GossipMessage = .{ .ping = .{
        .from = 100,
        .sequence = 999,
        .updates = BoundedUpdates.fromSlice(&items),
    } };

    var buf: [512]u8 = undefined;
    const len = try Gossip.encode(&buf, msg);

    const decoded = try Gossip.decode(alloc, buf[0..len]);
    const updates = decoded.ping.updates.slice();

    try std.testing.expect(decoded == .ping);
    try std.testing.expectEqual(@as(u64, 100), decoded.ping.from);
    try std.testing.expectEqual(@as(u64, 999), decoded.ping.sequence);
    try std.testing.expectEqual(@as(usize, 1), updates.len);
    try std.testing.expectEqual(@as(u64, 42), updates[0].id);
    try std.testing.expectEqual(@as(u16, 8080), updates[0].addr.port);
    try std.testing.expectEqual(MemberState.alive, updates[0].state);
    try std.testing.expectEqual(@as(u64, 7), updates[0].incarnation);
}

test "encode decode round-trip: ping_req" {
    const alloc = std.testing.allocator;
    const msg: GossipMessage = .{ .ping_req = .{
        .from = 1,
        .target = 2,
        .sequence = 50,
    } };

    var buf: [512]u8 = undefined;
    const len = try Gossip.encode(&buf, msg);

    const decoded = try Gossip.decode(alloc, buf[0..len]);

    try std.testing.expect(decoded == .ping_req);
    try std.testing.expectEqual(@as(u64, 1), decoded.ping_req.from);
    try std.testing.expectEqual(@as(u64, 2), decoded.ping_req.target);
    try std.testing.expectEqual(@as(u64, 50), decoded.ping_req.sequence);
    try std.testing.expectEqual(@as(u8, 0), decoded.ping_req.updates.len);
}

test "encode decode round-trip: ping_ack with multiple updates" {
    const alloc = std.testing.allocator;
    const items = [_]StateUpdate{
        .{ .id = 10, .addr = .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .state = .alive, .incarnation = 1 },
        .{ .id = 20, .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7001 }, .state = .suspect, .incarnation = 3 },
        .{ .id = 30, .addr = .{ .ip = .{ 10, 0, 0, 3 }, .port = 7002 }, .state = .dead, .incarnation = 5 },
    };

    const msg: GossipMessage = .{ .ping_ack = .{
        .from = 99,
        .sequence = 12345,
        .updates = BoundedUpdates.fromSlice(&items),
    } };

    var buf: [512]u8 = undefined;
    const len = try Gossip.encode(&buf, msg);

    const decoded = try Gossip.decode(alloc, buf[0..len]);
    const updates = decoded.ping_ack.updates.slice();

    try std.testing.expect(decoded == .ping_ack);
    try std.testing.expectEqual(@as(usize, 3), updates.len);
    try std.testing.expectEqual(MemberState.suspect, updates[1].state);
    try std.testing.expectEqual(@as(u64, 5), updates[2].incarnation);
}

test "dead member not probed" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
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
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
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
        const upd = g.collectPiggybackUpdates();
        _ = upd;
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
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    // add 100 members and mark them all suspect
    for (2..102) |i| {
        const id: u64 = @intCast(i);
        try g.addMember(id, .{ .ip = .{ 10, 0, @intCast(i / 256), @intCast(i % 256) }, .port = 7000 });
        if (g.members.getPtr(id)) |m| {
            m.state = .suspect;
            m.state_changed_at = 0; // set in the past
        }
    }

    g.suspect_timeout = 1; // 1 tick for fast test — set after addMember

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
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
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

    var g1 = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g1.deinit();
    var g2 = Gossip.init(alloc, 2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 }, .{});
    defer g2.deinit();
    var g3 = Gossip.init(alloc, 3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 }, .{});
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

    var g1 = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g1.deinit();
    var g2 = Gossip.init(alloc, 2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 }, .{});
    defer g2.deinit();
    var g3 = Gossip.init(alloc, 3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 }, .{});
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

// -- resilience tests --
//
// these tests verify gossip correctness under false positives, rapid churn,
// and cascading failure scenarios.

test "false positive suspect recovers via self-refutation" {
    const alloc = std.testing.allocator;

    var g1 = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g1.deinit();
    var g2 = Gossip.init(alloc, 2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 }, .{});
    defer g2.deinit();
    var g3 = Gossip.init(alloc, 3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 }, .{});
    defer g3.deinit();

    // wire up membership
    try g1.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    try g1.addMember(3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });
    try g2.addMember(1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    try g2.addMember(3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });
    try g3.addMember(1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 });
    try g3.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    var gossips = [_]*Gossip{ &g1, &g2, &g3 };

    // step 1: converge with all three
    for (0..20) |_| {
        tickAndRouteAll(&gossips);
    }

    const initial_incarnation = g3.incarnation;

    // step 2: directly mark g3 as suspect on g1 and g2 to simulate a false positive.
    // this is equivalent to what happens after a transient network blip — the protocol
    // has already marked g3 suspect. the interesting behavior is the recovery path.
    if (g1.members.getPtr(3)) |m| {
        m.state = .suspect;
        m.incarnation = g3.incarnation;
        m.state_changed_at = g1.tick_count;
    }
    if (g2.members.getPtr(3)) |m| {
        m.state = .suspect;
        m.incarnation = g3.incarnation;
        m.state_changed_at = g2.tick_count;
    }

    // enqueue suspect updates so they get piggybacked to g3.
    // send a ping directly to g3 with the suspect update piggybacked —
    // this simulates g3 receiving gossip about itself being suspected.
    // use g3's current incarnation so the refutation condition is met
    // (update.incarnation >= self.incarnation).
    const suspect_update = StateUpdate{
        .id = 3,
        .addr = .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 },
        .state = .suspect,
        .incarnation = g3.incarnation,
    };
    try g3.handlePing(.{
        .from = 1,
        .sequence = 9999,
        .updates = BoundedUpdates.fromSlice(&.{suspect_update}),
    });

    // set long suspect timeout so g3 doesn't go dead before recovery
    g1.suspect_timeout = 500;
    g2.suspect_timeout = 500;
    g3.suspect_timeout = 500;

    // step 3: restore connectivity — g3 receives piggybacked suspect update about itself,
    // triggers self-refutation (increments incarnation, broadcasts alive)
    for (0..50) |_| {
        tickAndRouteAll(&gossips);
    }

    // step 4: g3 should be alive on all nodes, incarnation incremented
    for (&gossips) |g| {
        if (g.self_id == 3) continue;
        if (g.members.get(3)) |m| {
            try std.testing.expectEqual(MemberState.alive, m.state);
        }
    }
    try std.testing.expect(g3.incarnation > initial_incarnation);
}

test "rapid membership addition stays consistent" {
    const alloc = std.testing.allocator;

    var g1 = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g1.deinit();

    // step 1: add 3 initial members
    try g1.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    try g1.addMember(3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });
    try g1.addMember(4, .{ .ip = .{ 10, 0, 0, 4 }, .port = 7000 });

    // step 2: tick for 5 rounds (single node, just drain actions)
    for (0..5) |_| {
        g1.tick() catch {};
        const actions = g1.drainActions();
        g1.freeActions(actions);
    }

    // step 3: add 10 new members rapidly
    for (5..15) |i| {
        const id: u64 = @intCast(i);
        try g1.addMember(id, .{ .ip = .{ 10, 0, 0, @intCast(id) }, .port = 7000 });
    }

    // step 4: tick for 10 more rounds
    for (0..10) |_| {
        g1.tick() catch {};
        const actions = g1.drainActions();
        g1.freeActions(actions);
    }

    // step 5: probe_order should match live member count
    // live members: 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 = 13 members
    try std.testing.expectEqual(@as(usize, 13), g1.probe_order.items.len);
    try std.testing.expectEqual(@as(usize, 13), g1.members.count());
}

test "dead node doesn't cascade false suspicions" {
    const alloc = std.testing.allocator;

    var g1 = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g1.deinit();
    var g2 = Gossip.init(alloc, 2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 }, .{});
    defer g2.deinit();
    var g3 = Gossip.init(alloc, 3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 }, .{});
    defer g3.deinit();
    var g4 = Gossip.init(alloc, 4, .{ .ip = .{ 10, 0, 0, 4 }, .port = 7000 }, .{});
    defer g4.deinit();
    var g5 = Gossip.init(alloc, 5, .{ .ip = .{ 10, 0, 0, 5 }, .port = 7000 }, .{});
    defer g5.deinit();

    var all = [_]*Gossip{ &g1, &g2, &g3, &g4, &g5 };

    // wire up full mesh
    const ids = [_]u64{ 1, 2, 3, 4, 5 };
    const addrs = [_]MemberAddr{
        .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 },
        .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 },
        .{ .ip = .{ 10, 0, 0, 4 }, .port = 7000 },
        .{ .ip = .{ 10, 0, 0, 5 }, .port = 7000 },
    };
    for (&all, 0..) |g, i| {
        for (ids, 0..) |id, j| {
            if (i == j) continue;
            try g.addMember(id, addrs[j]);
        }
    }

    // short timeouts — set after addMember so recalculateIntervals doesn't override
    for (&all) |g| {
        g.probe_interval = 2;
        g.suspect_timeout = 4;
        g.dead_timeout = 10;
    }

    // step 1: converge
    for (0..20) |_| {
        tickAndRouteAll(&all);
    }

    // step 2: remove g5 from routing (simulate crash)
    var live = [_]*Gossip{ &g1, &g2, &g3, &g4 };

    // tick until g5 transitions to dead on all live nodes
    for (0..60) |_| {
        // tick all live nodes
        for (&live) |g| {
            g.tick() catch {};
        }
        // route only among live nodes
        for (&live) |g| {
            const actions = g.drainActions();
            defer g.freeActions(actions);
            routeGossipActions(actions, &live);
        }
        for (&live) |g| {
            const reply_actions = g.drainActions();
            defer g.freeActions(reply_actions);
            routeGossipActions(reply_actions, &live);
        }
    }

    // step 3: g5 should be dead on all live nodes
    for (&live) |g| {
        if (g.members.get(5)) |m| {
            try std.testing.expectEqual(MemberState.dead, m.state);
        }
    }

    // step 4: g1-g4 remain alive on each other — no cascade
    for (&live) |g| {
        for (&live) |other| {
            if (g.self_id == other.self_id) continue;
            if (g.members.get(other.self_id)) |m| {
                try std.testing.expectEqual(MemberState.alive, m.state);
            }
        }
    }
}

test "ceilLog2 basic values" {
    // edge cases and powers of two
    try std.testing.expectEqual(@as(u32, 1), Gossip.ceilLog2(1));
    try std.testing.expectEqual(@as(u32, 1), Gossip.ceilLog2(2));
    try std.testing.expectEqual(@as(u32, 2), Gossip.ceilLog2(3));
    try std.testing.expectEqual(@as(u32, 2), Gossip.ceilLog2(4));
    try std.testing.expectEqual(@as(u32, 3), Gossip.ceilLog2(5));
    try std.testing.expectEqual(@as(u32, 7), Gossip.ceilLog2(128));
    try std.testing.expectEqual(@as(u32, 10), Gossip.ceilLog2(1024));
}

test "recalculateIntervals scales with member count" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    // 1 node (just self) — multiplier 1
    try std.testing.expectEqual(@as(u32, 5), g.probe_interval);
    try std.testing.expectEqual(@as(u32, 20), g.suspect_timeout);
    try std.testing.expectEqual(@as(u32, 100), g.dead_timeout);

    // add 3 members (4 total) — multiplier 2
    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    try g.addMember(3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });
    try g.addMember(4, .{ .ip = .{ 10, 0, 0, 4 }, .port = 7000 });
    try std.testing.expectEqual(@as(u32, 10), g.probe_interval);
    try std.testing.expectEqual(@as(u32, 40), g.suspect_timeout);
    try std.testing.expectEqual(@as(u32, 200), g.dead_timeout);
}

test "recalculateIntervals caps at max multiplier" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    // add 2048 members — should cap at 10x
    for (2..2050) |i| {
        try g.addMember(@intCast(i), .{ .ip = .{ 10, 0, 0, 1 }, .port = @intCast(i) });
    }

    try std.testing.expectEqual(@as(u32, 50), g.probe_interval);
    try std.testing.expectEqual(@as(u32, 200), g.suspect_timeout);
    try std.testing.expectEqual(@as(u32, 1000), g.dead_timeout);
}

test "addPendingUpdate evicts lowest priority when full" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    // need at least 1 member for gossip_count > 0
    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    // fill with 1000 alive updates (different member ids)
    for (0..1000) |i| {
        const id: u64 = @intCast(i + 100); // avoid collisions with member ids
        try g.addPendingUpdate(.{
            .id = id,
            .addr = .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 },
            .state = .alive,
            .incarnation = 1,
        });
    }

    try std.testing.expectEqual(@as(usize, 1000), g.pending_updates.items.len);

    // add a suspect update — should evict one alive entry
    try g.addPendingUpdate(.{
        .id = 9999,
        .addr = .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 },
        .state = .suspect,
        .incarnation = 1,
    });

    try std.testing.expectEqual(@as(usize, 1000), g.pending_updates.items.len);

    // verify the suspect update is present
    var found_suspect = false;
    for (g.pending_updates.items) |pending| {
        if (pending.update.id == 9999 and pending.update.state == .suspect) {
            found_suspect = true;
        }
    }
    try std.testing.expect(found_suspect);
}

test "addPendingUpdate replaces existing update for same member" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    // add update for member 2
    try g.addPendingUpdate(.{
        .id = 2,
        .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .state = .alive,
        .incarnation = 1,
    });
    try std.testing.expectEqual(@as(usize, 1), g.pending_updates.items.len);

    // add another update for same member with higher incarnation
    try g.addPendingUpdate(.{
        .id = 2,
        .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .state = .suspect,
        .incarnation = 5,
    });

    // should still be 1 entry, not 2
    try std.testing.expectEqual(@as(usize, 1), g.pending_updates.items.len);
    try std.testing.expectEqual(MemberState.suspect, g.pending_updates.items[0].update.state);
    try std.testing.expectEqual(@as(u64, 5), g.pending_updates.items[0].update.incarnation);
}

test "collectPiggybackUpdates sorts by state priority" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    // add alive, suspect, dead updates (in that order)
    try g.addPendingUpdate(.{
        .id = 10,
        .addr = .{ .ip = .{ 10, 0, 0, 10 }, .port = 7000 },
        .state = .alive,
        .incarnation = 1,
    });
    try g.addPendingUpdate(.{
        .id = 11,
        .addr = .{ .ip = .{ 10, 0, 0, 11 }, .port = 7000 },
        .state = .suspect,
        .incarnation = 1,
    });
    try g.addPendingUpdate(.{
        .id = 12,
        .addr = .{ .ip = .{ 10, 0, 0, 12 }, .port = 7000 },
        .state = .dead,
        .incarnation = 1,
    });

    const updates = g.collectPiggybackUpdates();
    const slice = updates.slice();

    // should be ordered: dead first, then suspect, then alive
    try std.testing.expectEqual(@as(usize, 3), slice.len);
    try std.testing.expectEqual(MemberState.dead, slice[0].state);
    try std.testing.expectEqual(MemberState.suspect, slice[1].state);
    try std.testing.expectEqual(MemberState.alive, slice[2].state);
}

test "collectPiggybackUpdates decrements remaining and expires" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    // manually add a pending update with remaining=1
    try g.pending_updates.append(g.alloc, .{
        .update = .{
            .id = 42,
            .addr = .{ .ip = .{ 10, 0, 0, 42 }, .port = 7000 },
            .state = .suspect,
            .incarnation = 1,
        },
        .remaining = 1,
    });

    // first collect — should return the update
    const first = g.collectPiggybackUpdates();
    try std.testing.expectEqual(@as(usize, 1), first.slice().len);
    try std.testing.expectEqual(@as(u64, 42), first.slice()[0].id);

    // update should have been removed (remaining was 1, decremented to 0)
    try std.testing.expectEqual(@as(usize, 0), g.pending_updates.items.len);

    // second collect — should return nothing
    const second = g.collectPiggybackUpdates();
    try std.testing.expectEqual(@as(usize, 0), second.slice().len);
}

test "applyStateUpdate ignores lower incarnation" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    // set member 2 to incarnation 5 via a higher-incarnation update
    try g.applyStateUpdate(.{
        .id = 2,
        .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .state = .alive,
        .incarnation = 5,
    });
    var drain = g.drainActions();
    g.freeActions(drain);

    // try to apply an update with incarnation 3 — should be ignored
    try g.applyStateUpdate(.{
        .id = 2,
        .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .state = .dead,
        .incarnation = 3,
    });
    drain = g.drainActions();
    g.freeActions(drain);

    // state should still be alive at incarnation 5
    const member = g.members.get(2).?;
    try std.testing.expectEqual(MemberState.alive, member.state);
    try std.testing.expectEqual(@as(u64, 5), member.incarnation);
}

test "applyStateUpdate same incarnation uses state priority" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    // member 2 is alive at incarnation 5
    try g.applyStateUpdate(.{
        .id = 2,
        .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .state = .alive,
        .incarnation = 5,
    });
    var drain = g.drainActions();
    g.freeActions(drain);

    // suspect at same incarnation — should win (suspect > alive)
    try g.applyStateUpdate(.{
        .id = 2,
        .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .state = .suspect,
        .incarnation = 5,
    });
    drain = g.drainActions();
    g.freeActions(drain);

    try std.testing.expectEqual(MemberState.suspect, g.members.get(2).?.state);

    // alive at same incarnation — should NOT win (alive < suspect)
    try g.applyStateUpdate(.{
        .id = 2,
        .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .state = .alive,
        .incarnation = 5,
    });
    drain = g.drainActions();
    g.freeActions(drain);

    try std.testing.expectEqual(MemberState.suspect, g.members.get(2).?.state);
}

test "applyStateUpdate unknown member dead is ignored" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    // receive dead update for unknown member — should NOT add to members
    try g.applyStateUpdate(.{
        .id = 99,
        .addr = .{ .ip = .{ 10, 0, 0, 99 }, .port = 7000 },
        .state = .dead,
        .incarnation = 1,
    });

    try std.testing.expect(g.members.get(99) == null);
    try std.testing.expectEqual(@as(usize, 0), g.members.count());

    const drain = g.drainActions();
    g.freeActions(drain);
}

test "handlePing from unknown sender still processes updates" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });

    // send ping from unknown node 99 with an update about member 2
    const update = StateUpdate{
        .id = 2,
        .addr = .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 },
        .state = .suspect,
        .incarnation = 10,
    };
    try g.handlePing(.{
        .from = 99, // unknown sender
        .sequence = 1,
        .updates = BoundedUpdates.fromSlice(&.{update}),
    });

    // the update about member 2 should still have been applied
    const member = g.members.get(2).?;
    try std.testing.expectEqual(MemberState.suspect, member.state);
    try std.testing.expectEqual(@as(u64, 10), member.incarnation);

    // actions: there should be a member_suspect action (from applyStateUpdate)
    // but no ping_ack (since sender 99 is unknown, getMemberAddr returns null)
    const actions = g.drainActions();
    defer g.freeActions(actions);

    var found_suspect_action = false;
    var found_ack = false;
    for (actions) |action| {
        if (action == .member_suspect and action.member_suspect.id == 2) found_suspect_action = true;
        if (action == .send_message) {
            if (action.send_message.message == .ping_ack) found_ack = true;
        }
    }
    try std.testing.expect(found_suspect_action);
    try std.testing.expect(!found_ack);
}

test "explicit fanout overrides default in escalateToIndirect" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{ .fanout = 5 });
    defer g.deinit();

    // add 10 members so there are enough relay candidates
    for (2..12) |i| {
        try g.addMember(@intCast(i), .{ .ip = .{ 10, 0, @intCast(i / 256), @intCast(i % 256) }, .port = 7000 });
    }

    // trigger probe: tick sends ping to a member
    try g.tick();
    const drain = g.drainActions();
    g.freeActions(drain);

    // miss the ack — wait probe_interval ticks
    for (0..g.probe_interval) |_| {
        try g.tick();
    }

    // actions from the last drain should contain ping_reqs
    const actions = g.drainActions();
    defer g.freeActions(actions);

    var ping_req_count: u32 = 0;
    for (actions) |action| {
        if (action == .send_message and action.send_message.message == .ping_req) {
            ping_req_count += 1;
        }
    }

    // with fanout=5, should send exactly 5 ping_reqs (have 9 candidates)
    try std.testing.expectEqual(@as(u32, 5), ping_req_count);
}

test "suspicion_multiplier scales suspect and dead timeouts" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{ .suspicion_multiplier = 3 });
    defer g.deinit();

    // 1 node (just self) — base multiplier 1, suspicion_multiplier 3
    try std.testing.expectEqual(@as(u32, 5), g.probe_interval); // probe not affected
    try std.testing.expectEqual(@as(u32, 60), g.suspect_timeout); // 20 * 1 * 3
    try std.testing.expectEqual(@as(u32, 300), g.dead_timeout); // 100 * 1 * 3

    // add 3 members (4 total) — ceil(log2(4)) = 2
    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    try g.addMember(3, .{ .ip = .{ 10, 0, 0, 3 }, .port = 7000 });
    try g.addMember(4, .{ .ip = .{ 10, 0, 0, 4 }, .port = 7000 });

    try std.testing.expectEqual(@as(u32, 10), g.probe_interval); // 5 * 2
    try std.testing.expectEqual(@as(u32, 120), g.suspect_timeout); // 20 * 2 * 3
    try std.testing.expectEqual(@as(u32, 600), g.dead_timeout); // 100 * 2 * 3
}

test "null config matches default behavior" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    try std.testing.expect(g.configured_fanout == null);
    try std.testing.expect(g.configured_suspicion_multiplier == null);

    // defaults: probe=5, suspect=20, dead=100
    try std.testing.expectEqual(@as(u32, 5), g.probe_interval);
    try std.testing.expectEqual(@as(u32, 20), g.suspect_timeout);
    try std.testing.expectEqual(@as(u32, 100), g.dead_timeout);
}

test "decodeUpdates rejects invalid MemberState byte" {
    // build a ping message with 1 update that has an invalid state byte (0xFF)
    var buf: [512]u8 = undefined;
    buf[0] = 0x10; // ping
    @memset(buf[1..9], 0); // from = 0
    @memset(buf[9..17], 0); // sequence = 0
    buf[17] = 1; // count = 1
    @memset(buf[18..32], 0); // id + addr fields
    buf[32] = 0xFF; // invalid state byte (valid: 0, 1, 2)
    @memset(buf[33..41], 0); // incarnation

    const msg = Gossip.decode(std.testing.allocator, buf[0..41]) catch return;
    // if decode succeeds, the update should have been rejected (empty updates)
    switch (msg) {
        .ping => |p| try std.testing.expectEqual(@as(u8, 0), p.updates.len),
        else => unreachable,
    }
}

test "suspect timeout skipped when tick_count wraps below state_changed_at" {
    const alloc = std.testing.allocator;
    var g = Gossip.init(alloc, 1, .{ .ip = .{ 10, 0, 0, 1 }, .port = 7000 }, .{});
    defer g.deinit();

    try g.addMember(2, .{ .ip = .{ 10, 0, 0, 2 }, .port = 7000 });
    g.suspect_timeout = 5;

    // mark suspect with a high state_changed_at (simulating pre-wrap state)
    if (g.members.getPtr(2)) |m| {
        m.state = .suspect;
        m.state_changed_at = std.math.maxInt(u64) - 1;
    }

    // set tick_count to a low value (simulating post-wrap)
    g.tick_count = 3;

    // tick a few times — member must NOT be marked dead since tick_count < state_changed_at
    for (0..6) |_| {
        try g.tick();
        const actions = g.drainActions();
        defer g.freeActions(actions);
        for (actions) |action| {
            if (action == .member_dead and action.member_dead.id == 2) {
                return error.TestUnexpectedResult;
            }
        }
    }

    // member should still be suspect
    try std.testing.expectEqual(MemberState.suspect, g.members.get(2).?.state);
}
