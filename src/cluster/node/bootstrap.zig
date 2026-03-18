const std = @import("std");
const logger = @import("../../lib/log.zig");
const gossip_mod = @import("../gossip.zig");

const StartError = error{
    InitFailed,
    AlreadyStarted,
};

pub fn raftDbPath(buf: []u8, data_dir: []const u8) ?[:0]const u8 {
    return bufPrintZ(buf, "{s}/raft.db", .{data_dir});
}

pub fn stateDbPath(buf: []u8, data_dir: []const u8) ?[:0]const u8 {
    return bufPrintZ(buf, "{s}/state.db", .{data_dir});
}

pub fn snapshotPath(buf: []u8, data_dir: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, "{s}/snapshot.dat", .{data_dir}) catch null;
}

pub fn initGossip(alloc: std.mem.Allocator, config: anytype, transport: anytype) ?*gossip_mod.Gossip {
    const gossip_port: u16 = if (config.gossip_port != 0) config.gossip_port else config.port +| 100;
    const gossip_state = alloc.create(gossip_mod.Gossip) catch return null;
    gossip_state.* = gossip_mod.Gossip.init(alloc, config.id, .{ .ip = .{ 0, 0, 0, 0 }, .port = gossip_port }, .{
        .fanout = config.gossip_fanout,
        .suspicion_multiplier = config.gossip_suspicion_multiplier,
    });

    transport.initUdp(gossip_port) catch {
        logger.warn("gossip: failed to bind UDP port {}, running without gossip", .{gossip_port});
        gossip_state.deinit();
        alloc.destroy(gossip_state);
        return null;
    };

    logger.info("gossip: initialized on UDP port {}", .{gossip_port});
    return gossip_state;
}

pub fn start(self: anytype) StartError!void {
    if (self.running.load(.acquire)) return StartError.AlreadyStarted;
    self.running.store(true, .release);
    self.raft.log = &self.log;

    self.tick_thread = std.Thread.spawn(.{}, @TypeOf(self.*).tickLoop, .{self}) catch {
        self.running.store(false, .release);
        return StartError.InitFailed;
    };
    errdefer {
        self.running.store(false, .release);
        if (self.tick_thread) |thread| {
            thread.join();
            self.tick_thread = null;
        }
    }

    self.recv_thread = std.Thread.spawn(.{}, @TypeOf(self.*).recvLoop, .{self}) catch {
        return StartError.InitFailed;
    };
}

fn bufPrintZ(buf: []u8, comptime fmt: []const u8, args: anytype) ?[:0]const u8 {
    const slice = std.fmt.bufPrint(buf, fmt, args) catch return null;
    if (slice.len >= buf.len) return null;
    buf[slice.len] = 0;
    return buf[0..slice.len :0];
}
