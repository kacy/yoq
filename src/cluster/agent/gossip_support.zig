const std = @import("std");
const log = @import("../../lib/log.zig");
const paths = @import("../../lib/paths.zig");
const ip_mod = @import("../../network/ip.zig");
const gossip_mod = @import("../gossip.zig");
const gossip_sender_validation = @import("../gossip_sender_validation.zig");
const transport_mod = @import("../transport.zig");
const agent_store = @import("../agent_store.zig");

const default_gossip_port: u16 = 9800;

pub fn parseGossipSeeds(self: anytype, body: []const u8) void {
    const key = "\"gossip_seeds\":[";
    const key_pos = std.mem.indexOf(u8, body, key) orelse return;
    const arr_start = key_pos + key.len;
    const arr_end = std.mem.indexOfPos(u8, body, arr_start, "]") orelse return;
    const arr = body[arr_start..arr_end];
    if (arr.len == 0) return;

    var seeds: std.ArrayListUnmanaged([]const u8) = .{};
    var pos: usize = 0;
    while (pos < arr.len) {
        const quote_start = std.mem.indexOfPos(u8, arr, pos, "\"") orelse break;
        const quote_end = std.mem.indexOfPos(u8, arr, quote_start + 1, "\"") orelse break;
        const seed = arr[quote_start + 1 .. quote_end];
        if (seed.len > 0) {
            const duped = self.alloc.dupe(u8, seed) catch break;
            seeds.append(self.alloc, duped) catch {
                self.alloc.free(duped);
                break;
            };
        }
        pos = quote_end + 1;
    }

    if (seeds.items.len > 0) {
        self.gossip_seeds = seeds.toOwnedSlice(self.alloc) catch {
            for (seeds.items) |seed| self.alloc.free(seed);
            seeds.deinit(self.alloc);
            return;
        };
        log.info("received {d} gossip seeds", .{self.gossip_seeds.?.len});
    } else {
        seeds.deinit(self.alloc);
    }
}

pub fn initGossip(self: anytype) void {
    const nid = self.node_id orelse return;
    const seeds = self.gossip_seeds orelse return;
    if (seeds.len == 0) return;

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var shared_key: [32]u8 = undefined;
    HmacSha256.create(&shared_key, "yoq-raft-transport-key", self.token);

    const transport = self.alloc.create(transport_mod.Transport) catch return;
    transport.* = transport_mod.Transport.init(self.alloc, 0) catch {
        self.alloc.destroy(transport);
        return;
    };
    transport.setLocalNodeId(@as(u64, nid));
    transport.shared_key = shared_key;
    transport.initUdp(default_gossip_port) catch {
        log.warn("gossip: failed to bind UDP port {}, running without gossip", .{default_gossip_port});
        transport.deinit();
        self.alloc.destroy(transport);
        return;
    };

    const gossip_state = self.alloc.create(gossip_mod.Gossip) catch {
        transport.deinit();
        self.alloc.destroy(transport);
        return;
    };
    gossip_state.* = gossip_mod.Gossip.init(self.alloc, @as(u64, nid), .{
        .ip = self.overlay_ip orelse .{ 0, 0, 0, 0 },
        .port = default_gossip_port,
    }, .{});

    var added: u32 = 0;
    for (seeds) |seed| {
        const parsed = parseSeedAddr(seed) orelse continue;
        gossip_state.addMember(parsed.id, .{ .ip = parsed.ip, .port = default_gossip_port }) catch continue;
        added += 1;
    }

    if (added == 0) {
        gossip_state.deinit();
        self.alloc.destroy(gossip_state);
        transport.deinit();
        self.alloc.destroy(transport);
        return;
    }

    self.gossip = gossip_state;
    self.gossip_transport = transport;
    log.info("gossip: initialized with {d} seeds on UDP port {}", .{ added, default_gossip_port });
}

pub fn initCache(_: anytype) void {
    paths.ensureDataDir("") catch {
        log.warn("failed to create data dir for agent cache", .{});
        return;
    };
    var path_buf: [paths.max_path]u8 = undefined;
    const db_path = paths.dataPath(&path_buf, "agent-cache.db") catch {
        log.warn("failed to get data path for agent cache", .{});
        return;
    };
    agent_store.initWithPath(db_path) catch |e| {
        log.warn("failed to init agent cache: {}", .{e});
    };
}

pub fn tickGossipLoop(self: anytype) void {
    const gossip = self.gossip orelse return;
    const transport = self.gossip_transport orelse return;

    gossip.tick() catch return;
    const actions = gossip.drainActions();
    defer gossip.freeActions(actions);

    for (actions) |action| {
        switch (action) {
            .send_message => |msg| {
                var encode_buf: [512]u8 = undefined;
                const len = gossip_mod.Gossip.encode(&encode_buf, msg.message) catch continue;
                transport.sendGossip(msg.addr.ip, msg.addr.port, encode_buf[0..len]) catch {};
            },
            .member_dead, .member_alive, .member_suspect => {},
        }
    }
}

pub fn receiveGossipLoop(self: anytype) void {
    const gossip = self.gossip orelse return;
    const transport = self.gossip_transport orelse return;

    var buf: [1500]u8 = undefined;
    var msg_idx: u32 = 0;
    while (msg_idx < 5) : (msg_idx += 1) {
        const result = transport.receiveGossip(&buf) catch break;
        const recv = result orelse break;
        if (!gossip_sender_validation.isTrustedSender(gossip, recv)) {
            log.warn("gossip: rejected spoofed sender {} from unexpected source", .{recv.sender_id});
            continue;
        }

        const msg = gossip_mod.Gossip.decode(self.alloc, recv.payload) catch continue;
        switch (msg) {
            .ping => |payload| gossip.handlePing(payload) catch {},
            .ping_ack => |payload| gossip.handlePingAck(payload) catch {},
            .ping_req => |payload| gossip.handlePingReq(payload) catch {},
        }

        const actions = gossip.drainActions();
        defer gossip.freeActions(actions);
        for (actions) |action| {
            switch (action) {
                .send_message => |send| {
                    var encode_buf: [512]u8 = undefined;
                    const len = gossip_mod.Gossip.encode(&encode_buf, send.message) catch continue;
                    transport.sendGossip(send.addr.ip, send.addr.port, encode_buf[0..len]) catch {};
                },
                .member_dead, .member_alive, .member_suspect => {},
            }
        }
    }
}

pub fn parseSeedAddr(seed: []const u8) ?struct { id: u64, ip: [4]u8 } {
    const at_pos = std.mem.indexOf(u8, seed, "@") orelse return null;
    const id = std.fmt.parseInt(u64, seed[0..at_pos], 10) catch return null;
    const ip = ip_mod.parseIp(seed[at_pos + 1 ..]) orelse return null;
    return .{ .id = id, .ip = ip };
}
