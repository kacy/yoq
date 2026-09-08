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
    const Registration = struct {
        gossip_server: ?struct { id: u64, port: u16 } = null,
        gossip_seeds: []const []const u8 = &.{},
    };
    const parsed = std.json.parseFromSlice(Registration, self.alloc, body, .{ .ignore_unknown_fields = true }) catch return;
    defer parsed.deinit();
    var seeds: std.ArrayListUnmanaged([]const u8) = .empty;
    const server = parsed.value.gossip_server;
    if (server) |peer| {
        if (peer.id != 0 and peer.port != 0 and peer.id != (self.node_id orelse 0)) {
            const ip = self.server_addr;
            const seed = std.fmt.allocPrint(self.alloc, "{d}@{d}.{d}.{d}.{d}:{d}", .{ peer.id, ip[0], ip[1], ip[2], ip[3], peer.port }) catch return;
            seeds.append(self.alloc, seed) catch {
                self.alloc.free(seed);
                return;
            };
        }
    }
    for (parsed.value.gossip_seeds) |seed| {
        const peer = parseSeedAddr(seed) orelse continue;
        if (peer.id == (self.node_id orelse 0)) continue;
        if (server) |pinned| {
            if (peer.id == pinned.id) continue;
        }
        const duped = self.alloc.dupe(u8, seed) catch break;
        seeds.append(self.alloc, duped) catch {
            self.alloc.free(duped);
            break;
        };
    }

    if (seeds.items.len > 0) {
        const owned = seeds.toOwnedSlice(self.alloc) catch {
            for (seeds.items) |seed| self.alloc.free(seed);
            seeds.deinit(self.alloc);
            return;
        };
        if (self.gossip_seeds) |previous| {
            for (previous) |seed| self.alloc.free(seed);
            self.alloc.free(previous);
        }
        self.gossip_seeds = owned;
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
        if (parsed.id == nid) continue;
        gossip_state.addMember(parsed.id, .{ .ip = parsed.ip, .port = parsed.port }) catch continue;
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
    const actions = gossip.drainActions() catch |err| {
        log.warn("gossip: failed to drain tick actions: {}", .{err});
        return;
    };
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

        const actions = gossip.drainActions() catch |err| {
            log.warn("gossip: failed to drain received-message actions: {}", .{err});
            return;
        };
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

pub fn parseSeedAddr(seed: []const u8) ?struct { id: u64, ip: [4]u8, port: u16 } {
    const at_pos = std.mem.indexOfScalar(u8, seed, '@') orelse return null;
    const id = std.fmt.parseInt(u64, seed[0..at_pos], 10) catch return null;
    if (id == 0) return null;
    const endpoint = seed[at_pos + 1 ..];
    const colon = std.mem.indexOfScalar(u8, endpoint, ':');
    const ip = ip_mod.parseIp(if (colon) |pos| endpoint[0..pos] else endpoint) orelse return null;
    const port = if (colon) |pos| std.fmt.parseInt(u16, endpoint[pos + 1 ..], 10) catch return null else default_gossip_port;
    if (port == 0) return null;
    return .{ .id = id, .ip = ip, .port = port };
}

test "gossip bootstrap pins first worker to server identity and actual port" {
    const alloc = std.testing.allocator;
    var agent = struct {
        alloc: std.mem.Allocator,
        server_addr: [4]u8 = .{ 10, 0, 0, 1 },
        node_id: ?u16 = 2,
        gossip_seeds: ?[][]const u8 = null,
    }{ .alloc = alloc };
    defer if (agent.gossip_seeds) |seeds| {
        for (seeds) |seed| alloc.free(seed);
        alloc.free(seeds);
    };
    // A self seed and a conflicting server endpoint must not replace the API
    // server's pinned address. Non-default server gossip ports are preserved.
    parseGossipSeeds(&agent, "{\"gossip_server\":{\"id\":1,\"port\":19800},\"gossip_seeds\":[\"2@10.0.0.2\",\"1@10.0.0.99:9800\"]}");
    const seeds = agent.gossip_seeds.?;
    try std.testing.expectEqual(@as(usize, 1), seeds.len);
    const server = parseSeedAddr(seeds[0]).?;
    try std.testing.expectEqual(@as(u64, 1), server.id);
    try std.testing.expectEqual(agent.server_addr, server.ip);
    try std.testing.expectEqual(@as(u16, 19800), server.port);

    var gossip = gossip_mod.Gossip.init(alloc, 2, .{ .ip = .{ 10, 0, 0, 2 }, .port = default_gossip_port }, .{});
    defer gossip.deinit();
    try gossip.addMember(server.id, .{ .ip = server.ip, .port = server.port });
    const Address = @import("linux_platform").net.Address;
    var packet = transport_mod.GossipReceiveResult{
        .sender_id = 1,
        .from_addr = Address.initIp4(server.ip, server.port),
        .payload = "ping",
    };
    try std.testing.expect(gossip_sender_validation.isTrustedSender(&gossip, packet));
    packet.from_addr = Address.initIp4(server.ip, default_gossip_port);
    try std.testing.expect(!gossip_sender_validation.isTrustedSender(&gossip, packet));
    packet.from_addr = Address.initIp4(.{ 10, 0, 0, 99 }, server.port);
    try std.testing.expect(!gossip_sender_validation.isTrustedSender(&gossip, packet));
}

test "gossip bootstrap retains legacy ports and rejects invalid endpoints" {
    try std.testing.expectEqual(@as(u16, 9800), parseSeedAddr("3@10.0.0.3").?.port);
    for ([_][]const u8{ "0@10.0.0.1", "1@10.0.0.1:0", "1@10.0.0.1:65536", "1@10.0.0.1:no" }) |seed|
        try std.testing.expect(parseSeedAddr(seed) == null);
}
