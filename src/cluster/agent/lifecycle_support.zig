const std = @import("std");
const setup = @import("../../network/setup.zig");
const agent_store = @import("../agent_store.zig");
const cluster_config = @import("../config.zig");
const agent_mod = @import("../agent.zig");
const loop_runtime = @import("loop_runtime.zig");

pub fn init(alloc: std.mem.Allocator, server_addr: [4]u8, server_port: u16, token: []const u8, owned_token: ?[]u8) agent_mod.Agent {
    return .{
        .alloc = alloc,
        .id = undefined,
        .server_addr = server_addr,
        .server_port = server_port,
        .token = if (owned_token) |owned| owned else token,
        .owned_token = owned_token,
        .running = std.atomic.Value(bool).init(false),
        .loop_thread = null,
        .local_containers = std.StringHashMap(agent_mod.ContainerState).init(alloc),
        .container_lock = .{},
        .node_id = null,
        .wg_keypair = null,
        .overlay_ip = null,
        .wg_listen_port = 51820,
        .role = cluster_config.NodeRole.both,
        .region = null,
        .gossip_seeds = null,
        .gossip = null,
        .gossip_transport = null,
        .known_peers_count = 0,
        .known_peers = std.AutoHashMap(u16, [44]u8).init(alloc),
    };
}

pub fn initOwned(alloc: std.mem.Allocator, server_addr: [4]u8, server_port: u16, token: []const u8) !agent_mod.Agent {
    const owned = try alloc.dupe(u8, token);
    return init(alloc, server_addr, server_port, owned, owned);
}

pub fn start(self: anytype) !void {
    self.running.store(true, .release);
    self.loop_thread = std.Thread.spawn(.{}, loop_runtime.agentLoop, .{self}) catch {
        self.running.store(false, .release);
        return error.ThreadSpawnFailed;
    };
}

pub fn stop(self: anytype) void {
    self.running.store(false, .release);
    if (self.loop_thread) |t| {
        t.join();
        self.loop_thread = null;
    }

    if (self.node_id != null) {
        setup.teardownClusterNetworking();
    }

    if (self.owned_token) |token| {
        std.crypto.secureZero(u8, token);
    }
}

pub fn wait(self: anytype) void {
    if (self.loop_thread) |t| {
        t.join();
        self.loop_thread = null;
    }
}

pub fn deinit(self: anytype) void {
    stop(self);

    self.container_lock.lock();
    defer self.container_lock.unlock();

    var it = self.local_containers.iterator();
    while (it.next()) |entry| {
        self.alloc.free(entry.key_ptr.*);
    }
    self.local_containers.deinit();

    self.known_peers.deinit();

    if (self.gossip) |g| {
        g.deinit();
        self.alloc.destroy(g);
        self.gossip = null;
    }
    if (self.gossip_transport) |t| {
        t.deinit();
        self.alloc.destroy(t);
        self.gossip_transport = null;
    }

    if (self.gossip_seeds) |seeds| {
        for (seeds) |s| self.alloc.free(s);
        self.alloc.free(seeds);
        self.gossip_seeds = null;
    }

    if (self.owned_token) |token| {
        self.alloc.free(token);
        self.owned_token = null;
        self.token = "";
    }

    agent_store.closeDb();
}
