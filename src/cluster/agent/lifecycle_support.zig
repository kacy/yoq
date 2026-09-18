const std = @import("std");
const setup = @import("../../network/setup.zig");
const agent_store = @import("../agent_store.zig");
const cluster_config = @import("../config.zig");
const agent_mod = @import("../agent.zig");
const log_server = @import("log_server.zig");
const loop_runtime = @import("loop_runtime.zig");

pub fn init(alloc: std.mem.Allocator, server_addr: [4]u8, server_port: u16, token: []const u8, owned_token: ?[]u8) agent_mod.Agent {
    return .{
        .alloc = alloc,
        .id = undefined,
        .server_addr = server_addr,
        .server_port = server_port,
        .token = if (owned_token) |owned| owned else token,
        .owned_token = owned_token,
        .agent_api_port = 7701,
        .running = std.atomic.Value(bool).init(false),
        .loop_thread = null,
        .log_server = null,
        .log_server_thread = null,
        .local_containers = std.StringHashMap(*agent_mod.LocalAssignment).init(alloc),
        .container_lock = .init,
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
    self.assignment_workers.restart();
    self.running.store(true, .release);
    errdefer {
        self.running.store(false, .release);
        stopLogServer(self);
    }
    self.log_server = try log_server.LogServer.init(self.alloc, self.agent_api_port, self.token);
    self.log_server_thread = std.Thread.spawn(.{}, runLogServer, .{self}) catch return error.ThreadSpawnFailed;
    self.loop_thread = std.Thread.spawn(.{}, loop_runtime.agentLoop, .{self}) catch return error.ThreadSpawnFailed;
}

fn stopLogServer(self: anytype) void {
    if (self.log_server) |*server| server.stop();
    if (self.log_server_thread) |thread| {
        thread.join();
        self.log_server_thread = null;
    }
    if (self.log_server) |*server| server.deinit();
    self.log_server = null;
}

fn runLogServer(self: anytype) void {
    if (self.log_server) |*server| server.run();
}

pub fn stop(self: anytype) void {
    self.running.store(false, .release);
    self.assignment_workers.cancel();
    if (self.loop_thread) |t| {
        t.join();
        self.loop_thread = null;
    }
    self.assignment_workers.join();
    if (self.worker_credential != null) @import("assignment_runtime.zig").flushShutdownResults(self);
    @import("../../manifest/alerts/runtime.zig").shutdownIfUnused();
    stopLogServer(self);

    if (self.node_id != null) {
        setup.teardownClusterNetworking();
    }

    if (self.owned_token) |token| {
        std.crypto.secureZero(u8, token);
    }
    if (self.worker_credential) |secret| std.crypto.secureZero(u8, secret);
}

// signal handlers set the shared flag; joining alone cannot stop the agent loop.
pub fn waitForShutdown(self: anytype, canceled: *const std.atomic.Value(bool)) void {
    while (self.running.load(.acquire) and !canceled.load(.acquire)) {
        if (!@import("../../lib/runtime_wait.zig").sleep(.fromMilliseconds(100), "agent shutdown wait")) break;
    }
    self.stop();
}

pub fn wait(self: anytype) void {
    if (self.loop_thread) |t| {
        t.join();
        self.loop_thread = null;
    }
    self.assignment_workers.join();
    if (self.worker_credential != null) @import("assignment_runtime.zig").flushShutdownResults(self);
    @import("../../manifest/alerts/runtime.zig").shutdownIfUnused();
    stopLogServer(self);
}

pub fn deinit(self: anytype) void {
    stop(self);

    self.container_lock.lockUncancelable(std.Options.debug_io);
    defer self.container_lock.unlock(std.Options.debug_io);

    var it = self.local_containers.iterator();
    while (it.next()) |entry| {
        self.alloc.free(entry.key_ptr.*);
        self.alloc.destroy(entry.value_ptr.*);
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

    if (self.worker_credential) |secret| {
        std.crypto.secureZero(u8, secret);
        self.alloc.free(secret);
        self.worker_credential = null;
    }
    agent_store.closeDb();
}

test "agent enrollment shutdown wait stops a running agent and retains pending results" {
    const alloc = std.testing.allocator;
    var agent = agent_mod.Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "cluster-token");
    defer agent.deinit();
    agent.id = "worker000001".*;
    try agent_store.initTestDb();
    const results = @import("result_store.zig");
    try std.testing.expect(try results.claim(&agent.id, "assignment", 1));
    try results.record(&agent.id, "assignment", 1, "failed", "image_pull_failed");
    agent.running.store(true, .release);
    var canceled: std.atomic.Value(bool) = .init(false);
    const Worker = struct {
        fn run(target: *agent_mod.Agent, flag: *const std.atomic.Value(bool)) void {
            waitForShutdown(target, flag);
        }
    };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{ &agent, &canceled });
    canceled.store(true, .release);
    thread.join();
    try std.testing.expect(!agent.running.load(.acquire));
    const pending = try results.list(alloc, &agent.id);
    defer {
        for (pending) |result| result.deinit(alloc);
        alloc.free(pending);
    }
    try std.testing.expectEqual(@as(usize, 1), pending.len);
    try std.testing.expectEqualStrings("failed", pending[0].status);
    try std.testing.expectEqual(@as(i64, 0), pending[0].delivered);
}
