// agent — cluster agent runtime
//
// an agent is a worker node that connects to the cluster server,
// reports its capacity, and runs assigned containers. the agent
// uses a pull-based model: it polls the server every few seconds
// for heartbeat updates and work assignments.
//
// flow:
//   1. register with server (POST /agents/register)
//   2. enter loop: heartbeat + reconcile assignments every 5s
//   3. for each pending assignment: pull image, start container, report status
//   4. on shutdown, stop local containers and exit
//
// the agent reuses the existing container runtime for actually
// running containers — same code path as the local orchestrator.

const std = @import("std");
const http_client = @import("http_client.zig");
const agent_types = @import("agent_types.zig");
const cli = @import("../lib/cli.zig");
const json_helpers = @import("../lib/json_helpers.zig");
const log = @import("../lib/log.zig");
const wireguard = @import("../network/wireguard.zig");
const ip_mod = @import("../network/ip.zig");
const setup = @import("../network/setup.zig");
const cluster_config = @import("config.zig");
const gossip_mod = @import("gossip.zig");
const transport_mod = @import("transport.zig");
const agent_store = @import("agent_store.zig");
const lifecycle_support = @import("agent/lifecycle_support.zig");
const request_support = @import("agent/request_support.zig");
const resource_support = @import("agent/resource_support.zig");
const gossip_support = @import("agent/gossip_support.zig");
const assignment_runtime = @import("agent/assignment_runtime.zig");
const loop_runtime = @import("agent/loop_runtime.zig");
const log_server_mod = @import("agent/log_server.zig");

const Allocator = std.mem.Allocator;
const AgentResources = agent_types.AgentResources;

const writeErr = cli.writeErr;

pub const AgentError = error{
    /// POST /agents/register returned a non-200 status or connection failed
    RegisterFailed,
    /// the registration response could not be parsed (missing or malformed agent ID)
    InvalidResponse,
};

/// tracks the local state of a container spawned from an assignment.
pub const ContainerState = enum {
    starting,
    running,
    stopped,
    failed,
};

// max peers in the wireguard mesh — matches max node_id (1-65534).
const max_peers = 65534;

pub const Agent = struct {
    alloc: Allocator,
    id: [12]u8,
    server_addr: [4]u8,
    server_port: u16,
    token: []const u8,
    owned_token: ?[]u8 = null,
    agent_api_port: u16 = 7701,
    running: std.atomic.Value(bool),
    loop_thread: ?std.Thread,
    log_server: ?log_server_mod.LogServer = null,
    log_server_thread: ?std.Thread = null,

    /// tracks assignment_id → local container state.
    /// protected by mutex since container threads update it.
    local_containers: std.StringHashMap(ContainerState),
    container_lock: std.Io.Mutex,

    // wireguard mesh networking fields (set during registration if the
    // server assigns a node_id)
    node_id: ?u16 = null,
    wg_keypair: ?wireguard.KeyPair = null,
    overlay_ip: ?[4]u8 = null,
    wg_listen_port: u16 = 51820,

    // role separation fields — set by the join command before registration
    role: cluster_config.NodeRole = .both,
    region: ?[]const u8 = null,

    /// gossip seed addresses returned by the server during registration.
    /// format: "node_id@address" — used to bootstrap gossip membership.
    gossip_seeds: ?[][]const u8 = null,

    /// SWIM gossip state machine for failure detection.
    /// initialized after registration if gossip_seeds are available.
    gossip: ?*gossip_mod.Gossip = null,
    gossip_transport: ?*transport_mod.Transport = null,

    /// number of peers we currently have configured in the wireguard mesh.
    /// compared against the server's peers_count on each heartbeat to detect
    /// membership changes. when they differ, we re-fetch the full peer list
    /// and reconcile.
    known_peers_count: u32 = 0,

    /// maps node_id → public_key for currently configured wireguard peers.
    /// used by reconcilePeers to detect which peers to add/remove.
    /// dynamic sizing supports up to 65534 nodes.
    known_peers: std.AutoHashMap(u16, [44]u8),

    pub fn init(alloc: Allocator, server_addr: [4]u8, server_port: u16, token: []const u8) Agent {
        return lifecycle_support.init(alloc, server_addr, server_port, token, null);
    }

    pub fn initOwned(alloc: Allocator, server_addr: [4]u8, server_port: u16, token: []const u8) !Agent {
        return lifecycle_support.initOwned(alloc, server_addr, server_port, token);
    }

    /// register this agent with the cluster server.
    /// on success, self.id is set to the server-assigned agent ID.
    /// generates a wireguard keypair and sends the public key to the
    /// server, which assigns a node_id and overlay IP in response.
    pub fn register(self: *Agent) AgentError!void {
        const resources = resource_support.getSystemResources();

        // generate a wireguard keypair for mesh networking
        var threaded_io = std.Io.Threaded.init(self.alloc, .{});
        defer threaded_io.deinit();

        const kp = wireguard.generateKeyPair(threaded_io.io()) catch {
            writeErr("failed to generate wireguard keypair\n", .{});
            return AgentError.RegisterFailed;
        };
        const pub_key = &kp.public_key;

        // detect our local IP for the wireguard endpoint
        var local_ip_buf: [16]u8 = undefined;
        const local_ip = resource_support.detectLocalIp(self.server_addr, &local_ip_buf);

        const body = request_support.buildRegisterBody(self.alloc, self.token, local_ip, self.agent_api_port, resources, pub_key, self.wg_listen_port, self.role, self.region) catch
            return AgentError.RegisterFailed;
        defer self.alloc.free(body);

        var resp = http_client.postWithAuth(
            self.alloc,
            self.server_addr,
            self.server_port,
            "/agents/register",
            body,
            self.token,
        ) catch return AgentError.RegisterFailed;

        // follow leader hint on not-leader error and retry once
        if (resp.status_code != 200) {
            if (extractJsonString(resp.body, "leader")) |leader_str| {
                if (request_support.parseHostPort(leader_str)) |hp| {
                    log.info("registration redirected to leader at {s}", .{leader_str});
                    self.server_addr = hp.addr;
                    self.server_port = hp.port;
                    resp.deinit(self.alloc);
                    resp = http_client.postWithAuth(
                        self.alloc,
                        self.server_addr,
                        self.server_port,
                        "/agents/register",
                        body,
                        self.token,
                    ) catch return AgentError.RegisterFailed;
                }
            }
            if (resp.status_code != 200) {
                writeErr("registration failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
                resp.deinit(self.alloc);
                return AgentError.RegisterFailed;
            }
        }
        defer resp.deinit(self.alloc);

        // parse agent ID from response: {"id":"xxxxxxxxxxxx","node_id":N,"overlay_ip":"10.40.0.N"}
        const id_str = extractJsonString(resp.body, "id") orelse {
            writeErr("invalid registration response\n", .{});
            return AgentError.InvalidResponse;
        };

        if (id_str.len != 12) {
            writeErr("unexpected agent ID length: {d}\n", .{id_str.len});
            return AgentError.InvalidResponse;
        }

        @memcpy(&self.id, id_str);

        // store wireguard state
        self.wg_keypair = kp;

        // parse optional node_id and overlay_ip from the response
        if (extractJsonInt(resp.body, "node_id")) |nid| {
            if (nid >= 1 and nid <= 65534) {
                self.node_id = @intCast(nid);
            }
        }

        if (extractJsonString(resp.body, "overlay_ip")) |ip_str| {
            if (ip_mod.parseIp(ip_str)) |ip| {
                self.overlay_ip = ip;
            }
        }

        // parse gossip_seeds from the response for gossip bootstrap.
        // format: "gossip_seeds":["node_id@addr",...]
        gossip_support.parseGossipSeeds(self, resp.body);

        // initialize gossip if we have seeds and a node_id
        gossip_support.initGossip(self);

        // initialize the local assignment cache for offline resilience
        gossip_support.initCache(self);

        if (self.node_id) |nid| {
            log.info("registered as agent {s} (node_id={d}, role={s})", .{ &self.id, nid, self.role.toString() });
        } else {
            log.info("registered as agent {s} (role={s})", .{ &self.id, self.role.toString() });
        }
    }

    /// start the agent loop in a background thread.
    pub fn start(self: *Agent) !void {
        return lifecycle_support.start(self);
    }

    /// signal the agent to stop and wait for the loop thread to exit.
    /// tears down the wireguard interface and securely zeroes any owned join token.
    pub fn stop(self: *Agent) void {
        lifecycle_support.stop(self);
    }

    pub fn deinit(self: *Agent) void {
        lifecycle_support.deinit(self);
    }

    /// block until the agent stops (used by cmdJoin).
    pub fn wait(self: *Agent) void {
        lifecycle_support.wait(self);
    }

    /// compute adaptive heartbeat interval in 100ms ticks.
    /// scales with ceil(log2(N)) where N is the gossip member count,
    /// so large clusters heartbeat less frequently.
    fn agentHeartbeatTicks(self: *Agent) u32 {
        return loop_runtime.agentHeartbeatTicks(self);
    }

    fn agentLoop(self: *Agent) void {
        loop_runtime.agentLoop(self);
    }

    fn doHeartbeat(self: *Agent) void {
        loop_runtime.doHeartbeat(self);
    }

    /// fetch the full peer list from the server and reconcile with
    /// our local wireguard configuration. adds new peers and removes
    /// peers that are no longer in the server's list.
    fn reconcilePeers(self: *Agent) void {
        loop_runtime.reconcilePeers(self);
    }

    /// GET /wireguard/peers from the server.
    /// agents with role=agent request only server peers (hub-and-spoke);
    /// role=both gets all peers (full-mesh).
    fn fetchPeers(self: *Agent) ?http_client.Response {
        return loop_runtime.fetchPeers(self);
    }

    /// parse gossip seed addresses from a registration response body.
    /// format: "gossip_seeds":["addr1","addr2",...]
    /// best-effort — failure just means no seeds (gossip will discover peers).
    fn parseGossipSeeds(self: *Agent, body: []const u8) void {
        gossip_support.parseGossipSeeds(self, body);
    }

    // -- gossip integration --

    /// initialize gossip after registration if we have seeds and a node_id.
    /// creates a gossip state machine and UDP transport, then adds each
    /// seed as a member. non-fatal: if anything fails, agent runs without gossip.
    fn initGossip(self: *Agent) void {
        gossip_support.initGossip(self);
    }

    /// initialize the local assignment cache database.
    /// non-fatal — agent continues without cache on failure.
    fn initCache(self: *Agent) void {
        gossip_support.initCache(self);
    }

    /// tick gossip state machine and process outgoing actions.
    fn tickGossipLoop(self: *Agent) void {
        gossip_support.tickGossipLoop(self);
    }

    /// receive and dispatch incoming gossip UDP messages.
    fn receiveGossipLoop(self: *Agent) void {
        gossip_support.receiveGossipLoop(self);
    }

    /// parse a gossip seed string "node_id@ip_address" into its components.
    fn parseSeedAddr(seed: []const u8) ?struct { id: u64, ip: [4]u8 } {
        const parsed = gossip_support.parseSeedAddr(seed) orelse return null;
        return .{ .id = parsed.id, .ip = parsed.ip };
    }

    /// fetch assignments from the server and start containers for any
    /// gang scheduling info for a container assignment.
    /// when present, the agent injects NCCL mesh environment variables.
    pub const GangInfo = assignment_runtime.GangInfo;

    /// new pending assignments. this is the core reconciliation loop.
    fn reconcile(self: *Agent) void {
        assignment_runtime.reconcile(self);
    }

    /// parse "host:port" into an IP address and port number.
    fn parseHostPort(s: []const u8) ?struct { addr: [4]u8, port: u16 } {
        const parsed = request_support.parseHostPort(s) orelse return null;
        return .{ .addr = parsed.addr, .port = parsed.port };
    }
};

fn buildRegisterBody(
    alloc: Allocator,
    token: []const u8,
    address: []const u8,
    agent_api_port: u16,
    resources: AgentResources,
    pub_key: []const u8,
    wg_listen_port: u16,
    role: cluster_config.NodeRole,
    region: ?[]const u8,
) ![]u8 {
    return request_support.buildRegisterBody(alloc, token, address, agent_api_port, resources, pub_key, wg_listen_port, role, region);
}

fn buildHeartbeatBody(alloc: Allocator, resources: AgentResources, gpu_health_label: []const u8) ![]u8 {
    return request_support.buildHeartbeatBody(alloc, resources, gpu_health_label);
}

/// read system resources from /proc/meminfo and cpu count.
pub fn getSystemResources() AgentResources {
    return resource_support.getSystemResources();
}

// use shared JSON extraction helpers
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

/// detect this machine's local IP address by binding a UDP socket toward
/// the server address and reading back the local address the kernel chose.
/// this is the standard "get my IP toward a destination" trick — it never
/// sends any data, just uses the kernel's routing table to determine which
/// interface would be used.
pub fn detectLocalIp(target: [4]u8, buf: *[16]u8) []const u8 {
    return resource_support.detectLocalIp(target, buf);
}

/// derive overlay IP from node_id.
/// nodes 1-254:  10.40.0.{node_id}
/// nodes 255+:   10.40.{node_id >> 8}.{node_id & 0xFF}
fn overlayIpForNode(node_id: u16) [4]u8 {
    return resource_support.overlayIpForNode(node_id);
}

// -- tests --

test "getSystemResources returns reasonable values" {
    const res = getSystemResources();
    try std.testing.expect(res.cpu_cores >= 1);
    try std.testing.expect(res.memory_mb >= 1);
}

test "ContainerState enum values" {
    const s: ContainerState = .starting;
    try std.testing.expect(s == .starting);
    try std.testing.expect(s != .running);
    try std.testing.expect(s != .stopped);
    try std.testing.expect(s != .failed);
}

test "Agent init creates empty local_containers" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.deinit();

    try std.testing.expectEqual(@as(u32, 0), agent.local_containers.count());
    try std.testing.expect(!agent.running.load(.acquire));
}

test "Agent init wireguard fields default to null" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.deinit();

    try std.testing.expect(agent.node_id == null);
    try std.testing.expect(agent.wg_keypair == null);
    try std.testing.expect(agent.overlay_ip == null);
    try std.testing.expectEqual(@as(u16, 51820), agent.wg_listen_port);
}

test "detectLocalIp returns a dotted-quad string" {
    var buf: [16]u8 = undefined;
    const ip = detectLocalIp(.{ 127, 0, 0, 1 }, &buf);

    // should be a valid IP with at least 3 dots
    var dots: usize = 0;
    for (ip) |c| {
        if (c == '.') dots += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), dots);
    try std.testing.expect(ip.len >= 7); // "x.x.x.x" minimum
}

test "Agent init peer tracking defaults to zero" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.deinit();

    try std.testing.expectEqual(@as(u32, 0), agent.known_peers_count);
}

test "max_peers matches node_id range" {
    try std.testing.expectEqual(@as(usize, 65534), max_peers);
}

test "overlayIpForNode original range" {
    try std.testing.expectEqual([4]u8{ 10, 40, 0, 1 }, overlayIpForNode(1));
    try std.testing.expectEqual([4]u8{ 10, 40, 0, 254 }, overlayIpForNode(254));
}

test "overlayIpForNode extended range" {
    // 255: 255 >> 8 = 0, 255 & 0xFF = 255
    try std.testing.expectEqual([4]u8{ 10, 40, 0, 255 }, overlayIpForNode(255));
    // 256: 256 >> 8 = 1, 256 & 0xFF = 0
    try std.testing.expectEqual([4]u8{ 10, 40, 1, 0 }, overlayIpForNode(256));
    // 1000: 1000 >> 8 = 3, 1000 & 0xFF = 232
    try std.testing.expectEqual([4]u8{ 10, 40, 3, 232 }, overlayIpForNode(1000));
}

test "Agent init role defaults to both" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.deinit();

    try std.testing.expectEqual(cluster_config.NodeRole.both, agent.role);
    try std.testing.expect(agent.region == null);
    try std.testing.expect(agent.gossip_seeds == null);
}

test "Agent role can be set before registration" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.deinit();

    agent.role = .agent;
    agent.region = "us-east-1";

    try std.testing.expectEqual(cluster_config.NodeRole.agent, agent.role);
    try std.testing.expectEqualStrings("us-east-1", agent.region.?);
}

test "parseGossipSeeds with valid seeds" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.deinit();

    agent.parseGossipSeeds("{\"gossip_seeds\":[\"5@10.0.0.1\",\"6@10.0.0.2\"]}");

    try std.testing.expect(agent.gossip_seeds != null);
    try std.testing.expectEqual(@as(usize, 2), agent.gossip_seeds.?.len);
    try std.testing.expectEqualStrings("5@10.0.0.1", agent.gossip_seeds.?[0]);
    try std.testing.expectEqualStrings("6@10.0.0.2", agent.gossip_seeds.?[1]);
}

test "parseGossipSeeds with empty array" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.deinit();

    agent.parseGossipSeeds("{\"gossip_seeds\":[]}");

    try std.testing.expect(agent.gossip_seeds == null);
}

test "parseGossipSeeds with no seeds key" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.deinit();

    agent.parseGossipSeeds("{\"id\":\"abc123\"}");

    try std.testing.expect(agent.gossip_seeds == null);
}

test "parseSeedAddr with valid seed" {
    const result = Agent.parseSeedAddr("5@10.0.0.1");
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u64, 5), result.?.id);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, result.?.ip);
}

test "parseSeedAddr with invalid format" {
    try std.testing.expect(Agent.parseSeedAddr("no-at-sign") == null);
    try std.testing.expect(Agent.parseSeedAddr("abc@10.0.0.1") == null);
    try std.testing.expect(Agent.parseSeedAddr("5@not-an-ip") == null);
    try std.testing.expect(Agent.parseSeedAddr("") == null);
}

test "Agent gossip fields default to null" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.deinit();

    try std.testing.expect(agent.gossip == null);
    try std.testing.expect(agent.gossip_transport == null);
}

test "parseHostPort parses valid address" {
    const result = Agent.parseHostPort("10.0.0.1:7700");
    try std.testing.expect(result != null);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, result.?.addr);
    try std.testing.expectEqual(@as(u16, 7700), result.?.port);
}

test "parseHostPort returns null for invalid input" {
    try std.testing.expect(Agent.parseHostPort("") == null);
    try std.testing.expect(Agent.parseHostPort("no-colon") == null);
    try std.testing.expect(Agent.parseHostPort("not-ip:7700") == null);
    try std.testing.expect(Agent.parseHostPort("10.0.0.1:") == null);
    try std.testing.expect(Agent.parseHostPort("10.0.0.1:99999") == null);
}

test "buildRegisterBody escapes quoted string fields" {
    const alloc = std.testing.allocator;
    const body = try buildRegisterBody(
        alloc,
        "tok\"en",
        "10.0.0.1",
        7701,
        .{
            .cpu_cores = 4,
            .memory_mb = 8192,
            .gpu_count = 1,
            .gpu_model = "A\"100",
            .gpu_vram_mb = 40960,
        },
        "pub\"key",
        51820,
        .agent,
        "us-\"east",
    );
    defer alloc.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"role\":\"agent\"") != null);
}

test "buildHeartbeatBody escapes gpu health string" {
    const alloc = std.testing.allocator;
    const body = try buildHeartbeatBody(alloc, .{
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 1,
        .memory_used_mb = 2,
        .containers = 3,
        .gpu_count = 1,
        .gpu_used = 1,
    }, "warn\"ing");
    defer alloc.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "warn\\\"ing") != null);
}
