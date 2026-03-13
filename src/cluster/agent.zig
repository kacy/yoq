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
const posix = std.posix;
const http_client = @import("http_client.zig");
const agent_types = @import("agent_types.zig");
const cli = @import("../lib/cli.zig");
const json_helpers = @import("../lib/json_helpers.zig");
const log = @import("../lib/log.zig");
const container = @import("../runtime/container.zig");
const image_registry = @import("../image/registry.zig");
const image_layer = @import("../image/layer.zig");
const image_spec = @import("../image/spec.zig");
const store = @import("../state/store.zig");
const logs = @import("../runtime/logs.zig");
const wireguard = @import("../network/wireguard.zig");
const ip_mod = @import("../network/ip.zig");
const setup = @import("../network/setup.zig");

const paths = @import("../lib/paths.zig");
const gpu_detect = @import("../gpu/detect.zig");
const gpu_health = @import("../gpu/health.zig");
const gpu_mig = @import("../gpu/mig.zig");
const cluster_config = @import("config.zig");
const gossip_mod = @import("gossip.zig");
const transport_mod = @import("transport.zig");
const agent_store = @import("agent_store.zig");

const Allocator = std.mem.Allocator;
const AgentResources = agent_types.AgentResources;

const write = cli.write;
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
    running: std.atomic.Value(bool),
    loop_thread: ?std.Thread,

    /// tracks assignment_id → local container state.
    /// protected by mutex since container threads update it.
    local_containers: std.StringHashMap(ContainerState),
    container_lock: std.Thread.Mutex,

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
        return .{
            .alloc = alloc,
            .id = undefined,
            .server_addr = server_addr,
            .server_port = server_port,
            .token = token,
            .running = std.atomic.Value(bool).init(false),
            .loop_thread = null,
            .local_containers = std.StringHashMap(ContainerState).init(alloc),
            .container_lock = .{},
            .known_peers = std.AutoHashMap(u16, [44]u8).init(alloc),
        };
    }

    /// register this agent with the cluster server.
    /// on success, self.id is set to the server-assigned agent ID.
    /// generates a wireguard keypair and sends the public key to the
    /// server, which assigns a node_id and overlay IP in response.
    pub fn register(self: *Agent) AgentError!void {
        const resources = getSystemResources();

        // generate a wireguard keypair for mesh networking
        const kp = wireguard.generateKeyPair() catch {
            writeErr("failed to generate wireguard keypair\n", .{});
            return AgentError.RegisterFailed;
        };
        const pub_key = &kp.public_key;

        // detect our local IP for the wireguard endpoint
        var local_ip_buf: [16]u8 = undefined;
        const local_ip = detectLocalIp(self.server_addr, &local_ip_buf);

        // build registration JSON with wireguard, role, and GPU info
        var body_buf: [2048]u8 = undefined;
        var body_len: usize = 0;

        // base fields
        const base = std.fmt.bufPrint(
            &body_buf,
            "{{\"token\":\"{s}\",\"address\":\"{s}\",\"cpu_cores\":{d},\"memory_mb\":{d},\"wg_public_key\":\"{s}\",\"wg_listen_port\":{d},\"role\":\"{s}\"",
            .{ self.token, local_ip, resources.cpu_cores, resources.memory_mb, pub_key, self.wg_listen_port, self.role.toString() },
        ) catch return AgentError.RegisterFailed;
        body_len = base.len;

        // optional region
        if (self.region) |reg| {
            const suffix = std.fmt.bufPrint(
                body_buf[body_len..],
                ",\"region\":\"{s}\"",
                .{reg},
            ) catch return AgentError.RegisterFailed;
            body_len += suffix.len;
        }

        // GPU info
        if (resources.gpu_count > 0) {
            const gpu_suffix = std.fmt.bufPrint(
                body_buf[body_len..],
                ",\"gpu_count\":{d},\"gpu_vram_mb\":{d}",
                .{ resources.gpu_count, resources.gpu_vram_mb },
            ) catch return AgentError.RegisterFailed;
            body_len += gpu_suffix.len;

            if (resources.gpu_model) |model| {
                const model_suffix = std.fmt.bufPrint(
                    body_buf[body_len..],
                    ",\"gpu_model\":\"{s}\"",
                    .{model},
                ) catch return AgentError.RegisterFailed;
                body_len += model_suffix.len;
            }
        }

        // close object
        if (body_len >= body_buf.len) return AgentError.RegisterFailed;
        body_buf[body_len] = '}';
        body_len += 1;
        const body = body_buf[0..body_len];

        var resp = http_client.postWithAuth(
            self.alloc,
            self.server_addr,
            self.server_port,
            "/agents/register",
            body,
            self.token,
        ) catch return AgentError.RegisterFailed;
        defer resp.deinit(self.alloc);

        if (resp.status_code != 200) {
            writeErr("registration failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
            return AgentError.RegisterFailed;
        }

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
        self.parseGossipSeeds(resp.body);

        // initialize gossip if we have seeds and a node_id
        self.initGossip();

        // initialize the local assignment cache for offline resilience
        self.initCache();

        if (self.node_id) |nid| {
            log.info("registered as agent {s} (node_id={d}, role={s})", .{ &self.id, nid, self.role.toString() });
        } else {
            log.info("registered as agent {s} (role={s})", .{ &self.id, self.role.toString() });
        }
    }

    /// start the agent loop in a background thread.
    pub fn start(self: *Agent) !void {
        self.running.store(true, .release);
        self.loop_thread = std.Thread.spawn(.{}, agentLoop, .{self}) catch {
            self.running.store(false, .release);
            return error.ThreadSpawnFailed;
        };
    }

    /// signal the agent to stop and wait for the loop thread to exit.
    /// tears down the wireguard interface and securely zeroes the join token.
    pub fn stop(self: *Agent) void {
        self.running.store(false, .release);
        if (self.loop_thread) |t| {
            t.join();
            self.loop_thread = null;
        }

        // tear down wireguard interface if we set one up during registration.
        // deleting the interface also removes all peers and routes, so this
        // is a clean single-step teardown.
        if (self.node_id != null) {
            setup.teardownClusterNetworking();
        }

        // zero the token so it doesn't linger in memory after shutdown.
        // the token slice points into caller-owned memory, but we still
        // want to wipe our reference to prevent accidental leaks.
        if (self.token.len > 0) {
            const token_ptr: [*]u8 = @constCast(self.token.ptr);
            std.crypto.secureZero(u8, token_ptr[0..self.token.len]);
        }

        // clean up the local containers map
        self.container_lock.lock();
        defer self.container_lock.unlock();

        var it = self.local_containers.iterator();
        while (it.next()) |entry| {
            self.alloc.free(entry.key_ptr.*);
        }
        self.local_containers.deinit();

        // clean up the peer tracking map
        self.known_peers.deinit();

        // clean up gossip
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

        // clean up gossip seeds
        if (self.gossip_seeds) |seeds| {
            for (seeds) |s| self.alloc.free(s);
            self.alloc.free(seeds);
            self.gossip_seeds = null;
        }

        // close the agent cache database
        agent_store.closeDb();
    }

    /// block until the agent stops (used by cmdJoin).
    pub fn wait(self: *Agent) void {
        if (self.loop_thread) |t| {
            t.join();
            self.loop_thread = null;
        }
    }

    /// compute adaptive heartbeat interval in 100ms ticks.
    /// scales with ceil(log2(N)) where N is the gossip member count,
    /// so large clusters heartbeat less frequently.
    fn agentHeartbeatTicks(self: *Agent) u32 {
        if (self.gossip) |g| {
            const member_count = g.members.count() + 1;
            const multiplier: u32 = @min(gossip_mod.Gossip.ceilLog2(member_count), gossip_mod.Gossip.max_interval_multiplier);
            return 50 * multiplier;
        }
        return 50;
    }

    fn agentLoop(self: *Agent) void {
        while (self.running.load(.acquire)) {
            self.doHeartbeat();
            self.reconcile();

            // sleep between cycles, ticking gossip every 500ms
            var remaining: u32 = self.agentHeartbeatTicks();
            while (remaining > 0 and self.running.load(.acquire)) : (remaining -= 1) {
                std.Thread.sleep(100 * std.time.ns_per_ms);

                // tick gossip every 500ms and check for incoming messages
                if (remaining % 5 == 0) self.tickGossipLoop();
                self.receiveGossipLoop();
            }
        }
    }

    fn doHeartbeat(self: *Agent) void {
        const resources = getSystemResources();

        // poll GPU health if NVML is available
        var gpu_health_worst: gpu_health.GpuHealth = .healthy;
        if (cached_gpu_info) |info| {
            if (info.detect_result) |dr| {
                if (dr.nvml) |*nvml| {
                    const metrics = gpu_health.pollAllMetrics(nvml, @intCast(info.count));
                    // report worst-case health across all GPUs
                    for (0..@min(info.count, gpu_detect.max_gpus)) |i| {
                        if (metrics[i]) |m| {
                            const h = m.health();
                            if (h == .unhealthy) {
                                gpu_health_worst = .unhealthy;
                                break;
                            } else if (h == .warning) {
                                gpu_health_worst = .warning;
                            }
                        }
                    }
                }
            }
        }

        var body_buf: [512]u8 = undefined;
        const body = std.fmt.bufPrint(
            &body_buf,
            "{{\"cpu_cores\":{d},\"memory_mb\":{d},\"cpu_used\":{d},\"memory_used_mb\":{d},\"containers\":{d},\"gpu_count\":{d},\"gpu_used\":{d},\"gpu_health\":\"{s}\"}}",
            .{
                resources.cpu_cores,
                resources.memory_mb,
                resources.cpu_used,
                resources.memory_used_mb,
                resources.containers,
                resources.gpu_count,
                resources.gpu_used,
                @tagName(gpu_health_worst),
            },
        ) catch return;

        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/heartbeat", .{self.id}) catch return;

        var resp = http_client.postWithAuth(
            self.alloc,
            self.server_addr,
            self.server_port,
            path,
            body,
            self.token,
        ) catch return;
        defer resp.deinit(self.alloc);

        // check if server says we're being drained
        if (resp.status_code == 200) {
            const status = extractJsonString(resp.body, "status");
            if (status) |s| {
                if (std.mem.eql(u8, s, "draining")) {
                    writeErr("agent is being drained, stopping...\n", .{});
                    self.running.store(false, .release);
                }
            }

            // check if the peer list has changed. the server includes
            // peers_count in the heartbeat response so the agent can
            // detect membership changes without polling the full list
            // every cycle.
            if (self.node_id != null) {
                if (extractJsonInt(resp.body, "peers_count")) |count| {
                    const server_count: u32 = if (count >= 0 and count <= max_peers)
                        @intCast(count)
                    else
                        0;

                    if (server_count != self.known_peers_count) {
                        log.info("peer count changed ({d} -> {d}), reconciling", .{
                            self.known_peers_count, server_count,
                        });
                        self.reconcilePeers();
                    }
                }
            }
        }
    }

    /// fetch the full peer list from the server and reconcile with
    /// our local wireguard configuration. adds new peers and removes
    /// peers that are no longer in the server's list.
    fn reconcilePeers(self: *Agent) void {
        var resp = self.fetchPeers() orelse return;
        defer resp.deinit(self.alloc);

        // parse peer objects from the response into a new map.
        // each peer is: {"node_id":N,"public_key":"...","endpoint":"...","overlay_ip":"...","container_subnet":"..."}
        var new_peers = std.AutoHashMap(u16, [44]u8).init(self.alloc);
        defer new_peers.deinit();

        var iter = json_helpers.extractJsonObjects(resp.body);
        while (iter.next()) |obj| {
            const pub_key = extractJsonString(obj, "public_key") orelse continue;
            const overlay_str = extractJsonString(obj, "overlay_ip") orelse continue;
            const node_id_val = extractJsonInt(obj, "node_id") orelse continue;
            const endpoint = extractJsonString(obj, "endpoint") orelse "";

            // skip ourselves
            if (self.node_id) |our_id| {
                if (node_id_val == our_id) continue;
            }

            const peer_node: u16 = if (node_id_val >= 1 and node_id_val <= 65534)
                @intCast(node_id_val)
            else
                continue;

            const overlay_ip = ip_mod.parseIp(overlay_str) orelse continue;

            // check if this peer is already configured
            const already_known = self.known_peers.contains(peer_node);

            if (!already_known) {
                // new peer — add it
                log.info("adding peer node_id={d}", .{peer_node});
                setup.addClusterPeer(.{
                    .public_key = pub_key,
                    .endpoint = endpoint,
                    .overlay_ip = overlay_ip,
                    .container_subnet_node = peer_node,
                }) catch |e| {
                    log.warn("failed to add cluster peer (node {d}): {}", .{ peer_node, e });
                };
            }

            // track this peer in the new map
            if (pub_key.len <= 44) {
                var key_buf: [44]u8 = undefined;
                @memcpy(key_buf[0..pub_key.len], pub_key);
                // zero the rest so the buffer is deterministic
                @memset(key_buf[pub_key.len..], 0);
                new_peers.put(peer_node, key_buf) catch {};
            }
        }

        // remove peers that are no longer in the server's list
        var old_iter = self.known_peers.iterator();
        while (old_iter.next()) |entry| {
            const old_node = entry.key_ptr.*;

            if (!new_peers.contains(old_node)) {
                const old_key = entry.value_ptr;
                // find the length of the key (first null byte)
                var key_len: usize = 44;
                for (old_key, 0..) |b, i| {
                    if (b == 0) {
                        key_len = i;
                        break;
                    }
                }
                log.info("removing peer node_id={d}", .{old_node});
                setup.removeClusterPeer(.{
                    .public_key = old_key[0..key_len],
                    .endpoint = "", // not needed for removal
                    .overlay_ip = overlayIpForNode(old_node),
                    .container_subnet_node = old_node,
                });
            }
        }

        // swap the maps: replace known_peers with new_peers
        self.known_peers.deinit();
        self.known_peers = new_peers.move();
        self.known_peers_count = @intCast(self.known_peers.count());

        log.info("peer reconciliation complete ({d} peers)", .{self.known_peers_count});
    }

    /// GET /wireguard/peers from the server.
    /// agents with role=agent request only server peers (hub-and-spoke);
    /// role=both gets all peers (full-mesh).
    fn fetchPeers(self: *Agent) ?http_client.Response {
        const path = if (self.role == .agent)
            "/wireguard/peers?servers_only=1"
        else
            "/wireguard/peers";
        return http_client.getWithAuth(
            self.alloc,
            self.server_addr,
            self.server_port,
            path,
            self.token,
        ) catch return null;
    }

    /// parse gossip seed addresses from a registration response body.
    /// format: "gossip_seeds":["addr1","addr2",...]
    /// best-effort — failure just means no seeds (gossip will discover peers).
    fn parseGossipSeeds(self: *Agent, body: []const u8) void {
        const key = "\"gossip_seeds\":[";
        const key_pos = std.mem.indexOf(u8, body, key) orelse return;
        const arr_start = key_pos + key.len;
        const arr_end = std.mem.indexOfPos(u8, body, arr_start, "]") orelse return;
        const arr = body[arr_start..arr_end];
        if (arr.len == 0) return;

        var seeds: std.ArrayListUnmanaged([]const u8) = .{};

        // parse quoted strings from the array
        var pos: usize = 0;
        while (pos < arr.len) {
            const quote_start = std.mem.indexOfPos(u8, arr, pos, "\"") orelse break;
            const quote_end = std.mem.indexOfPos(u8, arr, quote_start + 1, "\"") orelse break;
            const seed = arr[quote_start + 1 .. quote_end];
            if (seed.len > 0) {
                const dupe = self.alloc.dupe(u8, seed) catch break;
                seeds.append(self.alloc, dupe) catch {
                    self.alloc.free(dupe);
                    break;
                };
            }
            pos = quote_end + 1;
        }

        if (seeds.items.len > 0) {
            self.gossip_seeds = seeds.toOwnedSlice(self.alloc) catch {
                for (seeds.items) |s| self.alloc.free(s);
                seeds.deinit(self.alloc);
                return;
            };
            log.info("received {d} gossip seeds", .{self.gossip_seeds.?.len});
        } else {
            seeds.deinit(self.alloc);
        }
    }

    // -- gossip integration --

    /// default gossip port for agents.
    const default_gossip_port: u16 = 9800;

    /// initialize gossip after registration if we have seeds and a node_id.
    /// creates a gossip state machine and UDP transport, then adds each
    /// seed as a member. non-fatal: if anything fails, agent runs without gossip.
    fn initGossip(self: *Agent) void {
        const nid = self.node_id orelse return;
        const seeds = self.gossip_seeds orelse return;
        if (seeds.len == 0) return;

        // derive shared key from join token (same KDF as server)
        const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
        var shared_key: [32]u8 = undefined;
        HmacSha256.create(&shared_key, "yoq-raft-transport-key", self.token);

        // create transport for UDP gossip (TCP port 0 = OS-assigned, unused)
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

        // create gossip state machine
        const gossip_state = self.alloc.create(gossip_mod.Gossip) catch {
            transport.deinit();
            self.alloc.destroy(transport);
            return;
        };
        gossip_state.* = gossip_mod.Gossip.init(self.alloc, @as(u64, nid), .{
            .ip = self.overlay_ip orelse .{ 0, 0, 0, 0 },
            .port = default_gossip_port,
        }, .{});

        // add seeds as gossip members. format: "node_id@address"
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

    /// initialize the local assignment cache database.
    /// non-fatal — agent continues without cache on failure.
    fn initCache(_: *Agent) void {
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

    /// tick gossip state machine and process outgoing actions.
    fn tickGossipLoop(self: *Agent) void {
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
                // agents don't act on membership changes — the server leader does
                .member_dead, .member_alive, .member_suspect => {},
            }
        }
    }

    /// receive and dispatch incoming gossip UDP messages.
    fn receiveGossipLoop(self: *Agent) void {
        const gossip = self.gossip orelse return;
        const transport = self.gossip_transport orelse return;

        var buf: [1500]u8 = undefined;

        // drain up to 5 messages per call
        var msg_idx: u32 = 0;
        while (msg_idx < 5) : (msg_idx += 1) {
            const result = transport.receiveGossip(&buf) catch break;
            const recv = result orelse break;

            const msg = gossip_mod.Gossip.decode(self.alloc, recv.payload) catch continue;

            switch (msg) {
                .ping => |payload| gossip.handlePing(payload) catch {},
                .ping_ack => |payload| gossip.handlePingAck(payload) catch {},
                .ping_req => |payload| gossip.handlePingReq(payload) catch {},
            }

            // send any response actions immediately
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

    /// parse a gossip seed string "node_id@ip_address" into its components.
    fn parseSeedAddr(seed: []const u8) ?struct { id: u64, ip: [4]u8 } {
        const at_pos = std.mem.indexOf(u8, seed, "@") orelse return null;
        const id = std.fmt.parseInt(u64, seed[0..at_pos], 10) catch return null;
        const ip = ip_mod.parseIp(seed[at_pos + 1 ..]) orelse return null;
        return .{ .id = id, .ip = ip };
    }

    /// fetch assignments from the server and start containers for any
    /// new pending assignments. this is the core reconciliation loop.
    fn reconcile(self: *Agent) void {
        var resp = self.fetchAssignments() orelse {
            // server unreachable — fall back to cache
            self.reconcileFromCache();
            return;
        };
        defer resp.deinit(self.alloc);

        const now = std.time.timestamp();

        var iter = json_helpers.extractJsonObjects(resp.body);
        while (iter.next()) |obj| {
            const assignment_id = extractJsonString(obj, "id") orelse continue;
            const status = extractJsonString(obj, "status") orelse continue;
            const image = extractJsonString(obj, "image") orelse continue;
            const command = extractJsonString(obj, "command") orelse "";
            const cpu_limit = extractJsonInt(obj, "cpu_limit") orelse 1000;
            const memory_limit_mb = extractJsonInt(obj, "memory_limit_mb") orelse 256;

            // skip terminal assignments — just remove from cache
            if (std.mem.eql(u8, status, "stopped") or std.mem.eql(u8, status, "failed")) {
                agent_store.removeAssignment(assignment_id) catch {};
                continue;
            }

            // cache assignment state (only non-terminal)
            agent_store.upsertAssignment(.{
                .id = assignment_id,
                .image = image,
                .command = command,
                .status = status,
                .cpu_limit = cpu_limit,
                .memory_limit_mb = memory_limit_mb,
                .synced_at = now,
            }) catch {};

            if (std.mem.eql(u8, status, "pending")) {
                self.startPendingAssignment(assignment_id, image, command);
            }
        }
    }

    /// fall back to cached assignments when the server is unreachable.
    /// reads from the local cache and starts any pending assignments.
    fn reconcileFromCache(self: *Agent) void {
        const cached = agent_store.listPendingAssignments(self.alloc) catch return;
        defer {
            for (cached) |a| a.deinit(self.alloc);
            self.alloc.free(cached);
        }

        if (cached.len == 0) return;
        log.warn("server unreachable, reconciling from cache ({d} assignments)", .{cached.len});

        for (cached) |assignment| {
            self.startPendingAssignment(assignment.id, assignment.image, assignment.command);
        }
    }

    /// dupe strings, track in local_containers, and spawn runAssignment thread.
    /// skips silently if the assignment is already tracked or on alloc failure.
    fn startPendingAssignment(self: *Agent, id: []const u8, image: []const u8, command: []const u8) void {
        self.container_lock.lock();
        const already_tracked = self.local_containers.contains(id);
        self.container_lock.unlock();
        if (already_tracked) return;

        const id_copy = self.alloc.dupe(u8, id) catch return;
        const image_copy = self.alloc.dupe(u8, image) catch {
            self.alloc.free(id_copy);
            return;
        };
        const command_copy = self.alloc.dupe(u8, command) catch {
            self.alloc.free(id_copy);
            self.alloc.free(image_copy);
            return;
        };

        self.container_lock.lock();
        self.local_containers.put(id_copy, .starting) catch {
            self.container_lock.unlock();
            self.alloc.free(id_copy);
            self.alloc.free(image_copy);
            self.alloc.free(command_copy);
            return;
        };
        self.container_lock.unlock();

        log.info("starting assignment {s} (image: {s})", .{ id_copy, image_copy });

        _ = std.Thread.spawn(.{}, runAssignment, .{
            self, id_copy, image_copy, command_copy,
        }) catch {
            log.warn("failed to spawn thread for assignment {s}", .{id_copy});
            self.container_lock.lock();
            _ = self.local_containers.remove(id_copy);
            self.container_lock.unlock();
            self.alloc.free(id_copy);
            self.alloc.free(image_copy);
            self.alloc.free(command_copy);
        };
    }

    /// GET /agents/{id}/assignments from the server.
    fn fetchAssignments(self: *Agent) ?http_client.Response {
        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/assignments", .{self.id}) catch return null;

        return http_client.getWithAuth(
            self.alloc,
            self.server_addr,
            self.server_port,
            path,
            self.token,
        ) catch return null;
    }

    /// run a single assignment in its own thread.
    /// pulls the image, starts the container, and blocks until it exits.
    /// reports status back to the server at each stage.
    fn runAssignment(self: *Agent, assignment_id: []const u8, image: []const u8, command: []const u8) void {
        defer {
            self.alloc.free(image);
            self.alloc.free(command);
            // note: assignment_id stays in local_containers map (key is owned by the map)
        }

        // report running status to server
        self.reportStatus(assignment_id, "running");

        self.container_lock.lock();
        if (self.local_containers.getPtr(assignment_id)) |state| {
            state.* = .running;
        }
        self.container_lock.unlock();

        // pull image
        const ref = image_spec.parseImageRef(image);
        var pull_result = image_registry.pull(self.alloc, ref) catch {
            log.warn("failed to pull image {s} for assignment {s}", .{ image, assignment_id });
            self.setContainerState(assignment_id, .failed);
            self.reportStatus(assignment_id, "failed");
            return;
        };
        defer pull_result.deinit();

        // assemble rootfs from layers
        const layer_paths = image_layer.assembleRootfs(self.alloc, pull_result.layer_digests) catch {
            log.warn("failed to assemble rootfs for assignment {s}", .{assignment_id});
            self.setContainerState(assignment_id, .failed);
            self.reportStatus(assignment_id, "failed");
            return;
        };
        defer {
            for (layer_paths) |p| self.alloc.free(p);
            self.alloc.free(layer_paths);
        }

        // determine rootfs path (topmost layer)
        const rootfs = if (layer_paths.len > 0) layer_paths[layer_paths.len - 1] else "/";

        // generate a local container ID
        var id_buf: [12]u8 = undefined;
        container.generateId(&id_buf) catch {
            log.warn("failed to generate container ID for assignment {s}", .{assignment_id});
            self.setContainerState(assignment_id, .failed);
            self.reportStatus(assignment_id, "failed");
            return;
        };
        const container_id = id_buf[0..];

        // save container record to local store
        store.save(.{
            .id = container_id,
            .rootfs = rootfs,
            .command = if (command.len > 0) command else "/bin/sh",
            .hostname = "agent",
            .status = "created",
            .pid = null,
            .exit_code = null,
            .created_at = std.time.timestamp(),
        }) catch {
            log.warn("failed to save container record for assignment {s}", .{assignment_id});
            self.setContainerState(assignment_id, .failed);
            self.reportStatus(assignment_id, "failed");
            return;
        };

        // create and start the container
        var c = container.Container{
            .config = .{
                .id = container_id,
                .rootfs = rootfs,
                .command = if (command.len > 0) command else "/bin/sh",
                .lower_dirs = layer_paths,
            },
            .status = .created,
            .pid = null,
            .exit_code = null,
            .created_at = std.time.timestamp(),
        };

        log.info("starting container {s} for assignment {s}", .{ container_id, assignment_id });
        c.start() catch {
            log.warn("container {s} failed to start for assignment {s}", .{ container_id, assignment_id });
            self.setContainerState(assignment_id, .failed);
            self.reportStatus(assignment_id, "failed");
            cleanup(container_id);
            return;
        };

        _ = c.wait() catch 255;

        // container exited normally
        log.info("container {s} exited for assignment {s}", .{ container_id, assignment_id });
        self.setContainerState(assignment_id, .stopped);
        self.reportStatus(assignment_id, "stopped");
        cleanup(container_id);
    }

    /// report assignment status to the server. best-effort — log on failure.
    fn reportStatus(self: *Agent, assignment_id: []const u8, status: []const u8) void {
        var path_buf: [128]u8 = undefined;
        const path = std.fmt.bufPrint(
            &path_buf,
            "/agents/{s}/assignments/{s}/status",
            .{ self.id, assignment_id },
        ) catch return;

        var body_buf: [64]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf, "{{\"status\":\"{s}\"}}", .{status}) catch return;

        var resp = http_client.postWithAuth(
            self.alloc,
            self.server_addr,
            self.server_port,
            path,
            body,
            self.token,
        ) catch {
            log.warn("failed to report status '{s}' for assignment {s}", .{ status, assignment_id });
            return;
        };
        resp.deinit(self.alloc);
    }

    /// update the local container state (thread-safe).
    fn setContainerState(self: *Agent, assignment_id: []const u8, state: ContainerState) void {
        self.container_lock.lock();
        defer self.container_lock.unlock();
        if (self.local_containers.getPtr(assignment_id)) |s| {
            s.* = state;
        }
    }

    /// clean up container files after exit.
    fn cleanup(container_id: []const u8) void {
        logs.deleteLogFile(container_id);
        container.cleanupContainerDirs(container_id);
        store.remove(container_id) catch {};
    }
};

/// read system resources from /proc/meminfo and cpu count.
pub fn getSystemResources() AgentResources {
    const cpu_cores: u32 = @intCast(std.Thread.getCpuCount() catch 1);

    // read total memory from /proc/meminfo
    var memory_mb: u64 = 0;
    const meminfo = std.fs.cwd().readFileAlloc(std.heap.page_allocator, "/proc/meminfo", 8192) catch "";
    defer if (meminfo.len > 0) std.heap.page_allocator.free(meminfo);

    if (meminfo.len > 0) {
        // find "MemTotal:" line and parse the value
        if (std.mem.indexOf(u8, meminfo, "MemTotal:")) |pos| {
            var start = pos + "MemTotal:".len;
            // skip whitespace
            while (start < meminfo.len and meminfo[start] == ' ') start += 1;
            // find end of number
            var end = start;
            while (end < meminfo.len and meminfo[end] >= '0' and meminfo[end] <= '9') end += 1;
            if (end > start) {
                const kb = std.fmt.parseInt(u64, meminfo[start..end], 10) catch 0;
                memory_mb = kb / 1024;
            }
        }
    }

    // detect GPUs (cached — detection involves dlopen/sysfs scans)
    const gpu_info = cachedGpuDetect();

    return .{
        .cpu_cores = cpu_cores,
        .memory_mb = memory_mb,
        .gpu_count = gpu_info.count,
        .gpu_model = gpu_info.model,
        .gpu_vram_mb = gpu_info.vram_mb,
    };
}

/// cached GPU detection — avoids repeated dlopen/sysfs scans on every heartbeat.
/// detection runs once on first call; result is stored in a global.
/// we keep the full DetectResult alive so the NvmlHandle stays open for
/// health polling and MIG discovery.
const CachedGpuInfo = struct {
    count: u32,
    model: ?[]const u8,
    vram_mb: u64,
    detect_result: ?*gpu_detect.DetectResult,
    mig_inventories: [gpu_detect.max_gpus]gpu_mig.MigInventory = .{gpu_mig.MigInventory{}} ** gpu_detect.max_gpus,
    mig_gpu_count: u32 = 0,
};

var cached_gpu_info: ?CachedGpuInfo = null;
var cached_detect_storage: gpu_detect.DetectResult = undefined;

fn cachedGpuDetect() CachedGpuInfo {
    if (cached_gpu_info) |info| return info;
    cached_detect_storage = gpu_detect.detect();
    const count = @as(u32, cached_detect_storage.count);

    // extract model and VRAM from first GPU (representative for the node)
    var model: ?[]const u8 = null;
    var vram_mb: u64 = 0;
    if (count > 0) {
        const gpu = &cached_detect_storage.gpus[0];
        const name = gpu.getName();
        if (name.len > 0) model = name;
        vram_mb = gpu.vram_mb;
    }

    // run MIG discovery if NVML is available and GPU is MIG-capable
    var mig_inventories: [gpu_detect.max_gpus]gpu_mig.MigInventory = .{gpu_mig.MigInventory{}} ** gpu_detect.max_gpus;
    var mig_gpu_count: u32 = 0;
    if (cached_detect_storage.nvml) |*nvml| {
        for (0..count) |i| {
            const gpu = &cached_detect_storage.gpus[i];
            if (gpu.mig_capable) {
                const inventory = gpu_mig.discoverInstances(nvml, @intCast(i));
                mig_inventories[i] = inventory;
                if (inventory.count > 0) {
                    mig_gpu_count += 1;
                    log.info("GPU {d}: MIG mode active, {d} instance(s)", .{ i, inventory.count });
                }
            }
        }
    }

    const info = CachedGpuInfo{
        .count = count,
        .model = model,
        .vram_mb = vram_mb,
        .detect_result = if (count > 0) &cached_detect_storage else null,
        .mig_inventories = mig_inventories,
        .mig_gpu_count = mig_gpu_count,
    };
    cached_gpu_info = info;
    return info;
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
    const addr = std.net.Address.initIp4(target, 80);

    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch {
        return std.fmt.bufPrint(buf, "127.0.0.1", .{}) catch "127.0.0.1";
    };
    defer posix.close(sock);

    posix.connect(sock, &addr.any, addr.getOsSockLen()) catch {
        return std.fmt.bufPrint(buf, "127.0.0.1", .{}) catch "127.0.0.1";
    };

    var local_addr: posix.sockaddr.storage = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    posix.getsockname(sock, @ptrCast(&local_addr), &addr_len) catch {
        return std.fmt.bufPrint(buf, "127.0.0.1", .{}) catch "127.0.0.1";
    };

    // extract IPv4 address bytes
    const sa_in: *const posix.sockaddr.in = @ptrCast(@alignCast(&local_addr));
    const ip_bytes: [4]u8 = @bitCast(sa_in.addr);
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] }) catch "127.0.0.1";
}

/// derive overlay IP from node_id.
/// nodes 1-254:  10.40.0.{node_id}
/// nodes 255+:   10.40.{node_id >> 8}.{node_id & 0xFF}
fn overlayIpForNode(node_id: u16) [4]u8 {
    if (node_id <= 254) {
        return .{ 10, 40, 0, @intCast(node_id) };
    }
    return .{ 10, 40, @intCast(node_id >> 8), @intCast(node_id & 0xFF) };
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
    defer agent.local_containers.deinit();
    defer agent.known_peers.deinit();

    try std.testing.expectEqual(@as(u32, 0), agent.local_containers.count());
    try std.testing.expect(!agent.running.load(.acquire));
}

test "Agent init wireguard fields default to null" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.local_containers.deinit();
    defer agent.known_peers.deinit();

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
    defer agent.local_containers.deinit();
    defer agent.known_peers.deinit();

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
    defer agent.local_containers.deinit();
    defer agent.known_peers.deinit();

    try std.testing.expectEqual(cluster_config.NodeRole.both, agent.role);
    try std.testing.expect(agent.region == null);
    try std.testing.expect(agent.gossip_seeds == null);
}

test "Agent role can be set before registration" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.local_containers.deinit();
    defer agent.known_peers.deinit();

    agent.role = .agent;
    agent.region = "us-east-1";

    try std.testing.expectEqual(cluster_config.NodeRole.agent, agent.role);
    try std.testing.expectEqualStrings("us-east-1", agent.region.?);
}

test "parseGossipSeeds with valid seeds" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.local_containers.deinit();
    defer agent.known_peers.deinit();

    agent.parseGossipSeeds("{\"gossip_seeds\":[\"5@10.0.0.1\",\"6@10.0.0.2\"]}");
    defer {
        if (agent.gossip_seeds) |seeds| {
            for (seeds) |s| alloc.free(s);
            alloc.free(seeds);
        }
    }

    try std.testing.expect(agent.gossip_seeds != null);
    try std.testing.expectEqual(@as(usize, 2), agent.gossip_seeds.?.len);
    try std.testing.expectEqualStrings("5@10.0.0.1", agent.gossip_seeds.?[0]);
    try std.testing.expectEqualStrings("6@10.0.0.2", agent.gossip_seeds.?[1]);
}

test "parseGossipSeeds with empty array" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.local_containers.deinit();
    defer agent.known_peers.deinit();

    agent.parseGossipSeeds("{\"gossip_seeds\":[]}");

    try std.testing.expect(agent.gossip_seeds == null);
}

test "parseGossipSeeds with no seeds key" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.local_containers.deinit();
    defer agent.known_peers.deinit();

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
    defer agent.local_containers.deinit();
    defer agent.known_peers.deinit();

    try std.testing.expect(agent.gossip == null);
    try std.testing.expect(agent.gossip_transport == null);
}
