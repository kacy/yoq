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
const setup = @import("../network/setup.zig");

const Allocator = std.mem.Allocator;
const AgentResources = agent_types.AgentResources;

const write = cli.write;
const writeErr = cli.writeErr;

pub const AgentError = error{
    RegisterFailed,
    InvalidResponse,
};

/// tracks the local state of a container spawned from an assignment.
pub const ContainerState = enum {
    starting,
    running,
    stopped,
    failed,
};

// max peers in the wireguard mesh — matches max node_id (1-254).
const max_peers = 254;

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
    node_id: ?u8 = null,
    wg_keypair: ?wireguard.KeyPair = null,
    overlay_ip: ?[4]u8 = null,
    wg_listen_port: u16 = 51820,

    /// number of peers we currently have configured in the wireguard mesh.
    /// compared against the server's peers_count on each heartbeat to detect
    /// membership changes. when they differ, we re-fetch the full peer list
    /// and reconcile.
    known_peers_count: u32 = 0,

    /// public keys of currently configured wireguard peers.
    /// used by reconcilePeers to detect which peers to add/remove.
    /// fixed capacity of 254 matches the max node count (node_id 1-254).
    known_peer_keys: [max_peers][44]u8 = undefined,
    known_peer_key_lens: [max_peers]u8 = [_]u8{0} ** max_peers,
    known_peer_nodes: [max_peers]u8 = [_]u8{0} ** max_peers,

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

        // build registration JSON with wireguard info
        var body_buf: [1024]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf,
            "{{\"token\":\"{s}\",\"address\":\"{s}\",\"cpu_cores\":{d},\"memory_mb\":{d},\"wg_public_key\":\"{s}\",\"wg_listen_port\":{d}}}",
            .{ self.token, local_ip, resources.cpu_cores, resources.memory_mb, pub_key, self.wg_listen_port },
        ) catch return AgentError.RegisterFailed;

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
            if (nid >= 1 and nid <= 254) {
                self.node_id = @intCast(nid);
            }
        }

        if (extractJsonString(resp.body, "overlay_ip")) |ip_str| {
            if (parseOverlayIp(ip_str)) |ip| {
                self.overlay_ip = ip;
            }
        }

        if (self.node_id) |nid| {
            log.info("registered as agent {s} (node_id={d})", .{ &self.id, nid });
        } else {
            log.info("registered as agent {s}", .{&self.id});
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
    /// securely zeroes the join token to prevent it lingering in memory.
    pub fn stop(self: *Agent) void {
        self.running.store(false, .release);
        if (self.loop_thread) |t| {
            t.join();
            self.loop_thread = null;
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
    }

    /// block until the agent stops (used by cmdJoin).
    pub fn wait(self: *Agent) void {
        if (self.loop_thread) |t| {
            t.join();
            self.loop_thread = null;
        }
    }

    fn agentLoop(self: *Agent) void {
        while (self.running.load(.acquire)) {
            self.doHeartbeat();
            self.reconcile();

            // sleep 5 seconds between cycles
            var remaining: u32 = 50; // 50 * 100ms = 5s
            while (remaining > 0 and self.running.load(.acquire)) : (remaining -= 1) {
                std.Thread.sleep(100 * std.time.ns_per_ms);
            }
        }
    }

    fn doHeartbeat(self: *Agent) void {
        const resources = getSystemResources();

        var body_buf: [256]u8 = undefined;
        const body = std.fmt.bufPrint(&body_buf,
            "{{\"cpu_cores\":{d},\"memory_mb\":{d},\"cpu_used\":{d},\"memory_used_mb\":{d},\"containers\":{d}}}",
            .{
                resources.cpu_cores,
                resources.memory_mb,
                resources.cpu_used,
                resources.memory_used_mb,
                resources.containers,
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

        // parse peer objects from the response.
        // each peer is: {"node_id":N,"public_key":"...","endpoint":"...","overlay_ip":"...","container_subnet":"..."}
        var new_count: u32 = 0;
        var new_keys: [max_peers][44]u8 = undefined;
        var new_key_lens: [max_peers]u8 = [_]u8{0} ** max_peers;
        var new_nodes: [max_peers]u8 = [_]u8{0} ** max_peers;

        var iter = json_helpers.extractJsonObjects(resp.body);
        while (iter.next()) |obj| {
            if (new_count >= max_peers) break;

            const pub_key = extractJsonString(obj, "public_key") orelse continue;
            const overlay_str = extractJsonString(obj, "overlay_ip") orelse continue;
            const node_id_val = extractJsonInt(obj, "node_id") orelse continue;
            const endpoint = extractJsonString(obj, "endpoint") orelse "";

            // skip ourselves
            if (self.node_id) |our_id| {
                if (node_id_val == our_id) continue;
            }

            const peer_node: u8 = if (node_id_val >= 1 and node_id_val <= 254)
                @intCast(node_id_val)
            else
                continue;

            const overlay_ip = parseOverlayIp(overlay_str) orelse continue;

            // check if this peer is already configured
            var found = false;
            for (0..self.known_peers_count) |i| {
                const existing_key = self.known_peer_keys[i][0..self.known_peer_key_lens[i]];
                if (pub_key.len == existing_key.len and
                    std.mem.eql(u8, pub_key, existing_key))
                {
                    found = true;
                    break;
                }
            }

            if (!found) {
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

            // track this peer in the new list
            if (pub_key.len <= 44) {
                const idx = new_count;
                @memcpy(new_keys[idx][0..pub_key.len], pub_key);
                new_key_lens[idx] = @intCast(pub_key.len);
                new_nodes[idx] = peer_node;
                new_count += 1;
            }
        }

        // remove peers that are no longer in the server's list
        for (0..self.known_peers_count) |i| {
            const old_key = self.known_peer_keys[i][0..self.known_peer_key_lens[i]];
            const old_node = self.known_peer_nodes[i];

            var still_present = false;
            for (0..new_count) |j| {
                const new_key = new_keys[j][0..new_key_lens[j]];
                if (old_key.len == new_key.len and std.mem.eql(u8, old_key, new_key)) {
                    still_present = true;
                    break;
                }
            }

            if (!still_present) {
                log.info("removing peer node_id={d}", .{old_node});
                setup.removeClusterPeer(.{
                    .public_key = old_key,
                    .endpoint = "", // not needed for removal
                    .overlay_ip = .{ 10, 40, 0, old_node },
                    .container_subnet_node = old_node,
                });
            }
        }

        // update our local tracking state
        self.known_peers_count = new_count;
        for (0..new_count) |i| {
            self.known_peer_keys[i] = new_keys[i];
            self.known_peer_key_lens[i] = new_key_lens[i];
            self.known_peer_nodes[i] = new_nodes[i];
        }

        log.info("peer reconciliation complete ({d} peers)", .{new_count});
    }

    /// GET /wireguard/peers from the server.
    fn fetchPeers(self: *Agent) ?http_client.Response {
        return http_client.getWithAuth(
            self.alloc,
            self.server_addr,
            self.server_port,
            "/wireguard/peers",
            self.token,
        ) catch return null;
    }

    /// fetch assignments from the server and start containers for any
    /// new pending assignments. this is the core reconciliation loop.
    fn reconcile(self: *Agent) void {
        var resp = self.fetchAssignments() orelse return;
        defer resp.deinit(self.alloc);

        var iter = json_helpers.extractJsonObjects(resp.body);
        while (iter.next()) |obj| {
            const assignment_id = extractJsonString(obj, "id") orelse continue;
            const status = extractJsonString(obj, "status") orelse continue;

            // only act on pending assignments
            if (!std.mem.eql(u8, status, "pending")) continue;

            // skip if we're already tracking this assignment
            self.container_lock.lock();
            const already_tracked = self.local_containers.contains(assignment_id);
            self.container_lock.unlock();
            if (already_tracked) continue;

            const image = extractJsonString(obj, "image") orelse continue;
            const command = extractJsonString(obj, "command") orelse "";

            // allocate copies for the thread (the response buffer will be freed)
            const id_copy = self.alloc.dupe(u8, assignment_id) catch continue;
            const image_copy = self.alloc.dupe(u8, image) catch {
                self.alloc.free(id_copy);
                continue;
            };
            const command_copy = self.alloc.dupe(u8, command) catch {
                self.alloc.free(id_copy);
                self.alloc.free(image_copy);
                continue;
            };

            // mark as starting before spawning thread
            self.container_lock.lock();
            self.local_containers.put(id_copy, .starting) catch {
                self.container_lock.unlock();
                self.alloc.free(id_copy);
                self.alloc.free(image_copy);
                self.alloc.free(command_copy);
                continue;
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
        container.generateId(&id_buf);
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

        // create and start the container (blocks until exit)
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

    return .{
        .cpu_cores = cpu_cores,
        .memory_mb = memory_mb,
    };
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

/// parse a dotted-quad overlay IP string into 4 bytes.
fn parseOverlayIp(str: []const u8) ?[4]u8 {
    var ip: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var start: usize = 0;

    for (str, 0..) |c, i| {
        if (c == '.') {
            if (octet_idx >= 3) return null;
            ip[octet_idx] = std.fmt.parseInt(u8, str[start..i], 10) catch return null;
            octet_idx += 1;
            start = i + 1;
        }
    }

    if (octet_idx != 3) return null;
    ip[3] = std.fmt.parseInt(u8, str[start..], 10) catch return null;

    return ip;
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

    try std.testing.expectEqual(@as(u32, 0), agent.local_containers.count());
    try std.testing.expect(!agent.running.load(.acquire));
}

test "Agent init wireguard fields default to null" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.local_containers.deinit();

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

test "parseOverlayIp valid" {
    const ip = parseOverlayIp("10.40.0.3").?;
    try std.testing.expectEqual([4]u8{ 10, 40, 0, 3 }, ip);
}

test "parseOverlayIp invalid" {
    try std.testing.expect(parseOverlayIp("not.an.ip") == null);
    try std.testing.expect(parseOverlayIp("10.42.0") == null);
    try std.testing.expect(parseOverlayIp("") == null);
    try std.testing.expect(parseOverlayIp("999.0.0.1") == null);
}

test "Agent init peer tracking defaults to zero" {
    const alloc = std.testing.allocator;
    var agent = Agent.init(alloc, .{ 127, 0, 0, 1 }, 7700, "test-token");
    defer agent.local_containers.deinit();

    try std.testing.expectEqual(@as(u32, 0), agent.known_peers_count);
}

test "max_peers matches node_id range" {
    try std.testing.expectEqual(@as(usize, 254), max_peers);
}
