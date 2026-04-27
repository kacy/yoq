// cluster test harness — utilities for multi-node cluster testing
//
// provides TestCluster for orchestrating multiple yoq server nodes
// on localhost for integration testing. each node gets isolated
// data directories and unique ports.

const std = @import("std");
const helpers = @import("helpers");
const http_client = @import("http_client");
const linux_platform = @import("linux_platform");
const runtime_preflight = @import("runtime_preflight");
const lposix = linux_platform.posix;

fn nowMillis() i64 {
    return std.Io.Clock.real.now(std.testing.io).toMilliseconds();
}

pub const ClusterNode = struct {
    id: u64,
    raft_port: u16,
    api_port: u16,
    data_dir: []const u8,
    process: ?std.process.Child = null,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *ClusterNode) void {
        self.stop();
        self.alloc.free(self.data_dir);
    }

    pub fn stop(self: *ClusterNode) void {
        if (self.process) |*proc| {
            proc.kill(std.testing.io);
            self.process = null;
        }
    }

    pub fn isRunning(self: *const ClusterNode) bool {
        return self.process != null;
    }
};

pub const TestCluster = struct {
    alloc: std.mem.Allocator,
    nodes: std.ArrayListUnmanaged(ClusterNode) = .empty,
    base_raft_port: u16,
    base_api_port: u16,
    join_token: []const u8,
    api_token: []const u8,
    tmp_dir: helpers.TmpDir,

    pub const Config = struct {
        node_count: usize = 3,
        base_raft_port: u16 = 19700, // Use high ports to avoid conflicts
        base_api_port: u16 = 17700,
    };

    pub fn init(alloc: std.mem.Allocator, config: Config) !TestCluster {
        try runtime_preflight.requireRuntimeCluster(&.{
            .{ .base = config.base_raft_port, .count = config.node_count },
            .{ .base = config.base_api_port, .count = config.node_count },
        });

        const tmp_dir = try helpers.tmpDir();
        errdefer tmp_dir.cleanup();

        // Generate tokens
        var join_token_buf: [64]u8 = undefined;
        var api_token_buf: [64]u8 = undefined;
        try generateHexToken(&join_token_buf);
        try generateHexToken(&api_token_buf);

        var self = TestCluster{
            .alloc = alloc,
            .base_raft_port = config.base_raft_port,
            .base_api_port = config.base_api_port,
            .join_token = try alloc.dupe(u8, &join_token_buf),
            .api_token = try alloc.dupe(u8, &api_token_buf),
            .tmp_dir = tmp_dir,
        };
        errdefer self.deinit();

        // Create nodes
        for (0..config.node_count) |i| {
            const node_id = i + 1;
            const raft_port = config.base_raft_port + @as(u16, @intCast(i));
            const api_port = config.base_api_port + @as(u16, @intCast(i));

            const data_dir = try std.fmt.allocPrint(alloc, "{s}/node{d}", .{
                tmp_dir.slice(),
                node_id,
            });
            errdefer alloc.free(data_dir);

            try std.Io.Dir.cwd().createDirPath(std.testing.io, data_dir);

            // Write API token to node's data dir
            const token_path = try std.fmt.allocPrint(alloc, "{s}/api_token", .{data_dir});
            defer alloc.free(token_path);
            try helpers.writeFile(data_dir, "api_token", &api_token_buf);

            try self.nodes.append(alloc, .{
                .id = node_id,
                .raft_port = raft_port,
                .api_port = api_port,
                .data_dir = data_dir,
                .alloc = alloc,
            });
        }

        return self;
    }

    pub fn deinit(self: *TestCluster) void {
        self.stopAll();

        for (self.nodes.items) |*node| {
            node.deinit();
        }
        self.nodes.deinit(self.alloc);

        self.alloc.free(self.join_token);
        self.alloc.free(self.api_token);
        self.tmp_dir.cleanup();
    }

    pub fn startAll(self: *TestCluster) !void {
        const start_time = nowMillis();

        // Pre-compute the full peer list for each node (all nodes are peers)
        var all_nodes_peers: [][512]u8 = try self.alloc.alloc([512]u8, self.nodes.items.len);
        defer self.alloc.free(all_nodes_peers);

        for (self.nodes.items, 0..) |*node, i| {
            var peers_buf: [512]u8 = undefined;
            var peers_writer: std.Io.Writer = .fixed(&peers_buf);

            var first = true;
            for (self.nodes.items) |other| {
                if (other.id == node.id) continue;

                if (!first) try peers_writer.writeByte(',');
                first = false;

                try peers_writer.print("{d}@127.0.0.1:{d}", .{
                    other.id,
                    other.raft_port,
                });
            }

            const peers_len = peers_writer.buffered().len;
            @memcpy(all_nodes_peers[i][0..peers_len], peers_buf[0..peers_len]);
            all_nodes_peers[i][peers_len] = 0; // null terminate
        }

        // Start all nodes in parallel with full peer lists
        for (self.nodes.items, 0..) |*node, i| {
            const peers_len = std.mem.indexOf(u8, &all_nodes_peers[i], &[_]u8{0}) orelse 0;
            const peers = if (peers_len > 0) all_nodes_peers[i][0..peers_len] else "";

            try self.spawnNodeInternal(node, peers);
        }

        // Wait for all nodes to be ready
        var all_ready = false;
        var attempts: u32 = 0;
        const wait_timeout_ms: u64 = 10000; // 10 second total timeout

        const wait_start = nowMillis();
        while (!all_ready and nowMillis() - wait_start < wait_timeout_ms) {
            attempts += 1;
            all_ready = true;

            for (self.nodes.items) |*node| {
                if (!node.isRunning()) {
                    all_ready = false;
                    continue;
                }

                // Check if API is responding
                if (!tryConnect(node.api_port)) {
                    all_ready = false;
                }
            }

            if (!all_ready) {
                // Simple backoff with max 500ms
                const wait_ms: u64 = @min(50 * attempts, 500);
                std.Io.sleep(std.testing.io, std.Io.Duration.fromNanoseconds(@intCast(wait_ms * std.time.ns_per_ms)), .awake) catch unreachable;
            }
        }

        if (!all_ready) {
            std.debug.print("✗ Failed to start all nodes within timeout\n", .{});
            self.printDiagnostics();
            return error.NodeStartupTimeout;
        }

        std.debug.print("✓ All {d} nodes ready after {d}ms ({d} attempts)\n", .{ self.nodes.items.len, nowMillis() - start_time, attempts });
    }

    fn spawnNodeInternal(self: *TestCluster, node: *ClusterNode, peers: []const u8) !void {
        if (node.isRunning()) return;

        var env_map = std.process.Environ.Map.init(self.alloc);
        defer env_map.deinit();
        try env_map.put("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        try env_map.put("HOME", node.data_dir);
        try env_map.put("XDG_DATA_HOME", node.data_dir);

        const cwd = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", self.alloc);
        defer self.alloc.free(cwd);

        const id_str = try std.fmt.allocPrint(self.alloc, "{d}", .{node.id});
        defer self.alloc.free(id_str);
        const raft_port_str = try std.fmt.allocPrint(self.alloc, "{d}", .{node.raft_port});
        defer self.alloc.free(raft_port_str);
        const api_port_str = try std.fmt.allocPrint(self.alloc, "{d}", .{node.api_port});
        defer self.alloc.free(api_port_str);

        const child = try std.process.spawn(std.testing.io, .{
            .argv = &.{
                "zig-out/bin/yoq",
                "init-server",
                "--id",
                id_str,
                "--port",
                raft_port_str,
                "--api-port",
                api_port_str,
                "--peers",
                peers,
                "--token",
                self.join_token,
                "--api-token",
                self.api_token,
            },
            .stdin = .ignore,
            .stdout = .inherit,
            .stderr = .inherit,
            .environ_map = &env_map,
            .cwd = .{ .path = cwd },
        });
        node.process = child;
    }

    pub fn startNode(self: *TestCluster, node: *ClusterNode) !void {
        // Build full peer list for this node (all other nodes)
        var peers_buf: [512]u8 = undefined;
        var peers_writer: std.Io.Writer = .fixed(&peers_buf);

        var first = true;
        for (self.nodes.items) |other| {
            if (other.id == node.id) continue;

            if (!first) try peers_writer.writeByte(',');
            first = false;
            try peers_writer.print("{d}@127.0.0.1:{d}", .{
                other.id,
                other.raft_port,
            });
        }
        const peers = peers_writer.buffered();

        try self.spawnNodeInternal(node, peers);

        // Wait for ready
        var attempt: u32 = 0;
        while (attempt < 50) : (attempt += 1) {
            if (node.process != null) {
                if (tryConnect(node.api_port)) {
                    return;
                }
            }
            std.Io.sleep(std.testing.io, std.Io.Duration.fromNanoseconds(@intCast(200 * std.time.ns_per_ms)), .awake) catch unreachable;
        }

        std.debug.print("node {d} failed to become ready on api port {d}\n", .{ node.id, node.api_port });
        self.printDiagnostics();
        return error.NodeStartupTimeout;
    }

    pub fn stopAll(self: *TestCluster) void {
        for (self.nodes.items) |*node| {
            node.stop();
        }
    }

    pub fn stopNode(self: *TestCluster, node_id: u64) void {
        for (self.nodes.items) |*node| {
            if (node.id == node_id) {
                node.stop();
                return;
            }
        }
    }

    pub fn getNode(self: *TestCluster, node_id: u64) ?*ClusterNode {
        for (self.nodes.items) |*node| {
            if (node.id == node_id) return node;
        }
        return null;
    }

    pub fn getLeader(self: *TestCluster, timeout_ms: u64) !?*ClusterNode {
        const start_time = nowMillis();

        while (nowMillis() - start_time < timeout_ms) {
            for (self.nodes.items) |*node| {
                if (!node.isRunning()) continue;

                const status = self.getNodeStatus(node) catch continue;
                defer self.alloc.free(status);

                if (std.mem.indexOf(u8, status, "\"role\":\"leader\"") != null) {
                    return node;
                }
            }

            std.Io.sleep(std.testing.io, std.Io.Duration.fromNanoseconds(@intCast(100 * std.time.ns_per_ms)), .awake) catch unreachable;
        }

        return null;
    }

    pub fn getNodeStatus(self: *TestCluster, node: *ClusterNode) ![]const u8 {
        // Use the simple HTTP client from the cluster module
        const addr = [4]u8{ 127, 0, 0, 1 };

        var response = try http_client.getWithAuth(
            self.alloc,
            addr,
            node.api_port,
            "/cluster/status",
            self.api_token,
        );
        defer response.deinit(self.alloc);

        if (response.status_code != 200) {
            return error.RequestFailed;
        }

        // Duplicate the body for return
        const body = try self.alloc.dupe(u8, response.body);
        errdefer self.alloc.free(body);

        return body;
    }

    pub fn waitForLeader(self: *TestCluster, timeout_ms: u64) !*ClusterNode {
        const leader = try self.getLeader(timeout_ms);
        if (leader) |l| return l;
        std.debug.print("leader election timed out after {d}ms\n", .{timeout_ms});
        self.printDiagnostics();
        return error.LeaderElectionTimeout;
    }

    /// POST JSON to a node's API endpoint with auth.
    /// caller must free the returned body.
    pub fn postToNode(self: *TestCluster, node: *ClusterNode, path: []const u8, body: []const u8) !http_client.Response {
        const addr = [4]u8{ 127, 0, 0, 1 };
        return http_client.postWithAuth(
            self.alloc,
            addr,
            node.api_port,
            path,
            body,
            self.api_token,
        );
    }

    /// GET from a node's API endpoint with auth.
    /// caller must free the returned body.
    pub fn getFromNode(self: *TestCluster, node: *ClusterNode, path: []const u8) !http_client.Response {
        const addr = [4]u8{ 127, 0, 0, 1 };
        return http_client.getWithAuth(
            self.alloc,
            addr,
            node.api_port,
            path,
            self.api_token,
        );
    }

    pub fn verifyAllNodesAgreeOnLeader(self: *TestCluster) !bool {
        var leader_id: ?u64 = null;

        for (self.nodes.items) |*node| {
            if (!node.isRunning()) continue;

            const status = try self.getNodeStatus(node);
            defer self.alloc.free(status);

            // Extract leader ID from status
            if (std.mem.indexOf(u8, status, "\"role\":\"leader\"")) |_| {
                if (leader_id != null and leader_id != node.id) {
                    return false; // Multiple leaders!
                }
                leader_id = node.id;
            }
        }

        return leader_id != null;
    }

    /// kill a node with SIGKILL (not graceful). simulates a crash.
    pub fn killNode(self: *TestCluster, node_id: u64) void {
        const node = self.getNode(node_id) orelse return;
        if (node.process) |*proc| {
            // SIGKILL — no chance to clean up, simulates hard crash
            if (proc.id) |pid| _ = std.posix.kill(pid, .KILL) catch {};
            _ = proc.wait(std.testing.io) catch {};
            node.process = null;
        }
    }

    /// restart a killed node — kill (if running) then start with same config.
    pub fn restartNode(self: *TestCluster, node_id: u64) !void {
        const node = self.getNode(node_id) orelse return;
        self.killNode(node_id);
        try self.startNode(node);
    }

    /// wait until all running nodes agree on the same leader.
    /// returns the agreed-upon leader node, or error on timeout.
    pub fn waitForConvergence(self: *TestCluster, timeout_ms: u64) !*ClusterNode {
        const start_time = nowMillis();

        while (nowMillis() - start_time < timeout_ms) {
            var leader_id: ?u64 = null;
            var all_agree = true;
            var checked: u32 = 0;

            for (self.nodes.items) |*node| {
                if (!node.isRunning()) continue;

                const status = self.getNodeStatus(node) catch {
                    all_agree = false;
                    continue;
                };
                defer self.alloc.free(status);

                checked += 1;

                // extract leader_id from JSON — look for "leader_id":N
                if (std.mem.indexOf(u8, status, "\"role\":\"leader\"")) |_| {
                    if (leader_id == null) {
                        leader_id = node.id;
                    } else if (leader_id != node.id) {
                        all_agree = false; // multiple leaders
                    }
                } else if (std.mem.indexOf(u8, status, "\"role\":\"follower\"")) |_| {
                    // follower is fine — just make sure it knows about a leader
                } else {
                    all_agree = false; // candidate or unknown
                }
            }

            if (all_agree and leader_id != null and checked > 0) {
                return self.getNode(leader_id.?).?;
            }

            std.Io.sleep(std.testing.io, std.Io.Duration.fromNanoseconds(@intCast(200 * std.time.ns_per_ms)), .awake) catch unreachable;
        }

        return error.ConvergenceTimeout;
    }

    pub fn printDiagnostics(self: *TestCluster) void {
        std.debug.print("cluster diagnostics: tmp_dir={s} nodes={d}\n", .{ self.tmp_dir.slice(), self.nodes.items.len });
        for (self.nodes.items) |*node| {
            const running = node.isRunning();
            std.debug.print(
                "  node {d}: running={} raft_port={d} api_port={d} data_dir={s}\n",
                .{ node.id, running, node.raft_port, node.api_port, node.data_dir },
            );
            if (!running) continue;

            const status = self.getNodeStatus(node) catch |err| {
                std.debug.print("    status unavailable: {s}\n", .{@errorName(err)});
                continue;
            };
            defer self.alloc.free(status);
            std.debug.print("    status: {s}\n", .{status});
        }
    }
};

fn tryConnect(port: u16) bool {
    const addr = linux_platform.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, port);
    const fd = lposix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch return false;
    defer lposix.close(fd);
    lposix.connect(fd, &addr.any, addr.getOsSockLen()) catch return false;
    return true;
}

fn generateHexToken(buf: *[64]u8) !void {
    var rand_bytes: [32]u8 = undefined;
    std.Options.debug_io.random(&rand_bytes);
    _ = try std.fmt.bufPrint(buf, "{s}", .{std.fmt.bytesToHex(rand_bytes[0..], .lower)});
}

fn freeStrings(alloc: std.mem.Allocator, strings: []const []const u8) void {
    for (strings) |s| {
        alloc.free(s);
    }
}
