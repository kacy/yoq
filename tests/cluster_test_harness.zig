// cluster test harness — utilities for multi-node cluster testing
//
// provides TestCluster for orchestrating multiple yoq server nodes
// on localhost for integration testing. each node gets isolated
// data directories and unique ports.

const std = @import("std");
const helpers = @import("helpers");
const http_client = @import("http_client");

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
            _ = proc.kill() catch {};
            _ = proc.wait() catch {};
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

            try std.fs.cwd().makePath(data_dir);

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
        for (self.nodes.items) |*node| {
            try self.startNode(node);
        }
    }

    pub fn startNode(self: *TestCluster, node: *ClusterNode) !void {
        if (node.isRunning()) return;

        // Build peers string (all other nodes)
        var peers_buf: [512]u8 = undefined;
        var peers_stream = std.io.fixedBufferStream(&peers_buf);
        const peers_writer = peers_stream.writer();

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
        const peers = peers_stream.getWritten();

        var env_map = try std.process.getEnvMap(self.alloc);
        defer env_map.deinit();

        const cwd = try std.fs.cwd().realpathAlloc(self.alloc, ".");
        defer self.alloc.free(cwd);

        // Spawn yoq init-server process
        var child = std.process.Child.init(&.{
            "zig-out/bin/yoq",
            "init-server",
            "--id",
            try std.fmt.allocPrint(self.alloc, "{d}", .{node.id}),
            "--port",
            try std.fmt.allocPrint(self.alloc, "{d}", .{node.raft_port}),
            "--api-port",
            try std.fmt.allocPrint(self.alloc, "{d}", .{node.api_port}),
            "--peers",
            peers,
            "--token",
            self.join_token,
            "--api-token",
            self.api_token,
        }, self.alloc);

        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        child.env_map = &env_map;
        child.cwd = cwd;

        try child.spawn();
        node.process = child;

        // Wait a moment for the node to start
        std.Thread.sleep(500 * std.time.ns_per_ms);
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
        const start_time = std.time.milliTimestamp();

        while (std.time.milliTimestamp() - start_time < timeout_ms) {
            for (self.nodes.items) |*node| {
                if (!node.isRunning()) continue;

                const status = try self.getNodeStatus(node);
                if (std.mem.indexOf(u8, status, "\"role\":\"leader\"") != null) {
                    return node;
                }
            }

            std.Thread.sleep(100 * std.time.ns_per_ms);
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
        return error.LeaderElectionTimeout;
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
};

fn generateHexToken(buf: *[64]u8) !void {
    var rand_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&rand_bytes);
    _ = try std.fmt.bufPrint(buf, "{s}", .{std.fmt.bytesToHex(rand_bytes[0..], .lower)});
}

fn freeStrings(alloc: std.mem.Allocator, strings: []const []const u8) void {
    for (strings) |s| {
        alloc.free(s);
    }
}
