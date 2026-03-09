// cluster integration tests — multi-node cluster formation and leader election
//
// these tests spin up multiple yoq server nodes on localhost and verify
// that they form a working cluster with proper leader election.

const std = @import("std");
const helpers = @import("helpers");
const cluster_harness = @import("cluster_test_harness");

const alloc = std.testing.allocator;

// Skip these tests by default as they require the yoq binary to be built
// and take significant time to run. Enable with: zig test --test-filter "cluster"

test "3-node cluster forms and elects a leader" {
    // This test requires the yoq binary to be built
    const yoq_path = "zig-out/bin/yoq";
    if (!fileExists(yoq_path)) {
        std.debug.print("Skipping cluster test: yoq binary not found at {s}\n", .{yoq_path});
        return error.SkipZigTest;
    }

    var cluster = try cluster_harness.TestCluster.init(alloc, .{
        .node_count = 3,
        .base_raft_port = 29700, // Use different ports to avoid conflicts with other tests
        .base_api_port = 27700,
    });
    defer cluster.deinit();

    // Start all 3 nodes
    try cluster.startAll();

    // Wait for leader election with longer timeout since simultaneous startup
    // may need more time for randomized election timeouts to resolve
    const leader = try cluster.waitForLeader(15000);
    try std.testing.expect(leader.isRunning());

    // Verify all nodes see the same leader
    const all_agree = try cluster.verifyAllNodesAgreeOnLeader();
    try std.testing.expect(all_agree);

    std.debug.print("✓ Cluster formed successfully with {d} nodes, leader is node {d}\n", .{
        cluster.nodes.items.len,
        leader.id,
    });
}

test "cluster continues after leader failure" {
    const yoq_path = "zig-out/bin/yoq";
    if (!fileExists(yoq_path)) {
        std.debug.print("Skipping cluster test: yoq binary not found\n", .{});
        return error.SkipZigTest;
    }

    var cluster = try cluster_harness.TestCluster.init(alloc, .{
        .node_count = 3,
        .base_raft_port = 29710,
        .base_api_port = 27710,
    });
    defer cluster.deinit();

    // Start all nodes and wait for leader
    try cluster.startAll();
    const original_leader = try cluster.waitForLeader(15000);

    const original_leader_id = original_leader.id;
    std.debug.print("✓ Original leader is node {d}\n", .{original_leader_id});

    // Kill the leader
    cluster.stopNode(original_leader_id);
    std.debug.print("✓ Killed leader node {d}, waiting for new leader election...\n", .{original_leader_id});

    // Wait for new leader to be elected
    const new_leader = try cluster.waitForLeader(10000);
    try std.testing.expect(new_leader.id != original_leader_id);

    std.debug.print("✓ New leader elected: node {d}\n", .{new_leader.id});

    // Verify cluster is still functional
    const all_agree = try cluster.verifyAllNodesAgreeOnLeader();
    try std.testing.expect(all_agree);
}

test "cluster maintains consensus with 5 nodes" {
    const yoq_path = "zig-out/bin/yoq";
    if (!fileExists(yoq_path)) {
        std.debug.print("Skipping cluster test: yoq binary not found\n", .{});
        return error.SkipZigTest;
    }

    var cluster = try cluster_harness.TestCluster.init(alloc, .{
        .node_count = 5,
        .base_raft_port = 29720,
        .base_api_port = 27720,
    });
    defer cluster.deinit();

    try cluster.startAll();

    // With 5 nodes, election needs more time for randomized timeouts to resolve
    _ = try cluster.waitForLeader(20000);

    // Verify exactly one leader
    var leader_count: usize = 0;
    for (cluster.nodes.items) |*node| {
        const status = try cluster.getNodeStatus(node);
        defer alloc.free(status);

        if (std.mem.indexOf(u8, status, "\"role\":\"leader\"")) |_| {
            leader_count += 1;
        }
    }

    try std.testing.expectEqual(@as(usize, 1), leader_count);

    std.debug.print("✓ 5-node cluster formed with exactly 1 leader\n", .{});
}

test "leader replicates proposed data to followers" {
    const yoq_path = "zig-out/bin/yoq";
    if (!fileExists(yoq_path)) {
        std.debug.print("Skipping cluster test: yoq binary not found\n", .{});
        return error.SkipZigTest;
    }

    var cluster = try cluster_harness.TestCluster.init(alloc, .{
        .node_count = 3,
        .base_raft_port = 29730,
        .base_api_port = 27730,
    });
    defer cluster.deinit();

    try cluster.startAll();
    const leader = try cluster.waitForLeader(15000);

    // register an agent via the leader's API
    var body_buf: [512]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"token\":\"{s}\",\"address\":\"10.0.0.99:9090\",\"cpu_cores\":4,\"memory_mb\":8192}}", .{cluster.join_token}) catch unreachable;

    var post_resp = try cluster.postToNode(leader, "/agents/register", body);
    defer post_resp.deinit(alloc);
    try std.testing.expectEqual(@as(u16, 200), post_resp.status_code);

    // wait for replication
    std.Thread.sleep(3 * std.time.ns_per_s);

    // verify the agent appears on a follower
    var follower: ?*cluster_harness.ClusterNode = null;
    for (cluster.nodes.items) |*node| {
        if (node.id != leader.id and node.isRunning()) {
            follower = node;
            break;
        }
    }

    if (follower) |f| {
        var get_resp = try cluster.getFromNode(f, "/agents");
        defer get_resp.deinit(alloc);
        try std.testing.expectEqual(@as(u16, 200), get_resp.status_code);

        // the registered agent should appear in the follower's response
        try std.testing.expect(std.mem.indexOf(u8, get_resp.body, "10.0.0.99:9090") != null);

        std.debug.print("data replicated to follower\n", .{});
    }
}

test "5-node cluster survives minority failure" {
    const yoq_path = "zig-out/bin/yoq";
    if (!fileExists(yoq_path)) {
        std.debug.print("Skipping cluster test: yoq binary not found\n", .{});
        return error.SkipZigTest;
    }

    var cluster = try cluster_harness.TestCluster.init(alloc, .{
        .node_count = 5,
        .base_raft_port = 29740,
        .base_api_port = 27740,
    });
    defer cluster.deinit();

    try cluster.startAll();
    const leader = try cluster.waitForLeader(20000);

    // kill 2 non-leader nodes (minority)
    var killed: u32 = 0;
    for (cluster.nodes.items) |*node| {
        if (node.id != leader.id and killed < 2) {
            cluster.stopNode(node.id);
            killed += 1;
        }
    }

    // cluster should still have a leader (quorum of 3 from 5 met)
    std.Thread.sleep(2 * std.time.ns_per_s);
    const still_leader = try cluster.getLeader(5000);
    try std.testing.expect(still_leader != null);

    // verify status is queryable
    if (still_leader) |l| {
        const status = try cluster.getNodeStatus(l);
        defer alloc.free(status);
        try std.testing.expect(std.mem.indexOf(u8, status, "\"role\":\"leader\"") != null);
    }

    std.debug.print("5-node cluster survived 2 node failures\n", .{});
}

test "cluster loses quorum when majority fails" {
    const yoq_path = "zig-out/bin/yoq";
    if (!fileExists(yoq_path)) {
        std.debug.print("Skipping cluster test: yoq binary not found\n", .{});
        return error.SkipZigTest;
    }

    var cluster = try cluster_harness.TestCluster.init(alloc, .{
        .node_count = 5,
        .base_raft_port = 29750,
        .base_api_port = 27750,
    });
    defer cluster.deinit();

    try cluster.startAll();
    _ = try cluster.waitForLeader(20000);

    // kill 3 nodes (majority) — no quorum possible from remaining 2
    var killed: u32 = 0;
    for (cluster.nodes.items) |*node| {
        if (killed < 3) {
            cluster.stopNode(node.id);
            killed += 1;
        }
    }

    // wait for election timeout to expire
    std.Thread.sleep(5 * std.time.ns_per_s);

    // no leader should be elected (quorum of 3 not met with only 2 alive)
    const no_leader = try cluster.getLeader(5000);
    try std.testing.expect(no_leader == null);

    std.debug.print("cluster correctly lost quorum with 3/5 nodes down\n", .{});
}

fn fileExists(path: []const u8) bool {
    const file = std.fs.cwd().openFile(path, .{}) catch return false;
    file.close();
    return true;
}
