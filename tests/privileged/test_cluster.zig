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

    // Wait for leader election (should happen within 5 seconds)
    const leader = try cluster.waitForLeader(5000);
    try std.testing.expect(leader != null);
    try std.testing.expect(leader.?.isRunning());

    // Verify all nodes see the same leader
    const all_agree = try cluster.verifyAllNodesAgreeOnLeader();
    try std.testing.expect(all_agree);

    std.debug.print("✓ Cluster formed successfully with {d} nodes, leader is node {d}\n", .{
        cluster.nodes.items.len,
        leader.?.id,
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
    const original_leader = try cluster.waitForLeader(5000);
    try std.testing.expect(original_leader != null);

    const original_leader_id = original_leader.?.id;
    std.debug.print("✓ Original leader is node {d}\n", .{original_leader_id});

    // Kill the leader
    cluster.stopNode(original_leader_id);
    std.debug.print("✓ Killed leader node {d}, waiting for new leader election...\n", .{original_leader_id});

    // Wait for new leader to be elected
    const new_leader = try cluster.waitForLeader(10000);
    try std.testing.expect(new_leader != null);
    try std.testing.expect(new_leader.?.id != original_leader_id);

    std.debug.print("✓ New leader elected: node {d}\n", .{new_leader.?.id});

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

    // With 5 nodes, election might take slightly longer
    const leader = try cluster.waitForLeader(8000);
    try std.testing.expect(leader != null);

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

fn fileExists(path: []const u8) bool {
    const file = std.fs.cwd().openFile(path, .{}) catch return false;
    file.close();
    return true;
}
