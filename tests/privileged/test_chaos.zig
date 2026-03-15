// test_chaos — chaos test scenarios for cluster resilience
//
// exercises failure modes: node crashes, leader failover, majority loss,
// and sequential restarts. requires root for container/namespace ops.
//
// these tests use SIGKILL to simulate hard crashes (not graceful shutdown)
// and verify the cluster recovers within bounded time.

const std = @import("std");
const helpers = @import("helpers");
const cluster_test_harness = @import("cluster_test_harness");

const TestCluster = cluster_test_harness.TestCluster;

fn initCluster(node_count: usize) !TestCluster {
    const alloc = std.testing.allocator;
    var cluster = try TestCluster.init(alloc, .{
        .node_count = node_count,
        .base_raft_port = 19800,
        .base_api_port = 17800,
    });
    errdefer cluster.deinit();
    try cluster.startAll();
    return cluster;
}

test "chaos: kill non-leader, verify cluster continues, restart and rejoin" {
    var cluster = try initCluster(3);
    defer cluster.deinit();

    // wait for initial leader election
    const leader = try cluster.waitForLeader(15000);
    const leader_id = leader.id;

    // find a non-leader node and kill it
    var victim_id: u64 = 0;
    for (cluster.nodes.items) |*node| {
        if (node.id != leader_id and node.isRunning()) {
            victim_id = node.id;
            break;
        }
    }
    try std.testing.expect(victim_id != 0);

    cluster.killNode(victim_id);
    try std.testing.expect(!cluster.getNode(victim_id).?.isRunning());

    // cluster should still have a leader (majority intact: 2 of 3)
    const still_leader = try cluster.waitForLeader(5000);
    try std.testing.expect(still_leader != null);

    // restart the killed node
    try cluster.restartNode(victim_id);
    try std.testing.expect(cluster.getNode(victim_id).?.isRunning());

    // wait for convergence — all nodes agree on leader
    _ = try cluster.waitForConvergence(15000);
}

test "chaos: kill leader, verify re-election within 15s" {
    var cluster = try initCluster(3);
    defer cluster.deinit();

    const old_leader = try cluster.waitForLeader(15000);
    const old_leader_id = old_leader.id;

    // kill the leader
    cluster.killNode(old_leader_id);
    try std.testing.expect(!cluster.getNode(old_leader_id).?.isRunning());

    // a new leader should be elected from the remaining 2 nodes
    const new_leader = try cluster.waitForLeader(15000);
    try std.testing.expect(new_leader.id != old_leader_id);
}

test "chaos: kill 2 of 5 nodes, verify cluster still operates" {
    var cluster = try initCluster(5);
    defer cluster.deinit();

    _ = try cluster.waitForLeader(15000);

    // kill 2 non-leader nodes (majority of 3 remains)
    var killed: u32 = 0;
    const leader = try cluster.waitForLeader(5000);
    for (cluster.nodes.items) |*node| {
        if (node.id != leader.id and node.isRunning() and killed < 2) {
            cluster.killNode(node.id);
            killed += 1;
        }
    }
    try std.testing.expectEqual(@as(u32, 2), killed);

    // cluster should still have a leader (3 of 5 alive = majority)
    _ = try cluster.waitForLeader(10000);
    try std.testing.expect(try cluster.verifyAllNodesAgreeOnLeader());
}

test "chaos: restart all nodes sequentially, verify zero-downtime" {
    var cluster = try initCluster(3);
    defer cluster.deinit();

    _ = try cluster.waitForLeader(15000);

    // restart each node one at a time
    for (cluster.nodes.items) |*node| {
        const node_id = node.id;
        try cluster.restartNode(node_id);

        // after each restart, cluster should still have a leader
        _ = try cluster.waitForLeader(15000);
    }

    // final convergence check
    _ = try cluster.waitForConvergence(15000);
}

test "chaos: rapid leader kill, verify recovery" {
    var cluster = try initCluster(3);
    defer cluster.deinit();

    // kill the leader twice in succession
    for (0..2) |_| {
        const leader = try cluster.waitForLeader(15000);
        cluster.killNode(leader.id);

        // wait a moment for re-election to start
        std.Thread.sleep(1000 * std.time.ns_per_ms);

        // restart the killed node
        try cluster.restartNode(leader.id);
    }

    // cluster should converge after the chaos
    _ = try cluster.waitForConvergence(20000);
}
