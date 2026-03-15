// test_stress — cluster stress tests
//
// validates correctness under concurrent load: simultaneous deploys,
// rapid heartbeats, concurrent API reads/writes, and repeated lifecycle
// operations. requires root for cluster operations.

const std = @import("std");
const helpers = @import("helpers");
const cluster_test_harness = @import("cluster_test_harness");
const http_client = @import("http_client");

const TestCluster = cluster_test_harness.TestCluster;

const alloc = std.testing.allocator;
const addr = [4]u8{ 127, 0, 0, 1 };

fn initCluster(count: usize) !TestCluster {
    var cluster = try TestCluster.init(alloc, .{
        .node_count = count,
        .base_raft_port = 19950,
        .base_api_port = 17950,
    });
    errdefer cluster.deinit();
    try cluster.startAll();
    return cluster;
}

test "stress: concurrent API reads don't degrade or crash" {
    var cluster = try initCluster(3);
    defer cluster.deinit();

    _ = try cluster.waitForLeader(15000);
    const port = cluster.nodes.items[0].api_port;
    const token = cluster.api_token;

    // launch 20 concurrent GET requests
    var threads: [20]std.Thread = undefined;
    var results: [20]u16 = undefined;
    var started: usize = 0;

    for (0..20) |i| {
        threads[i] = std.Thread.spawn(.{}, struct {
            fn run(p: u16, tok: []const u8, result: *u16) void {
                const a = std.heap.page_allocator;
                var resp = http_client.getWithAuth(a, addr, p, "/health", tok) catch {
                    result.* = 0;
                    return;
                };
                result.* = resp.status_code;
                resp.deinit(a);
            }
        }.run, .{ port, token, &results[i] }) catch continue;
        started += 1;
    }

    for (0..started) |i| {
        threads[i].join();
    }

    // all successful requests should get 200
    var success_count: usize = 0;
    for (0..started) |i| {
        if (results[i] == 200) success_count += 1;
    }

    // at least 80% should succeed
    try std.testing.expect(success_count >= started * 8 / 10);
}

test "stress: concurrent reads and writes don't crash" {
    var cluster = try initCluster(3);
    defer cluster.deinit();

    const leader = try cluster.waitForLeader(15000);
    const port = leader.api_port;
    const token = cluster.api_token;

    // mix of reads and writes concurrently
    var threads: [20]std.Thread = undefined;
    var results: [20]u16 = undefined;
    var started: usize = 0;

    for (0..20) |i| {
        const is_write = (i % 4 == 0);
        threads[i] = std.Thread.spawn(.{}, struct {
            fn run(p: u16, tok: []const u8, write: bool, result: *u16) void {
                const a = std.heap.page_allocator;
                if (write) {
                    // POST a deploy (will fail validation but shouldn't crash)
                    var resp = http_client.postWithAuth(a, addr, p, "/v1/deploy", "{}", tok) catch {
                        result.* = 0;
                        return;
                    };
                    result.* = resp.status_code;
                    resp.deinit(a);
                } else {
                    var resp = http_client.getWithAuth(a, addr, p, "/health", tok) catch {
                        result.* = 0;
                        return;
                    };
                    result.* = resp.status_code;
                    resp.deinit(a);
                }
            }
        }.run, .{ port, token, is_write, &results[i] }) catch continue;
        started += 1;
    }

    for (0..started) |i| {
        threads[i].join();
    }

    // no 500 errors
    for (0..started) |i| {
        if (results[i] != 0) {
            try std.testing.expect(results[i] != 500);
        }
    }
}

test "stress: cluster withstands rapid sequential requests" {
    var cluster = try initCluster(3);
    defer cluster.deinit();

    _ = try cluster.waitForLeader(15000);
    const port = cluster.nodes.items[0].api_port;
    const token = cluster.api_token;

    // 50 rapid sequential requests
    var success_count: usize = 0;
    for (0..50) |_| {
        var resp = http_client.getWithAuth(alloc, addr, port, "/health", token) catch continue;
        defer resp.deinit(alloc);
        if (resp.status_code == 200) success_count += 1;
    }

    // at least 90% should succeed
    try std.testing.expect(success_count >= 45);
}

test "stress: repeated cluster status queries are consistent" {
    var cluster = try initCluster(3);
    defer cluster.deinit();

    _ = try cluster.waitForLeader(15000);

    // query each node's status 10 times
    for (0..10) |_| {
        const agrees = cluster.verifyAllNodesAgreeOnLeader() catch false;
        if (!agrees) {
            // allow a brief window for convergence
            std.Thread.sleep(500 * std.time.ns_per_ms);
        }
    }

    // final check — should be converged
    try std.testing.expect(try cluster.verifyAllNodesAgreeOnLeader());
}
