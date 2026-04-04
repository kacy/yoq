const std = @import("std");

test "simulation smoke test" {
    try std.testing.expect(true);
}

comptime {
    _ = @import("cluster/raft.zig");
    _ = @import("cluster/gossip.zig");
    _ = @import("cluster/gossip_sender_validation.zig");
    _ = @import("test_cluster_sim.zig");
}
