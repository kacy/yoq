const std = @import("std");

test "network smoke root" {
    try std.testing.expect(true);
}

comptime {
    _ = @import("api/routes/status_metrics.zig");
    _ = @import("network/service_registry_bridge.zig");
    _ = @import("network/service_reconciler.zig");
    _ = @import("network/service_rollout.zig");
}
