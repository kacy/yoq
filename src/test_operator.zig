const std = @import("std");

test "operator smoke root" {
    try std.testing.expect(true);
}

comptime {
    _ = @import("runtime/cli/status_command.zig");
    _ = @import("manifest/cli/ops.zig");
    _ = @import("manifest/release_history.zig");
    _ = @import("manifest/rollback_snapshot.zig");
    _ = @import("api/routes/cluster_agents/app_routes.zig");
}
