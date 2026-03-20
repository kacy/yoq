const std = @import("std");

test "gpu smoke test" {
    try std.testing.expect(true);
}

comptime {
    _ = @import("gpu/env_buffer.zig");
    _ = @import("gpu/detect.zig");
    _ = @import("gpu/passthrough.zig");
    _ = @import("gpu/health.zig");
    _ = @import("gpu/scheduler.zig");
    _ = @import("gpu/mesh.zig");
    _ = @import("gpu/mig.zig");
    _ = @import("gpu/mps.zig");
    _ = @import("gpu/commands.zig");
    _ = @import("manifest/gpu_runtime.zig");
}
