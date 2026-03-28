const proxy_runtime = @import("runtime.zig");
const steering_runtime = @import("steering_runtime.zig");

pub fn refreshIfEnabled() void {
    proxy_runtime.bootstrapIfEnabled();
    steering_runtime.syncIfEnabled();
}
