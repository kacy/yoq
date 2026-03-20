const std = @import("std");
const cli = @import("../../../lib/cli.zig");
const net_setup = @import("../../../network/setup.zig");
const cgroups = @import("../../cgroups.zig");
const run_state = @import("../../run_state.zig");

pub const ContainerError = error{
    InvalidArgument,
    NotSupported,
    ContainerNotFound,
    OutOfMemory,
    ProcessNotFound,
    ContainerRunning,
    InvalidStatus,
    StateUnknown,
    PullFailed,
    CommandResolveFailed,
    ConfigSaveFailed,
    InvalidLimits,
    StoreError,
};

pub const RunFlags = struct {
    port_maps: std.ArrayList(net_setup.PortMap),
    env: std.ArrayList([]const u8),
    volume_specs: std.ArrayList(cli.VolumeMountSpec),
    networking_enabled: bool,
    container_name: ?[]const u8,
    detach: bool,
    limits: cgroups.ResourceLimits,
    restart_policy: run_state.RestartPolicy,
    target: []const u8,
    user_argv: std.ArrayList([]const u8),

    pub fn deinit(self: *RunFlags, alloc: std.mem.Allocator) void {
        self.port_maps.deinit(alloc);
        self.env.deinit(alloc);
        self.volume_specs.deinit(alloc);
        self.user_argv.deinit(alloc);
    }
};
