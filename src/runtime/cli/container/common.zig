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
    port_maps: std.ArrayList(net_setup.PortMap) = .empty,
    // Environment entries are owned. A bare name removes an inherited variable.
    env: std.ArrayList([]const u8) = .empty,
    volume_specs: std.ArrayList(cli.VolumeMountSpec) = .empty,
    networking_enabled: bool = true,
    container_name: ?[]const u8 = null,
    hostname: ?[]const u8 = null,
    entrypoint: ?[]const u8 = null,
    working_dir: ?[]const u8 = null,
    user: ?[]const u8 = null,
    pull_policy: @import("../../../image/commands.zig").PullPolicy = .missing,
    detach: bool = false,
    limits: cgroups.ResourceLimits = .{},
    restart_policy: run_state.RestartPolicy = .no,
    target: []const u8 = "",
    user_argv: std.ArrayList([]const u8) = .empty,

    pub fn deinit(self: *RunFlags, alloc: std.mem.Allocator) void {
        self.port_maps.deinit(alloc);
        for (self.env.items) |value| alloc.free(value);
        self.env.deinit(alloc);
        self.volume_specs.deinit(alloc);
        self.user_argv.deinit(alloc);
    }
};
