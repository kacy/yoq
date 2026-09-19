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
    // environment entries are owned. an unset bare name removes an inherited value.
    env: std.ArrayList([]const u8) = .empty,
    volume_specs: std.ArrayList(cli.VolumeMountSpec) = .empty,
    tmpfs_mounts: std.ArrayList(@import("../../filesystem.zig").TmpfsMount) = .empty,
    shm_size: u64 = @import("../../filesystem.zig").default_shm_size,
    networking_enabled: bool = true,
    container_name: ?[]const u8 = null,
    hostname: ?[]const u8 = null,
    entrypoint: ?[]const u8 = null,
    working_dir: ?[]const u8 = null,
    user: ?[]const u8 = null,
    pull_policy: @import("../../../image/commands.zig").PullPolicy = .missing,
    detach: bool = false,
    auto_remove: bool = false,
    interactive: bool = false,
    tty: bool = false,
    no_healthcheck: bool = false,
    health_command: ?[]const u8 = null,
    health_interval: ?i64 = null,
    health_timeout: ?i64 = null,
    health_start_period: ?i64 = null,
    health_start_interval: ?i64 = null,
    health_retries: ?i64 = null,
    network_name: ?[]const u8 = null,
    network_aliases: std.ArrayList([]const u8) = .empty,
    stop_signal: ?u8 = null,
    stop_timeout_seconds: u32 = 10,
    limits: cgroups.ResourceLimits = .{},
    restart_policy: run_state.RestartPolicy = .no,
    restart_max_retries: ?u32 = null,
    target: []const u8 = "",
    user_argv: std.ArrayList([]const u8) = .empty,

    pub fn deinit(self: *RunFlags, alloc: std.mem.Allocator) void {
        self.port_maps.deinit(alloc);
        self.network_aliases.deinit(alloc);
        for (self.env.items) |value| alloc.free(value);
        self.env.deinit(alloc);
        self.volume_specs.deinit(alloc);
        self.tmpfs_mounts.deinit(alloc);
        self.user_argv.deinit(alloc);
    }
};
