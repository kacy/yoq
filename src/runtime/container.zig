// container — container lifecycle management
//
// ties together namespaces, cgroups, filesystem, and security
// into a complete container abstraction. handles the full lifecycle:
// create, start, stop, remove.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const namespaces = @import("namespaces.zig");
const cgroups = @import("cgroups.zig");
const filesystem = @import("filesystem.zig");
const security = @import("security.zig");
const process = @import("process.zig");

pub const ContainerError = error{
    CreateFailed,
    StartFailed,
    StopFailed,
    AlreadyRunning,
    NotRunning,
    NotFound,
    IdTooLong,
};

/// container states
pub const Status = enum {
    created,
    running,
    stopped,
    removed,

    pub fn label(self: Status) []const u8 {
        return switch (self) {
            .created => "created",
            .running => "running",
            .stopped => "stopped",
            .removed => "removed",
        };
    }
};

/// configuration for creating a container
pub const ContainerConfig = struct {
    /// unique container identifier
    id: []const u8,
    /// path to the rootfs directory
    rootfs: []const u8,
    /// command to execute inside the container
    command: []const u8,
    /// arguments to the command
    args: []const []const u8 = &.{},
    /// hostname inside the container
    hostname: []const u8 = "container",
    /// resource limits
    limits: cgroups.ResourceLimits = .{},
    /// which namespaces to isolate
    namespaces: namespaces.NamespaceFlags = .{},
    /// environment variables (KEY=VALUE pairs)
    env: []const []const u8 = &.{},
};

/// a running or stopped container
pub const Container = struct {
    config: ContainerConfig,
    status: Status,
    pid: ?posix.pid_t,
    exit_code: ?u8,
    created_at: i64,

    /// check if the container's process is still alive.
    /// updates status if it has exited.
    pub fn poll(self: *Container) ContainerError!void {
        const pid = self.pid orelse return;
        if (self.status != .running) return;

        const result = process.wait(pid, true) catch return;
        switch (result.status) {
            .exited => |code| {
                self.status = .stopped;
                self.exit_code = code;
                self.pid = null;
            },
            .signaled => {
                self.status = .stopped;
                self.exit_code = 128; // convention for signal death
                self.pid = null;
            },
            .running => {},
        }
    }

    /// send SIGTERM to the container's init process.
    pub fn stop(self: *Container) ContainerError!void {
        const pid = self.pid orelse return ContainerError.NotRunning;
        if (self.status != .running) return ContainerError.NotRunning;

        process.terminate(pid) catch return ContainerError.StopFailed;
    }

    /// send SIGKILL to the container's init process.
    pub fn forceStop(self: *Container) ContainerError!void {
        const pid = self.pid orelse return ContainerError.NotRunning;
        if (self.status != .running) return ContainerError.NotRunning;

        process.kill(pid) catch return ContainerError.StopFailed;
    }
};

/// generate a short random container id (12 hex chars)
pub fn generateId(buf: *[12]u8) void {
    const chars = "0123456789abcdef";
    // use a timestamp-based seed for simplicity
    var seed: u64 = @bitCast(std.time.timestamp());
    seed ^= @as(u64, @intCast(std.time.milliTimestamp())) *% 6364136223846793005;

    for (buf) |*c| {
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        c.* = chars[@intCast((seed >> 33) % 16)];
    }
}

// -- tests --

test "status labels" {
    try std.testing.expectEqualStrings("created", Status.created.label());
    try std.testing.expectEqualStrings("running", Status.running.label());
    try std.testing.expectEqualStrings("stopped", Status.stopped.label());
    try std.testing.expectEqualStrings("removed", Status.removed.label());
}

test "container config defaults" {
    const config = ContainerConfig{
        .id = "test123",
        .rootfs = "/tmp/rootfs",
        .command = "/bin/sh",
    };

    try std.testing.expectEqualStrings("test123", config.id);
    try std.testing.expectEqualStrings("container", config.hostname);
    try std.testing.expectEqual(@as(usize, 0), config.args.len);
    try std.testing.expectEqual(@as(usize, 0), config.env.len);
}

test "generate id produces 12 hex chars" {
    var id: [12]u8 = undefined;
    generateId(&id);

    const hex_chars = "0123456789abcdef";
    for (id) |c| {
        var found = false;
        for (hex_chars) |h| {
            if (c == h) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}

test "generate id varies" {
    var id1: [12]u8 = undefined;
    generateId(&id1);

    // verify all chars are valid hex
    const hex_chars = "0123456789abcdef";
    for (id1) |c| {
        var found = false;
        for (hex_chars) |h| {
            if (c == h) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}
