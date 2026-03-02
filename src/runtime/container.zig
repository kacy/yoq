// container — container lifecycle management
//
// ties together namespaces, cgroups, filesystem, and security
// into a complete container abstraction. handles the full lifecycle:
// create, start, stop, remove.

const std = @import("std");
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
    /// working directory inside the container
    working_dir: []const u8 = "/",
    /// image layer paths for overlayfs (bottom to top)
    lower_dirs: []const []const u8 = &.{},
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

/// base directory for per-container overlay storage
const containers_subdir = ".local/share/yoq/containers";

/// paths to the overlay directories for a container
pub const OverlayDirs = struct {
    upper: [512]u8,
    upper_len: usize,
    work: [512]u8,
    work_len: usize,
    merged: [512]u8,
    merged_len: usize,

    pub fn upperPath(self: *const OverlayDirs) []const u8 {
        return self.upper[0..self.upper_len];
    }

    pub fn workPath(self: *const OverlayDirs) []const u8 {
        return self.work[0..self.work_len];
    }

    pub fn mergedPath(self: *const OverlayDirs) []const u8 {
        return self.merged[0..self.merged_len];
    }
};

/// create the per-container overlay directories:
///   ~/.local/share/yoq/containers/<id>/upper
///   ~/.local/share/yoq/containers/<id>/work
///   ~/.local/share/yoq/containers/<id>/rootfs  (merged mount point)
pub fn createContainerDirs(container_id: []const u8) ContainerError!OverlayDirs {
    const home = std.posix.getenv("HOME") orelse return ContainerError.CreateFailed;

    var dirs: OverlayDirs = undefined;

    const upper_slice = std.fmt.bufPrint(&dirs.upper, "{s}/{s}/{s}/upper", .{
        home, containers_subdir, container_id,
    }) catch return ContainerError.CreateFailed;
    dirs.upper_len = upper_slice.len;

    const work_slice = std.fmt.bufPrint(&dirs.work, "{s}/{s}/{s}/work", .{
        home, containers_subdir, container_id,
    }) catch return ContainerError.CreateFailed;
    dirs.work_len = work_slice.len;

    const merged_slice = std.fmt.bufPrint(&dirs.merged, "{s}/{s}/{s}/rootfs", .{
        home, containers_subdir, container_id,
    }) catch return ContainerError.CreateFailed;
    dirs.merged_len = merged_slice.len;

    // create all three directories (makePath creates parents too)
    std.fs.cwd().makePath(dirs.upperPath()) catch return ContainerError.CreateFailed;
    std.fs.cwd().makePath(dirs.workPath()) catch return ContainerError.CreateFailed;
    std.fs.cwd().makePath(dirs.mergedPath()) catch return ContainerError.CreateFailed;

    return dirs;
}

/// remove all per-container directories
pub fn cleanupContainerDirs(container_id: []const u8) void {
    const home = std.posix.getenv("HOME") orelse return;

    var path_buf: [512]u8 = undefined;
    const dir_path = std.fmt.bufPrint(&path_buf, "{s}/{s}/{s}", .{
        home, containers_subdir, container_id,
    }) catch return;

    std.fs.cwd().deleteTree(dir_path) catch {};
}

/// generate a short random container id (12 hex chars)
pub fn generateId(buf: *[12]u8) void {
    const chars = "0123456789abcdef";
    // use crypto random when available, fall back to timestamp-based LCG
    var bytes: [6]u8 = undefined;
    std.crypto.random.bytes(&bytes);

    for (bytes, 0..) |b, i| {
        buf[i * 2] = chars[b >> 4];
        buf[i * 2 + 1] = chars[b & 0x0f];
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
    try std.testing.expectEqualStrings("/", config.working_dir);
    try std.testing.expectEqual(@as(usize, 0), config.lower_dirs.len);
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

test "generate id varies between calls" {
    var id1: [12]u8 = undefined;
    var id2: [12]u8 = undefined;
    generateId(&id1);
    generateId(&id2);

    // two random IDs should (almost certainly) differ
    try std.testing.expect(!std.mem.eql(u8, &id1, &id2));
}
