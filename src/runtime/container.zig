// container — container lifecycle management
//
// ties together namespaces, cgroups, filesystem, and security
// into a complete container abstraction. handles the full lifecycle:
// create, start, stop, remove.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const namespaces = @import("namespaces.zig");
const cgroups = @import("cgroups.zig");
const filesystem = @import("filesystem.zig");
const security = @import("security.zig");
const process = @import("process.zig");
const logs = @import("logs.zig");
const store = @import("../state/store.zig");
const paths = @import("../lib/paths.zig");
const net_setup = @import("../network/setup.zig");
const log = @import("../lib/log.zig");

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
    /// network configuration (bridge, port maps)
    network: ?net_setup.NetworkConfig = null,
};

/// a running or stopped container
pub const Container = struct {
    config: ContainerConfig,
    status: Status,
    pid: ?posix.pid_t,
    exit_code: ?u8,
    created_at: i64,
    net_info: ?net_setup.NetworkInfo = null,

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

    /// start the container: set up filesystem, spawn process in namespaces,
    /// capture logs, and block until the process exits.
    pub fn start(self: *Container) ContainerError!void {
        const config = self.config;
        const has_overlay = config.lower_dirs.len > 0;

        // create overlay directories if we have image layers
        var dirs: ?OverlayDirs = null;
        if (has_overlay) {
            dirs = createContainerDirs(config.id) catch return ContainerError.StartFailed;
        }

        // build filesystem config for the child
        const fs_config: filesystem.FilesystemConfig = if (dirs) |*d| .{
            .lower_dirs = config.lower_dirs,
            .upper_dir = d.upperPath(),
            .work_dir = d.workPath(),
            .merged_dir = d.mergedPath(),
        } else .{
            .lower_dirs = &.{},
            .upper_dir = "",
            .work_dir = "",
            .merged_dir = "",
        };

        // prepare child execution context
        // lives on our stack, gets copied to child's address space via clone3
        var child_ctx = ChildExecContext{
            .has_overlay = has_overlay,
            .fs_config = fs_config,
            .rootfs = config.rootfs,
            .command = config.command,
            .args = config.args,
            .env = config.env,
            .working_dir = config.working_dir,
            .hostname = config.hostname,
        };

        // create cgroup (non-fatal — container runs without limits if this fails)
        var cgroup: ?cgroups.Cgroup = cgroups.Cgroup.create(config.id) catch |e| blk: {
            log.warn("cgroup setup failed for {s}: {}", .{ config.id, e });
            break :blk null;
        };

        // spawn the container process in isolated namespaces.
        // the child blocks until we call signalReady(), giving us time
        // to set up networking before it proceeds.
        var spawn_result = namespaces.spawn(
            config.namespaces,
            null,
            childMain,
            @ptrCast(&child_ctx),
        ) catch {
            if (has_overlay) cleanupContainerDirs(config.id);
            if (cgroup) |*cg| cg.destroy() catch {};
            return ContainerError.StartFailed;
        };

        self.pid = spawn_result.pid;
        self.status = .running;

        // add child to cgroup and set resource limits
        if (cgroup) |*cg| {
            cg.addProcess(spawn_result.pid) catch |e| {
                log.warn("failed to add process to cgroup for {s}: {}", .{ config.id, e });
            };
            cg.setLimits(config.limits) catch |e| {
                log.warn("failed to set cgroup limits for {s}: {}", .{ config.id, e });
            };
        }

        // set up container networking (non-fatal — container works without it)
        if (config.network) |net_config| {
            var db = store.openDb() catch null;
            defer if (db) |*d| d.deinit();

            if (db) |*d| {
                if (net_setup.setupContainer(config.id, spawn_result.pid, net_config, d)) |info| {
                    self.net_info = info;

                    // persist network info in the database
                    var ip_buf: [16]u8 = undefined;
                    const ip_str = @import("../network/ip.zig").formatIp(info.ip, &ip_buf);
                    store.updateNetwork(config.id, ip_str, info.vethName()) catch |e| {
                        log.warn("failed to persist network info for {s}: {}", .{ config.id, e });
                    };

                    // write resolv.conf and hosts into the rootfs
                    if (dirs) |*overlay_dirs| {
                        net_setup.writeNetworkFiles(
                            overlay_dirs.mergedPath(),
                            info.ip,
                            config.hostname,
                        );
                    }
                } else |_| {
                    // networking failed, but container can still run
                }
            }
        }

        // signal child that all parent-side setup is complete
        spawn_result.signalReady();

        // open log file and start capture threads
        const log_file = logs.createLogFile(config.id) catch null;
        const stdout_label: []const u8 = "stdout";
        const stderr_label: []const u8 = "stderr";

        var stdout_thread: ?std.Thread = null;
        var stderr_thread: ?std.Thread = null;

        if (log_file) |lf| {
            stdout_thread = std.Thread.spawn(.{}, logs.captureStream, .{
                lf, spawn_result.stdout_fd, stdout_label,
            }) catch null;
            stderr_thread = std.Thread.spawn(.{}, logs.captureStream, .{
                lf, spawn_result.stderr_fd, stderr_label,
            }) catch null;
        }

        // close pipe fds that aren't being captured by a thread
        if (stdout_thread == null) posix.close(spawn_result.stdout_fd);
        if (stderr_thread == null) posix.close(spawn_result.stderr_fd);

        // update sqlite to "running"
        store.updateStatus(config.id, "running", spawn_result.pid, null) catch |e| {
            log.warn("failed to update status for {s}: {}", .{ config.id, e });
        };

        // block until the child exits
        const wait_result = process.wait(spawn_result.pid, false) catch {
            self.status = .stopped;
            self.exit_code = 255;
            store.updateStatus(config.id, "stopped", null, 255) catch {};
            return;
        };

        // determine exit code
        const exit_code: u8 = switch (wait_result.status) {
            .exited => |code| code,
            .signaled => 128,
            .running => 0,
        };

        self.status = .stopped;
        self.exit_code = exit_code;
        self.pid = null;

        // join log capture threads and close log file
        if (stdout_thread) |t| t.join();
        if (stderr_thread) |t| t.join();
        if (log_file) |lf| lf.close();

        // tear down networking
        if (self.net_info) |*info| {
            if (config.network) |net_config| {
                var db = store.openDb() catch null;
                defer if (db) |*d| d.deinit();
                if (db) |*d| {
                    net_setup.teardownContainer(config.id, info, net_config, d);
                }
            }
        }

        // destroy cgroup
        if (cgroup) |*cg| cg.destroy() catch {};

        // update sqlite with final status
        store.updateStatus(config.id, "stopped", null, exit_code) catch |e| {
            log.warn("failed to update final status for {s}: {}", .{ config.id, e });
        };
    }
};

// -- child process functions --
//
// these run inside the container's process after clone3.
// no heap allocation — everything uses stack buffers.
// this is critical because the heap is in an undefined state
// after clone3 (shared allocator metadata, no fork handler).

/// context passed to the child process after clone3.
/// contains everything needed to set up the container environment and exec.
const ChildExecContext = struct {
    has_overlay: bool,
    fs_config: filesystem.FilesystemConfig,
    rootfs: []const u8,
    command: []const u8,
    args: []const []const u8,
    env: []const []const u8,
    working_dir: []const u8,
    hostname: []const u8,
};

/// child process entry point (called after namespace creation).
/// sets up filesystem, security, and execs the container command.
/// returns 127 if exec fails (convention for "command not found").
fn childMain(arg: ?*anyopaque) callconv(.c) u8 {
    const ctx: *const ChildExecContext = @ptrCast(@alignCast(arg));

    // 1. set up filesystem
    if (ctx.has_overlay) {
        filesystem.mountOverlay(ctx.fs_config) catch return 1;
        filesystem.pivotRoot(ctx.fs_config.merged_dir) catch return 1;
    } else {
        filesystem.pivotRoot(ctx.rootfs) catch return 1;
    }

    // 2. mount essential filesystems (/proc, /dev, /sys, /tmp)
    filesystem.mountEssential() catch return 1;

    // 3. set hostname
    setHostname(ctx.hostname);

    // 4. chdir to working directory (fall back to / if it doesn't exist)
    posix.chdir(ctx.working_dir) catch {
        posix.chdir("/") catch {};
    };

    // 5. apply security restrictions (capabilities + seccomp)
    // must be after filesystem setup since mounting requires caps
    security.apply() catch return 1;

    // 6. exec the container command
    return execCommand(ctx.command, ctx.args, ctx.env);
}

/// build null-terminated argv and envp arrays on the stack and call execve.
/// uses a ~64KB stack buffer to avoid heap allocation in the child.
/// returns 127 if exec fails.
fn execCommand(command: []const u8, args: []const []const u8, env: []const []const u8) u8 {
    var str_buf: [65536]u8 = undefined;
    var str_pos: usize = 0;

    // argv: command + args + null terminator (max 256 entries)
    var argv: [257]?[*:0]const u8 = .{null} ** 257;
    argv[0] = packString(&str_buf, &str_pos, command) orelse return 127;

    var argv_idx: usize = 1;
    for (args) |arg| {
        if (argv_idx >= argv.len - 1) break;
        argv[argv_idx] = packString(&str_buf, &str_pos, arg) orelse return 127;
        argv_idx += 1;
    }

    // envp: env vars + null terminator (max 256 entries)
    var envp: [257]?[*:0]const u8 = .{null} ** 257;
    for (env, 0..) |e, i| {
        if (i >= envp.len - 1) break;
        envp[i] = packString(&str_buf, &str_pos, e) orelse return 127;
    }

    // replace this process with the container command
    _ = linux.syscall3(
        .execve,
        @intFromPtr(argv[0].?),
        @intFromPtr(&argv),
        @intFromPtr(&envp),
    );

    // if we get here, exec failed
    return 127;
}

/// copy a string into a buffer and null-terminate it.
/// returns a pointer suitable for execve argv/envp, or null if buffer is full.
fn packString(buf: *[65536]u8, pos: *usize, src: []const u8) ?[*:0]const u8 {
    if (pos.* + src.len + 1 > buf.len) return null;
    @memcpy(buf[pos.*..][0..src.len], src);
    buf[pos.* + src.len] = 0;
    const result: [*:0]const u8 = @ptrCast(&buf[pos.*]);
    pos.* += src.len + 1;
    return result;
}

/// set the container hostname via the sethostname syscall
fn setHostname(name: []const u8) void {
    if (name.len == 0) return;
    _ = linux.syscall2(.sethostname, @intFromPtr(name.ptr), name.len);
}

/// base directory for per-container overlay storage
const containers_subdir = "containers";

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
    var dirs: OverlayDirs = undefined;

    const upper_slice = paths.dataPathFmt(&dirs.upper, "{s}/{s}/upper", .{
        containers_subdir, container_id,
    }) catch return ContainerError.CreateFailed;
    dirs.upper_len = upper_slice.len;

    const work_slice = paths.dataPathFmt(&dirs.work, "{s}/{s}/work", .{
        containers_subdir, container_id,
    }) catch return ContainerError.CreateFailed;
    dirs.work_len = work_slice.len;

    const merged_slice = paths.dataPathFmt(&dirs.merged, "{s}/{s}/rootfs", .{
        containers_subdir, container_id,
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
    var path_buf: [paths.max_path]u8 = undefined;
    const dir_path = paths.dataPathFmt(&path_buf, "{s}/{s}", .{
        containers_subdir, container_id,
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
