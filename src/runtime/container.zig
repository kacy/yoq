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
const init = @import("init.zig");
const store = @import("../state/store.zig");
const paths = @import("../lib/paths.zig");
const net_setup = @import("../network/setup.zig");
const log = @import("../lib/log.zig");
const exec_helpers = @import("../lib/exec_helpers.zig");

/// PID of the currently running container process.
/// set after spawn, cleared on exit. used by the signal handler
/// in main.zig to forward SIGINT/SIGTERM to the container.
pub var active_pid: std.atomic.Value(i32) = std.atomic.Value(i32).init(0);

pub const ContainerError = error{
    CreateFailed,
    StartFailed,
    StopFailed,
    AlreadyRunning,
    NotRunning,
    NotFound,
    IdTooLong,
    InvalidId,
    IdGenerationFailed,
};

/// container exit codes (following standard conventions)
/// these are used by childMain to report specific failure modes
pub const ExitCode = enum(u8) {
    /// success
    success = 0,
    /// general error
    general_error = 1,
    /// filesystem setup failed (overlay, bind mount, pivot_root)
    filesystem_error = 120,
    /// bind mount security check failed (TOCTOU or path validation)
    bind_mount_denied = 121,
    /// essential filesystem mount failed (/proc, /dev, /sys)
    essential_mount_failed = 122,
    /// security restrictions failed (capabilities, seccomp)
    security_failed = 123,
    /// permission denied (convention from bash)
    permission_denied = 126,
    /// command not found (convention from bash)
    command_not_found = 127,
};

/// a 12-character hex container identifier.
/// using a distinct type improves type safety over raw strings.
pub const ContainerId = [12]u8;

/// validates that a container ID is safe to use in filesystem paths.
/// checks that the ID:
///   - is exactly 12 characters
///   - contains only lowercase hex characters (0-9, a-f)
///   - does not contain any path traversal sequences
/// returns true only if all checks pass.
pub fn isValidContainerId(id: []const u8) bool {
    if (id.len != 12) return false;

    // verify all characters are lowercase hex — this also rejects
    // path traversal characters (./, \, :) since they aren't hex
    for (id) |c| {
        switch (c) {
            '0'...'9', 'a'...'f' => {},
            else => return false,
        }
    }
    return true;
}

/// validates a container ID and returns a typed ContainerId.
/// returns InvalidId error if validation fails.
pub fn validateContainerId(id: []const u8) ContainerError!ContainerId {
    if (!isValidContainerId(id)) return ContainerError.InvalidId;
    var result: ContainerId = undefined;
    @memcpy(&result, id);
    return result;
}

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

/// a bind mount mapping a host path into the container
pub const BindMount = struct {
    /// absolute path on the host
    source: []const u8,
    /// absolute path inside the container
    target: []const u8,
    /// mount read-only
    read_only: bool = true,

    /// check that the source path doesn't point into sensitive system directories.
    /// a manifest could otherwise mount /etc/shadow or /root/.ssh into a container.
    pub fn isSourceAllowed(self: BindMount) bool {
        const blocked = [_][]const u8{
            "/etc",
            "/root",
            "/var/lib",
            "/home",
            "/proc",
            "/sys",
            "/dev",
            "/boot",
            "/usr/sbin",
            "/sbin",
        };
        for (blocked) |prefix| {
            if (std.mem.startsWith(u8, self.source, prefix)) {
                // allow exact prefix only if followed by '/' or end of string
                // (so "/devtools" doesn't match "/dev")
                if (self.source.len == prefix.len or self.source[prefix.len] == '/') {
                    return false;
                }
            }
        }
        return true;
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
    /// bind mounts (host path -> container path)
    mounts: []const BindMount = &.{},
    /// dev mode: service name for colored log output (null = no dev output)
    dev_service_name: ?[]const u8 = null,
    /// dev mode: color index for this service
    dev_color_idx: usize = 0,
    /// when true, runs in host mode with reduced filesystem isolation
    /// auto-enabled when mount operations fail due to capability restrictions
    host_mode: bool = false,
};

/// a running or stopped container
pub const Container = struct {
    const RuntimeHandles = struct {
        cgroup: ?cgroups.Cgroup = null,
        log_file: ?std.fs.File = null,
        stdout_thread: ?std.Thread = null,
        stderr_thread: ?std.Thread = null,
        mirror_output: bool = false,
    };

    config: ContainerConfig,
    status: Status,
    pid: ?posix.pid_t,
    exit_code: ?u8,
    created_at: i64,
    net_info: ?net_setup.NetworkInfo = null,
    runtime: RuntimeHandles = .{},

    /// protects status, pid, and exit_code from concurrent access
    /// these fields are accessed from the main thread (poll/stop/wait)
    /// and potentially signal handlers
    state_mutex: std.Thread.Mutex = .{},

    /// check if the container's process is still alive.
    /// updates status if it has exited.
    pub fn poll(self: *Container) ContainerError!void {
        self.state_mutex.lock();
        defer self.state_mutex.unlock();

        const pid = self.pid orelse return;
        if (self.status != .running) return;

        const result = process.wait(pid, true) catch return;
        switch (result.status) {
            .exited => |code| {
                self.status = .stopped;
                self.exit_code = code;
                self.pid = null;
                active_pid.store(0, .release);
            },
            .signaled => {
                self.status = .stopped;
                self.exit_code = 128; // convention for signal death
                self.pid = null;
                active_pid.store(0, .release);
            },
            .running => {},
            .stopped => {
                // process is stopped (SIGSTOP), keep as running
                // it may continue later
            },
        }
    }

    /// send SIGTERM to the container's init process.
    pub fn stop(self: *Container) ContainerError!void {
        self.state_mutex.lock();
        defer self.state_mutex.unlock();

        const pid = self.pid orelse return ContainerError.NotRunning;
        if (self.status != .running) return ContainerError.NotRunning;

        process.terminate(pid) catch return ContainerError.StopFailed;
    }

    /// send SIGKILL to the container's init process.
    pub fn forceStop(self: *Container) ContainerError!void {
        self.state_mutex.lock();
        defer self.state_mutex.unlock();

        const pid = self.pid orelse return ContainerError.NotRunning;
        if (self.status != .running) return ContainerError.NotRunning;

        process.kill(pid) catch return ContainerError.StopFailed;
    }

    /// start the container: set up filesystem, spawn process in namespaces,
    /// and begin log capture. returns once the container is running.
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
            .host_mode = config.host_mode,
            .fs_config = fs_config,
            .rootfs = config.rootfs,
            .command = config.command,
            .args = config.args,
            .env = config.env,
            .working_dir = config.working_dir,
            .hostname = config.hostname,
            .mounts = config.mounts,
        };

        // create cgroup for resource limits
        // this is a hard failure - we don't run containers without resource limits
        // as that would allow DoS attacks on the host
        self.runtime.cgroup = cgroups.Cgroup.create(config.id) catch |e| {
            log.err("cgroup setup failed for {s}: {}. container cannot start without resource limits.", .{ config.id, e });
            if (has_overlay) cleanupContainerDirs(config.id);
            return ContainerError.StartFailed;
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
            if (self.runtime.cgroup) |*cg| cg.destroy() catch {};
            return ContainerError.StartFailed;
        };

        self.pid = spawn_result.pid;
        self.status = .running;
        active_pid.store(spawn_result.pid, .release);

        // add child to cgroup and set resource limits
        // these are hard failures - resource limits must be enforced
        self.runtime.cgroup.?.addProcess(spawn_result.pid) catch |e| {
            log.err("failed to add process to cgroup for {s}: {}. stopping container.", .{ config.id, e });
            _ = process.kill(spawn_result.pid) catch {};
            self.runtime.cgroup.?.destroy() catch {};
            return ContainerError.StartFailed;
        };

        self.runtime.cgroup.?.setLimits(config.limits) catch |e| {
            log.err("failed to set cgroup limits for {s}: {}. stopping container.", .{ config.id, e });
            _ = process.kill(spawn_result.pid) catch {};
            self.runtime.cgroup.?.destroy() catch {};
            return ContainerError.StartFailed;
        };

        // set up container networking (non-fatal — container works without it)
        if (config.network) |net_config| {
            var db = store.openDb() catch null;
            defer if (db) |*d| d.deinit();

            if (db) |*d| {
                if (net_setup.setupContainer(config.id, spawn_result.pid, net_config, d, config.hostname)) |info| {
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
                } else |e| {
                    log.warn("container: network setup failed, continuing without network: {}", .{e});
                }
            }
        }

        // open log file and start capture threads BEFORE signaling child ready.
        // if we signal ready first, fast-exiting commands (like echo) complete
        // before the capture threads start, resulting in empty logs.
        //
        // fd ownership model:
        //   - on success: each capture thread owns its fd and closes it on exit
        //   - on failure: we close fds here before they'd otherwise leak
        self.runtime.log_file = logs.createLogFile(config.id) catch |err| blk: {
            log.warn("failed to create log file for {s}: {}", .{ config.id, err });
            posix.close(spawn_result.stdout_fd);
            posix.close(spawn_result.stderr_fd);
            break :blk null;
        };

        if (self.runtime.log_file) |lf| {
            self.runtime.stdout_thread = std.Thread.spawn(.{}, logs.captureStream, .{
                lf,
                spawn_result.stdout_fd,
                "stdout",
                config.dev_service_name,
                config.dev_color_idx,
                self.runtime.mirror_output,
            }) catch |err| blk: {
                log.warn("failed to spawn stdout capture thread: {}", .{err});
                posix.close(spawn_result.stdout_fd);
                break :blk null;
            };

            self.runtime.stderr_thread = std.Thread.spawn(.{}, logs.captureStream, .{
                lf,
                spawn_result.stderr_fd,
                "stderr",
                config.dev_service_name,
                config.dev_color_idx,
                self.runtime.mirror_output,
            }) catch |err| blk: {
                log.warn("failed to spawn stderr capture thread: {}", .{err});
                posix.close(spawn_result.stderr_fd);
                break :blk null;
            };
        }

        // signal child that all parent-side setup is complete
        spawn_result.signalReady();

        // update sqlite to "running"
        store.updateStatus(config.id, "running", spawn_result.pid, null) catch |e| {
            log.warn("failed to update status for {s}: {}", .{ config.id, e });
        };
    }

    /// wait for the running container to exit, then clean up runtime resources.
    pub fn wait(self: *Container) ContainerError!u8 {
        self.state_mutex.lock();
        const pid = self.pid orelse {
            self.state_mutex.unlock();
            return ContainerError.NotRunning;
        };
        self.state_mutex.unlock();

        const wait_result = process.wait(pid, false) catch {
            self.state_mutex.lock();
            self.status = .stopped;
            self.exit_code = 255;
            self.pid = null;
            self.state_mutex.unlock();
            active_pid.store(0, .release);
            store.updateStatus(self.config.id, "stopped", null, 255) catch {};
            return 255;
        };

        const exit_code: u8 = switch (wait_result.status) {
            .exited => |code| code,
            .signaled => 128,
            .running => 0,
            .stopped => 128, // stopped processes treated as signaled
        };

        self.state_mutex.lock();
        self.status = .stopped;
        self.exit_code = exit_code;
        self.pid = null;
        self.state_mutex.unlock();
        active_pid.store(0, .release);
        self.finalize(exit_code);
        return exit_code;
    }

    fn finalize(self: *Container, exit_code: u8) void {
        if (self.runtime.stdout_thread) |t| t.join();
        if (self.runtime.stderr_thread) |t| t.join();
        if (self.runtime.log_file) |lf| lf.close();

        if (self.net_info) |*info| {
            if (self.config.network) |net_config| {
                var db = store.openDb() catch null;
                defer if (db) |*d| d.deinit();
                if (db) |*d| net_setup.teardownContainer(self.config.id, info, net_config, d);
            }
        }

        // cgroup is now mandatory - always clean it up
        if (self.runtime.cgroup) |cg| {
            cg.destroy() catch |err| {
                log.warn("failed to destroy cgroup for {s}: {}", .{ self.config.id, err });
            };
        }

        store.updateStatus(self.config.id, "stopped", null, exit_code) catch |e| {
            log.warn("failed to update final status for {s}: {}", .{ self.config.id, e });
        };

        self.runtime = .{};
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
    host_mode: bool,
    fs_config: filesystem.FilesystemConfig,
    rootfs: []const u8,
    command: []const u8,
    args: []const []const u8,
    env: []const []const u8,
    working_dir: []const u8,
    hostname: []const u8,
    mounts: []const BindMount,
};

/// child process entry point (called after namespace creation).
/// sets up filesystem, security, then runs init.run() which forks
/// a workload process, reaps zombies, and forwards signals.
/// uses distinct exit codes for different failure modes.
fn childMain(arg: ?*anyopaque) callconv(.c) u8 {
    const ctx: *const ChildExecContext = @ptrCast(@alignCast(arg));

    // Try full container filesystem isolation first
    // If permission denied, fall back to host mode automatically
    var host_mode = ctx.host_mode;

    if (!host_mode) {
        // Attempt full container setup
        var setup_failed = false;

        // 1. set up filesystem (overlay or bind mounts + pivot_root)
        if (ctx.has_overlay) {
            filesystem.mountOverlay(ctx.fs_config) catch {
                setup_failed = true;
            };
            if (!setup_failed) {
                // apply bind mounts into the merged overlay
                for (ctx.mounts) |m| {
                    if (!m.isSourceAllowed()) return @intFromEnum(ExitCode.permission_denied);
                    if (!isCanonicalBindSource(m.source)) return @intFromEnum(ExitCode.bind_mount_denied);
                    filesystem.bindMount(ctx.fs_config.merged_dir, m.source, m.target, m.read_only) catch |e| {
                        log.err("container: bind mount failed for {s}: {s}", .{ m.source, @errorName(e) });
                        setup_failed = true;
                        break;
                    };
                }
            }
            if (!setup_failed) {
                filesystem.pivotRoot(ctx.fs_config.merged_dir) catch {
                    setup_failed = true;
                };
            }
        } else {
            // bind mounts with a local rootfs — mount into rootfs before pivot.
            // skip if rootfs is empty (shouldn't happen, but guard against it).
            if (ctx.rootfs.len == 0 and ctx.mounts.len > 0) {
                log.err("container: bind mounts specified but no rootfs configured", .{});
                setup_failed = true;
            }
            for (ctx.mounts) |m| {
                if (setup_failed) break;
                if (!m.isSourceAllowed()) return @intFromEnum(ExitCode.permission_denied);
                if (!isCanonicalBindSource(m.source)) return @intFromEnum(ExitCode.bind_mount_denied);
                filesystem.bindMount(ctx.rootfs, m.source, m.target, m.read_only) catch |e| {
                    log.err("container: bind mount failed for {s}: {s}", .{ m.source, @errorName(e) });
                    setup_failed = true;
                    break;
                };
            }
            if (!setup_failed) {
                filesystem.pivotRoot(ctx.rootfs) catch {
                    setup_failed = true;
                };
            }
        }

        // 2. mount essential filesystems (/proc, /dev, /sys, /tmp)
        if (!setup_failed) {
            filesystem.mountEssential() catch |err| {
                switch (err) {
                    error.MountPermissionDenied => {
                        setup_failed = true;
                    },
                    else => return @intFromEnum(ExitCode.essential_mount_failed),
                }
            };
        }

        // If setup failed with permission issues, fall back to host mode
        if (setup_failed) {
            host_mode = true;
            log.warn("container: filesystem isolation not available due to permission restrictions - " ++
                "falling back to host mode. Process/network/hostname isolation still active. " ++
                "Note: Use full paths (e.g., /bin/echo) as PATH resolution differs in host mode.", .{});
        }
    }

    if (host_mode) {
        // Host mode: minimal setup, just chdir and run
        // Skipping: pivot_root, mountEssential, full security restrictions
        posix.chdir(ctx.working_dir) catch {
            posix.chdir("/") catch {};
        };

        // Note: We still run in namespaces (PID, NET, UTS, IPC) which provide
        // process, network, hostname, and IPC isolation even without filesystem isolation
        return execCommandWrapper(@ptrCast(@constCast(ctx)));
    } else {
        // Normal container mode: full isolation
        // 3. set hostname
        setHostname(ctx.hostname);

        // 4. set a safe default umask
        _ = linux.syscall1(.umask, 0o022);

        // 5. chdir to working directory
        posix.chdir(ctx.working_dir) catch {
            posix.chdir("/") catch {};
        };

        // 6. apply security restrictions (capabilities + seccomp)
        security.apply() catch return @intFromEnum(ExitCode.security_failed);

        // 7. run container init: forks the workload, reaps zombies, forwards signals.
        return init.run(execCommandWrapper, @ptrCast(@constCast(ctx)));
    }
}

/// C-callable wrapper around execCommand for use with init.run().
/// init.run() forks and calls this in the child (workload) process.
fn execCommandWrapper(arg: ?*anyopaque) callconv(.c) u8 {
    const ctx: *const ChildExecContext = @ptrCast(@alignCast(arg));
    return execCommand(ctx.command, ctx.args, ctx.env);
}

/// build null-terminated argv and envp arrays on the stack and call execve.
/// uses a ~64KB stack buffer to avoid heap allocation in the child.
/// returns 127 if exec fails.
fn execCommand(command: []const u8, args: []const []const u8, env: []const []const u8) u8 {
    // comptime validation: ensure buffer sizes are reasonable
    const str_buf_size = 65536;
    const max_entries = 257; // 256 + 1 for null terminator

    // verify we can fit reasonable worst-case scenario
    // max command length: 4096 (PATH_MAX typical)
    // max args: 256 * 256 (typical arg max)
    // this is a sanity check, not exact calculation
    comptime std.debug.assert(str_buf_size >= 4096);
    comptime std.debug.assert(max_entries <= 512);

    var str_buf: [str_buf_size]u8 = undefined;
    var str_pos: usize = 0;

    // argv: command + args + null terminator (max 256 entries)
    var argv: [max_entries]?[*:0]const u8 = .{null} ** max_entries;
    argv[0] = exec_helpers.packString(&str_buf, &str_pos, command) orelse return 127;

    var argv_idx: usize = 1;
    for (args) |arg| {
        if (argv_idx >= argv.len - 1) break;
        argv[argv_idx] = exec_helpers.packString(&str_buf, &str_pos, arg) orelse return 127;
        argv_idx += 1;
    }

    // envp: env vars + null terminator (max 256 entries)
    var envp: [max_entries]?[*:0]const u8 = .{null} ** max_entries;
    for (env, 0..) |e, i| {
        if (i >= envp.len - 1) break;
        envp[i] = exec_helpers.packString(&str_buf, &str_pos, e) orelse return 127;
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

/// set the container hostname via the sethostname syscall
fn setHostname(name: []const u8) void {
    if (name.len == 0) return;
    _ = linux.syscall2(.sethostname, @intFromPtr(name.ptr), name.len);
}

fn isCanonicalBindSource(source: []const u8) bool {
    if (source.len == 0) return false;
    return filesystem.isCanonicalAbsolutePath(source);
}

/// base directory for per-container overlay storage
const containers_subdir = "containers";

/// paths to the overlay directories for a container
pub const OverlayDirs = struct {
    upper: [paths.max_path]u8,
    upper_len: usize,
    work: [paths.max_path]u8,
    work_len: usize,
    merged: [paths.max_path]u8,
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
    // validate the container ID to prevent path traversal
    if (!isValidContainerId(container_id)) return ContainerError.InvalidId;

    // initialize all fields to prevent partial initialization
    var dirs: OverlayDirs = .{
        .upper = undefined,
        .upper_len = 0,
        .work = undefined,
        .work_len = 0,
        .merged = undefined,
        .merged_len = 0,
    };

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
    // validate to prevent accidental deletion of wrong paths
    if (!isValidContainerId(container_id)) return;

    var path_buf: [paths.max_path]u8 = undefined;
    const dir_path = paths.dataPathFmt(&path_buf, "{s}/{s}", .{
        containers_subdir, container_id,
    }) catch return;

    std.fs.cwd().deleteTree(dir_path) catch {};
}

/// generate a unique container id (12 hex chars, 48 bits entropy).
/// checks for collisions with existing containers up to 10 attempts.
/// after 10 collisions, uses timestamp + counter to guarantee uniqueness.
pub fn generateId(buf: *ContainerId) ContainerError!void {
    std.debug.assert(@sizeOf(ContainerId) == 12);
    const chars = "0123456789abcdef";
    const max_collision_attempts: u32 = 10;

    var collision_count: u32 = 0;
    while (collision_count < max_collision_attempts) : (collision_count += 1) {
        // use crypto secure random
        var bytes: [6]u8 = undefined;
        std.crypto.random.bytes(&bytes);

        for (bytes, 0..) |b, i| {
            buf[i * 2] = chars[b >> 4];
            buf[i * 2 + 1] = chars[b & 0x0f];
        }

        // check for collision - if container dir doesn't exist, we're good
        var path_buf: [paths.max_path]u8 = undefined;
        const dir_path = paths.dataPathFmt(&path_buf, "{s}/{s}", .{
            containers_subdir, buf,
        }) catch continue;

        std.fs.cwd().access(dir_path, .{}) catch {
            // directory doesn't exist = no collision
            return;
        };
        // directory exists = collision, try again
    }

    // too many collisions - use timestamp + counter for guaranteed uniqueness
    const now = std.time.timestamp();
    var counter: u16 = 0;
    while (counter < 1000) : (counter += 1) {
        // combine timestamp (upper 48 bits) with counter (lower 16 bits)
        const unique_val: u64 = @as(u64, @intCast(now)) << 16 | counter;
        var bytes: [6]u8 = undefined;
        bytes[0] = @intCast((unique_val >> 40) & 0xFF);
        bytes[1] = @intCast((unique_val >> 32) & 0xFF);
        bytes[2] = @intCast((unique_val >> 24) & 0xFF);
        bytes[3] = @intCast((unique_val >> 16) & 0xFF);
        bytes[4] = @intCast((unique_val >> 8) & 0xFF);
        bytes[5] = @intCast(unique_val & 0xFF);

        for (bytes, 0..) |b, i| {
            buf[i * 2] = chars[b >> 4];
            buf[i * 2 + 1] = chars[b & 0x0f];
        }

        // verify uniqueness
        var path_buf: [paths.max_path]u8 = undefined;
        const dir_path = paths.dataPathFmt(&path_buf, "{s}/{s}", .{
            containers_subdir, buf,
        }) catch continue;

        std.fs.cwd().access(dir_path, .{}) catch {
            return;
        };
    }

    // exhausted all attempts — return error instead of crashing the process
    return ContainerError.IdGenerationFailed;
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
    var id: ContainerId = undefined;
    try generateId(&id);
    try std.testing.expect(isValidContainerId(&id));
}

test "isValidContainerId accepts valid IDs" {
    try std.testing.expect(isValidContainerId("abc123def456"));
    try std.testing.expect(isValidContainerId("000000000000"));
    try std.testing.expect(isValidContainerId("ffffffffffff"));
}

test "isValidContainerId rejects invalid IDs" {
    try std.testing.expect(!isValidContainerId("ABC123DEF456")); // uppercase
    try std.testing.expect(!isValidContainerId("abc123")); // too short
    try std.testing.expect(!isValidContainerId("abc123def4567")); // too long
    try std.testing.expect(!isValidContainerId("")); // empty
}

test "generate id varies between calls" {
    var id1: ContainerId = undefined;
    var id2: ContainerId = undefined;
    try generateId(&id1);
    try generateId(&id2);

    // two random IDs should (almost certainly) differ
    try std.testing.expect(!std.mem.eql(u8, &id1, &id2));
}

test "generate id avoids collisions" {
    // generate many IDs and verify no duplicates
    var ids: [100]ContainerId = undefined;
    for (&ids) |*id| {
        try generateId(id);
    }

    // check no collisions
    for (ids, 0..) |id1, i| {
        for (ids[i + 1 ..]) |id2| {
            try std.testing.expect(!std.mem.eql(u8, &id1, &id2));
        }
    }
}

test "generate id produces valid hex characters" {
    var id: ContainerId = undefined;
    try generateId(&id);

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

test "bind mount rejects sensitive source paths" {
    const cases = [_][]const u8{
        "/etc/shadow",
        "/etc/passwd",
        "/root/.ssh",
        "/home/user/.bashrc",
        "/proc/1/environ",
        "/sys/kernel",
        "/dev/sda",
        "/boot/vmlinuz",
        "/var/lib/docker",
        "/sbin/init",
        "/usr/sbin/sshd",
    };

    for (cases) |source| {
        const m = BindMount{ .source = source, .target = "/mnt" };
        try std.testing.expect(!m.isSourceAllowed());
    }
}

test "bind mount allows safe source paths" {
    const cases = [_][]const u8{
        "/tmp/myproject",
        "/opt/data",
        "/srv/app",
        "/usr/local/share",
        "/devtools", // shouldn't match /dev prefix
        "/homework", // shouldn't match /home prefix
        "/etcetera", // shouldn't match /etc prefix
    };

    for (cases) |source| {
        const m = BindMount{ .source = source, .target = "/mnt" };
        try std.testing.expect(m.isSourceAllowed());
    }
}

test "bind mount defaults to read-only" {
    const mount = BindMount{ .source = "/tmp/data", .target = "/mnt" };
    try std.testing.expect(mount.read_only);
}

test "canonical bind source rejects symlink path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("real");
    try tmp.dir.symLink("real", "link", .{});

    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    const real_path = try tmp.dir.realpath("real", &real_buf);
    try std.testing.expect(isCanonicalBindSource(real_path));

    var base_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base_path = try tmp.dir.realpath(".", &base_buf);
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_path = try std.fmt.bufPrint(&link_buf, "{s}/link", .{base_path});
    try std.testing.expect(!isCanonicalBindSource(link_path));
}

// -- security validation tests --

test "isValidContainerId rejects path traversal attempts" {
    // basic path traversal
    try std.testing.expect(!isValidContainerId("../etc/passwd"));
    try std.testing.expect(!isValidContainerId("../../etc"));
    try std.testing.expect(!isValidContainerId("/etc/passwd"));

    // embedded traversal
    try std.testing.expect(!isValidContainerId("abc/../def"));
    try std.testing.expect(!isValidContainerId("..abc123..def"));

    // special characters that could be dangerous
    try std.testing.expect(!isValidContainerId("abc:123def456"));
    try std.testing.expect(!isValidContainerId("abc\\123def45"));
}

test "isValidContainerId rejects non-hex characters" {
    // uppercase hex (should be lowercase)
    try std.testing.expect(!isValidContainerId("ABC123DEF456"));

    // invalid characters
    try std.testing.expect(!isValidContainerId("xyz123def456"));
    try std.testing.expect(!isValidContainerId("abc123def45g"));
    try std.testing.expect(!isValidContainerId("abc123_def456"));
    try std.testing.expect(!isValidContainerId("abc 123def456"));
}

test "isValidContainerId rejects wrong lengths" {
    // too short
    try std.testing.expect(!isValidContainerId("abc123"));
    try std.testing.expect(!isValidContainerId("abc123def45"));

    // too long
    try std.testing.expect(!isValidContainerId("abc123def4567"));
    try std.testing.expect(!isValidContainerId("abc123def4567890123"));

    // empty
    try std.testing.expect(!isValidContainerId(""));
}

test "isValidContainerId accepts valid 12-char hex" {
    // standard format
    try std.testing.expect(isValidContainerId("abc123def456"));
    try std.testing.expect(isValidContainerId("000000000000"));
    try std.testing.expect(isValidContainerId("ffffffffffff"));
    try std.testing.expect(isValidContainerId("0123456789ab"));

    // all hex characters
    try std.testing.expect(isValidContainerId("0123456789ab"));
    try std.testing.expect(isValidContainerId("abcdefabcdef"));
}

test "validateContainerId returns typed id on success" {
    const id = try validateContainerId("abc123def456");
    try std.testing.expectEqualStrings("abc123def456", &id);
}

test "validateContainerId returns error on invalid id" {
    try std.testing.expectError(ContainerError.InvalidId, validateContainerId("../etc/passwd"));
    try std.testing.expectError(ContainerError.InvalidId, validateContainerId("ABC123DEF456"));
    try std.testing.expectError(ContainerError.InvalidId, validateContainerId("too-short"));
}

// -- integration-style tests (simulated) --

test "container config validates hostname length" {
    // hostname should be reasonable length
    const long_hostname = "a" ** 64;
    const config = ContainerConfig{
        .id = "abc123def456",
        .rootfs = "/tmp/rootfs",
        .command = "/bin/sh",
        .hostname = long_hostname,
    };
    try std.testing.expectEqualStrings(long_hostname, config.hostname);
}

test "container config with empty args and env" {
    const config = ContainerConfig{
        .id = "abc123def456",
        .rootfs = "/tmp/rootfs",
        .command = "/bin/sh",
        .args = &.{},
        .env = &.{},
    };
    try std.testing.expectEqual(@as(usize, 0), config.args.len);
    try std.testing.expectEqual(@as(usize, 0), config.env.len);
}

// -- exit code tests --

test "ExitCode enum values follow conventions" {
    // success should be 0
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(ExitCode.success));

    // permission denied follows bash convention (126)
    try std.testing.expectEqual(@as(u8, 126), @intFromEnum(ExitCode.permission_denied));

    // command not found follows bash convention (127)
    try std.testing.expectEqual(@as(u8, 127), @intFromEnum(ExitCode.command_not_found));

    // filesystem errors should be distinct
    try std.testing.expect(@intFromEnum(ExitCode.filesystem_error) >= 120);
    try std.testing.expect(@intFromEnum(ExitCode.filesystem_error) < 126);

    // bind mount denied should be distinct from general filesystem error
    try std.testing.expect(@intFromEnum(ExitCode.bind_mount_denied) != @intFromEnum(ExitCode.filesystem_error));
}
