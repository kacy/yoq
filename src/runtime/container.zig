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
const store = @import("../state/store.zig");
const net_setup = @import("../network/setup.zig");
const log = @import("../lib/log.zig");
const exec_runtime = @import("container/exec_runtime.zig");
const id_paths = @import("container/id_paths.zig");
const start_support = @import("container/start_support.zig");
const startup = @import("container/startup_channel.zig");
const sqlite = @import("sqlite");

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
pub const ExitCode = exec_runtime.ExitCode;

/// a 12-character hex container identifier.
/// using a distinct type improves type safety over raw strings.
pub const ContainerId = id_paths.ContainerId;

/// validates that a container ID is safe to use in filesystem paths.
/// checks that the ID:
///   - is exactly 12 characters
///   - contains only lowercase hex characters (0-9, a-f)
///   - does not contain any path traversal sequences
/// returns true only if all checks pass.
pub fn isValidContainerId(id: []const u8) bool {
    return id_paths.isValidContainerId(id);
}

/// validates a container ID and returns a typed ContainerId.
/// returns InvalidId error if validation fails.
pub fn validateContainerId(id: []const u8) ContainerError!ContainerId {
    return id_paths.validateContainerId(id) catch ContainerError.InvalidId;
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
pub const BindMount = exec_runtime.BindMount;

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
    /// GPU indices to expose inside the container (e.g., [0, 1])
    /// when non-empty, setupGpuPassthrough creates /dev/nvidia* and injects env vars
    gpu_indices: []const u32 = &.{},
    /// when true, runs in host mode with reduced filesystem isolation
    /// this must be explicitly requested; isolation failures do not downgrade automatically
    host_mode: bool = false,
};

/// a running or stopped container
pub const Container = struct {
    const RuntimeHandles = struct {
        cgroup: ?cgroups.Cgroup = null,
        log_file: ?std.Io.File = null,
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
    state_mutex: std.Io.Mutex = .init,

    /// check if the container's process is still alive.
    /// updates status if it has exited.
    pub fn poll(self: *Container) ContainerError!void {
        self.state_mutex.lockUncancelable(std.Options.debug_io);
        defer self.state_mutex.unlock(std.Options.debug_io);

        const pid = self.pid orelse return;
        if (self.status != .running) return;

        const result = process.wait(pid, true) catch return;
        const exit_code: u8 = switch (result.status) {
            .exited => |code| code,
            .signaled => 128,
            .running, .stopped => return,
        };
        self.status = .stopped;
        self.exit_code = exit_code;
        self.pid = null;
        active_pid.store(0, .release);
        // Poll is also a terminal lifecycle path. Release the same owned
        // resources as wait(), before a caller can restart this instance.
        self.finalize(exit_code);
    }

    /// send SIGTERM to the container's init process.
    pub fn stop(self: *Container) ContainerError!void {
        self.state_mutex.lockUncancelable(std.Options.debug_io);
        defer self.state_mutex.unlock(std.Options.debug_io);

        const pid = self.pid orelse return ContainerError.NotRunning;
        if (self.status != .running) return ContainerError.NotRunning;

        process.terminate(pid) catch return ContainerError.StopFailed;
    }

    /// send SIGKILL to the container's init process.
    pub fn forceStop(self: *Container) ContainerError!void {
        self.state_mutex.lockUncancelable(std.Options.debug_io);
        defer self.state_mutex.unlock(std.Options.debug_io);

        const pid = self.pid orelse return ContainerError.NotRunning;
        if (self.status != .running) return ContainerError.NotRunning;

        process.kill(pid) catch return ContainerError.StopFailed;
    }

    /// start the container: set up filesystem, spawn process in namespaces,
    /// and begin log capture. returns once the container is running.
    pub fn start(self: *Container) ContainerError!void {
        self.state_mutex.lockUncancelable(std.Options.debug_io);
        defer self.state_mutex.unlock(std.Options.debug_io);
        if (self.pid != null or self.status == .running) return ContainerError.AlreadyRunning;
        if (self.net_info != null or self.runtime.cgroup != null) return ContainerError.StartFailed;

        const config = self.config;
        if (!config.host_mode and !config.namespaces.mount) return ContainerError.StartFailed;
        errdefer if (config.lower_dirs.len > 0) cleanupContainerDirs(config.id);
        const overlay = start_support.prepareOverlayRuntime(config, containers_subdir) catch return ContainerError.StartFailed;
        var child_ctx = start_support.initChildContext(config, &overlay);
        var channel = startup.Channel.init() catch return ContainerError.StartFailed;
        defer channel.deinit();
        child_ctx.startup_fd = channel.child;
        child_ctx.parent_startup_fd = channel.parent;

        // Retain the database used for network setup through rollback: cleanup
        // must not depend on successfully reopening it after a later failure.
        var network_db: ?sqlite.Db = null;
        defer if (network_db) |*db| db.deinit();
        var spawned: ?namespaces.SpawnResult = null;
        errdefer start_support.cleanupFailedStart(self, &spawned, if (network_db) |*db| db else null, &active_pid);

        self.runtime.cgroup = cgroups.Cgroup.create(config.id) catch |err| {
            log.err("cgroup setup failed for {s}: {}", .{ config.id, err });
            return ContainerError.StartFailed;
        };
        spawned = namespaces.spawn(config.namespaces, null, exec_runtime.childMain, @ptrCast(&child_ctx)) catch return ContainerError.StartFailed;
        const child = &spawned.?;
        startup.closeOwned(&channel.child);
        self.pid = child.pid;
        active_pid.store(child.pid, .release);

        self.runtime.cgroup.?.addProcess(child.pid) catch return ContainerError.StartFailed;
        self.runtime.cgroup.?.setLimits(config.limits) catch return ContainerError.StartFailed;
        start_support.startLogCapture(config, &self.runtime, child) catch return ContainerError.StartFailed;

        // Release namespace mapping first. The child mounts its root and final
        // /dev, but cannot execute user code until the second explicit gate.
        child.signalReady();
        startup.expect(channel.parent, .filesystem_ready) catch return ContainerError.StartFailed;
        var files: startup.NetworkFiles = .{};
        if (config.network != null) {
            network_db = store.openDb() catch return ContainerError.StartFailed;
            files = start_support.setupNetwork(config, child.pid, &self.net_info, &network_db.?) catch return ContainerError.StartFailed;
        }
        startup.sendNetwork(channel.parent, files) catch return ContainerError.StartFailed;
        startup.expect(channel.parent, .prepared) catch return ContainerError.StartFailed;

        start_support.updateRunningStatus(config.id, child.pid) catch return ContainerError.StartFailed;
        startup.notify(channel.parent, .execute) catch return ContainerError.StartFailed;
        self.status = .running;
    }

    /// wait for the running container to exit, then clean up runtime resources.
    pub fn wait(self: *Container) ContainerError!u8 {
        self.state_mutex.lockUncancelable(std.Options.debug_io);
        const pid = self.pid orelse {
            self.state_mutex.unlock(std.Options.debug_io);
            return ContainerError.NotRunning;
        };
        self.state_mutex.unlock(std.Options.debug_io);

        const wait_result = process.wait(pid, false) catch {
            self.state_mutex.lockUncancelable(std.Options.debug_io);
            self.status = .stopped;
            self.exit_code = 255;
            self.pid = null;
            self.state_mutex.unlock(std.Options.debug_io);
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

        self.state_mutex.lockUncancelable(std.Options.debug_io);
        self.status = .stopped;
        self.exit_code = exit_code;
        self.pid = null;
        self.state_mutex.unlock(std.Options.debug_io);
        active_pid.store(0, .release);
        self.finalize(exit_code);
        return exit_code;
    }

    fn finalize(self: *Container, exit_code: u8) void {
        start_support.finalizeRuntime(self, exit_code);
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
/// base directory for per-container overlay storage
const containers_subdir = "containers";
pub const OverlayDirs = id_paths.OverlayDirs;

/// create the per-container overlay directories:
///   ~/.local/share/yoq/containers/<id>/upper
///   ~/.local/share/yoq/containers/<id>/work
///   ~/.local/share/yoq/containers/<id>/rootfs  (merged mount point)
pub fn createContainerDirs(container_id: []const u8) ContainerError!OverlayDirs {
    return id_paths.createContainerDirs(containers_subdir, container_id) catch |err| switch (err) {
        error.CreateFailed => ContainerError.CreateFailed,
        error.InvalidId => ContainerError.InvalidId,
    };
}

/// remove all per-container directories
pub fn cleanupContainerDirs(container_id: []const u8) void {
    id_paths.cleanupContainerDirs(containers_subdir, container_id);
}

/// generate a unique container id (12 hex chars, 48 bits entropy).
/// checks for collisions with existing containers up to 10 attempts.
/// after 10 collisions, uses timestamp + counter to guarantee uniqueness.
pub fn generateId(buf: *ContainerId) ContainerError!void {
    return id_paths.generateId(containers_subdir, buf) catch ContainerError.IdGenerationFailed;
}

pub fn isCanonicalBindSource(source: []const u8) bool {
    return exec_runtime.isCanonicalBindSource(source);
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

test "bind mount denies unconfigured managed-looking home paths" {
    const m = BindMount{ .source = "/home/user/.local/share/yoq/volumes/myapp/data", .target = "/mnt" };
    try std.testing.expect(!m.isSourceAllowed());
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

    try tmp.dir.createDir(std.testing.io, "real", .default_dir);
    try tmp.dir.symLink(std.testing.io, "real", "link", .{});

    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    const real_len = try tmp.dir.realPathFile(std.testing.io, "real", &real_buf);
    const real_path = real_buf[0..real_len];
    try std.testing.expect(isCanonicalBindSource(real_path));

    var base_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPathFile(std.testing.io, ".", &base_buf);
    const base_path = base_buf[0..base_len];
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

test "startup refuses filesystem setup in the host mount namespace" {
    var instance = Container{
        .config = .{ .id = "0123456789ab", .rootfs = "/unused", .command = "unused", .namespaces = .{ .mount = false } },
        .status = .created,
        .pid = null,
        .exit_code = null,
        .created_at = 0,
    };
    try std.testing.expectError(error.StartFailed, instance.start());
    try std.testing.expect(instance.pid == null and instance.runtime.cgroup == null);
}

test "startup poll finalizes exited child before another start can replace handles" {
    const platform = @import("linux_platform");
    const logs = @import("logs.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const output = try platform.posix.pipe();
    const child = linux.fork();
    if (linux.errno(child) != .SUCCESS) return error.ForkFailed;
    if (child == 0) linux.exit_group(7);
    const pid: posix.pid_t = @intCast(child);
    platform.posix.close(output[1]);
    var instance = Container{
        .config = .{ .id = "0123456789ab", .rootfs = "", .command = "test" },
        .status = .running,
        .pid = pid,
        .exit_code = null,
        .created_at = 0,
    };
    var read_fd = output[0];
    defer {
        if (instance.pid) |remaining| {
            process.kill(remaining) catch {};
            _ = process.wait(remaining, false) catch {};
        }
        if (read_fd >= 0) platform.posix.close(read_fd);
        instance.finalize(instance.exit_code orelse 255);
    }
    instance.runtime.log_file = try tmp.dir.createFile(std.testing.io, "capture", .{});
    instance.runtime.stdout_thread = try std.Thread.spawn(.{}, logs.captureStream, .{ instance.runtime.log_file.?, read_fd, "stdout", @as(?[]const u8, null), @as(usize, 0), false });
    read_fd = -1;
    for (0..2000) |_| {
        try instance.poll();
        if (instance.status == .stopped) break;
        try std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(Status.stopped, instance.status);
    try std.testing.expectEqual(@as(?u8, 7), instance.exit_code);
    try std.testing.expect(instance.pid == null);
    try std.testing.expect(instance.runtime.stdout_thread == null);
    try std.testing.expect(instance.runtime.log_file == null);
    var survivor = try tmp.dir.createFile(std.testing.io, "survivor", .{});
    defer survivor.close(std.testing.io);
    try instance.poll();
    try survivor.writeStreamingAll(std.testing.io, "repeated poll is harmless");
}
