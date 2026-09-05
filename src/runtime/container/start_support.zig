const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;

const namespaces = @import("../namespaces.zig");
const filesystem = @import("../filesystem.zig");
const logs = @import("../logs.zig");
const process = @import("../process.zig");
const store = @import("../../state/store.zig");
const net_setup = @import("../../network/setup.zig");
const sqlite = @import("sqlite");
const startup = @import("startup_channel.zig");
const log = @import("../../lib/log.zig");
const ip = @import("../../network/ip.zig");
const bridge = @import("../../network/bridge.zig");
const exec_runtime = @import("exec_runtime.zig");
const id_paths = @import("id_paths.zig");

pub const OverlayRuntime = struct {
    has_overlay: bool,
    dirs: ?id_paths.OverlayDirs,
    // Borrowed paths are derived only after this owner reaches its final address.
    pub fn filesystemConfig(self: *const OverlayRuntime, lower_dirs: []const []const u8) filesystem.FilesystemConfig {
        return if (self.dirs) |*dirs| .{
            .lower_dirs = lower_dirs,
            .upper_dir = dirs.upperPath(),
            .work_dir = dirs.workPath(),
            .merged_dir = dirs.mergedPath(),
        } else .{ .lower_dirs = &.{}, .upper_dir = "", .work_dir = "", .merged_dir = "" };
    }
};

pub fn prepareOverlayRuntime(config: anytype, containers_subdir: []const u8) error{ CreateFailed, InvalidId }!OverlayRuntime {
    const has_overlay = config.lower_dirs.len > 0;
    return .{
        .has_overlay = has_overlay,
        .dirs = if (has_overlay) try id_paths.createContainerDirs(containers_subdir, config.id) else null,
    };
}

pub fn initChildContext(config: anytype, overlay: *const OverlayRuntime) exec_runtime.ChildExecContext {
    return .{
        .has_overlay = overlay.has_overlay,
        .host_mode = config.host_mode,
        .fs_config = overlay.filesystemConfig(config.lower_dirs),
        .gpu_indices = config.gpu_indices,
        .rootfs = config.rootfs,
        .command = config.command,
        .args = config.args,
        .env = config.env,
        .working_dir = config.working_dir,
        .hostname = config.hostname,
        .mounts = config.mounts,
    };
}

pub fn setupNetwork(config: anytype, pid: posix.pid_t, net_info: *?net_setup.NetworkInfo, db: *sqlite.Db) !startup.NetworkFiles {
    const net_config = config.network orelse return .{};
    const gateway = try gatewayForNode(net_config.node_id);
    net_info.* = try net_setup.setupContainer(config.id, pid, net_config, db, config.hostname);
    // Keep ownership even if persistence fails: rollback must remove the veth,
    // mappings, service registration, and allocated IP.
    const info = &net_info.*.?;
    var ip_buf: [16]u8 = undefined;
    try store.updateNetwork(config.id, ip.formatIp(info.ip, &ip_buf), info.vethName());
    return .{ .enabled = true, .address = info.ip, .gateway = gateway };
}

fn gatewayForNode(node_id: ?u16) ip.IpError![4]u8 {
    return if (node_id) |id| (try ip.subnetForNode(id)).gateway else bridge.gateway_ip;
}

test "gatewayForNode rejects node ids outside the subnet range" {
    try std.testing.expectError(ip.IpError.AllocationFailed, gatewayForNode(65535));
}

test "gatewayForNode returns bridge gateway for single-node containers" {
    try std.testing.expectEqualSlices(u8, &bridge.gateway_ip, &(try gatewayForNode(null)));
}

pub fn startLogCapture(config: anytype, runtime: anytype, spawn_result: *namespaces.SpawnResult) !void {
    runtime.log_file = try logs.createLogSink(config.id);
    try startCaptureWorkers(config, runtime, spawn_result, CaptureThreads{});
}

const CaptureThreads = struct {
    fn spawn(_: @This(), args: anytype) !std.Thread {
        return std.Thread.spawn(.{}, logs.captureStream, args);
    }
};

fn startCaptureWorkers(config: anytype, runtime: anytype, child: *namespaces.SpawnResult, threads: anytype) !void {
    const log_file = &runtime.log_file.?;
    runtime.stdout_thread = try threads.spawn(.{ log_file, child.stdout_fd, "stdout", config.dev_service_name, config.dev_color_idx, runtime.mirror_output });
    child.stdout_fd = -1;
    runtime.stderr_thread = try threads.spawn(.{ log_file, child.stderr_fd, "stderr", config.dev_service_name, config.dev_color_idx, runtime.mirror_output });
    child.stderr_fd = -1;
}

pub fn updateRunningStatus(container_id: []const u8, pid: posix.pid_t) !void {
    store.updateStatus(container_id, "running", pid, null) catch |err| {
        log.warn("failed to update status for {s}: {}", .{ container_id, err });
        return err;
    };
}

pub fn cleanupFailedStart(self: anytype, spawned: *?namespaces.SpawnResult, network_db: ?*sqlite.Db, active_pid: *std.atomic.Value(i32)) void {
    if (spawned.*) |*child| {
        // Startup has not authorized exec. Reap before joining capture workers
        // so every child-side writer is closed, including setup error paths.
        process.kill(child.pid) catch {};
        while (true) {
            const result = process.wait(child.pid, false) catch break;
            switch (result.status) {
                .stopped, .running => continue,
                else => break,
            }
        }
        startup.closeOwned(&child.ready_fd);
        startup.closeOwned(&child.stdout_fd);
        startup.closeOwned(&child.stderr_fd);
        spawned.* = null;
    }
    finishCapture(&self.runtime);
    if (self.net_info) |*info| {
        if (self.config.network) |config| {
            if (network_db) |db| net_setup.teardownContainer(self.config.id, info, config, db);
        }
        self.net_info = null;
        store.updateNetwork(self.config.id, null, null) catch {};
    }
    if (self.runtime.cgroup) |cgroup| {
        if (cgroup.destroy()) |_| {
            self.runtime.cgroup = null;
        } else |err| {
            log.warn("failed to roll back cgroup for {s}: {}", .{ self.config.id, err });
        }
    }
    self.pid = null;
    self.status = .created;
    active_pid.store(0, .release);
    store.updateStatus(self.config.id, if (self.runtime.cgroup == null) "created" else "cleanup_failed", null, null) catch {};
}

fn finishCapture(runtime: anytype) void {
    if (runtime.stdout_thread) |thread| thread.join();
    runtime.stdout_thread = null;
    if (runtime.stderr_thread) |thread| thread.join();
    runtime.stderr_thread = null;
    if (runtime.log_file) |*file| file.close();
    runtime.log_file = null;
}

pub fn finalizeRuntime(self: anytype, exit_code: u8) void {
    finishCapture(&self.runtime);
    var final_status: []const u8 = "stopped";

    if (self.net_info) |*info| {
        if (self.config.network) |net_config| {
            var db = store.openDb() catch null;
            defer if (db) |*d| d.deinit();
            if (db) |*d| {
                net_setup.teardownContainer(self.config.id, info, net_config, d);
                self.net_info = null;
                store.updateNetwork(self.config.id, null, null) catch {};
            } else {
                // Retain ownership so a restart cannot overwrite leaked state.
                final_status = "cleanup_failed";
            }
        }
    }

    if (self.runtime.cgroup) |cgroup| {
        if (cgroup.destroy()) |_| {
            self.runtime.cgroup = null;
        } else |err| {
            log.warn("failed to destroy cgroup for {s}: {}", .{ self.config.id, err });
            final_status = "cleanup_failed";
        }
    }

    store.updateStatus(self.config.id, final_status, null, exit_code) catch |err| {
        log.warn("failed to update final status for {s}: {}", .{ self.config.id, err });
    };
}

test "startup overlay views borrow the surviving owner after a move" {
    const Fixture = struct {
        noinline fn make() OverlayRuntime {
            var owner = OverlayRuntime{ .has_overlay = true, .dirs = .{
                .upper = undefined,
                .upper_len = 6,
                .work = undefined,
                .work_len = 5,
                .merged = undefined,
                .merged_len = 7,
            } };
            @memcpy(owner.dirs.?.upper[0..6], "/upper");
            @memcpy(owner.dirs.?.work[0..5], "/work");
            @memcpy(owner.dirs.?.merged[0..7], "/merged");
            return owner;
        }
    };
    const owner = Fixture.make();
    const config = @import("../container.zig").ContainerConfig{ .id = "0123456789ab", .rootfs = "", .command = "test", .lower_dirs = &.{"/lower"} };
    const ctx = initChildContext(config, &owner);
    try std.testing.expectEqual(@intFromPtr(&owner.dirs.?.upper), @intFromPtr(ctx.fs_config.upper_dir.ptr));
    try std.testing.expectEqual(@intFromPtr(&owner.dirs.?.work), @intFromPtr(ctx.fs_config.work_dir.ptr));
    try std.testing.expectEqual(@intFromPtr(&owner.dirs.?.merged), @intFromPtr(ctx.fs_config.merged_dir.ptr));
    try std.testing.expectEqualStrings("/upper", ctx.fs_config.upper_dir);
    try std.testing.expectEqualStrings("/merged", ctx.fs_config.merged_dir);
}

test "startup rollback reaps child and joins partial or complete capture ownership" {
    const Container = @import("../container.zig").Container;
    const linux = std.os.linux;
    try store.initTestDb();
    defer store.deinitTestDb();
    try store.save(.{ .id = "0123456789ab", .rootfs = "", .command = "test", .hostname = "test", .status = "created", .pid = null, .exit_code = null, .created_at = 0 });
    const Factory = struct {
        fail_after: usize,
        started: usize = 0,

        fn denyUpdates(_: ?*anyopaque, action: c_int, _: [*c]const u8, _: [*c]const u8, _: [*c]const u8, _: [*c]const u8) callconv(.c) c_int {
            return if (action == sqlite.c.SQLITE_UPDATE) sqlite.c.SQLITE_DENY else sqlite.c.SQLITE_OK;
        }

        fn rejectStatusWrites(enabled: bool) !void {
            var lease = try @import("../../state/store/common.zig").leaseDb();
            defer lease.deinit();
            try std.testing.expectEqual(@as(c_int, sqlite.c.SQLITE_OK), sqlite.c.sqlite3_set_authorizer(lease.db.db, if (enabled) denyUpdates else null, null));
        }

        fn spawn(self: *@This(), args: anytype) !std.Thread {
            if (self.started == self.fail_after) return error.InjectedFailure;
            self.started += 1;
            return std.Thread.spawn(.{}, logs.captureStream, args);
        }
    };
    for (0..3) |fail_after| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const stdout = try linux_platform.posix.pipe();
        const stderr = try linux_platform.posix.pipe();
        const gate = try linux_platform.posix.pipe();
        const rc = linux.fork();
        if (linux.errno(rc) != .SUCCESS) return error.ForkFailed;
        if (rc == 0) {
            linux_platform.posix.close(gate[1]);
            linux_platform.posix.close(stdout[0]);
            linux_platform.posix.close(stderr[0]);
            // Keep output writers open until rollback kills this blocked child.
            var byte: [1]u8 = undefined;
            _ = linux.read(gate[0], &byte, 1);
            linux.exit_group(0);
        }
        const pid: posix.pid_t = @intCast(rc);
        linux_platform.posix.close(gate[0]);
        linux_platform.posix.close(stdout[1]);
        linux_platform.posix.close(stderr[1]);
        var child: ?namespaces.SpawnResult = .{ .pid = pid, .stdout_fd = stdout[0], .stderr_fd = stderr[0], .ready_fd = gate[1] };
        var container = Container{
            .config = .{ .id = "0123456789ab", .rootfs = "", .command = "test" },
            .status = .created,
            .pid = pid,
            .exit_code = null,
            .created_at = 0,
        };
        var active = std.atomic.Value(i32).init(pid);
        defer cleanupFailedStart(&container, &child, null, &active);
        var capture_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const capture_root_len = try tmp.dir.realPath(std.testing.io, &capture_path_buf);
        const capture_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/capture.log", .{capture_path_buf[0..capture_root_len]});
        defer std.testing.allocator.free(capture_path);
        container.runtime.log_file = try logs.LogSink.init(try tmp.dir.createFile(std.testing.io, "capture.log", .{ .read = true }), capture_path);
        var factory = Factory{ .fail_after = fail_after };
        const result = startCaptureWorkers(container.config, &container.runtime, &child.?, &factory);
        if (fail_after < 2) try std.testing.expectError(error.InjectedFailure, result) else try result;
        try std.testing.expectEqual(fail_after > 0, child.?.stdout_fd == -1);
        try std.testing.expectEqual(fail_after > 1, child.?.stderr_fd == -1);
        if (fail_after == 2) {
            // Reject during preparation: this is a real persistence failure,
            // without leaving a failed statement for finalize to report again.
            try Factory.rejectStatusWrites(true);
            defer Factory.rejectStatusWrites(false) catch {};
            try std.testing.expectError(error.WriteFailed, updateRunningStatus(container.config.id, pid));
        }
        // The actual SQLite rejection above happens after both FD transfers.
        cleanupFailedStart(&container, &child, null, &active);
        try std.testing.expect(child == null and container.pid == null);
        try std.testing.expect(container.runtime.stdout_thread == null and container.runtime.stderr_thread == null and container.runtime.log_file == null);
        try std.testing.expectEqual(@as(i32, 0), active.load(.acquire));
        try std.testing.expectError(error.WaitFailed, process.wait(pid, true));
        // Repeated rollback must not close a newly reused descriptor.
        var survivor = try tmp.dir.createFile(std.testing.io, "survivor", .{});
        defer survivor.close(std.testing.io);
        cleanupFailedStart(&container, &child, null, &active);
        try survivor.writeStreamingAll(std.testing.io, "still owned");
    }
}
