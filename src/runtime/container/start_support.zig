const std = @import("std");
const posix = std.posix;

const namespaces = @import("../namespaces.zig");
const filesystem = @import("../filesystem.zig");
const logs = @import("../logs.zig");
const process = @import("../process.zig");
const store = @import("../../state/store.zig");
const net_setup = @import("../../network/setup.zig");
const gpu_passthrough = @import("../../gpu/passthrough.zig");
const log = @import("../../lib/log.zig");
const ip = @import("../../network/ip.zig");
const bridge = @import("../../network/bridge.zig");
const exec_runtime = @import("exec_runtime.zig");
const id_paths = @import("id_paths.zig");

pub const OverlayRuntime = struct {
    has_overlay: bool,
    dirs: ?id_paths.OverlayDirs,
    fs_config: filesystem.FilesystemConfig,
};

pub fn prepareOverlayRuntime(config: anytype, containers_subdir: []const u8) error{ CreateFailed, InvalidId }!OverlayRuntime {
    const has_overlay = config.lower_dirs.len > 0;
    var dirs: ?id_paths.OverlayDirs = null;
    if (has_overlay) {
        dirs = try id_paths.createContainerDirs(containers_subdir, config.id);
    }

    const fs_config: filesystem.FilesystemConfig = if (dirs) |*overlay_dirs| .{
        .lower_dirs = config.lower_dirs,
        .upper_dir = overlay_dirs.upperPath(),
        .work_dir = overlay_dirs.workPath(),
        .merged_dir = overlay_dirs.mergedPath(),
    } else .{
        .lower_dirs = &.{},
        .upper_dir = "",
        .work_dir = "",
        .merged_dir = "",
    };

    return .{
        .has_overlay = has_overlay,
        .dirs = dirs,
        .fs_config = fs_config,
    };
}

pub fn initChildContext(config: anytype, overlay: OverlayRuntime) exec_runtime.ChildExecContext {
    return .{
        .has_overlay = overlay.has_overlay,
        .host_mode = config.host_mode,
        .fs_config = overlay.fs_config,
        .rootfs = config.rootfs,
        .command = config.command,
        .args = config.args,
        .env = config.env,
        .working_dir = config.working_dir,
        .hostname = config.hostname,
        .mounts = config.mounts,
    };
}

pub fn setupNetwork(config: anytype, dirs: ?*const id_paths.OverlayDirs, pid: posix.pid_t, net_info: *?net_setup.NetworkInfo) void {
    if (config.network) |net_config| {
        var db = store.openDb() catch null;
        defer if (db) |*d| d.deinit();

        if (db) |*d| {
            if (net_setup.setupContainer(config.id, pid, net_config, d, config.hostname)) |info| {
                net_info.* = info;

                var ip_buf: [16]u8 = undefined;
                const ip_str = ip.formatIp(info.ip, &ip_buf);
                const gateway_ip = if (net_config.node_id) |node_id|
                    (ip.subnetForNode(node_id) catch unreachable).gateway
                else
                    bridge.gateway_ip;
                const network_root = if (dirs) |overlay_dirs|
                    overlay_dirs.mergedPath()
                else
                    config.rootfs;
                store.updateNetwork(config.id, ip_str, info.vethName()) catch |err| {
                    log.warn("failed to persist network info for {s}: {}", .{ config.id, err });
                };

                if (network_root.len > 0) {
                    net_setup.writeNetworkFiles(
                        network_root,
                        info.ip,
                        gateway_ip,
                        config.hostname,
                    );
                }
            } else |err| {
                log.warn("container: network setup failed, continuing without network: {}", .{err});
            }
        }
    }
}

pub fn setupGpu(config: anytype, dirs: ?*const id_paths.OverlayDirs) void {
    if (config.gpu_indices.len == 0) return;
    if (dirs) |overlay_dirs| {
        var gpu_env_buf: [4096]u8 = undefined;
        _ = gpu_passthrough.setupGpuPassthrough(
            overlay_dirs.mergedPath(),
            config.gpu_indices,
            &gpu_env_buf,
        ) catch |err| {
            log.warn("GPU passthrough setup failed for {s}: {}", .{ config.id, err });
        };
    }
}

pub fn startLogCapture(config: anytype, runtime: anytype, spawn_result: *namespaces.SpawnResult) void {
    runtime.log_file = logs.createLogFile(config.id) catch |err| blk: {
        log.warn("failed to create log file for {s}: {}", .{ config.id, err });
        posix.close(spawn_result.stdout_fd);
        posix.close(spawn_result.stderr_fd);
        break :blk null;
    };

    if (runtime.log_file) |log_file| {
        runtime.stdout_thread = std.Thread.spawn(.{}, logs.captureStream, .{
            log_file,
            spawn_result.stdout_fd,
            "stdout",
            config.dev_service_name,
            config.dev_color_idx,
            runtime.mirror_output,
        }) catch |err| blk: {
            log.warn("failed to spawn stdout capture thread: {}", .{err});
            posix.close(spawn_result.stdout_fd);
            break :blk null;
        };

        runtime.stderr_thread = std.Thread.spawn(.{}, logs.captureStream, .{
            log_file,
            spawn_result.stderr_fd,
            "stderr",
            config.dev_service_name,
            config.dev_color_idx,
            runtime.mirror_output,
        }) catch |err| blk: {
            log.warn("failed to spawn stderr capture thread: {}", .{err});
            posix.close(spawn_result.stderr_fd);
            break :blk null;
        };
    }
}

pub fn updateRunningStatus(container_id: []const u8, pid: posix.pid_t) !void {
    store.updateStatus(container_id, "running", pid, null) catch |err| {
        log.warn("failed to update status for {s}: {}", .{ container_id, err });
        return err;
    };
}

pub fn cleanupFailedSpawn(
    self: anytype,
    spawn_result: *namespaces.SpawnResult,
    active_pid: *std.atomic.Value(i32),
) void {
    process.kill(spawn_result.pid) catch {};
    self.runtime.cgroup.?.destroy() catch {};
    if (spawn_result.ready_fd >= 0) {
        std.posix.close(spawn_result.ready_fd);
        spawn_result.ready_fd = -1;
    }
    std.posix.close(spawn_result.stdout_fd);
    std.posix.close(spawn_result.stderr_fd);
    self.pid = null;
    self.status = .created;
    active_pid.store(0, .release);
}

pub fn finalizeRuntime(self: anytype, exit_code: u8) void {
    if (self.runtime.stdout_thread) |thread| thread.join();
    if (self.runtime.stderr_thread) |thread| thread.join();
    if (self.runtime.log_file) |log_file| log_file.close();

    var final_status: []const u8 = "stopped";

    if (self.net_info) |*info| {
        if (self.config.network) |net_config| {
            var db = store.openDb() catch null;
            defer if (db) |*d| d.deinit();
            if (db) |*d| net_setup.teardownContainer(self.config.id, info, net_config, d);
        }
    }

    if (self.runtime.cgroup) |cgroup| {
        cgroup.destroy() catch |err| {
            log.warn("failed to destroy cgroup for {s}: {}", .{ self.config.id, err });
            final_status = "cleanup_failed";
        };
    }

    store.updateStatus(self.config.id, final_status, null, exit_code) catch |err| {
        log.warn("failed to update final status for {s}: {}", .{ self.config.id, err });
    };

    self.runtime = .{};
}
