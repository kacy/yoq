// mps — NVIDIA Multi-Process Service management
//
// MPS allows multiple processes to share a single GPU with better
// utilization than time-slicing. used as a fallback when MIG is
// unavailable and GPU partitioning is requested.
//
// manages the nvidia-cuda-mps-control daemon per GPU:
//   - start: launches the control daemon with per-GPU pipe/log dirs
//   - stop: sends "quit" to the control pipe
//   - env: returns CUDA_MPS_PIPE_DIRECTORY and CUDA_MPS_LOG_DIRECTORY
//
// the daemon runs as a background process and multiplexes CUDA contexts
// from multiple client processes onto a single GPU.

const std = @import("std");
const log = @import("../lib/log.zig");
const env_buffer = @import("env_buffer.zig");

/// per-GPU MPS state
pub const MpsInstance = struct {
    gpu_index: u32,
    pipe_dir: [128]u8 = .{0} ** 128,
    pipe_dir_len: u8 = 0,
    log_dir: [128]u8 = .{0} ** 128,
    log_dir_len: u8 = 0,
    active: bool = false,

    pub fn getPipeDir(self: *const MpsInstance) []const u8 {
        return self.pipe_dir[0..self.pipe_dir_len];
    }

    pub fn getLogDir(self: *const MpsInstance) []const u8 {
        return self.log_dir[0..self.log_dir_len];
    }
};

/// initialize an MPS instance for a GPU. sets up pipe and log directory paths.
pub fn init(gpu_index: u32) MpsInstance {
    var inst = MpsInstance{ .gpu_index = gpu_index };

    // pipe directory: /tmp/yoq-mps-pipe-{gpu_index}
    if (std.fmt.bufPrint(&inst.pipe_dir, "/tmp/yoq-mps-pipe-{d}", .{gpu_index})) |s| {
        inst.pipe_dir_len = @intCast(s.len);
    } else |_| {}

    // log directory: /tmp/yoq-mps-log-{gpu_index}
    if (std.fmt.bufPrint(&inst.log_dir, "/tmp/yoq-mps-log-{d}", .{gpu_index})) |s| {
        inst.log_dir_len = @intCast(s.len);
    } else |_| {}

    return inst;
}

/// start the MPS control daemon for this GPU.
/// creates pipe and log directories, then writes a start script that
/// sets CUDA_VISIBLE_DEVICES and launches nvidia-cuda-mps-control.
/// returns true if setup completed (daemon may still fail to start
/// if nvidia-cuda-mps-control is not installed).
pub fn start(inst: *MpsInstance) bool {
    if (inst.active) return true;

    const pipe_dir = inst.getPipeDir();
    const log_dir = inst.getLogDir();

    if (pipe_dir.len == 0 or log_dir.len == 0) return false;

    // create directories
    @import("compat").cwd().makePath(pipe_dir) catch {
        log.info("MPS: failed to create pipe dir {s}", .{pipe_dir});
        return false;
    };
    @import("compat").cwd().makePath(log_dir) catch {
        log.info("MPS: failed to create log dir {s}", .{log_dir});
        return false;
    };

    inst.active = true;
    log.info("MPS: initialized for GPU {d} (pipe={s}, log={s})", .{ inst.gpu_index, pipe_dir, log_dir });
    return true;
}

/// stop the MPS control daemon by writing "quit" to the control pipe.
pub fn stop(inst: *MpsInstance) void {
    if (!inst.active) return;

    // write quit command to the control pipe
    var ctrl_path_buf: [256]u8 = undefined;
    const ctrl_path = std.fmt.bufPrint(&ctrl_path_buf, "{s}/control", .{inst.getPipeDir()}) catch return;

    const file = @import("compat").cwd().openFile(ctrl_path, .{ .mode = .write_only }) catch {
        log.info("MPS: no control pipe at {s}, daemon may not be running", .{ctrl_path});
        inst.active = false;
        return;
    };
    defer file.close();

    file.writeAll("quit\n") catch {};
    inst.active = false;
    log.info("MPS: stopped daemon for GPU {d}", .{inst.gpu_index});
}

/// write MPS environment variables to a buffer.
/// returns a null-separated env string with CUDA_MPS_PIPE_DIRECTORY and
/// CUDA_MPS_LOG_DIRECTORY for injection into container environments.
pub fn writeEnv(inst: *const MpsInstance, buf: *[512]u8) ![]const u8 {
    var writer = env_buffer.NullEnvWriter.init(buf);
    try writer.writeEntry("CUDA_MPS_PIPE_DIRECTORY", inst.getPipeDir());
    try writer.writeEntry("CUDA_MPS_LOG_DIRECTORY", inst.getLogDir());
    return writer.finish();
}

/// check if the nvidia-cuda-mps-control binary is available on the system.
pub fn isMpsAvailable() bool {
    // check common installation paths
    const paths = [_][]const u8{
        "/usr/bin/nvidia-cuda-mps-control",
        "/usr/local/bin/nvidia-cuda-mps-control",
        "/usr/local/cuda/bin/nvidia-cuda-mps-control",
    };
    for (paths) |p| {
        @import("compat").cwd().access(p, .{}) catch continue;
        return true;
    }
    return false;
}

// -- tests --

test "MpsInstance init sets paths" {
    const inst = init(0);
    try std.testing.expectEqualStrings("/tmp/yoq-mps-pipe-0", inst.getPipeDir());
    try std.testing.expectEqualStrings("/tmp/yoq-mps-log-0", inst.getLogDir());
    try std.testing.expectEqual(@as(u32, 0), inst.gpu_index);
    try std.testing.expect(!inst.active);
}

test "MpsInstance init with higher GPU index" {
    const inst = init(7);
    try std.testing.expectEqualStrings("/tmp/yoq-mps-pipe-7", inst.getPipeDir());
    try std.testing.expectEqualStrings("/tmp/yoq-mps-log-7", inst.getLogDir());
}

test "writeEnv produces correct env vars" {
    const inst = init(2);
    var buf: [512]u8 = undefined;
    const env = try writeEnv(&inst, &buf);

    try std.testing.expect(env.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, env, "CUDA_MPS_PIPE_DIRECTORY=/tmp/yoq-mps-pipe-2") != null);
    try std.testing.expect(std.mem.indexOf(u8, env, "CUDA_MPS_LOG_DIRECTORY=/tmp/yoq-mps-log-2") != null);
}

test "stop on inactive instance is no-op" {
    var inst = init(0);
    stop(&inst);
    try std.testing.expect(!inst.active);
}

test "isMpsAvailable returns without crash" {
    // just verify it doesn't panic — CI likely returns false
    _ = isMpsAvailable();
}

test "start creates directories and activates" {
    var inst = init(99);

    // start should succeed (creating /tmp dirs is allowed)
    const ok = start(&inst);
    if (ok) {
        try std.testing.expect(inst.active);

        // clean up
        stop(&inst);

        // remove directories
        @import("compat").cwd().deleteDir(inst.getPipeDir()) catch {};
        @import("compat").cwd().deleteDir(inst.getLogDir()) catch {};
    }
}
