// passthrough — GPU device passthrough for containers
//
// makes NVIDIA GPUs accessible inside containers by:
//   1. creating /dev/nvidia* device nodes (major 195)
//   2. discovering and bind-mounting host NVIDIA libraries
//   3. injecting GPU environment variables (CUDA_VISIBLE_DEVICES, etc.)
//
// called from container setup when gpu_count > 0, after mountOverlay
// and before pivotRoot.

const std = @import("std");
const log = @import("../lib/log.zig");
const syscall_util = @import("../lib/syscall.zig");
const posix = std.posix;
const linux = std.os.linux;

/// NVIDIA device major number
const nvidia_major: u32 = 195;

/// NVIDIA library names to bind-mount into containers
const nvidia_libs = [_][]const u8{
    "libcuda.so",
    "libcuda.so.1",
    "libnvidia-ml.so",
    "libnvidia-ml.so.1",
    "libnvidia-ptxjitcompiler.so",
    "libnvidia-ptxjitcompiler.so.1",
    "libnvidia-fatbinaryloader.so",
    "libnvcuvid.so",
    "libnvcuvid.so.1",
    "libnvidia-encode.so",
    "libnvidia-encode.so.1",
    "libnvidia-opencl.so",
    "libnvidia-opencl.so.1",
};

/// host paths to search for NVIDIA libraries
const lib_search_paths = [_][]const u8{
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib64",
    "/usr/local/cuda/lib64",
    "/usr/lib/aarch64-linux-gnu",
};

/// set up GPU passthrough for a container.
///
/// - merged_dir: container root filesystem path (overlay merged dir)
/// - gpu_indices: which GPU indices to expose (e.g., [0, 1])
/// - env_buf: output buffer for GPU environment variables
///
/// returns the env string slice within env_buf, or error.
pub fn setupGpuPassthrough(
    merged_dir: []const u8,
    gpu_indices: []const u32,
    env_buf: *[4096]u8,
) ![]const u8 {
    if (gpu_indices.len == 0) return env_buf[0..0];

    // create device nodes
    try createGpuDeviceNodes(merged_dir, gpu_indices);

    // discover and bind-mount NVIDIA libraries
    discoverAndMountLibs(merged_dir);

    // generate environment variable string
    return generateGpuEnv(gpu_indices, env_buf);
}

/// create /dev/nvidia{N} device nodes plus control devices in the container rootfs.
fn createGpuDeviceNodes(merged_dir: []const u8, gpu_indices: []const u32) !void {
    // ensure /dev exists in the merged dir
    var dev_path_buf: [512]u8 = undefined;
    const dev_path = std.fmt.bufPrint(&dev_path_buf, "{s}/dev", .{merged_dir}) catch return error.PathTooLong;
    std.fs.cwd().makeDir(dev_path) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return error.MkdirFailed,
    };

    // create per-GPU device nodes: /dev/nvidia0, /dev/nvidia1, ...
    for (gpu_indices) |idx| {
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "nvidia{d}", .{idx}) catch continue;
        createDevNode(merged_dir, name, nvidia_major, idx);
    }

    // create control devices
    createDevNode(merged_dir, "nvidiactl", nvidia_major, 255);

    // UVM devices use a different major (usually loaded as a separate module).
    // major 511 is commonly used for nvidia-uvm but it varies.
    // we use major 195 + high minors as a reasonable default.
    createDevNode(merged_dir, "nvidia-uvm", nvidia_major, 252);
    createDevNode(merged_dir, "nvidia-uvm-tools", nvidia_major, 253);
}

/// create a single character device node in the container rootfs.
fn createDevNode(merged_dir: []const u8, name: []const u8, major: u32, minor: u32) void {
    var path_buf: [512]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/dev/{s}", .{ merged_dir, name }) catch return;
    // null-terminate for syscall
    if (path.len >= path_buf.len) return;
    path_buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(path_buf[0..path.len :0]);

    const device_num: u32 = (major << 8) | minor;
    const mode: u32 = 0o020666; // S_IFCHR | rw-rw-rw-
    const rc = linux.syscall4(
        .mknodat,
        @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
        @intFromPtr(path_z),
        mode,
        device_num,
    );
    if (syscall_util.isError(rc)) {
        log.info("GPU device node skipped (no CAP_MKNOD?): /dev/{s}", .{name});
    }
}

/// discover NVIDIA libraries on the host and bind-mount them into the container.
fn discoverAndMountLibs(merged_dir: []const u8) void {
    // ensure container /usr/lib exists
    var lib_dir_buf: [512]u8 = undefined;
    const lib_dir = std.fmt.bufPrint(&lib_dir_buf, "{s}/usr/lib", .{merged_dir}) catch return;
    std.fs.cwd().makePath(lib_dir) catch return;

    for (nvidia_libs) |lib_name| {
        for (lib_search_paths) |search_path| {
            var src_buf: [512]u8 = undefined;
            const src = std.fmt.bufPrint(&src_buf, "{s}/{s}", .{ search_path, lib_name }) catch continue;

            var dst_buf: [512]u8 = undefined;
            const dst = std.fmt.bufPrint(&dst_buf, "{s}/usr/lib/{s}", .{ merged_dir, lib_name }) catch continue;

            // create empty file as mount target
            const f = std.fs.cwd().createFile(dst, .{}) catch continue;
            f.close();

            // bind mount — if source doesn't exist, this fails gracefully
            bindMount(src, dst);
            break; // found this lib, move to next
        }
    }
}

/// perform a bind mount via syscall.
fn bindMount(source: []const u8, target: []const u8) void {
    var src_buf: [513]u8 = undefined;
    var dst_buf: [513]u8 = undefined;

    if (source.len >= src_buf.len or target.len >= dst_buf.len) return;
    @memcpy(src_buf[0..source.len], source);
    src_buf[source.len] = 0;
    @memcpy(dst_buf[0..target.len], target);
    dst_buf[target.len] = 0;

    const src_z: [*:0]const u8 = @ptrCast(src_buf[0..source.len :0]);
    const dst_z: [*:0]const u8 = @ptrCast(dst_buf[0..target.len :0]);

    const rc = linux.syscall5(
        .mount,
        @intFromPtr(src_z),
        @intFromPtr(dst_z),
        0, // fstype (null for bind)
        linux.MS.BIND | linux.MS.REC,
        0, // data
    );
    if (syscall_util.isError(rc)) {
        log.info("GPU lib bind mount failed: {s} -> {s}", .{ source, target });
    }
}

/// generate GPU environment variables.
/// returns a slice like "NVIDIA_VISIBLE_DEVICES=0,1\nCUDA_VISIBLE_DEVICES=0,1\n..."
pub fn generateGpuEnv(gpu_indices: []const u32, buf: *[4096]u8) ![]const u8 {
    var pos: usize = 0;

    // NVIDIA_VISIBLE_DEVICES=0,1,...
    const nvd_prefix = "NVIDIA_VISIBLE_DEVICES=";
    @memcpy(buf[pos..][0..nvd_prefix.len], nvd_prefix);
    pos += nvd_prefix.len;
    pos = try appendGpuList(buf, pos, gpu_indices);
    buf[pos] = 0;
    pos += 1;

    // CUDA_VISIBLE_DEVICES=0,1,...
    const cuda_prefix = "CUDA_VISIBLE_DEVICES=";
    @memcpy(buf[pos..][0..cuda_prefix.len], cuda_prefix);
    pos += cuda_prefix.len;
    pos = try appendGpuList(buf, pos, gpu_indices);
    buf[pos] = 0;
    pos += 1;

    // NVIDIA_DRIVER_CAPABILITIES=compute,utility
    const caps = "NVIDIA_DRIVER_CAPABILITIES=compute,utility";
    @memcpy(buf[pos..][0..caps.len], caps);
    pos += caps.len;
    buf[pos] = 0;
    pos += 1;

    // LD_LIBRARY_PATH=/usr/lib
    const ld_path = "LD_LIBRARY_PATH=/usr/lib";
    @memcpy(buf[pos..][0..ld_path.len], ld_path);
    pos += ld_path.len;
    buf[pos] = 0;
    pos += 1;

    return buf[0..pos];
}

/// append comma-separated GPU indices to buffer.
fn appendGpuList(buf: *[4096]u8, start: usize, indices: []const u32) !usize {
    var pos = start;
    for (indices, 0..) |idx, i| {
        if (i > 0) {
            buf[pos] = ',';
            pos += 1;
        }
        const written = std.fmt.bufPrint(buf[pos..], "{d}", .{idx}) catch return error.BufferTooSmall;
        pos += written.len;
    }
    return pos;
}

// -- tests --

test "generateGpuEnv single GPU" {
    var buf: [4096]u8 = undefined;
    const env = try generateGpuEnv(&[_]u32{0}, &buf);
    try std.testing.expect(env.len > 0);

    // check it contains the expected env vars (null-separated)
    try std.testing.expect(std.mem.indexOf(u8, env, "NVIDIA_VISIBLE_DEVICES=0") != null);
    try std.testing.expect(std.mem.indexOf(u8, env, "CUDA_VISIBLE_DEVICES=0") != null);
    try std.testing.expect(std.mem.indexOf(u8, env, "NVIDIA_DRIVER_CAPABILITIES=compute,utility") != null);
    try std.testing.expect(std.mem.indexOf(u8, env, "LD_LIBRARY_PATH=/usr/lib") != null);
}

test "generateGpuEnv multiple GPUs" {
    var buf: [4096]u8 = undefined;
    const env = try generateGpuEnv(&[_]u32{ 0, 1, 2, 3 }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, env, "NVIDIA_VISIBLE_DEVICES=0,1,2,3") != null);
    try std.testing.expect(std.mem.indexOf(u8, env, "CUDA_VISIBLE_DEVICES=0,1,2,3") != null);
}

test "generateGpuEnv empty returns empty" {
    var buf: [4096]u8 = undefined;
    const env = try generateGpuEnv(&[_]u32{}, &buf);
    // with no GPUs, the env vars have empty values
    try std.testing.expect(std.mem.indexOf(u8, env, "NVIDIA_VISIBLE_DEVICES=") != null);
}

test "appendGpuList single" {
    var buf: [4096]u8 = undefined;
    const end = try appendGpuList(&buf, 0, &[_]u32{7});
    try std.testing.expectEqualStrings("7", buf[0..end]);
}

test "appendGpuList multiple" {
    var buf: [4096]u8 = undefined;
    const end = try appendGpuList(&buf, 0, &[_]u32{ 0, 2, 5 });
    try std.testing.expectEqualStrings("0,2,5", buf[0..end]);
}

test "setupGpuPassthrough no-op with empty indices" {
    var buf: [4096]u8 = undefined;
    const result = try setupGpuPassthrough("/nonexistent/path", &[_]u32{}, &buf);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}
