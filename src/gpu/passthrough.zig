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
const platform = @import("platform");
const log = @import("../lib/log.zig");
const syscall_util = @import("../lib/syscall.zig");
const env_buffer = @import("env_buffer.zig");
const posix = std.posix;
const linux = std.os.linux;
const detect_mod = @import("detect.zig");
const SysfsContent = detect_mod.SysfsContent;
const readSmallFile = detect_mod.readSysfsFile;
pub const mps = @import("mps.zig");

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
    try ensureContainerDevDir(merged_dir);

    for (gpu_indices) |idx| {
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "nvidia{d}", .{idx}) catch continue;
        createDevNode(merged_dir, name, nvidia_major, idx);
    }

    createCommonDeviceNodes(merged_dir);
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
    ensureContainerLibDir(merged_dir) catch return;

    for (nvidia_libs) |lib_name| {
        mountFirstAvailableLib(merged_dir, lib_name);
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
    var writer = env_buffer.NullEnvWriter.init(buf);

    var list_buf: [128]u8 = undefined;
    const gpu_list = try formatGpuList(&list_buf, gpu_indices);

    try writer.writeEntry("NVIDIA_VISIBLE_DEVICES", gpu_list);
    try writer.writeEntry("CUDA_VISIBLE_DEVICES", gpu_list);
    try writer.writeLiteralEntry("NVIDIA_DRIVER_CAPABILITIES=compute,utility");
    try writer.writeLiteralEntry("LD_LIBRARY_PATH=/usr/lib");

    return writer.finish();
}

fn formatGpuList(buf: []u8, indices: []const u32) ![]const u8 {
    var fixed = platform.fixedBufferStream(buf);
    for (indices, 0..) |idx, i| {
        if (i > 0) try fixed.writer().writeByte(',');
        try platform.format(fixed.writer(), "{d}", .{idx});
    }
    return fixed.getWritten();
}

/// apply NUMA affinity to a container cgroup by writing cpuset.mems and cpuset.cpus.
///
/// - cgroup_path: path to the container's cgroup directory
/// - numa_node: NUMA node index from GpuInfo.numa_node; if < 0, no-op
///
/// both sysfs reads and cgroup writes are best-effort — failures are silently ignored
/// so this works on systems without NUMA or without cgroup write access.
pub fn applyNumaAffinity(cgroup_path: []const u8, numa_node: i32) void {
    if (numa_node < 0) return;
    const node: u32 = @intCast(numa_node);

    // write cpuset.mems = numa_node number
    var mems_buf: [16]u8 = undefined;
    const mems_str = std.fmt.bufPrint(&mems_buf, "{d}", .{node}) catch return;
    writeCgroupFile(cgroup_path, "cpuset.mems", mems_str);

    // read the CPU list for this NUMA node from sysfs
    var cpulist_path_buf: [128]u8 = undefined;
    const cpulist_path = std.fmt.bufPrint(
        &cpulist_path_buf,
        "/sys/devices/system/node/node{d}/cpulist",
        .{node},
    ) catch return;

    const content = readSmallFile(cpulist_path) orelse return;
    const cpus = std.mem.trim(u8, content.slice(), " \t\n\r");
    if (cpus.len == 0) return;

    writeCgroupFile(cgroup_path, "cpuset.cpus", cpus);
}

/// write a value to a file inside a cgroup directory. best-effort; silent on failure.
fn writeCgroupFile(cgroup_path: []const u8, filename: []const u8, value: []const u8) void {
    var path_buf: [512]u8 = undefined;
    const file_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ cgroup_path, filename }) catch return;
    const file = platform.cwd().openFile(file_path, .{ .mode = .write_only }) catch return;
    defer file.close();
    file.writeAll(value) catch |e| {
        log.warn("gpu cgroup write failed for {s}/{s}: {}", .{ cgroup_path, filename, e });
    };
}

fn ensureContainerDevDir(merged_dir: []const u8) !void {
    var dev_path_buf: [512]u8 = undefined;
    const dev_path = std.fmt.bufPrint(&dev_path_buf, "{s}/dev", .{merged_dir}) catch return error.PathTooLong;
    platform.cwd().makeDir(dev_path) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return error.MkdirFailed,
    };
}

fn createCommonDeviceNodes(merged_dir: []const u8) void {
    createDevNode(merged_dir, "nvidiactl", nvidia_major, 255);
    createDevNode(merged_dir, "nvidia-uvm", nvidia_major, 252);
    createDevNode(merged_dir, "nvidia-uvm-tools", nvidia_major, 253);
}

fn ensureContainerLibDir(merged_dir: []const u8) !void {
    var lib_dir_buf: [512]u8 = undefined;
    const lib_dir = std.fmt.bufPrint(&lib_dir_buf, "{s}/usr/lib", .{merged_dir}) catch return error.PathTooLong;
    try platform.cwd().makePath(lib_dir);
}

fn mountFirstAvailableLib(merged_dir: []const u8, lib_name: []const u8) void {
    var source_buf: [512]u8 = undefined;
    const source = findHostLibrary(&source_buf, lib_name) orelse return;

    var target_buf: [512]u8 = undefined;
    const target = std.fmt.bufPrint(&target_buf, "{s}/usr/lib/{s}", .{ merged_dir, lib_name }) catch return;

    ensureMountTargetExists(target) catch return;
    bindMount(source, target);
}

fn findHostLibrary(buf: []u8, lib_name: []const u8) ?[]const u8 {
    return findHostLibraryInPaths(buf, lib_name, &lib_search_paths);
}

fn findHostLibraryInPaths(buf: []u8, lib_name: []const u8, search_paths: []const []const u8) ?[]const u8 {
    for (search_paths) |search_path| {
        const src = std.fmt.bufPrint(buf, "{s}/{s}", .{ search_path, lib_name }) catch continue;
        if (!pathExists(src)) continue;
        return src;
    }
    return null;
}

fn ensureMountTargetExists(target: []const u8) !void {
    const file = try platform.cwd().createFile(target, .{});
    file.close();
}

fn pathExists(path: []const u8) bool {
    platform.cwd().access(path, .{}) catch return false;
    return true;
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

test "formatGpuList single" {
    var buf: [32]u8 = undefined;
    const list = try formatGpuList(&buf, &[_]u32{7});
    try std.testing.expectEqualStrings("7", list);
}

test "formatGpuList multiple" {
    var buf: [32]u8 = undefined;
    const list = try formatGpuList(&buf, &[_]u32{ 0, 2, 5 });
    try std.testing.expectEqualStrings("0,2,5", list);
}

test "findHostLibraryInPaths finds fake library roots" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try platform.Dir.from(tmp.dir).makePath("lib-a");
    try platform.Dir.from(tmp.dir).makePath("lib-b");
    try platform.Dir.from(tmp.dir).writeFile(.{ .sub_path = "lib-b/libnvidia-ml.so.1", .data = "" });

    var root_a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var root_b_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_a = try platform.Dir.from(tmp.dir).realpath("lib-a", &root_a_buf);
    const root_b = try platform.Dir.from(tmp.dir).realpath("lib-b", &root_b_buf);

    var path_buf: [512]u8 = undefined;
    const found = findHostLibraryInPaths(&path_buf, "libnvidia-ml.so.1", &.{ root_a, root_b });
    try std.testing.expect(found != null);

    var expected_buf: [512]u8 = undefined;
    const expected = try std.fmt.bufPrint(&expected_buf, "{s}/libnvidia-ml.so.1", .{root_b});
    try std.testing.expectEqualStrings(expected, found.?);
}

test "findHostLibraryInPaths returns null for missing library" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try platform.Dir.from(tmp.dir).realpath(".", &root_buf);

    var path_buf: [512]u8 = undefined;
    try std.testing.expect(findHostLibraryInPaths(&path_buf, "libcuda.so.999", &.{root}) == null);
}

test "setupGpuPassthrough no-op with empty indices" {
    var buf: [4096]u8 = undefined;
    const result = try setupGpuPassthrough("/nonexistent/path", &[_]u32{}, &buf);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "applyNumaAffinity returns immediately for negative numa_node" {
    // must not crash; cgroup_path is irrelevant because we return before touching it
    applyNumaAffinity("/nonexistent/cgroup", -1);
}

test "applyNumaAffinity with valid node but nonexistent paths does not crash" {
    // sysfs read will return null (no such node on CI), so we return before cgroup writes
    applyNumaAffinity("/nonexistent/cgroup", 0);
}

test "writeCgroupFile on invalid path does not crash" {
    // should silently fail on openFile without panicking
    writeCgroupFile("/nonexistent/cgroup", "cpuset.mems", "0");
}
