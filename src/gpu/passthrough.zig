// passthrough — GPU device passthrough for containers
//
// makes NVIDIA GPUs accessible inside containers by:
//   1. creating /dev/nvidia* nodes with the host device identities
//   2. discovering and bind-mounting host NVIDIA libraries
//   3. injecting GPU environment variables (CUDA_VISIBLE_DEVICES, etc.)
//
// called from container setup when gpu_count > 0, after mountOverlay
// and before pivotRoot.

const std = @import("std");
const log = @import("../lib/log.zig");
const env_buffer = @import("env_buffer.zig");
const posix = std.posix;
const linux = std.os.linux;
const detect_mod = @import("detect.zig");
const SysfsContent = detect_mod.SysfsContent;
const readSmallFile = detect_mod.readSysfsFile;
pub const mps = @import("mps.zig");

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
    return setupWith(Operations{}, merged_dir, gpu_indices, env_buf);
}

/// Requested GPUs require the compute/utility runtime. Extra driver libraries
/// are optional when absent; a discovered library must be installed successfully.
fn setupWith(operations: anytype, root: []const u8, indices: []const u32, env_buf: *[4096]u8) ![]const u8 {
    if (indices.len == 0) return env_buf[0..0];
    try operations.prepare(root);
    for (indices) |index| {
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "nvidia{d}", .{index});
        try operations.device(root, name, true);
    }
    try operations.device(root, "nvidiactl", true);
    try operations.device(root, "nvidia-uvm", true);
    try operations.device(root, "nvidia-uvm-tools", false);
    for (nvidia_libs) |name| {
        const required = std.mem.eql(u8, name, "libcuda.so.1") or std.mem.eql(u8, name, "libnvidia-ml.so.1");
        try operations.library(root, name, required);
    }
    return generateGpuEnv(indices, env_buf);
}

const Operations = struct {
    fn prepare(_: @This(), root: []const u8) !void {
        try ensureContainerDevDir(root);
    }
    fn device(_: @This(), root: []const u8, name: []const u8, required: bool) !void {
        try createDevNode(root, name, required);
    }
    fn library(_: @This(), root: []const u8, name: []const u8, required: bool) !void {
        try mountFirstAvailableLib(root, name, required);
    }
};

fn createDevNode(root: []const u8, name: []const u8, required: bool) !void {
    var host_buf: [64]u8 = undefined;
    const host = try std.fmt.bufPrintZ(&host_buf, "/dev/{s}", .{name});
    var stat: linux.Statx = undefined;
    const result = linux.statx(linux.AT.FDCWD, host, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &stat);
    switch (linux.errno(result)) {
        .SUCCESS => {},
        .NOENT => if (required) return error.MissingGpuDevice else return,
        else => return error.GpuDeviceStatFailed,
    }
    if (stat.mode & linux.S.IFMT != linux.S.IFCHR) return error.InvalidGpuDevice;
    // UVM has a dynamically allocated major number; copying the host device
    // identity avoids creating a superficially valid but unusable node.
    const device = (@as(u64, stat.rdev_minor) & 0xff) |
        ((@as(u64, stat.rdev_major) & 0xfff) << 8) |
        ((@as(u64, stat.rdev_minor) & ~@as(u64, 0xff)) << 12) |
        ((@as(u64, stat.rdev_major) & ~@as(u64, 0xfff)) << 32);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "{s}/dev/{s}", .{ root, name });
    const rc = linux.syscall4(.mknodat, @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))), @intFromPtr(path), 0o020666, @intCast(device));
    if (linux.errno(rc) != .SUCCESS) return error.GpuDeviceCreateFailed;
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
    var fixed: std.Io.Writer = .fixed(buf);
    for (indices, 0..) |idx, i| {
        if (i > 0) try fixed.writeByte(',');
        try fixed.print("{d}", .{idx});
    }
    return fixed.buffered();
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
    var file = std.Io.Dir.cwd().openFile(std.Options.debug_io, file_path, .{ .mode = .write_only }) catch return;
    defer file.close(std.Options.debug_io);
    file.writeStreamingAll(std.Options.debug_io, value) catch |e| {
        log.warn("gpu cgroup write failed for {s}/{s}: {}", .{ cgroup_path, filename, e });
    };
}

fn ensureContainerDevDir(merged_dir: []const u8) !void {
    var dev_path_buf: [512]u8 = undefined;
    const dev_path = std.fmt.bufPrint(&dev_path_buf, "{s}/dev", .{merged_dir}) catch return error.PathTooLong;
    std.Io.Dir.cwd().createDir(std.Options.debug_io, dev_path, .default_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return error.MkdirFailed,
    };
}

fn mountFirstAvailableLib(merged_dir: []const u8, lib_name: []const u8, required: bool) !void {
    var source_buf: [512]u8 = undefined;
    const source = findHostLibrary(&source_buf, lib_name) orelse {
        if (required) return error.MissingGpuLibrary;
        return;
    };
    // Host SONAMEs are normally symlinks. Resolve them once before the pinned,
    // root-contained bind helper opens the source without symlink traversal.
    var canonical_buf: [std.fs.max_path_bytes]u8 = undefined;
    const canonical_len = try std.Io.Dir.cwd().realPathFile(std.Options.debug_io, source, &canonical_buf);
    var target_buf: [256]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "/usr/lib/{s}", .{lib_name});
    try @import("../runtime/filesystem.zig").bindMount(merged_dir, canonical_buf[0..canonical_len], target, true);
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

fn pathExists(path: []const u8) bool {
    std.Io.Dir.cwd().access(std.Options.debug_io, path, .{}) catch return false;
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

    try tmp.dir.createDirPath(std.testing.io, "lib-a");
    try tmp.dir.createDirPath(std.testing.io, "lib-b");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "lib-b/libnvidia-ml.so.1", .data = "" });

    var root_a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var root_b_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_a_len = try tmp.dir.realPathFile(std.testing.io, "lib-a", &root_a_buf);
    const root_b_len = try tmp.dir.realPathFile(std.testing.io, "lib-b", &root_b_buf);
    const root_a = root_a_buf[0..root_a_len];
    const root_b = root_b_buf[0..root_b_len];

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
    const root_len = try tmp.dir.realPathFile(std.testing.io, ".", &root_buf);
    const root = root_buf[0..root_len];

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

test "required GPU setup propagates every preparation device and library failure" {
    const Faults = struct {
        fail_at: usize,
        calls: usize = 0,
        fn step(self: *@This()) !void {
            self.calls += 1;
            if (self.calls == self.fail_at) return error.InjectedFailure;
        }
        fn prepare(self: *@This(), _: []const u8) !void {
            try self.step();
        }
        fn device(self: *@This(), _: []const u8, _: []const u8, _: bool) !void {
            try self.step();
        }
        fn library(self: *@This(), _: []const u8, _: []const u8, _: bool) !void {
            try self.step();
        }
    };
    var env: [4096]u8 = undefined;
    const total = 1 + 1 + 3 + nvidia_libs.len;
    for (1..total + 1) |fail_at| {
        var faults = Faults{ .fail_at = fail_at };
        try std.testing.expectError(error.InjectedFailure, setupWith(&faults, "/image", &.{0}, &env));
        try std.testing.expectEqual(fail_at, faults.calls);
    }
    var unused = Faults{ .fail_at = 1 };
    try std.testing.expectEqual(@as(usize, 0), (try setupWith(&unused, "/image", &.{}, &env)).len);
    try std.testing.expectEqual(@as(usize, 0), unused.calls);
}

test "required GPU setup permits absent optional components but requires compute and utility" {
    const Available = struct {
        devices: usize = 0,
        libraries: usize = 0,
        fn prepare(_: *@This(), _: []const u8) !void {}
        fn device(self: *@This(), _: []const u8, name: []const u8, required: bool) !void {
            if (!required) {
                try std.testing.expectEqualStrings("nvidia-uvm-tools", name);
                return;
            }
            self.devices += 1;
        }
        fn library(self: *@This(), _: []const u8, name: []const u8, required: bool) !void {
            if (!required) return;
            try std.testing.expect(std.mem.eql(u8, name, "libcuda.so.1") or std.mem.eql(u8, name, "libnvidia-ml.so.1"));
            self.libraries += 1;
        }
    };
    var available = Available{};
    var env: [4096]u8 = undefined;
    const result = try setupWith(&available, "/image", &.{ 0, 2 }, &env);
    try std.testing.expectEqual(@as(usize, 4), available.devices);
    try std.testing.expectEqual(@as(usize, 2), available.libraries);
    try std.testing.expect(std.mem.indexOf(u8, result, "CUDA_VISIBLE_DEVICES=0,2") != null);
}
