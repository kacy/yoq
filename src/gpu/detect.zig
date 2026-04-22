// detect — GPU discovery via NVML, procfs, and sysfs
//
// three-tier detection:
//   1. dlopen libnvidia-ml.so.1 — full NVML API (name, UUID, VRAM, PCI, NUMA)
//   2. /proc/driver/nvidia/gpus/ — PCI BDF from procfs subdirs
//   3. /sys/class/drm/card*/device — vendor 0x10de check via sysfs
//
// detect() returns a DetectResult with GPU info and which source was used.
// the NvmlHandle is kept open for health polling if NVML was available.

const std = @import("std");
const fallback_runtime = @import("detect/fallback_runtime.zig");
const nvml_runtime = @import("detect/nvml_runtime.zig");
const types = @import("detect/types.zig");

pub const max_gpus = types.max_gpus;
pub const DetectSource = types.DetectSource;
pub const GpuInfo = types.GpuInfo;
pub const NvmlDevice = types.NvmlDevice;
pub const NvmlGpuInstance = types.NvmlGpuInstance;
pub const NvmlComputeInstance = types.NvmlComputeInstance;
pub const NvmlMemory = types.NvmlMemory;
pub const NvmlUtilization = types.NvmlUtilization;
pub const NvmlHandle = types.NvmlHandle;
pub const DetectResult = types.DetectResult;
pub const SysfsContent = types.SysfsContent;

/// detect GPUs using the best available method.
pub fn detect() DetectResult {
    if (nvml_runtime.detectNvml()) |result| return result;
    if (fallback_runtime.detectProcfs()) |result| return result;
    if (fallback_runtime.detectSysfs()) |result| return result;
    return fallback_runtime.emptyDetectResult(.none, null);
}

pub fn readSysfsFile(path: []const u8) ?SysfsContent {
    return fallback_runtime.readSysfsFile(path);
}

/// extract PCI_SLOT_NAME from a uevent file content
pub fn parsePciBusIdFromUevent(content: []const u8) ?[]const u8 {
    return fallback_runtime.parsePciBusIdFromUevent(content);
}

/// resolve NVLink peer GPU indices after full detection.
pub fn resolveNvLinkPeers(gpus: []GpuInfo, count: u8, nvml: *NvmlHandle) void {
    return nvml_runtime.resolveNvLinkPeers(gpus, count, nvml);
}

fn testRealpath(dir: @import("compat").Dir, sub_path: []const u8, buf: []u8) ![]const u8 {
    return dir.realpath(sub_path, buf);
}

// -- tests --

test "GpuInfo defaults" {
    const gpu = GpuInfo{ .index = 0 };
    try std.testing.expectEqual(@as(u32, 0), gpu.index);
    try std.testing.expectEqual(@as(u64, 0), gpu.vram_mb);
    try std.testing.expectEqual(@as(i32, -1), gpu.numa_node);
    try std.testing.expect(!gpu.mig_capable);
    try std.testing.expectEqual(@as(usize, 0), gpu.getUuid().len);
    try std.testing.expectEqual(@as(usize, 0), gpu.getName().len);
}

test "GpuInfo name and uuid" {
    var gpu = GpuInfo{ .index = 0 };
    const name = "NVIDIA A100";
    @memcpy(gpu.name[0..name.len], name);
    gpu.name_len = name.len;
    try std.testing.expectEqualStrings("NVIDIA A100", gpu.getName());

    const uuid = "GPU-12345678-abcd";
    @memcpy(gpu.uuid[0..uuid.len], uuid);
    gpu.uuid_len = uuid.len;
    try std.testing.expectEqualStrings("GPU-12345678-abcd", gpu.getUuid());
}

test "DetectResult defaults" {
    var result = DetectResult{
        .gpus = undefined,
        .count = 0,
        .source = .none,
        .nvml = null,
    };
    defer result.deinit();
    try std.testing.expectEqual(@as(u8, 0), result.count);
    try std.testing.expectEqual(DetectSource.none, result.source);
    try std.testing.expect(result.nvml == null);
}

test "parsePciBusIdFromUevent extracts PCI slot" {
    const content =
        \\DRIVER=nvidia
        \\PCI_CLASS=30000
        \\PCI_ID=10DE:20B0
        \\PCI_SLOT_NAME=0000:65:00.0
    ;
    const pci = parsePciBusIdFromUevent(content);
    try std.testing.expect(pci != null);
    try std.testing.expectEqualStrings("0000:65:00.0", pci.?);
}

test "parsePciBusIdFromUevent returns null for no match" {
    const content = "DRIVER=nvidia\nPCI_CLASS=30000\n";
    try std.testing.expect(parsePciBusIdFromUevent(content) == null);
}

test "parsePciBusIdFromUevent handles empty" {
    try std.testing.expect(parsePciBusIdFromUevent("") == null);
}

test "detect returns gracefully when no GPUs" {
    var result = detect();
    defer result.deinit();
    try std.testing.expect(result.count <= max_gpus);
}

test "detectProcfs discovers fake GPU directories" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try @import("compat").Dir.from(tmp.dir).makePath("proc/driver/nvidia/gpus/0000:65:00.0");
    try @import("compat").Dir.from(tmp.dir).makePath("proc/driver/nvidia/gpus/0000:b3:00.0");

    var proc_buf: [std.fs.max_path_bytes]u8 = undefined;
    const proc_root = try testRealpath(@import("compat").Dir.from(tmp.dir), "proc/driver/nvidia/gpus", &proc_buf);

    fallback_runtime.setTestProbeRoots(.{ .procfs_gpus = proc_root });
    defer fallback_runtime.resetTestProbeRoots();

    const maybe_result = fallback_runtime.detectProcfs();
    try std.testing.expect(maybe_result != null);
    var result = maybe_result.?;
    defer result.deinit();

    try std.testing.expectEqual(DetectSource.procfs, result.source);
    try std.testing.expectEqual(@as(u8, 2), result.count);
    try std.testing.expectEqualStrings("0000:65:00.0", result.gpus[0].getPciBusId());
    try std.testing.expectEqualStrings("0000:b3:00.0", result.gpus[1].getPciBusId());
}

test "detectSysfs filters NVIDIA cards from fake drm tree" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try @import("compat").Dir.from(tmp.dir).makePath("sys/class/drm/card0/device");
    try @import("compat").Dir.from(tmp.dir).writeFile(.{ .sub_path = "sys/class/drm/card0/device/vendor", .data = "0x10de\n" });
    try @import("compat").Dir.from(tmp.dir).writeFile(.{ .sub_path = "sys/class/drm/card0/device/uevent", .data = "PCI_SLOT_NAME=0000:17:00.0\n" });

    try @import("compat").Dir.from(tmp.dir).makePath("sys/class/drm/card1/device");
    try @import("compat").Dir.from(tmp.dir).writeFile(.{ .sub_path = "sys/class/drm/card1/device/vendor", .data = "0x8086\n" });

    var drm_buf: [std.fs.max_path_bytes]u8 = undefined;
    const drm_root = try testRealpath(@import("compat").Dir.from(tmp.dir), "sys/class/drm", &drm_buf);

    fallback_runtime.setTestProbeRoots(.{ .drm_root = drm_root });
    defer fallback_runtime.resetTestProbeRoots();

    const maybe_result = fallback_runtime.detectSysfs();
    try std.testing.expect(maybe_result != null);
    var result = maybe_result.?;
    defer result.deinit();

    try std.testing.expectEqual(DetectSource.sysfs, result.source);
    try std.testing.expectEqual(@as(u8, 1), result.count);
    try std.testing.expectEqualStrings("0000:17:00.0", result.gpus[0].getPciBusId());
}

test "max_gpus constant" {
    try std.testing.expectEqual(@as(usize, 8), max_gpus);
}

test "GpuInfo nvlink defaults" {
    const gpu = GpuInfo{ .index = 0 };
    try std.testing.expectEqual(@as(u8, 0), gpu.nvlink_peer_count);
    for (gpu.nvlink_peers) |peer| {
        try std.testing.expectEqual(@as(u8, 0), peer);
    }
}

test "GpuInfo nvlink peers" {
    var gpu = GpuInfo{ .index = 0 };
    gpu.nvlink_peers[0] = 1;
    gpu.nvlink_peers[1] = 2;
    gpu.nvlink_peer_count = 2;
    try std.testing.expectEqual(@as(u8, 2), gpu.nvlink_peer_count);
    try std.testing.expectEqual(@as(u8, 1), gpu.nvlink_peers[0]);
    try std.testing.expectEqual(@as(u8, 2), gpu.nvlink_peers[1]);
}

test "GpuInfo compute_capability default is zero" {
    const gpu = GpuInfo{ .index = 0 };
    try std.testing.expectEqual(@as(u16, 0), gpu.compute_capability);
}

test "GpuInfo compute_capability encodes major.minor" {
    var gpu = GpuInfo{ .index = 0 };
    gpu.compute_capability = 80;
    try std.testing.expectEqual(@as(u16, 80), gpu.compute_capability);
}

test "resolveNvLinkPeers no-op without nvml functions" {
    var gpus = [_]GpuInfo{
        .{ .index = 0 },
        .{ .index = 1 },
    };
    var handle = NvmlHandle{
        .lib = undefined,
        .shutdown_fn = undefined,
        .device_get_count_fn = undefined,
        .device_get_handle_fn = undefined,
        .device_get_name_fn = undefined,
        .device_get_memory_fn = undefined,
        .device_get_uuid_fn = undefined,
        .device_get_pci_fn = undefined,
        .device_get_numa_fn = null,
        .device_get_nvlink_remote_pci_fn = null,
        .device_get_nvlink_state_fn = null,
    };
    resolveNvLinkPeers(gpus[0..], 2, &handle);
    try std.testing.expectEqual(@as(u8, 0), gpus[0].nvlink_peer_count);
}
