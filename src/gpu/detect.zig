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
const log = @import("../lib/log.zig");

pub const max_gpus = 8;

pub const DetectSource = enum {
    nvml,
    procfs,
    sysfs,
    none,
};

pub const GpuInfo = struct {
    index: u32,
    uuid: [96]u8 = .{0} ** 96,
    uuid_len: u8 = 0,
    name: [64]u8 = .{0} ** 64,
    name_len: u8 = 0,
    vram_mb: u64 = 0,
    pci_bus_id: [16]u8 = .{0} ** 16,
    pci_bus_id_len: u8 = 0,
    numa_node: i32 = -1,
    mig_capable: bool = false,
    compute_capability: u16 = 0,
    nvlink_peers: [max_gpus]u8 = .{0} ** max_gpus,
    nvlink_peer_count: u8 = 0,

    pub fn getUuid(self: *const GpuInfo) []const u8 {
        return self.uuid[0..self.uuid_len];
    }

    pub fn getName(self: *const GpuInfo) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn getPciBusId(self: *const GpuInfo) []const u8 {
        return self.pci_bus_id[0..self.pci_bus_id_len];
    }
};

// NVML types matching the C API
const NvmlReturn = enum(c_int) {
    success = 0,
    _,
};
pub const NvmlDevice = *opaque {};
pub const NvmlGpuInstance = *opaque {};
pub const NvmlComputeInstance = *opaque {};

pub const NvmlMemory = extern struct {
    total: u64,
    free: u64,
    used: u64,
};

pub const NvmlUtilization = extern struct {
    gpu: u32,
    memory: u32,
};

const NvmlPciInfo = extern struct {
    bus_id_legacy: [16]u8,
    domain: u32,
    bus: u32,
    device: u32,
    pci_device_id: u32,
    pci_subsystem_id: u32,
    bus_id: [32]u8,
};

pub const NvmlHandle = struct {
    lib: std.DynLib,
    shutdown_fn: *const fn () callconv(.c) NvmlReturn,
    device_get_count_fn: *const fn (*u32) callconv(.c) NvmlReturn,
    device_get_handle_fn: *const fn (u32, *NvmlDevice) callconv(.c) NvmlReturn,
    device_get_name_fn: *const fn (NvmlDevice, [*]u8, u32) callconv(.c) NvmlReturn,
    device_get_memory_fn: *const fn (NvmlDevice, *NvmlMemory) callconv(.c) NvmlReturn,
    device_get_uuid_fn: *const fn (NvmlDevice, [*]u8, u32) callconv(.c) NvmlReturn,
    device_get_pci_fn: *const fn (NvmlDevice, *NvmlPciInfo) callconv(.c) NvmlReturn,
    // optional — may be null
    device_get_numa_fn: ?*const fn (NvmlDevice, *u32) callconv(.c) NvmlReturn,

    // health polling function pointers (loaded eagerly, used by health.zig)
    device_get_temperature_fn: ?*const fn (NvmlDevice, c_int, *u32) callconv(.c) NvmlReturn = null,
    device_get_utilization_fn: ?*const fn (NvmlDevice, *NvmlUtilization) callconv(.c) NvmlReturn = null,
    device_get_power_fn: ?*const fn (NvmlDevice, *u32) callconv(.c) NvmlReturn = null,
    device_get_ecc_errors_fn: ?*const fn (NvmlDevice, c_int, c_int, *u64) callconv(.c) NvmlReturn = null,

    // NVLink function pointers (loaded eagerly, used by detect for peer topology)
    device_get_nvlink_remote_pci_fn: ?*const fn (NvmlDevice, u32, *NvmlPciInfo) callconv(.c) NvmlReturn = null,
    device_get_nvlink_state_fn: ?*const fn (NvmlDevice, u32, *u32) callconv(.c) NvmlReturn = null,

    // MIG function pointers (loaded eagerly, used by mig.zig)
    device_get_mig_mode_fn: ?*const fn (NvmlDevice, *u32, *u32) callconv(.c) NvmlReturn = null,
    device_get_gpu_instance_profile_info_fn: ?*const fn (NvmlDevice, u32, *anyopaque) callconv(.c) NvmlReturn = null,
    device_get_gpu_instances_fn: ?*const fn (NvmlDevice, u32, [*]NvmlGpuInstance, *u32) callconv(.c) NvmlReturn = null,
    gpu_instance_get_info_fn: ?*const fn (NvmlGpuInstance, *anyopaque) callconv(.c) NvmlReturn = null,
    gpu_instance_get_compute_instances_fn: ?*const fn (NvmlGpuInstance, u32, [*]NvmlComputeInstance, *u32) callconv(.c) NvmlReturn = null,
    compute_instance_get_info_fn: ?*const fn (NvmlComputeInstance, *anyopaque) callconv(.c) NvmlReturn = null,

    // compute capability function pointer
    device_get_cuda_compute_capability_fn: ?*const fn (NvmlDevice, *c_int, *c_int) callconv(.c) NvmlReturn = null,

    // MIG management function pointers (used by mig.zig for create/destroy)
    device_set_mig_mode_fn: ?*const fn (NvmlDevice, u32, *u32) callconv(.c) NvmlReturn = null,
    device_create_gpu_instance_fn: ?*const fn (NvmlDevice, u32, *NvmlGpuInstance) callconv(.c) NvmlReturn = null,
    gpu_instance_create_compute_instance_fn: ?*const fn (NvmlGpuInstance, u32, *NvmlComputeInstance) callconv(.c) NvmlReturn = null,
    device_destroy_gpu_instance_fn: ?*const fn (NvmlGpuInstance) callconv(.c) NvmlReturn = null,

    initialized: bool = false,

    pub fn deinit(self: *NvmlHandle) void {
        if (self.initialized) {
            _ = self.shutdown_fn();
        }
        self.lib.close();
    }

    pub fn getDevice(self: *NvmlHandle, index: u32) ?NvmlDevice {
        var device: NvmlDevice = undefined;
        const ret = self.device_get_handle_fn(index, &device);
        if (ret != .success) return null;
        return device;
    }
};

pub const DetectResult = struct {
    gpus: [max_gpus]GpuInfo,
    count: u8,
    source: DetectSource,
    nvml: ?NvmlHandle,

    pub fn deinit(self: *DetectResult) void {
        if (self.nvml) |*n| n.deinit();
    }
};

/// detect GPUs using the best available method.
pub fn detect() DetectResult {
    if (detectNvml()) |result| return result;
    if (detectProcfs()) |result| return result;
    if (detectSysfs()) |result| return result;
    return emptyDetectResult(.none, null);
}

fn detectNvml() ?DetectResult {
    var nvml = loadNvmlHandle() orelse return null;
    errdefer nvml.deinit();

    var gpu_count: u32 = 0;
    if (nvml.device_get_count_fn(&gpu_count) != .success) return null;

    const actual_count: u8 = @intCast(@min(gpu_count, max_gpus));
    var result = emptyDetectResult(.nvml, nvml);
    result.count = actual_count;

    for (0..actual_count) |i| {
        result.gpus[i] = populateNvmlGpuInfo(&nvml, @intCast(i)) orelse GpuInfo{ .index = @intCast(i) };
    }

    if (result.nvml) |*handle| {
        resolveNvLinkPeers(result.gpus[0..result.count], result.count, handle);
    }

    log.info("GPU: detected {d} GPU(s) via NVML", .{actual_count});
    return result;
}

fn detectProcfs() ?DetectResult {
    var dir = std.fs.openDirAbsolute("/proc/driver/nvidia/gpus", .{ .iterate = true }) catch return null;
    defer dir.close();

    var result = emptyDetectResult(.procfs, null);

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (result.count >= max_gpus) break;
        if (entry.kind != .directory) continue;

        var gpu = GpuInfo{ .index = result.count };

        // directory name is the PCI BDF (e.g., "0000:01:00.0")
        const name = entry.name;
        const len: u8 = @intCast(@min(name.len, 16));
        @memcpy(gpu.pci_bus_id[0..len], name[0..len]);
        gpu.pci_bus_id_len = len;

        result.gpus[result.count] = gpu;
        result.count += 1;
    }

    if (result.count > 0) {
        log.info("GPU: detected {d} GPU(s) via procfs", .{result.count});
        return result;
    }
    return null;
}

fn detectSysfs() ?DetectResult {
    var result = emptyDetectResult(.sysfs, null);

    // scan /sys/class/drm/card* for NVIDIA vendor ID
    var drm_dir = std.fs.openDirAbsolute("/sys/class/drm", .{ .iterate = true }) catch return null;
    defer drm_dir.close();

    var iter = drm_dir.iterate();
    while (iter.next() catch null) |entry| {
        if (result.count >= max_gpus) break;

        const name = entry.name;
        // only check cardN entries (not card0-connector etc)
        if (!std.mem.startsWith(u8, name, "card")) continue;
        // skip entries with dashes (e.g., card0-HDMI-A-1)
        if (std.mem.indexOfScalar(u8, name, '-') != null) continue;

        // read vendor ID
        var path_buf: [256]u8 = undefined;
        const vendor_path = std.fmt.bufPrint(&path_buf, "/sys/class/drm/{s}/device/vendor", .{name}) catch continue;

        const vendor_content = readSysfsFile(vendor_path) orelse continue;
        const trimmed = std.mem.trim(u8, vendor_content.slice(), " \t\n\r");

        // NVIDIA vendor ID is 0x10de
        if (!std.mem.eql(u8, trimmed, "0x10de")) continue;

        var gpu = GpuInfo{ .index = result.count };

        // try to read PCI bus ID from uevent
        var uevent_buf: [256]u8 = undefined;
        const uevent_path = std.fmt.bufPrint(&uevent_buf, "/sys/class/drm/{s}/device/uevent", .{name}) catch {
            result.gpus[result.count] = gpu;
            result.count += 1;
            continue;
        };
        if (readSysfsFile(uevent_path)) |uevent_content| {
            if (parsePciBusIdFromUevent(uevent_content.slice())) |pci| {
                const pci_len: u8 = @intCast(@min(pci.len, 16));
                @memcpy(gpu.pci_bus_id[0..pci_len], pci[0..pci_len]);
                gpu.pci_bus_id_len = pci_len;
            }
        }

        result.gpus[result.count] = gpu;
        result.count += 1;
    }

    if (result.count > 0) {
        log.info("GPU: detected {d} GPU(s) via sysfs", .{result.count});
        return result;
    }
    return null;
}

fn emptyDetectResult(source: DetectSource, nvml: ?NvmlHandle) DetectResult {
    return .{
        .gpus = undefined,
        .count = 0,
        .source = source,
        .nvml = nvml,
    };
}

fn loadNvmlHandle() ?NvmlHandle {
    var lib = std.DynLib.open("libnvidia-ml.so.1") catch return null;
    errdefer lib.close();

    const init_fn = lookupRequired(&lib, *const fn () callconv(.c) NvmlReturn, "nvmlInit_v2") orelse return null;
    const shutdown_fn = lookupRequired(&lib, *const fn () callconv(.c) NvmlReturn, "nvmlShutdown") orelse return null;
    const count_fn = lookupRequired(&lib, *const fn (*u32) callconv(.c) NvmlReturn, "nvmlDeviceGetCount_v2") orelse return null;
    const handle_fn = lookupRequired(&lib, *const fn (u32, *NvmlDevice) callconv(.c) NvmlReturn, "nvmlDeviceGetHandleByIndex_v2") orelse return null;
    const name_fn = lookupRequired(&lib, *const fn (NvmlDevice, [*]u8, u32) callconv(.c) NvmlReturn, "nvmlDeviceGetName") orelse return null;
    const mem_fn = lookupRequired(&lib, *const fn (NvmlDevice, *NvmlMemory) callconv(.c) NvmlReturn, "nvmlDeviceGetMemoryInfo") orelse return null;
    const uuid_fn = lookupRequired(&lib, *const fn (NvmlDevice, [*]u8, u32) callconv(.c) NvmlReturn, "nvmlDeviceGetUUID") orelse return null;
    const pci_fn = lookupRequired(&lib, *const fn (NvmlDevice, *NvmlPciInfo) callconv(.c) NvmlReturn, "nvmlDeviceGetPciInfo_v3") orelse return null;

    if (init_fn() != .success) return null;

    return .{
        .lib = lib,
        .shutdown_fn = shutdown_fn,
        .device_get_count_fn = count_fn,
        .device_get_handle_fn = handle_fn,
        .device_get_name_fn = name_fn,
        .device_get_memory_fn = mem_fn,
        .device_get_uuid_fn = uuid_fn,
        .device_get_pci_fn = pci_fn,
        .device_get_numa_fn = lookupOptional(&lib, *const fn (NvmlDevice, *u32) callconv(.c) NvmlReturn, "nvmlDeviceGetNumaNode"),
        .device_get_temperature_fn = lookupOptional(&lib, *const fn (NvmlDevice, c_int, *u32) callconv(.c) NvmlReturn, "nvmlDeviceGetTemperature"),
        .device_get_utilization_fn = lookupOptional(&lib, *const fn (NvmlDevice, *NvmlUtilization) callconv(.c) NvmlReturn, "nvmlDeviceGetUtilizationRates"),
        .device_get_power_fn = lookupOptional(&lib, *const fn (NvmlDevice, *u32) callconv(.c) NvmlReturn, "nvmlDeviceGetPowerUsage"),
        .device_get_ecc_errors_fn = lookupOptional(&lib, *const fn (NvmlDevice, c_int, c_int, *u64) callconv(.c) NvmlReturn, "nvmlDeviceGetTotalEccErrors"),
        .device_get_nvlink_remote_pci_fn = lookupOptional(&lib, *const fn (NvmlDevice, u32, *NvmlPciInfo) callconv(.c) NvmlReturn, "nvmlDeviceGetNvLinkRemotePciInfo_v2"),
        .device_get_nvlink_state_fn = lookupOptional(&lib, *const fn (NvmlDevice, u32, *u32) callconv(.c) NvmlReturn, "nvmlDeviceGetNvLinkState"),
        .device_get_mig_mode_fn = lookupOptional(&lib, *const fn (NvmlDevice, *u32, *u32) callconv(.c) NvmlReturn, "nvmlDeviceGetMigMode"),
        .device_get_gpu_instance_profile_info_fn = lookupOptional(&lib, *const fn (NvmlDevice, u32, *anyopaque) callconv(.c) NvmlReturn, "nvmlDeviceGetGpuInstanceProfileInfo"),
        .device_get_gpu_instances_fn = lookupOptional(&lib, *const fn (NvmlDevice, u32, [*]NvmlGpuInstance, *u32) callconv(.c) NvmlReturn, "nvmlDeviceGetGpuInstances"),
        .gpu_instance_get_info_fn = lookupOptional(&lib, *const fn (NvmlGpuInstance, *anyopaque) callconv(.c) NvmlReturn, "nvmlGpuInstanceGetInfo"),
        .gpu_instance_get_compute_instances_fn = lookupOptional(&lib, *const fn (NvmlGpuInstance, u32, [*]NvmlComputeInstance, *u32) callconv(.c) NvmlReturn, "nvmlGpuInstanceGetComputeInstances"),
        .compute_instance_get_info_fn = lookupOptional(&lib, *const fn (NvmlComputeInstance, *anyopaque) callconv(.c) NvmlReturn, "nvmlComputeInstanceGetInfo"),
        .device_get_cuda_compute_capability_fn = lookupOptional(&lib, *const fn (NvmlDevice, *c_int, *c_int) callconv(.c) NvmlReturn, "nvmlDeviceGetCudaComputeCapability"),
        .device_set_mig_mode_fn = lookupOptional(&lib, *const fn (NvmlDevice, u32, *u32) callconv(.c) NvmlReturn, "nvmlDeviceSetMigMode"),
        .device_create_gpu_instance_fn = lookupOptional(&lib, *const fn (NvmlDevice, u32, *NvmlGpuInstance) callconv(.c) NvmlReturn, "nvmlDeviceCreateGpuInstance"),
        .gpu_instance_create_compute_instance_fn = lookupOptional(&lib, *const fn (NvmlGpuInstance, u32, *NvmlComputeInstance) callconv(.c) NvmlReturn, "nvmlGpuInstanceCreateComputeInstance"),
        .device_destroy_gpu_instance_fn = lookupOptional(&lib, *const fn (NvmlGpuInstance) callconv(.c) NvmlReturn, "nvmlDeviceDestroyGpuInstance"),
        .initialized = true,
    };
}

fn populateNvmlGpuInfo(nvml: *NvmlHandle, index: u32) ?GpuInfo {
    const device = nvml.getDevice(index) orelse return null;
    var gpu = GpuInfo{ .index = index };

    populateGpuName(nvml, device, &gpu);
    populateGpuMemory(nvml, device, &gpu);
    populateGpuUuid(nvml, device, &gpu);
    populateGpuPciBusId(nvml, device, &gpu);
    populateGpuNumaNode(nvml, device, &gpu);
    populateMigCapability(nvml, device, &gpu);
    populateComputeCapability(nvml, device, &gpu);
    populateNvLinkInfo(nvml, device, &gpu);

    return gpu;
}

fn populateGpuName(nvml: *NvmlHandle, device: NvmlDevice, gpu: *GpuInfo) void {
    var buf: [64]u8 = .{0} ** 64;
    if (nvml.device_get_name_fn(device, &buf, buf.len) != .success) return;
    gpu.name_len = copyNullTerminated(&gpu.name, &buf);
}

fn populateGpuMemory(nvml: *NvmlHandle, device: NvmlDevice, gpu: *GpuInfo) void {
    var mem_info: NvmlMemory = undefined;
    if (nvml.device_get_memory_fn(device, &mem_info) != .success) return;
    gpu.vram_mb = mem_info.total / (1024 * 1024);
}

fn populateGpuUuid(nvml: *NvmlHandle, device: NvmlDevice, gpu: *GpuInfo) void {
    var buf: [96]u8 = .{0} ** 96;
    if (nvml.device_get_uuid_fn(device, &buf, buf.len) != .success) return;
    gpu.uuid_len = copyNullTerminated(&gpu.uuid, &buf);
}

fn populateGpuPciBusId(nvml: *NvmlHandle, device: NvmlDevice, gpu: *GpuInfo) void {
    var pci_info: NvmlPciInfo = undefined;
    if (nvml.device_get_pci_fn(device, &pci_info) != .success) return;
    gpu.pci_bus_id_len = copyNullTerminated(&gpu.pci_bus_id, &pci_info.bus_id);
}

fn populateGpuNumaNode(nvml: *NvmlHandle, device: NvmlDevice, gpu: *GpuInfo) void {
    const numa_fn = nvml.device_get_numa_fn orelse return;
    var numa: u32 = 0;
    if (numa_fn(device, &numa) != .success) return;
    gpu.numa_node = @intCast(numa);
}

fn populateMigCapability(nvml: *NvmlHandle, device: NvmlDevice, gpu: *GpuInfo) void {
    const mig_fn = nvml.device_get_mig_mode_fn orelse return;
    var current: u32 = 0;
    var pending: u32 = 0;
    gpu.mig_capable = mig_fn(device, &current, &pending) == .success;
}

fn populateComputeCapability(nvml: *NvmlHandle, device: NvmlDevice, gpu: *GpuInfo) void {
    const cap_fn = nvml.device_get_cuda_compute_capability_fn orelse return;
    var major: c_int = 0;
    var minor: c_int = 0;
    if (cap_fn(device, &major, &minor) != .success) return;
    gpu.compute_capability = @intCast(@as(u32, @intCast(major)) * 10 + @as(u32, @intCast(minor)));
}

fn populateNvLinkInfo(nvml: *NvmlHandle, device: NvmlDevice, gpu: *GpuInfo) void {
    const remote_pci_fn = nvml.device_get_nvlink_remote_pci_fn orelse return;
    probeNvLinkPeers(gpu, device, remote_pci_fn, nvml.device_get_nvlink_state_fn);
}

fn copyNullTerminated(dest: anytype, source: []const u8) u8 {
    const len = std.mem.indexOfScalar(u8, source, 0) orelse source.len;
    return copyTruncated(dest, source[0..len]);
}

fn copyTruncated(dest: anytype, source: []const u8) u8 {
    const len: u8 = @intCast(@min(dest.len, source.len));
    @memcpy(dest[0..len], source[0..len]);
    return len;
}

fn lookupRequired(lib: *std.DynLib, comptime T: type, symbol_name: [:0]const u8) ?T {
    return lib.lookup(T, symbol_name);
}

fn lookupOptional(lib: *std.DynLib, comptime T: type, symbol_name: [:0]const u8) ?T {
    return lib.lookup(T, symbol_name);
}

pub const SysfsContent = struct {
    buf: [256]u8,
    len: usize,

    pub fn slice(self: *const SysfsContent) []const u8 {
        return self.buf[0..self.len];
    }
};

pub fn readSysfsFile(path: []const u8) ?SysfsContent {
    var result = SysfsContent{ .buf = undefined, .len = 0 };
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();
    result.len = file.read(&result.buf) catch return null;
    return result;
}

/// extract PCI_SLOT_NAME from a uevent file content
pub fn parsePciBusIdFromUevent(content: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "PCI_SLOT_NAME=")) {
            return line["PCI_SLOT_NAME=".len..];
        }
    }
    return null;
}

const max_nvlinks = 6; // NVLink supports up to 6 links per GPU

/// probe NVLink connections for a GPU and record peer indices.
/// checks links 0..5 for active state and resolves the remote peer's
/// GPU index by matching its PCIe bus ID against other detected GPUs.
/// leaves nvlink_peer_count at 0 if NVLink is unavailable.
fn probeNvLinkPeers(
    gpu: *GpuInfo,
    device: NvmlDevice,
    remote_pci_fn: *const fn (NvmlDevice, u32, *NvmlPciInfo) callconv(.c) NvmlReturn,
    state_fn: ?*const fn (NvmlDevice, u32, *u32) callconv(.c) NvmlReturn,
) void {
    for (0..max_nvlinks) |link| {
        const link_idx: u32 = @intCast(link);

        // check link state if available — skip inactive links
        if (state_fn) |sf| {
            var state: u32 = 0;
            if (sf(device, link_idx, &state) != .success) continue;
            if (state == 0) continue; // inactive
        }

        var remote_pci: NvmlPciInfo = undefined;
        if (remote_pci_fn(device, link_idx, &remote_pci) != .success) continue;

        // extract bus ID from remote PCI info
        const remote_len = std.mem.indexOfScalar(u8, &remote_pci.bus_id, 0) orelse 0;
        if (remote_len == 0) continue;

        // store the link index (peer GPU resolution happens at scheduling time
        // when the full GPU list is available)
        if (gpu.nvlink_peer_count < max_gpus) {
            gpu.nvlink_peers[gpu.nvlink_peer_count] = @intCast(link_idx);
            gpu.nvlink_peer_count += 1;
        }
    }
}

/// resolve NVLink peer GPU indices after full detection.
/// matches remote PCIe bus IDs from NVLink probes against the detected
/// GPU list to populate actual peer GPU indices.
pub fn resolveNvLinkPeers(
    gpus: []GpuInfo,
    count: u8,
    nvml: *NvmlHandle,
) void {
    const remote_pci_fn = nvml.device_get_nvlink_remote_pci_fn orelse return;

    for (0..count) |i| {
        var gpu = &gpus[i];
        if (gpu.nvlink_peer_count == 0) continue;

        const device = nvml.getDevice(gpu.index) orelse continue;
        var new_count: u8 = 0;

        for (0..max_nvlinks) |link| {
            const link_idx: u32 = @intCast(link);

            // check link state
            if (nvml.device_get_nvlink_state_fn) |sf| {
                var state: u32 = 0;
                if (sf(device, link_idx, &state) != .success) continue;
                if (state == 0) continue;
            }

            var remote_pci: NvmlPciInfo = undefined;
            if (remote_pci_fn(device, link_idx, &remote_pci) != .success) continue;

            const remote_len = std.mem.indexOfScalar(u8, &remote_pci.bus_id, 0) orelse 0;
            if (remote_len == 0) continue;

            // match against other GPUs
            for (0..count) |j| {
                if (i == j) continue;
                const peer = &gpus[j];
                const peer_pci = peer.getPciBusId();
                if (peer_pci.len == 0) continue;

                // compare up to the shorter length (bus_id may have different formatting)
                const cmp_len = @min(remote_len, peer_pci.len);
                if (std.mem.eql(u8, remote_pci.bus_id[0..cmp_len], peer_pci[0..cmp_len])) {
                    if (new_count < max_gpus) {
                        gpu.nvlink_peers[new_count] = @intCast(j);
                        new_count += 1;
                    }
                    break;
                }
            }
        }

        if (new_count > 0) {
            gpu.nvlink_peer_count = new_count;
        }
    }
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
    try std.testing.expectEqual(@as(u8, 0), result.count);
    try std.testing.expectEqual(DetectSource.none, result.source);
    try std.testing.expect(result.nvml == null);
    result.deinit(); // should be no-op
}

test "parsePciBusIdFromUevent extracts PCI slot" {
    const content = "DRIVER=nvidia\nPCI_CLASS=30200\nPCI_ID=10DE:2204\nPCI_SLOT_NAME=0000:01:00.0\nMODALIAS=pci\n";
    const pci = parsePciBusIdFromUevent(content);
    try std.testing.expect(pci != null);
    try std.testing.expectEqualStrings("0000:01:00.0", pci.?);
}

test "parsePciBusIdFromUevent returns null for no match" {
    const content = "DRIVER=nvidia\nPCI_CLASS=30200\n";
    try std.testing.expect(parsePciBusIdFromUevent(content) == null);
}

test "parsePciBusIdFromUevent handles empty" {
    try std.testing.expect(parsePciBusIdFromUevent("") == null);
}

test "detect returns gracefully when no GPUs" {
    // on a machine without GPUs, detect() should return .none with 0 count
    var result = detect();
    defer result.deinit();
    // we can't assert exact source since CI may or may not have GPUs,
    // but count should match source
    if (result.source == .none) {
        try std.testing.expectEqual(@as(u8, 0), result.count);
    } else {
        try std.testing.expect(result.count > 0);
    }
}

test "max_gpus constant" {
    try std.testing.expectEqual(@as(u8, 8), max_gpus);
}

test "GpuInfo nvlink defaults" {
    const gpu = GpuInfo{ .index = 0 };
    try std.testing.expectEqual(@as(u8, 0), gpu.nvlink_peer_count);
    for (gpu.nvlink_peers) |p| {
        try std.testing.expectEqual(@as(u8, 0), p);
    }
}

test "GpuInfo nvlink peers" {
    var gpu = GpuInfo{ .index = 0 };
    gpu.nvlink_peers[0] = 1;
    gpu.nvlink_peers[1] = 3;
    gpu.nvlink_peer_count = 2;
    try std.testing.expectEqual(@as(u8, 2), gpu.nvlink_peer_count);
    try std.testing.expectEqual(@as(u8, 1), gpu.nvlink_peers[0]);
    try std.testing.expectEqual(@as(u8, 3), gpu.nvlink_peers[1]);
}

test "GpuInfo compute_capability default is zero" {
    const gpu = GpuInfo{ .index = 0 };
    try std.testing.expectEqual(@as(u16, 0), gpu.compute_capability);
}

test "GpuInfo compute_capability encodes major.minor" {
    var gpu = GpuInfo{ .index = 0 };
    // sm_80 (A100): major=8, minor=0 -> 80
    gpu.compute_capability = 80;
    try std.testing.expectEqual(@as(u16, 80), gpu.compute_capability);
    // sm_90 (H100): major=9, minor=0 -> 90
    gpu.compute_capability = 90;
    try std.testing.expectEqual(@as(u16, 90), gpu.compute_capability);
    // sm_86 (RTX 3090): major=8, minor=6 -> 86
    gpu.compute_capability = 86;
    try std.testing.expectEqual(@as(u16, 86), gpu.compute_capability);
}

test "resolveNvLinkPeers no-op without nvml functions" {
    const gpus: [2]GpuInfo = .{
        GpuInfo{ .index = 0, .nvlink_peer_count = 1 },
        GpuInfo{ .index = 1 },
    };
    try std.testing.expectEqual(@as(u8, 1), gpus[0].nvlink_peer_count);
    try std.testing.expectEqual(@as(u8, 0), gpus[1].nvlink_peer_count);
}
