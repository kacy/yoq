const std = @import("std");
const log = std.log;
const fallback_runtime = @import("fallback_runtime.zig");
const types = @import("types.zig");

const DetectResult = types.DetectResult;
const GpuInfo = types.GpuInfo;
const NvmlDevice = types.NvmlDevice;
const NvmlHandle = types.NvmlHandle;
const NvmlMemory = types.NvmlMemory;
const NvmlPciInfo = types.NvmlPciInfo;
const NvmlReturn = types.NvmlReturn;
const DetectSource = types.DetectSource;
const max_gpus = types.max_gpus;
const max_nvlinks = 6;

pub fn detectNvml() ?DetectResult {
    var nvml = loadNvmlHandle() orelse return null;
    errdefer nvml.deinit();

    var gpu_count: u32 = 0;
    if (nvml.device_get_count_fn(&gpu_count) != .success) return null;

    const actual_count: u8 = @intCast(@min(gpu_count, max_gpus));
    var result = fallback_runtime.emptyDetectResult(.nvml, nvml);
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
        .device_get_utilization_fn = lookupOptional(&lib, *const fn (NvmlDevice, *types.NvmlUtilization) callconv(.c) NvmlReturn, "nvmlDeviceGetUtilizationRates"),
        .device_get_power_fn = lookupOptional(&lib, *const fn (NvmlDevice, *u32) callconv(.c) NvmlReturn, "nvmlDeviceGetPowerUsage"),
        .device_get_ecc_errors_fn = lookupOptional(&lib, *const fn (NvmlDevice, c_int, c_int, *u64) callconv(.c) NvmlReturn, "nvmlDeviceGetTotalEccErrors"),
        .device_get_nvlink_remote_pci_fn = lookupOptional(&lib, *const fn (NvmlDevice, u32, *NvmlPciInfo) callconv(.c) NvmlReturn, "nvmlDeviceGetNvLinkRemotePciInfo_v2"),
        .device_get_nvlink_state_fn = lookupOptional(&lib, *const fn (NvmlDevice, u32, *u32) callconv(.c) NvmlReturn, "nvmlDeviceGetNvLinkState"),
        .device_get_mig_mode_fn = lookupOptional(&lib, *const fn (NvmlDevice, *u32, *u32) callconv(.c) NvmlReturn, "nvmlDeviceGetMigMode"),
        .device_get_gpu_instance_profile_info_fn = lookupOptional(&lib, *const fn (NvmlDevice, u32, *anyopaque) callconv(.c) NvmlReturn, "nvmlDeviceGetGpuInstanceProfileInfo"),
        .device_get_gpu_instances_fn = lookupOptional(&lib, *const fn (NvmlDevice, u32, [*]types.NvmlGpuInstance, *u32) callconv(.c) NvmlReturn, "nvmlDeviceGetGpuInstances"),
        .gpu_instance_get_info_fn = lookupOptional(&lib, *const fn (types.NvmlGpuInstance, *anyopaque) callconv(.c) NvmlReturn, "nvmlGpuInstanceGetInfo"),
        .gpu_instance_get_compute_instances_fn = lookupOptional(&lib, *const fn (types.NvmlGpuInstance, u32, [*]types.NvmlComputeInstance, *u32) callconv(.c) NvmlReturn, "nvmlGpuInstanceGetComputeInstances"),
        .compute_instance_get_info_fn = lookupOptional(&lib, *const fn (types.NvmlComputeInstance, *anyopaque) callconv(.c) NvmlReturn, "nvmlComputeInstanceGetInfo"),
        .device_get_cuda_compute_capability_fn = lookupOptional(&lib, *const fn (NvmlDevice, *c_int, *c_int) callconv(.c) NvmlReturn, "nvmlDeviceGetCudaComputeCapability"),
        .device_set_mig_mode_fn = lookupOptional(&lib, *const fn (NvmlDevice, u32, *u32) callconv(.c) NvmlReturn, "nvmlDeviceSetMigMode"),
        .device_create_gpu_instance_fn = lookupOptional(&lib, *const fn (NvmlDevice, u32, *types.NvmlGpuInstance) callconv(.c) NvmlReturn, "nvmlDeviceCreateGpuInstance"),
        .gpu_instance_create_compute_instance_fn = lookupOptional(&lib, *const fn (types.NvmlGpuInstance, u32, *types.NvmlComputeInstance) callconv(.c) NvmlReturn, "nvmlGpuInstanceCreateComputeInstance"),
        .device_destroy_gpu_instance_fn = lookupOptional(&lib, *const fn (types.NvmlGpuInstance) callconv(.c) NvmlReturn, "nvmlDeviceDestroyGpuInstance"),
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

fn probeNvLinkPeers(
    gpu: *GpuInfo,
    device: NvmlDevice,
    remote_pci_fn: *const fn (NvmlDevice, u32, *NvmlPciInfo) callconv(.c) NvmlReturn,
    state_fn: ?*const fn (NvmlDevice, u32, *u32) callconv(.c) NvmlReturn,
) void {
    for (0..max_nvlinks) |link| {
        const link_idx: u32 = @intCast(link);
        if (state_fn) |sf| {
            var state: u32 = 0;
            if (sf(device, link_idx, &state) != .success) continue;
            if (state == 0) continue;
        }

        var remote_pci: NvmlPciInfo = undefined;
        if (remote_pci_fn(device, link_idx, &remote_pci) != .success) continue;
        const remote_len = std.mem.indexOfScalar(u8, &remote_pci.bus_id, 0) orelse 0;
        if (remote_len == 0) continue;

        if (gpu.nvlink_peer_count < max_gpus) {
            gpu.nvlink_peers[gpu.nvlink_peer_count] = @intCast(link_idx);
            gpu.nvlink_peer_count += 1;
        }
    }
}

pub fn resolveNvLinkPeers(gpus: []GpuInfo, count: u8, nvml: *NvmlHandle) void {
    const remote_pci_fn = nvml.device_get_nvlink_remote_pci_fn orelse return;

    for (0..count) |i| {
        var gpu = &gpus[i];
        if (gpu.nvlink_peer_count == 0) continue;

        const device = nvml.getDevice(gpu.index) orelse continue;
        var new_count: u8 = 0;

        for (0..max_nvlinks) |link| {
            const link_idx: u32 = @intCast(link);
            if (nvml.device_get_nvlink_state_fn) |sf| {
                var state: u32 = 0;
                if (sf(device, link_idx, &state) != .success) continue;
                if (state == 0) continue;
            }

            var remote_pci: NvmlPciInfo = undefined;
            if (remote_pci_fn(device, link_idx, &remote_pci) != .success) continue;

            const remote_len = std.mem.indexOfScalar(u8, &remote_pci.bus_id, 0) orelse 0;
            if (remote_len == 0) continue;

            for (0..count) |j| {
                if (i == j) continue;
                const peer = &gpus[j];
                const peer_pci = peer.getPciBusId();
                if (peer_pci.len == 0) continue;

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

        if (new_count > 0) gpu.nvlink_peer_count = new_count;
    }
}
