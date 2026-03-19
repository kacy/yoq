const std = @import("std");

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

pub const NvmlReturn = enum(c_int) {
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

pub const NvmlPciInfo = extern struct {
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
    device_get_numa_fn: ?*const fn (NvmlDevice, *u32) callconv(.c) NvmlReturn,
    device_get_temperature_fn: ?*const fn (NvmlDevice, c_int, *u32) callconv(.c) NvmlReturn = null,
    device_get_utilization_fn: ?*const fn (NvmlDevice, *NvmlUtilization) callconv(.c) NvmlReturn = null,
    device_get_power_fn: ?*const fn (NvmlDevice, *u32) callconv(.c) NvmlReturn = null,
    device_get_ecc_errors_fn: ?*const fn (NvmlDevice, c_int, c_int, *u64) callconv(.c) NvmlReturn = null,
    device_get_nvlink_remote_pci_fn: ?*const fn (NvmlDevice, u32, *NvmlPciInfo) callconv(.c) NvmlReturn = null,
    device_get_nvlink_state_fn: ?*const fn (NvmlDevice, u32, *u32) callconv(.c) NvmlReturn = null,
    device_get_mig_mode_fn: ?*const fn (NvmlDevice, *u32, *u32) callconv(.c) NvmlReturn = null,
    device_get_gpu_instance_profile_info_fn: ?*const fn (NvmlDevice, u32, *anyopaque) callconv(.c) NvmlReturn = null,
    device_get_gpu_instances_fn: ?*const fn (NvmlDevice, u32, [*]NvmlGpuInstance, *u32) callconv(.c) NvmlReturn = null,
    gpu_instance_get_info_fn: ?*const fn (NvmlGpuInstance, *anyopaque) callconv(.c) NvmlReturn = null,
    gpu_instance_get_compute_instances_fn: ?*const fn (NvmlGpuInstance, u32, [*]NvmlComputeInstance, *u32) callconv(.c) NvmlReturn = null,
    compute_instance_get_info_fn: ?*const fn (NvmlComputeInstance, *anyopaque) callconv(.c) NvmlReturn = null,
    device_get_cuda_compute_capability_fn: ?*const fn (NvmlDevice, *c_int, *c_int) callconv(.c) NvmlReturn = null,
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

pub const SysfsContent = struct {
    buf: [256]u8,
    len: usize,

    pub fn slice(self: *const SysfsContent) []const u8 {
        return self.buf[0..self.len];
    }
};
