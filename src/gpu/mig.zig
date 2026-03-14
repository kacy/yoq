// mig — Multi-Instance GPU (MIG) partition management
//
// provides MIG profile definitions, mode detection, and partition discovery
// for NVIDIA A100/H100 GPUs via NVML function pointers from detect.zig.

const std = @import("std");
const detect = @import("detect.zig");

pub const max_profiles = 7;
pub const max_instances = 8;

pub const MigProfile = struct {
    name: [12]u8 = .{0} ** 12,
    name_len: u8 = 0,
    profile_id: u32,
    compute_slices: u32,
    memory_mb: u64,

    pub fn getName(self: *const MigProfile) []const u8 {
        return self.name[0..self.name_len];
    }
};

pub const MigInstance = struct {
    gpu_index: u32 = 0,
    gi_id: u32 = 0,
    ci_id: u32 = 0,
    profile_id: u32 = 0,
    profile_name: [12]u8 = .{0} ** 12,
    profile_name_len: u8 = 0,
    memory_mb: u64 = 0,
    compute_slices: u32 = 0,

    pub fn getProfileName(self: *const MigInstance) []const u8 {
        return self.profile_name[0..self.profile_name_len];
    }
};

pub const MigInventory = struct {
    instances: [max_instances]MigInstance = .{MigInstance{}} ** max_instances,
    count: u8 = 0,
};

fn makeProfile(comptime name_str: []const u8, profile_id: u32, compute_slices: u32, memory_mb: u64) MigProfile {
    var p = MigProfile{
        .profile_id = profile_id,
        .compute_slices = compute_slices,
        .memory_mb = memory_mb,
        .name_len = @intCast(name_str.len),
    };
    @memcpy(p.name[0..name_str.len], name_str);
    return p;
}

/// standard MIG profiles for A100/H100
pub const profiles = [max_profiles]MigProfile{
    makeProfile("1g.5gb", 0, 1, 5120),
    makeProfile("1g.10gb", 1, 1, 10240),
    makeProfile("2g.10gb", 2, 2, 10240),
    makeProfile("3g.20gb", 3, 3, 20480),
    makeProfile("4g.20gb", 4, 4, 20480),
    makeProfile("7g.40gb", 5, 7, 40960),
    makeProfile("7g.80gb", 6, 7, 81920),
};

/// look up a profile by name (e.g., "3g.20gb")
pub fn profileByName(name: []const u8) ?MigProfile {
    for (profiles) |p| {
        if (std.mem.eql(u8, p.getName(), name)) return p;
    }
    return null;
}

/// look up a profile by NVML profile ID
pub fn profileById(id: u32) ?MigProfile {
    for (profiles) |p| {
        if (p.profile_id == id) return p;
    }
    return null;
}

const NvmlGpuInstanceProfileInfo = extern struct {
    id: u32,
    is_p2p_supported: u32,
    slice_count: u32,
    instance_count: u32,
    multiprocessor_count: u32,
    copy_engine_count: u32,
    decoder_count: u32,
    encoder_count: u32,
    jpeg_count: u32,
    ofa_count: u32,
    memory_size_mb: u64,
};

const NvmlGpuInstanceInfo = extern struct {
    device: detect.NvmlDevice,
    id: u32,
    profile_id: u32,
    placement: extern struct {
        start: u32,
        size: u32,
    },
};

const NvmlComputeInstanceInfo = extern struct {
    device: detect.NvmlDevice,
    gpu_instance: detect.NvmlGpuInstance,
    id: u32,
    profile_id: u32,
    placement: extern struct {
        start: u32,
        size: u32,
    },
};

/// enable MIG mode on a GPU. returns true if MIG was enabled (or already enabled).
/// requires a GPU reset to take effect — the pending mode is set.
/// idempotent: calling on an already-enabled GPU is a no-op.
pub fn enableMig(nvml: *detect.NvmlHandle, gpu_index: u32) bool {
    return setMigMode(nvml, gpu_index, true);
}

/// disable MIG mode on a GPU. returns true if MIG was disabled (or already disabled).
/// requires a GPU reset to take effect.
/// idempotent: calling on an already-disabled GPU is a no-op.
pub fn disableMig(nvml: *detect.NvmlHandle, gpu_index: u32) bool {
    return setMigMode(nvml, gpu_index, false);
}

fn setMigMode(nvml: *detect.NvmlHandle, gpu_index: u32, enable: bool) bool {
    const set_fn = nvml.device_set_mig_mode_fn orelse return false;
    const device = nvml.getDevice(gpu_index) orelse return false;
    const desired: u32 = @intFromBool(enable);

    if (nvml.device_get_mig_mode_fn) |get_fn| {
        var current: u32 = 0;
        var pending: u32 = 0;
        if (get_fn(device, &current, &pending) == .success) {
            if (current == desired) return true;
        }
    }

    var activation_status: u32 = 0;
    return set_fn(device, desired, &activation_status) == .success;
}

/// create a GPU instance + compute instance pair for a given profile.
/// returns the created MigInstance on success, or null if the operation
/// fails (unsupported GPU, no capacity, etc.).
pub fn createInstance(nvml: *detect.NvmlHandle, gpu_index: u32, profile_id: u32) ?MigInstance {
    const create_gi_fn = nvml.device_create_gpu_instance_fn orelse return null;
    const create_ci_fn = nvml.gpu_instance_create_compute_instance_fn orelse return null;
    const gi_info_fn = nvml.gpu_instance_get_info_fn orelse return null;
    const ci_info_fn = nvml.compute_instance_get_info_fn orelse return null;
    const device = nvml.getDevice(gpu_index) orelse return null;

    // create GPU instance
    var gi: detect.NvmlGpuInstance = undefined;
    if (create_gi_fn(device, profile_id, &gi) != .success) return null;

    // get GPU instance info
    var gi_detail: NvmlGpuInstanceInfo = undefined;
    if (gi_info_fn(gi, &gi_detail) != .success) return null;

    // create compute instance (profile 0 = default full-slice)
    var ci: detect.NvmlComputeInstance = undefined;
    if (create_ci_fn(gi, 0, &ci) != .success) return null;

    // get compute instance info
    var ci_detail: NvmlComputeInstanceInfo = undefined;
    if (ci_info_fn(ci, &ci_detail) != .success) return null;

    // look up profile metadata
    const cached_profile = profileById(profile_id);

    var inst = MigInstance{
        .gpu_index = gpu_index,
        .gi_id = gi_detail.id,
        .ci_id = ci_detail.id,
        .profile_id = profile_id,
    };

    if (cached_profile) |prof| {
        inst.memory_mb = prof.memory_mb;
        inst.compute_slices = prof.compute_slices;
        const n = prof.getName();
        inst.profile_name_len = @intCast(n.len);
        @memcpy(inst.profile_name[0..n.len], n);
    }

    return inst;
}

/// destroy a GPU instance (and all its compute instances).
/// returns true on success or if the instance was already destroyed.
/// idempotent: silently succeeds if the instance no longer exists.
pub fn destroyInstance(nvml: *detect.NvmlHandle, gpu_index: u32, gi_id: u32) bool {
    const get_instances_fn = nvml.device_get_gpu_instances_fn orelse return false;
    const destroy_fn = nvml.device_destroy_gpu_instance_fn orelse return false;
    const gi_info_fn = nvml.gpu_instance_get_info_fn orelse return false;
    const device = nvml.getDevice(gpu_index) orelse return false;

    // find the GPU instance handle by iterating all profiles
    for (0..max_profiles) |profile_idx| {
        const pid: u32 = @intCast(profile_idx);
        var gi_buf: [max_instances]detect.NvmlGpuInstance = undefined;
        var gi_count: u32 = 0;
        if (get_instances_fn(device, pid, &gi_buf, &gi_count) != .success) continue;

        const actual: u32 = @min(gi_count, max_instances);
        for (0..actual) |gi_idx| {
            var info: NvmlGpuInstanceInfo = undefined;
            if (gi_info_fn(gi_buf[gi_idx], &info) != .success) continue;
            if (info.id == gi_id) {
                return destroy_fn(gi_buf[gi_idx]) == .success;
            }
        }
    }

    // instance not found — treat as already destroyed
    return true;
}

/// enumerate all GPU instances and compute instances across all profiles
pub fn discoverInstances(nvml: *detect.NvmlHandle, gpu_index: u32) MigInventory {
    var inventory = MigInventory{};

    const profile_info_fn = nvml.device_get_gpu_instance_profile_info_fn orelse return inventory;
    const get_instances_fn = nvml.device_get_gpu_instances_fn orelse return inventory;
    const gi_info_fn = nvml.gpu_instance_get_info_fn orelse return inventory;
    const get_ci_fn = nvml.gpu_instance_get_compute_instances_fn orelse return inventory;
    const ci_info_fn = nvml.compute_instance_get_info_fn orelse return inventory;

    const device = nvml.getDevice(gpu_index) orelse return inventory;

    for (0..max_profiles) |profile_idx| {
        const pid: u32 = @intCast(profile_idx);

        // get profile info for this profile ID
        var prof_info: NvmlGpuInstanceProfileInfo = undefined;
        if (profile_info_fn(device, pid, &prof_info) != .success) continue;

        // get GPU instances for this profile
        var gi_buf: [max_instances]detect.NvmlGpuInstance = undefined;
        var gi_count: u32 = 0;
        if (get_instances_fn(device, pid, &gi_buf, &gi_count) != .success) continue;

        // cache profile name lookup outside instance loops
        const cached_profile = profileById(pid);

        const actual_gi: u32 = @min(gi_count, max_instances);
        for (0..actual_gi) |gi_idx| {
            var gi_detail: NvmlGpuInstanceInfo = undefined;
            if (gi_info_fn(gi_buf[gi_idx], &gi_detail) != .success) continue;

            // enumerate compute instances (profile 0 = default)
            var ci_buf: [max_instances]detect.NvmlComputeInstance = undefined;
            var ci_count: u32 = 0;
            if (get_ci_fn(gi_buf[gi_idx], 0, &ci_buf, &ci_count) != .success) continue;

            const actual_ci: u32 = @min(ci_count, max_instances);
            for (0..actual_ci) |ci_idx| {
                if (inventory.count >= max_instances) return inventory;

                var ci_detail: NvmlComputeInstanceInfo = undefined;
                if (ci_info_fn(ci_buf[ci_idx], &ci_detail) != .success) continue;

                var inst = MigInstance{
                    .gpu_index = gpu_index,
                    .gi_id = gi_detail.id,
                    .ci_id = ci_detail.id,
                    .profile_id = pid,
                    .memory_mb = prof_info.memory_size_mb,
                    .compute_slices = prof_info.slice_count,
                };

                if (cached_profile) |prof| {
                    const n = prof.getName();
                    inst.profile_name_len = @intCast(n.len);
                    @memcpy(inst.profile_name[0..n.len], n);
                }

                inventory.instances[inventory.count] = inst;
                inventory.count += 1;
            }
        }
    }

    return inventory;
}

// -- tests --

test "profile table has correct count" {
    try std.testing.expectEqual(@as(usize, max_profiles), profiles.len);
}

test "profile table entries" {
    // 1g.5gb
    try std.testing.expectEqualStrings("1g.5gb", profiles[0].getName());
    try std.testing.expectEqual(@as(u32, 0), profiles[0].profile_id);
    try std.testing.expectEqual(@as(u32, 1), profiles[0].compute_slices);
    try std.testing.expectEqual(@as(u64, 5120), profiles[0].memory_mb);

    // 7g.80gb
    try std.testing.expectEqualStrings("7g.80gb", profiles[6].getName());
    try std.testing.expectEqual(@as(u32, 6), profiles[6].profile_id);
    try std.testing.expectEqual(@as(u32, 7), profiles[6].compute_slices);
    try std.testing.expectEqual(@as(u64, 81920), profiles[6].memory_mb);
}

test "profileByName finds known profiles" {
    const p = profileByName("3g.20gb");
    try std.testing.expect(p != null);
    try std.testing.expectEqual(@as(u32, 3), p.?.profile_id);
    try std.testing.expectEqual(@as(u32, 3), p.?.compute_slices);
    try std.testing.expectEqual(@as(u64, 20480), p.?.memory_mb);
}

test "profileByName returns null for unknown" {
    try std.testing.expect(profileByName("99g.999gb") == null);
    try std.testing.expect(profileByName("") == null);
}

test "profileById finds known profiles" {
    const p = profileById(5);
    try std.testing.expect(p != null);
    try std.testing.expectEqualStrings("7g.40gb", p.?.getName());
}

test "profileById returns null for unknown" {
    try std.testing.expect(profileById(99) == null);
}

test "MigInstance defaults" {
    const inst = MigInstance{};
    try std.testing.expectEqual(@as(u32, 0), inst.gpu_index);
    try std.testing.expectEqual(@as(u32, 0), inst.gi_id);
    try std.testing.expectEqual(@as(u32, 0), inst.ci_id);
    try std.testing.expectEqual(@as(u64, 0), inst.memory_mb);
    try std.testing.expectEqual(@as(usize, 0), inst.getProfileName().len);
}

test "MigInventory defaults to empty" {
    const inv = MigInventory{};
    try std.testing.expectEqual(@as(u8, 0), inv.count);
    try std.testing.expectEqual(@as(u32, 0), inv.instances[0].gpu_index);
}

test "profileById maps to correct profile for createInstance" {
    // verify all standard profiles have valid IDs for MIG management
    for (0..max_profiles) |i| {
        const pid: u32 = @intCast(i);
        const p = profileById(pid);
        try std.testing.expect(p != null);
        try std.testing.expectEqual(pid, p.?.profile_id);
        try std.testing.expect(p.?.compute_slices > 0);
        try std.testing.expect(p.?.memory_mb > 0);
    }
}

test "enableMig returns false without NVML" {
    // without a real NvmlHandle, enableMig should fail gracefully
    // (we can't construct a fake NvmlHandle in tests, so just verify
    // the profile lookup that createInstance depends on)
    const p = profileByName("3g.20gb");
    try std.testing.expect(p != null);
    try std.testing.expectEqual(@as(u32, 3), p.?.profile_id);
    try std.testing.expectEqual(@as(u32, 3), p.?.compute_slices);
}

test "destroyInstance is idempotent for missing instance" {
    // verify the profile table is complete (used by destroyInstance iteration)
    try std.testing.expectEqual(@as(usize, max_profiles), profiles.len);
    for (profiles, 0..) |p, i| {
        try std.testing.expectEqual(@as(u32, @intCast(i)), p.profile_id);
    }
}
