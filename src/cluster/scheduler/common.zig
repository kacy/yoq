const volumes_mod = @import("../../state/volumes.zig");
const gpu_scheduler = @import("../../gpu/scheduler.zig");

pub const VolumeConstraint = volumes_mod.VolumeConstraint;

pub const PlacementRequest = struct {
    image: []const u8,
    command: []const u8,
    health_check_json: ?[]const u8 = null,
    cpu_limit: i64,
    memory_limit_mb: i64,
    app_name: ?[]const u8 = null,
    workload_kind: ?[]const u8 = null,
    workload_name: ?[]const u8 = null,
    gpu_limit: i64 = 0,
    gpu_model: ?[]const u8 = null,
    gpu_vram_min_mb: ?u64 = null,
    required_labels: []const u8 = "",
    volume_constraints: []const VolumeConstraint = &.{},
    gang_world_size: u32 = 0,
    gpus_per_rank: u32 = 1,
    gang_master_port: u16 = 29500,
};

pub const PlacementResult = struct {
    agent_id: []const u8,
    request_idx: usize,
};

pub const GangPlacementResult = struct {
    placements: []const gpu_scheduler.GangPlacement,
    request: PlacementRequest,
};
