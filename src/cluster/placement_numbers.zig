const std = @import("std");
const numbers = @import("../lib/json_numbers.zig");

// Bounds also leave the byte/quota conversions representable in the runtime.
pub const max_cpu: i64 = @intCast(std.math.maxInt(u64) / 1000);
pub const max_memory_mb: i64 = @intCast(std.math.maxInt(u64) / (1024 * 1024));

pub const Resources = struct {
    cpu: i64,
    memory_mb: i64,
    gpus: i64,
    vram_mb: ?u64,
    world_size: u32,
    gpus_per_rank: u32,
    master_port: u16,

    pub fn parse(object: std.json.Value, default_memory: i64) !Resources {
        return .{
            .cpu = try numbers.field(i64, object, "cpu_limit", 1, max_cpu, 1000),
            .memory_mb = try numbers.field(i64, object, "memory_limit_mb", 4, max_memory_mb, default_memory),
            .gpus = try numbers.field(i64, object, "gpu_limit", 0, std.math.maxInt(u32), 0),
            .vram_mb = try numbers.optional(u64, object, "gpu_vram_min_mb", 0, std.math.maxInt(i64)),
            .world_size = try numbers.field(u32, object, "gang_world_size", 0, std.math.maxInt(u32), 0),
            .gpus_per_rank = try numbers.field(u32, object, "gpus_per_rank", 1, std.math.maxInt(u32), 1),
            .master_port = try numbers.field(u16, object, "gang_master_port", 1, std.math.maxInt(u16), 29500),
        };
    }
};

pub fn validateWorkloads(root: std.json.Value) !void {
    if (root != .object) return error.InvalidRequest;
    for ([_][]const u8{ "services", "workers", "training_jobs", "crons" }) |kind| {
        const array = root.object.get(kind) orelse continue;
        if (array != .array) return error.InvalidRequest;
        for (array.array.items) |workload| {
            _ = try Resources.parse(workload, 256);
            _ = try numbers.optional(u32, workload, "gpus", 0, std.math.maxInt(u32));
            _ = try numbers.optional(u64, workload, "every", 1, std.math.maxInt(u32));
            if (workload.object.get("gpu")) |gpu| {
                _ = try numbers.optional(u32, gpu, "count", 0, std.math.maxInt(u32));
                _ = try numbers.optional(u64, gpu, "vram_min_mb", 0, std.math.maxInt(i64));
            }
            if (workload.object.get("health_check")) |health| try validateHealth(health);
        }
    }
}

pub fn validateHealth(health: std.json.Value) !void {
    for ([_][]const u8{ "interval", "timeout", "retries", "start_period" }) |key|
        _ = try numbers.optional(u32, health, key, 0, std.math.maxInt(u32));
    _ = try numbers.optional(u16, health, "port", 1, std.math.maxInt(u16));
}
