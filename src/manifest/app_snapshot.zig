const std = @import("std");
const json_helpers = @import("../lib/json_helpers.zig");

pub const Summary = struct {
    service_count: usize = 0,
    worker_count: usize = 0,
    cron_count: usize = 0,
    training_job_count: usize = 0,

    pub fn hasAny(self: Summary) bool {
        return self.service_count + self.worker_count + self.cron_count + self.training_job_count > 0;
    }
};

pub const WorkerRunSpec = struct {
    name: []const u8,
    image: []const u8,
    command: []const u8,
    required_labels: []const u8 = "",
    gpu_limit: i64 = 0,
    gpu_model: ?[]const u8 = null,
    gpu_vram_min_mb: ?u64 = null,

    pub fn deinit(self: WorkerRunSpec, alloc: std.mem.Allocator) void {
        alloc.free(self.command);
    }
};

pub const TrainingJobSpec = struct {
    name: []const u8,
    image: []const u8,
    command: []const u8,
    gpus: u32,
    gpu_type: ?[]const u8,
    cpu_limit: i64,
    memory_limit_mb: i64,
    checkpoint_path: ?[]const u8,

    pub fn deinit(self: TrainingJobSpec, alloc: std.mem.Allocator) void {
        alloc.free(self.command);
    }
};

pub fn summarize(json: []const u8) Summary {
    return .{
        .service_count = countArrayObjects(json, "services"),
        .worker_count = countArrayObjects(json, "workers"),
        .cron_count = countArrayObjects(json, "crons"),
        .training_job_count = countArrayObjects(json, "training_jobs"),
    };
}

pub fn findWorkerRunSpec(alloc: std.mem.Allocator, json: []const u8, name: []const u8) !?WorkerRunSpec {
    const obj = findNamedObject(json, "workers", name) orelse return null;

    const image = json_helpers.extractJsonString(obj, "image") orelse return null;
    const command = try extractCommandString(alloc, obj);
    errdefer alloc.free(command);

    var gpu_limit: i64 = 0;
    var gpu_model: ?[]const u8 = null;
    var gpu_vram_min_mb: ?u64 = null;
    if (json_helpers.extractJsonObject(obj, "gpu")) |gpu| {
        gpu_limit = json_helpers.extractJsonInt(gpu, "count") orelse 0;
        gpu_model = json_helpers.extractJsonString(gpu, "model");
        if (json_helpers.extractJsonInt(gpu, "vram_min_mb")) |v| {
            gpu_vram_min_mb = @intCast(@max(@as(i64, 0), v));
        }
    }

    return .{
        .name = name,
        .image = image,
        .command = command,
        .required_labels = json_helpers.extractJsonString(obj, "required_labels") orelse "",
        .gpu_limit = gpu_limit,
        .gpu_model = gpu_model,
        .gpu_vram_min_mb = gpu_vram_min_mb,
    };
}

pub fn findTrainingJobSpec(alloc: std.mem.Allocator, json: []const u8, name: []const u8) !?TrainingJobSpec {
    const obj = findNamedObject(json, "training_jobs", name) orelse return null;

    const image = json_helpers.extractJsonString(obj, "image") orelse return null;
    const command = try extractCommandString(alloc, obj);
    errdefer alloc.free(command);

    const checkpoint_path = if (json_helpers.extractJsonObject(obj, "checkpoint")) |checkpoint|
        json_helpers.extractJsonString(checkpoint, "path")
    else
        null;

    return .{
        .name = name,
        .image = image,
        .command = command,
        .gpus = @intCast(@max(@as(i64, 0), json_helpers.extractJsonInt(obj, "gpus") orelse 0)),
        .gpu_type = json_helpers.extractJsonString(obj, "gpu_type"),
        .cpu_limit = json_helpers.extractJsonInt(obj, "cpu_limit") orelse 1000,
        .memory_limit_mb = json_helpers.extractJsonInt(obj, "memory_limit_mb") orelse 65536,
        .checkpoint_path = checkpoint_path,
    };
}

fn countArrayObjects(json: []const u8, key: []const u8) usize {
    const array = json_helpers.extractJsonArray(json, key) orelse return 0;
    var count: usize = 0;
    var iter = json_helpers.extractJsonObjects(array);
    while (iter.next() != null) count += 1;
    return count;
}

fn findNamedObject(json: []const u8, key: []const u8, name: []const u8) ?[]const u8 {
    const array = json_helpers.extractJsonArray(json, key) orelse return null;
    var iter = json_helpers.extractJsonObjects(array);
    while (iter.next()) |obj| {
        const obj_name = json_helpers.extractJsonString(obj, "name") orelse continue;
        if (std.mem.eql(u8, obj_name, name)) return obj;
    }
    return null;
}

fn extractJsonStringArray(alloc: std.mem.Allocator, json: []const u8, key: []const u8) !?[]u8 {
    const array_json = json_helpers.extractJsonArray(json, key) orelse return null;
    if (array_json.len < 2) return null;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    var pos: usize = 1;
    var first = true;
    while (pos < array_json.len - 1) {
        while (pos < array_json.len - 1 and (array_json[pos] == ' ' or array_json[pos] == '\n' or array_json[pos] == '\r' or array_json[pos] == '\t' or array_json[pos] == ',')) : (pos += 1) {}
        if (pos >= array_json.len - 1) break;
        if (array_json[pos] != '"') return error.InvalidRequest;
        pos += 1;
        const start = pos;

        while (pos < array_json.len - 1) : (pos += 1) {
            if (array_json[pos] == '\\') {
                pos += 1;
                if (pos >= array_json.len - 1) return error.InvalidRequest;
                continue;
            }
            if (array_json[pos] == '"') break;
        }
        if (pos >= array_json.len - 1) return error.InvalidRequest;

        if (!first) try out.append(alloc, ' ');
        first = false;
        try out.appendSlice(alloc, array_json[start..pos]);
        pos += 1;
    }

    return try out.toOwnedSlice(alloc);
}

fn extractCommandString(alloc: std.mem.Allocator, obj: []const u8) ![]const u8 {
    if (json_helpers.extractJsonString(obj, "command")) |command| {
        return alloc.dupe(u8, command);
    }
    if (try extractJsonStringArray(alloc, obj, "command")) |joined| {
        return joined;
    }
    return alloc.dupe(u8, "");
}

test "summarize counts all workload kinds" {
    const summary = summarize(
        \\{"app_name":"demo","services":[{"name":"web"}],"workers":[{"name":"migrate"}],"crons":[{"name":"cleanup"}],"training_jobs":[{"name":"train"}]}
    );

    try std.testing.expectEqual(@as(usize, 1), summary.service_count);
    try std.testing.expectEqual(@as(usize, 1), summary.worker_count);
    try std.testing.expectEqual(@as(usize, 1), summary.cron_count);
    try std.testing.expectEqual(@as(usize, 1), summary.training_job_count);
}

test "findWorkerRunSpec extracts worker scheduler fields" {
    const alloc = std.testing.allocator;
    const json =
        \\{"app_name":"demo","workers":[{"name":"migrate","image":"alpine","command":["sh","-c","migrate"],"required_labels":"gpu=true","gpu":{"count":1,"model":"L4","vram_min_mb":20480}}]}
    ;

    const worker = (try findWorkerRunSpec(alloc, json, "migrate")).?;
    defer worker.deinit(alloc);

    try std.testing.expectEqualStrings("alpine", worker.image);
    try std.testing.expectEqualStrings("sh -c migrate", worker.command);
    try std.testing.expectEqualStrings("gpu=true", worker.required_labels);
    try std.testing.expectEqual(@as(i64, 1), worker.gpu_limit);
    try std.testing.expectEqualStrings("L4", worker.gpu_model.?);
    try std.testing.expectEqual(@as(u64, 20480), worker.gpu_vram_min_mb.?);
}

test "findTrainingJobSpec extracts training scheduler fields" {
    const alloc = std.testing.allocator;
    const json =
        \\{"app_name":"demo","training_jobs":[{"name":"finetune","image":"trainer:v1","command":["torchrun","train.py"],"gpus":4,"gpu_type":"H100","cpu_limit":2000,"memory_limit_mb":131072,"checkpoint":{"path":"/ckpt","interval_secs":1800,"keep":3}}]}
    ;

    const job = (try findTrainingJobSpec(alloc, json, "finetune")).?;
    defer job.deinit(alloc);

    try std.testing.expectEqualStrings("trainer:v1", job.image);
    try std.testing.expectEqualStrings("torchrun train.py", job.command);
    try std.testing.expectEqual(@as(u32, 4), job.gpus);
    try std.testing.expectEqualStrings("H100", job.gpu_type.?);
    try std.testing.expectEqual(@as(i64, 2000), job.cpu_limit);
    try std.testing.expectEqual(@as(i64, 131072), job.memory_limit_mb);
    try std.testing.expectEqualStrings("/ckpt", job.checkpoint_path.?);
}
