const std = @import("std");
const scheduler = @import("../../../cluster/scheduler.zig");
const volumes_mod = @import("../../../state/volumes.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const spec = @import("../../../manifest/spec.zig");
const common = @import("../common.zig");

const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;
const extractJsonArray = json_helpers.extractJsonArray;

pub const ApplyRequest = struct {
    app_name: ?[]const u8,
    summary: app_snapshot.Summary,
    requests: std.ArrayListUnmanaged(ServiceRequest) = .empty,

    pub fn deinit(self: *ApplyRequest, alloc: std.mem.Allocator) void {
        for (self.requests.items) |req| alloc.free(req.request.command);
        self.requests.deinit(alloc);
    }

    pub fn setVolumeConstraints(self: *ApplyRequest, constraints: []const volumes_mod.VolumeConstraint) void {
        if (constraints.len == 0) return;
        for (self.requests.items) |*req| {
            req.request.volume_constraints = constraints;
        }
    }
};

pub const ServiceRequest = struct {
    request: scheduler.PlacementRequest,
    rollout: spec.RolloutPolicy = .{},
};

pub const ParseError = error{
    MissingAppName,
    MissingServicesArray,
    NoServices,
    OutOfMemory,
    InvalidRequest,
    InvalidRolloutConfig,
};

pub fn parse(alloc: std.mem.Allocator, body: []const u8, require_app_name: bool) ParseError!ApplyRequest {
    var parsed: ApplyRequest = .{
        .app_name = extractJsonString(body, "app_name") orelse extractJsonString(body, "volume_app"),
        .summary = app_snapshot.summarize(body),
    };
    errdefer parsed.deinit(alloc);

    if (require_app_name and parsed.app_name == null) {
        return ParseError.MissingAppName;
    }

    if (extractJsonArray(body, "services")) |services_json| {
        var iter = json_helpers.extractJsonObjects(services_json);
        while (iter.next()) |block| {
            const image = extractJsonString(block, "image") orelse continue;
            const command = extractCommandString(alloc, block) catch return ParseError.OutOfMemory;

            if (!common.validateClusterInput(image)) {
                alloc.free(command);
                continue;
            }
            if (command.len > 0 and !common.validateClusterInput(command)) {
                alloc.free(command);
                continue;
            }

            const rollout = parseRolloutPolicy(block) catch {
                alloc.free(command);
                return ParseError.InvalidRolloutConfig;
            };

            parsed.requests.append(alloc, .{
                .request = .{
                    .image = image,
                    .command = command,
                    .health_check_json = json_helpers.extractJsonObject(block, "health_check"),
                    .app_name = parsed.app_name,
                    .workload_kind = if (parsed.app_name != null) "service" else null,
                    .workload_name = if (parsed.app_name != null) (extractJsonString(block, "name") orelse "") else null,
                    .cpu_limit = extractJsonInt(block, "cpu_limit") orelse 1000,
                    .memory_limit_mb = extractJsonInt(block, "memory_limit_mb") orelse 256,
                    .gpu_limit = extractJsonInt(block, "gpu_limit") orelse 0,
                    .gpu_model = extractJsonString(block, "gpu_model"),
                    .gpu_vram_min_mb = if (extractJsonInt(block, "gpu_vram_min_mb")) |v| @as(u64, @intCast(@max(0, v))) else null,
                    .required_labels = extractJsonString(block, "required_labels") orelse "",
                    .gang_world_size = if (extractJsonInt(block, "gang_world_size")) |v| @intCast(@max(0, v)) else 0,
                    .gpus_per_rank = if (extractJsonInt(block, "gpus_per_rank")) |v| @intCast(@max(1, v)) else 1,
                },
                .rollout = rollout,
            }) catch {
                alloc.free(command);
                return ParseError.OutOfMemory;
            };
        }
    } else if (parsed.summary.hasAny()) {
        return parsed;
    }

    if (parsed.requests.items.len == 0) {
        if (parsed.summary.hasAny()) return parsed;
        return ParseError.NoServices;
    }
    return parsed;
}

fn parseRolloutPolicy(block: []const u8) error{InvalidRolloutConfig}!spec.RolloutPolicy {
    const rollout_json = json_helpers.extractJsonObject(block, "rollout") orelse return .{};
    const strategy = if (extractJsonString(rollout_json, "strategy")) |value|
        if (std.mem.eql(u8, value, "rolling"))
            spec.RolloutStrategy.rolling
        else if (std.mem.eql(u8, value, "blue_green"))
            spec.RolloutStrategy.blue_green
        else if (std.mem.eql(u8, value, "canary"))
            spec.RolloutStrategy.canary
        else
            return error.InvalidRolloutConfig
    else
        spec.RolloutStrategy.rolling;

    const parallelism = if (extractJsonInt(rollout_json, "parallelism")) |v| blk: {
        if (v < 1) return error.InvalidRolloutConfig;
        break :blk @as(u32, @intCast(v));
    } else 1;

    const delay_between_batches = if (extractJsonInt(rollout_json, "delay_between_batches")) |v| blk: {
        if (v < 0) return error.InvalidRolloutConfig;
        break :blk @as(u32, @intCast(v));
    } else 0;

    const failure_action = if (extractJsonString(rollout_json, "failure_action")) |action|
        if (std.mem.eql(u8, action, "pause"))
            spec.RolloutFailureAction.pause
        else if (std.mem.eql(u8, action, "rollback"))
            spec.RolloutFailureAction.rollback
        else
            return error.InvalidRolloutConfig
    else
        spec.RolloutFailureAction.rollback;

    const health_check_timeout = if (extractJsonInt(rollout_json, "health_check_timeout")) |v| blk: {
        if (v < 0) return error.InvalidRolloutConfig;
        break :blk @as(u32, @intCast(v));
    } else 0;

    return .{
        .strategy = strategy,
        .parallelism = parallelism,
        .delay_between_batches = delay_between_batches,
        .failure_action = failure_action,
        .health_check_timeout = health_check_timeout,
    };
}

fn extractJsonStringArray(alloc: std.mem.Allocator, json: []const u8, key: []const u8) !?[]u8 {
    const array_json = extractJsonArray(json, key) orelse return null;
    if (array_json.len < 2) return null;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    var pos: usize = 1;
    var first = true;
    while (pos < array_json.len - 1) {
        while (pos < array_json.len - 1 and (array_json[pos] == ' ' or array_json[pos] == '\n' or array_json[pos] == '\r' or array_json[pos] == '\t' or array_json[pos] == ',')) : (pos += 1) {}
        if (pos >= array_json.len - 1) break;
        if (array_json[pos] != '"') return ParseError.InvalidRequest;
        pos += 1;
        const start = pos;

        while (pos < array_json.len - 1) : (pos += 1) {
            if (array_json[pos] == '\\') {
                pos += 1;
                if (pos >= array_json.len - 1) return ParseError.InvalidRequest;
                continue;
            }
            if (array_json[pos] == '"') break;
        }
        if (pos >= array_json.len - 1) return ParseError.InvalidRequest;

        if (!first) try out.append(alloc, ' ');
        first = false;
        try out.appendSlice(alloc, array_json[start..pos]);
        pos += 1;
    }

    return try out.toOwnedSlice(alloc);
}

fn extractCommandString(alloc: std.mem.Allocator, block: []const u8) ![]const u8 {
    if (extractJsonString(block, "command")) |command| {
        return alloc.dupe(u8, command);
    }
    if (try extractJsonStringArray(alloc, block, "command")) |joined| {
        defer alloc.free(joined);
        return alloc.dupe(u8, joined);
    }
    return alloc.dupe(u8, "");
}

test "parse finds services array regardless of field order" {
    const alloc = std.testing.allocator;
    const json =
        \\{"services":[{"name":"svc-a","image":"alpine","gpu":{"devices":["../../dev/sda"]}},{"image":"busybox","name":"svc-b"}]}
    ;

    var parsed = try parse(alloc, json, false);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 2), parsed.requests.items.len);
    try std.testing.expectEqualStrings("alpine", parsed.requests.items[0].request.image);
    try std.testing.expectEqualStrings("busybox", parsed.requests.items[1].request.image);
}

test "parse joins structured command arrays" {
    const alloc = std.testing.allocator;
    const json =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx","command":["nginx","-g","daemon off"]}]}
    ;

    var parsed = try parse(alloc, json, true);
    defer parsed.deinit(alloc);

    try std.testing.expectEqualStrings("demo-app", parsed.app_name.?);
    try std.testing.expectEqual(@as(usize, 1), parsed.requests.items.len);
    try std.testing.expectEqualStrings("nginx -g daemon off", parsed.requests.items[0].request.command);
}

test "parse accepts training-only app apply payloads" {
    const alloc = std.testing.allocator;
    const json =
        \\{"app_name":"demo-app","workers":[],"crons":[],"training_jobs":[{"name":"finetune","image":"trainer:v1","command":["torchrun","train.py"],"gpus":4}],"services":[]}
    ;

    var parsed = try parse(alloc, json, true);
    defer parsed.deinit(alloc);

    try std.testing.expectEqualStrings("demo-app", parsed.app_name.?);
    try std.testing.expectEqual(@as(usize, 0), parsed.requests.items.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.summary.training_job_count);
}

test "parse preserves service workload metadata and rollout policy" {
    const alloc = std.testing.allocator;
    const json =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx","command":["nginx","-g","daemon off"],"rollout":{"parallelism":2,"delay_between_batches":3,"failure_action":"pause","health_check_timeout":12}}]}
    ;

    var parsed = try parse(alloc, json, true);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), parsed.requests.items.len);
    try std.testing.expectEqualStrings("demo-app", parsed.requests.items[0].request.app_name.?);
    try std.testing.expectEqualStrings("service", parsed.requests.items[0].request.workload_kind.?);
    try std.testing.expectEqualStrings("web", parsed.requests.items[0].request.workload_name.?);
    try std.testing.expectEqual(@as(u32, 2), parsed.requests.items[0].rollout.parallelism);
    try std.testing.expectEqual(@as(u32, 3), parsed.requests.items[0].rollout.delay_between_batches);
    try std.testing.expectEqual(spec.RolloutFailureAction.pause, parsed.requests.items[0].rollout.failure_action);
    try std.testing.expectEqual(@as(u32, 12), parsed.requests.items[0].rollout.health_check_timeout);
}

test "parse defaults rollout health gate to disabled when omitted" {
    const alloc = std.testing.allocator;
    const json =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx","command":["nginx","-g","daemon off"],"rollout":{"parallelism":2}}]}
    ;

    var parsed = try parse(alloc, json, true);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), parsed.requests.items.len);
    try std.testing.expectEqual(@as(u32, 0), parsed.requests.items[0].rollout.health_check_timeout);
}

test "parse accepts non-rolling rollout strategies" {
    const alloc = std.testing.allocator;
    const json =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx","command":["nginx","-g","daemon off"],"rollout":{"strategy":"blue_green"}},{"name":"api","image":"nginx","command":["nginx","-g","daemon off"],"rollout":{"strategy":"canary"}}]}
    ;

    var parsed = try parse(alloc, json, true);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(spec.RolloutStrategy.blue_green, parsed.requests.items[0].rollout.strategy);
    try std.testing.expectEqual(spec.RolloutStrategy.canary, parsed.requests.items[1].rollout.strategy);
}

test "parse rejects unsupported rollout strategy" {
    const alloc = std.testing.allocator;
    const json =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx","command":["nginx","-g","daemon off"],"rollout":{"strategy":"wave"}}]}
    ;

    try std.testing.expectError(ParseError.InvalidRolloutConfig, parse(alloc, json, true));
}

test "parse rejects invalid rollout failure action" {
    const alloc = std.testing.allocator;
    const json =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx","command":["nginx","-g","daemon off"],"rollout":{"failure_action":"ignore"}}]}
    ;

    try std.testing.expectError(ParseError.InvalidRolloutConfig, parse(alloc, json, true));
}

test "parse preserves service health checks for agent readiness" {
    const alloc = std.testing.allocator;
    const json =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx","command":["nginx","-g","daemon off"],"health_check":{"kind":"http","path":"/ready","port":8080,"interval":5,"timeout":2,"retries":3,"start_period":1}}]}
    ;

    var parsed = try parse(alloc, json, true);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), parsed.requests.items.len);
    try std.testing.expect(parsed.requests.items[0].request.health_check_json != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed.requests.items[0].request.health_check_json.?, "\"kind\":\"http\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed.requests.items[0].request.health_check_json.?, "\"path\":\"/ready\"") != null);
}
