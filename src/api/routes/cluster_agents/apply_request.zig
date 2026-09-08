const std = @import("std");
const scheduler = @import("../../../cluster/scheduler.zig");
const volumes_mod = @import("../../../state/volumes.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const spec = @import("../../../manifest/spec.zig");
const common = @import("../common.zig");

const extractJsonString = json_helpers.extractJsonString;
const numbers = @import("../../../lib/json_numbers.zig");
const placement_numbers = @import("../../../cluster/placement_numbers.zig");
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
    const document = numbers.parse(alloc, body) catch return ParseError.InvalidRequest;
    defer document.deinit();
    placement_numbers.validateWorkloads(document.value) catch return ParseError.InvalidRequest;

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
            const command = extractCommandString(alloc, block) catch |err| return if (err == error.OutOfMemory) ParseError.OutOfMemory else ParseError.InvalidRequest;

            if (!common.validateClusterInput(image)) {
                alloc.free(command);
                continue;
            }

            const numeric = numbers.parse(alloc, block) catch {
                alloc.free(command);
                return ParseError.InvalidRequest;
            };
            defer numeric.deinit();
            const resources = placement_numbers.Resources.parse(numeric.value, 256) catch {
                alloc.free(command);
                return ParseError.InvalidRequest;
            };
            const rollout = parseRolloutPolicy(numeric.value, block) catch {
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
                    .cpu_limit = resources.cpu,
                    .memory_limit_mb = resources.memory_mb,
                    .gpu_limit = resources.gpus,
                    .gpu_model = extractJsonString(block, "gpu_model"),
                    .gpu_vram_min_mb = resources.vram_mb,
                    .required_labels = extractJsonString(block, "required_labels") orelse "",
                    .gang_world_size = resources.world_size,
                    .gpus_per_rank = resources.gpus_per_rank,
                    .gang_master_port = resources.master_port,
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

fn parseRolloutPolicy(object: std.json.Value, block: []const u8) error{InvalidRolloutConfig}!spec.RolloutPolicy {
    const rollout = object.object.get("rollout") orelse return .{};
    if (rollout != .object) return error.InvalidRolloutConfig;
    const rollout_json = json_helpers.extractJsonObject(block, "rollout") orelse "{}";
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

    const parallelism = numbers.field(u32, rollout, "parallelism", 1, std.math.maxInt(u32), 1) catch return error.InvalidRolloutConfig;

    const delay_between_batches = numbers.field(u32, rollout, "delay_between_batches", 0, std.math.maxInt(u32), 0) catch return error.InvalidRolloutConfig;

    const failure_action = if (extractJsonString(rollout_json, "failure_action")) |action|
        if (std.mem.eql(u8, action, "pause"))
            spec.RolloutFailureAction.pause
        else if (std.mem.eql(u8, action, "rollback"))
            spec.RolloutFailureAction.rollback
        else
            return error.InvalidRolloutConfig
    else
        spec.RolloutFailureAction.rollback;

    const health_check_timeout = numbers.field(u32, rollout, "health_check_timeout", 0, std.math.maxInt(u32), 0) catch return error.InvalidRolloutConfig;

    return .{
        .strategy = strategy,
        .parallelism = parallelism,
        .delay_between_batches = delay_between_batches,
        .failure_action = failure_action,
        .health_check_timeout = health_check_timeout,
    };
}

fn extractCommandString(alloc: std.mem.Allocator, block: []const u8) ![]const u8 {
    return @import("../../../cluster/assignment_spec.zig").fromWorkload(alloc, block);
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

test "parse preserves structured command arrays" {
    const alloc = std.testing.allocator;
    const json =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx","command":["nginx","-g","daemon off"]}]}
    ;

    var parsed = try parse(alloc, json, true);
    defer parsed.deinit(alloc);

    try std.testing.expectEqualStrings("demo-app", parsed.app_name.?);
    try std.testing.expectEqual(@as(usize, 1), parsed.requests.items.len);
    var execution = try @import("../../../cluster/assignment_spec.zig").decode(alloc, parsed.requests.items[0].request.command);
    defer execution.deinit();
    try std.testing.expectEqualStrings("daemon off", execution.value.argv[2]);
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
