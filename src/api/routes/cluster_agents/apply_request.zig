const std = @import("std");
const scheduler = @import("../../../cluster/scheduler.zig");
const volumes_mod = @import("../../../state/volumes.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const spec = @import("../../../manifest/spec.zig");
const names = @import("../../../manifest/names.zig");
const common = @import("../common.zig");

const extractJsonString = json_helpers.extractJsonString;
const numbers = @import("../../../lib/json_numbers.zig");
const placement_numbers = @import("../../../cluster/placement_numbers.zig");
const extractJsonArray = json_helpers.extractJsonArray;

pub const ApplyRequest = struct {
    app_name: ?[]const u8,
    summary: app_snapshot.Summary,
    requests: std.ArrayListUnmanaged(ServiceRequest) = .empty,
    /// the request mounts host paths: a bind mount, or a host or parallel
    /// volume driver. those need more than apps:write.
    uses_host_paths: bool = false,

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
    replicas: u32 = 1,
    request: scheduler.PlacementRequest,
    rollout: spec.RolloutPolicy = .{},
};

pub const ParseError = error{
    MissingAppName,
    MissingServicesArray,
    NoServices,
    OutOfMemory,
    InvalidRequest,
    InvalidImage,
    RelativeBindSource,
    InvalidRolloutConfig,
};

pub fn parse(alloc: std.mem.Allocator, body: []const u8, require_app_name: bool) ParseError!ApplyRequest {
    const document = numbers.parse(alloc, body) catch return ParseError.InvalidRequest;
    defer document.deinit();
    placement_numbers.validateWorkloads(document.value) catch return ParseError.InvalidRequest;
    const uses_host_paths = try validateNamedVolumes(document.value);
    try validateImages(document.value);

    var parsed: ApplyRequest = .{
        .app_name = extractJsonString(body, "app_name") orelse extractJsonString(body, "volume_app"),
        .summary = app_snapshot.summarize(body),
        .uses_host_paths = uses_host_paths,
    };
    errdefer parsed.deinit(alloc);

    if (require_app_name and parsed.app_name == null) {
        return ParseError.MissingAppName;
    }
    // agents build host paths from the app name
    if (parsed.app_name) |name| if (!names.isValid(name)) return ParseError.InvalidRequest;

    if (extractJsonArray(body, "services")) |services_json| {
        var iter = json_helpers.extractJsonObjects(services_json);
        while (iter.next()) |block| {
            // validateImages already checked the parsed document. a raw lookup
            // that still misses means the body was formatted in a way this
            // scanner cannot read, so refuse it rather than drop the service.
            const image = extractJsonString(block, "image") orelse return ParseError.InvalidImage;
            if (!common.validateClusterInput(image)) return ParseError.InvalidImage;
            const encoded = extractCommandString(alloc, block) catch |err| return if (err == error.OutOfMemory) ParseError.OutOfMemory else ParseError.InvalidRequest;
            defer alloc.free(encoded);
            const command = @import("../../../cluster/assignment_spec.zig").withVolumeDefinitions(alloc, encoded, body) catch |err| return if (err == error.OutOfMemory) ParseError.OutOfMemory else ParseError.InvalidRequest;

            const numeric = numbers.parse(alloc, block) catch {
                alloc.free(command);
                return ParseError.InvalidRequest;
            };
            defer numeric.deinit();
            const resources = placement_numbers.Resources.parse(numeric.value, 256) catch {
                alloc.free(command);
                return ParseError.InvalidRequest;
            };
            const replicas = numbers.field(u32, numeric.value, "replicas", 1, spec.max_service_replicas, 1) catch {
                alloc.free(command);
                return ParseError.InvalidRequest;
            };
            if (@as(u64, replicas) * @max(@as(u64, 1), resources.world_size) > spec.max_service_replicas) {
                alloc.free(command);
                return ParseError.InvalidRequest;
            }
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
                .replicas = replicas,
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

/// every workload must name an image the agents can pull. an apply that
/// skipped a bad one would report success while the service never runs.
fn validateImages(root: std.json.Value) ParseError!void {
    for ([_][]const u8{ "services", "workers", "crons", "training_jobs" }) |kind| {
        const workloads = root.object.get(kind) orelse continue;
        if (workloads != .array) return error.InvalidRequest;
        for (workloads.array.items) |workload| {
            if (workload != .object) return error.InvalidRequest;
            const image = workload.object.get("image") orelse return error.InvalidImage;
            if (image != .string or !common.validateClusterInput(image.string)) return error.InvalidImage;
        }
    }
}

/// checks named volume references and reports whether any mount reaches a
/// host path chosen by the caller.
fn validateNamedVolumes(root: std.json.Value) ParseError!bool {
    var uses_host_paths = false;
    const definitions = root.object.get("volume_definitions");
    if (definitions) |volumes| {
        if (volumes != .array) return error.InvalidRequest;
        for (volumes.array.items) |volume| {
            if (volume != .object) return error.InvalidRequest;
            const name = volume.object.get("name") orelse return error.InvalidRequest;
            if (name != .string or !names.isValid(name.string)) return error.InvalidRequest;
            if (volume.object.get("driver")) |driver| {
                if (driver == .object and (driver.object.get("host") != null or driver.object.get("parallel") != null))
                    uses_host_paths = true;
            }
        }
    }
    for ([_][]const u8{ "services", "workers", "crons", "training_jobs" }) |kind| {
        const workloads = root.object.get(kind) orelse continue;
        if (workloads != .array) return error.InvalidRequest;
        for (workloads.array.items) |workload| {
            if (workload != .object) return error.InvalidRequest;
            if (workload.object.get("name")) |name| {
                if (name != .string or !names.isValid(name.string)) return error.InvalidRequest;
            }
            const mounts = workload.object.get("volumes") orelse continue;
            if (mounts != .array) return error.InvalidRequest;
            for (mounts.array.items) |mount| {
                if (mount != .object) return error.InvalidRequest;
                const mount_kind = mount.object.get("kind") orelse return error.InvalidRequest;
                if (mount_kind != .string) return error.InvalidRequest;
                if (std.mem.eql(u8, mount_kind.string, "bind")) {
                    // an agent would resolve a relative source against its
                    // own working directory, which is never what was meant
                    const source = mount.object.get("source") orelse return error.InvalidRequest;
                    if (source != .string or !std.fs.path.isAbsolute(source.string)) return error.RelativeBindSource;
                    uses_host_paths = true;
                    continue;
                }
                if (!std.mem.eql(u8, mount_kind.string, "named")) return error.InvalidRequest;
                const source = mount.object.get("source") orelse return error.InvalidRequest;
                if (source != .string) return error.InvalidRequest;
                const volumes = definitions orelse return error.InvalidRequest;
                for (volumes.array.items) |volume| {
                    if (std.mem.eql(u8, volume.object.get("name").?.string, source.string)) break;
                } else return error.InvalidRequest;
            }
        }
    }
    return uses_host_paths;
}

fn extractCommandString(alloc: std.mem.Allocator, block: []const u8) ![]const u8 {
    return @import("../../../cluster/assignment_spec.zig").fromWorkload(alloc, block);
}

test "parse refuses app, workload and volume names that could become host paths" {
    const alloc = std.testing.allocator;
    const refused = [_][]const u8{
        \\{"app_name":"../../etc","services":[{"name":"web","image":"alpine"}]}
        ,
        \\{"app_name":"demo","services":[{"name":"a/b","image":"alpine"}]}
        ,
        \\{"app_name":"demo","volume_definitions":[{"name":"../../../../usr/lib","driver":{"local":{}}}],"services":[{"name":"web","image":"alpine"}]}
        ,
        \\{"app_name":"demo","volume_definitions":[{"name":"..","driver":{"local":{}}}],"services":[{"name":"web","image":"alpine"}]}
        ,
        \\{"app_name":"","services":[{"name":"web","image":"alpine"}]}
        ,
    };
    for (refused) |json| try std.testing.expectError(ParseError.InvalidRequest, parse(alloc, json, false));

    var accepted = try parse(alloc,
        \\{"app_name":"demo-app","volume_definitions":[{"name":"pg.v2","driver":{"local":{}}}],"services":[{"name":"data-1","image":"alpine"}]}
    , true);
    defer accepted.deinit(alloc);
    try std.testing.expectEqualStrings("demo-app", accepted.app_name.?);
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

test "parse keeps replica instances under one logical service request" {
    const alloc = std.testing.allocator;
    var parsed = try parse(alloc, "{\"app_name\":\"demo\",\"services\":[{\"name\":\"web\",\"image\":\"nginx\",\"replicas\":3,\"required_labels\":\"zone=east\"}]}", true);
    defer parsed.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), parsed.requests.items.len);
    try std.testing.expectEqual(@as(u32, 3), parsed.requests.items[0].replicas);
    try std.testing.expectEqualStrings("web", parsed.requests.items[0].request.workload_name.?);
    try std.testing.expectEqualStrings("zone=east", parsed.requests.items[0].request.required_labels);
}

test "parse refuses a workload with a missing or unusable image instead of skipping it" {
    const alloc = std.testing.allocator;
    const long_image = "r/" ++ "a" ** 300;
    const bad_services = [_][]const u8{
        "{\"name\":\"api\",\"command\":[]}",
        "{\"name\":\"api\",\"image\":\"\",\"command\":[]}",
        "{\"name\":\"api\",\"image\":\"" ++ long_image ++ "\",\"command\":[]}",
        "{\"name\":\"api\",\"image\":\"bad\\\\image\",\"command\":[]}",
        "{\"name\":\"api\",\"image\":7,\"command\":[]}",
    };
    for (bad_services) |bad| {
        const body = try std.fmt.allocPrint(alloc,
            \\{{"app_name":"demo","services":[{{"name":"web","image":"nginx","command":[]}},{s}]}}
        , .{bad});
        defer alloc.free(body);
        try std.testing.expectError(ParseError.InvalidImage, parse(alloc, body, true));
    }

    // dropping the only service used to leave the cron behind and report
    // the apply as completed with nothing placed
    try std.testing.expectError(ParseError.InvalidImage, parse(alloc,
        \\{"app_name":"demo","services":[{"name":"web","image":"","command":[]}],"crons":[{"name":"tick","image":"alpine","every":60}]}
    , true));
    try std.testing.expectError(ParseError.InvalidImage, parse(alloc,
        \\{"app_name":"demo","services":[],"workers":[{"name":"migrate","command":[]}]}
    , true));
}

test "manifest apply rejects undeclared named volumes in every workload collection" {
    const alloc = std.testing.allocator;
    for ([_][]const u8{ "services", "workers", "crons", "training_jobs" }) |kind| {
        const body = try std.fmt.allocPrint(alloc, "{{\"app_name\":\"app\",\"{s}\":[{{\"name\":\"test\",\"image\":\"scratch\",\"volumes\":[{{\"source\":\"data\",\"target\":\"/data\",\"kind\":\"named\"}}]}}]}}", .{kind});
        defer alloc.free(body);
        try std.testing.expectError(error.InvalidRequest, parse(alloc, body, true));
        const declared = try std.fmt.allocPrint(alloc, "{s},\"volume_definitions\":[{{\"name\":\"data\",\"driver\":{{\"local\":{{}}}}}}]}}", .{body[0 .. body.len - 1]});
        defer alloc.free(declared);
        var parsed = try parse(alloc, declared, true);
        defer parsed.deinit(alloc);
    }
}
