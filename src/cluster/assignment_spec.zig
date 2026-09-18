const std = @import("std");
const oci = @import("../image/oci.zig");
const image_spec = @import("../image/spec.zig");
const manifest = @import("../manifest/spec.zig");
pub const max_encoded_bytes = 8192;
pub const sql_buffer_size = max_encoded_bytes * 2 + 4096;

/// Stored in the existing command column so replication and cache copies retain
/// argument boundaries and workload overrides without another schema migration.
pub const Execution = struct {
    version: u8 = 1,
    argv: []const []const u8 = &.{},
    env: []const []const u8 = &.{},
    working_dir: ?[]const u8 = null,
    alerts: ?manifest.AlertSpec = null,
    alert_generation: u64 = 0,
    volumes: []const manifest.VolumeMount = &.{},
    volume_definitions: []const manifest.Volume = &.{},
    ports: []const manifest.PortMapping = &.{},
    gpu_count: u32 = 0,
    gpu_model: ?[]const u8 = null,
    gpu_vram_min_mb: ?u64 = null,
    checkpoint: ?manifest.CheckpointSpec = null,
    resume_checkpoint: bool = false,
    ib_required: bool = false,
};

pub fn fromWorkload(alloc: std.mem.Allocator, json: []const u8) ![]u8 {
    const Workload = struct {
        command: std.json.Value = .null,
        env: []const []const u8 = &.{},
        working_dir: ?[]const u8 = null,
        alerts: ?manifest.AlertSpec = null,
        volumes: []const manifest.VolumeMount = &.{},
        volume_definitions: []const manifest.Volume = &.{},
        ports: []const manifest.PortMapping = &.{},
        gpu: ?manifest.GpuSpec = null,
        gpu_mesh: ?manifest.GpuMeshSpec = null,
        gpus: u32 = 0,
        gpu_limit: u32 = 0,
        gpu_model: ?[]const u8 = null,
        gpu_vram_min_mb: ?u64 = null,
        gpus_per_rank: u32 = 0,
        gpu_type: ?[]const u8 = null,
        checkpoint: ?manifest.CheckpointSpec = null,
        ib_required: bool = false,
    };
    const parsed = try std.json.parseFromSlice(Workload, alloc, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(alloc);
    switch (parsed.value.command) {
        .null => {},
        .string => |value| if (value.len > 0) {
            try argv.append(alloc, value);
        },
        .array => |values| for (values.items) |value| {
            if (value != .string) return error.InvalidRequest;
            try argv.append(alloc, value.string);
        },
        else => return error.InvalidRequest,
    }
    const execution = Execution{
        .argv = argv.items,
        .env = parsed.value.env,
        .working_dir = parsed.value.working_dir,
        .alerts = parsed.value.alerts,
        .volumes = parsed.value.volumes,
        .volume_definitions = parsed.value.volume_definitions,
        .ports = parsed.value.ports,
        .gpu_count = if (parsed.value.gpus > 0) 1 else if (parsed.value.gpu_mesh) |mesh| mesh.gpus_per_rank else if (parsed.value.gpu) |gpu| gpu.count else if (parsed.value.gpus_per_rank > 0) parsed.value.gpus_per_rank else parsed.value.gpu_limit,
        .gpu_model = parsed.value.gpu_type orelse parsed.value.gpu_model orelse if (parsed.value.gpu) |gpu| gpu.model else null,
        .gpu_vram_min_mb = parsed.value.gpu_vram_min_mb orelse if (parsed.value.gpu) |gpu| gpu.vram_min_mb else null,
        .checkpoint = parsed.value.checkpoint,
        .ib_required = parsed.value.ib_required,
    };
    try validate(execution);
    const encoded = try std.json.Stringify.valueAlloc(alloc, execution, .{});
    errdefer alloc.free(encoded);
    if (encoded.len > max_encoded_bytes) return error.InvalidRequest;
    return encoded;
}

pub fn withVolumeDefinitions(alloc: std.mem.Allocator, encoded: []const u8, snapshot: []const u8) ![]u8 {
    var parsed = try decode(alloc, encoded);
    defer parsed.deinit();
    const Definitions = struct { volume_definitions: []const manifest.Volume = &.{} };
    const definitions = try std.json.parseFromSlice(Definitions, alloc, snapshot, .{ .ignore_unknown_fields = true });
    defer definitions.deinit();
    parsed.value.volume_definitions = definitions.value.volume_definitions;
    const result = try std.json.Stringify.valueAlloc(alloc, parsed.value, .{});
    errdefer alloc.free(result);
    if (result.len > max_encoded_bytes) return error.InvalidRequest;
    return result;
}

// placement stamps the guarded state index into the existing command payload.
// it remains unchanged when the same assignment is rescheduled.
pub fn withAlertGeneration(alloc: std.mem.Allocator, encoded: []const u8, generation: u64) ![]u8 {
    var execution = try decode(alloc, encoded);
    defer execution.deinit();
    if (generation > std.math.maxInt(i64)) return error.InvalidRequest;
    execution.value.alert_generation = generation;
    const result = try std.json.Stringify.valueAlloc(alloc, execution.value, .{});
    errdefer alloc.free(result);
    if (result.len > max_encoded_bytes) return error.InvalidRequest;
    return result;
}

pub fn decode(alloc: std.mem.Allocator, encoded: []const u8) !std.json.Parsed(Execution) {
    if (encoded.len > max_encoded_bytes) return error.InvalidRequest;
    if (std.mem.startsWith(u8, encoded, "{")) {
        var parsed = try std.json.parseFromSlice(Execution, alloc, encoded, .{});
        errdefer parsed.deinit();
        try validate(parsed.value);
        return parsed;
    }
    // Old entries contain one executable string. Do not guess shell quoting.
    const legacy = Execution{ .argv = if (encoded.len == 0) &.{} else &.{encoded} };
    const json = try std.json.Stringify.valueAlloc(alloc, legacy, .{});
    defer alloc.free(json);
    return std.json.parseFromSlice(Execution, alloc, json, .{ .allocate = .alloc_always });
}

fn validate(execution: Execution) !void {
    if (execution.alert_generation > std.math.maxInt(i64)) return error.InvalidRequest;
    if (execution.version != 1 or execution.argv.len > 256 or execution.env.len > 256) return error.InvalidRequest;
    for (execution.argv, 0..) |arg, index| {
        if ((index == 0 and arg.len == 0) or std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidRequest;
    }
    for (execution.env) |env| {
        if (std.mem.indexOfScalar(u8, env, 0) != null or std.mem.indexOfScalar(u8, env, '=') == null) return error.InvalidRequest;
    }
    if (execution.volumes.len > 128 or execution.ports.len > 128 or execution.gpu_count > 8) return error.InvalidRequest;
    for (execution.volumes) |mount| {
        if (mount.source.len == 0 or std.mem.indexOfScalar(u8, mount.source, 0) != null or mount.target.len == 0 or mount.target[0] != '/' or std.mem.indexOfScalar(u8, mount.target, 0) != null) return error.InvalidRequest;
    }
    for (execution.ports) |port| if (port.host_port == 0 or port.container_port == 0) return error.InvalidRequest;
    if (execution.working_dir) |dir| {
        if (dir.len == 0 or dir[0] != '/' or std.mem.indexOfScalar(u8, dir, 0) != null) return error.InvalidRequest;
    }
}

pub const Resolved = struct {
    command: oci.ResolvedCommand,
    env: std.ArrayList([]const u8),
    working_dir: []const u8,

    pub fn deinit(self: *Resolved, alloc: std.mem.Allocator) void {
        self.command.args.deinit(alloc);
        self.env.deinit(alloc);
    }
};

pub fn resolve(alloc: std.mem.Allocator, execution: Execution, image: ?image_spec.ContainerConfig, extra_env: []const []const u8) !Resolved {
    const defaults = image orelse image_spec.ContainerConfig{};
    var command = try oci.resolveCommand(alloc, defaults.Entrypoint orelse &.{}, defaults.Cmd orelse &.{}, execution.argv);
    errdefer command.args.deinit(alloc);
    var env: std.ArrayList([]const u8) = .empty;
    errdefer env.deinit(alloc);
    for ([_][]const []const u8{ defaults.Env orelse &.{}, execution.env, extra_env }) |source| {
        for (source) |entry| {
            const key_end = std.mem.indexOfScalar(u8, entry, '=') orelse return error.InvalidRequest;
            var replaced = false;
            for (env.items) |*existing| {
                const existing_end = std.mem.indexOfScalar(u8, existing.*, '=') orelse continue;
                if (std.mem.eql(u8, entry[0..key_end], existing.*[0..existing_end])) {
                    existing.* = entry;
                    replaced = true;
                    break;
                }
            }
            if (!replaced) try env.append(alloc, entry);
        }
    }
    const image_dir = defaults.WorkingDir orelse "/";
    return .{ .command = command, .env = env, .working_dir = execution.working_dir orelse if (image_dir.len > 0) image_dir else "/" };
}

pub fn resourceLimits(cpu_millicores: i64, memory_mb: i64) !@import("../runtime/cgroups.zig").ResourceLimits {
    if (cpu_millicores <= 0 or memory_mb < 4) return error.InvalidRequest;
    // Linux requires at least 1 ms of quota. Extend the usual 100 ms period
    // only for tiny allocations that cannot meet that minimum otherwise.
    const period: u64 = if (cpu_millicores < 10) 1_000_000 else 100_000;
    const cpu = try std.math.mul(u64, @intCast(cpu_millicores), period / 1000);
    const memory = try std.math.mul(u64, @intCast(memory_mb), 1024 * 1024);
    return .{ .cpu_max_usec = cpu, .cpu_max_period = period, .memory_max = memory };
}

test "assignment execution preserves escaped argv and OCI defaults" {
    const alloc = std.testing.allocator;
    const encoded = try fromWorkload(alloc,
        \\{"command":["-c","printf '%s' \"a b\""],"env":["MODE=override"]}
    );
    defer alloc.free(encoded);
    var decoded = try decode(alloc, encoded);
    defer decoded.deinit();
    var resolved = try resolve(alloc, decoded.value, .{ .Entrypoint = &.{"/bin/sh"}, .Cmd = &.{"ignored"}, .Env = &.{ "MODE=image", "KEEP=yes" }, .WorkingDir = "/app" }, &.{"RANK=2"});
    defer resolved.deinit(alloc);
    try std.testing.expectEqualStrings("/bin/sh", resolved.command.command);
    try std.testing.expectEqualStrings("printf '%s' \"a b\"", resolved.command.args.items[1]);
    try std.testing.expectEqualStrings("/app", resolved.working_dir);
    try std.testing.expectEqualStrings("MODE=override", resolved.env.items[0]);
    try std.testing.expectEqualStrings("KEEP=yes", resolved.env.items[1]);
    try std.testing.expectEqualStrings("RANK=2", resolved.env.items[2]);
    const limits = try resourceLimits(1500, 1024);
    try std.testing.expectEqual(@as(?u64, 150000), limits.cpu_max_usec);
    try std.testing.expectEqual(@as(?u64, 1073741824), limits.memory_max);
    try std.testing.expectError(error.InvalidRequest, resourceLimits(-1, 128));
    try std.testing.expectError(error.Overflow, resourceLimits(1, std.math.maxInt(i64)));
}

test "assignment execution runs preserved argv and image environment in a real process" {
    const alloc = std.testing.allocator;
    const encoded = try fromWorkload(alloc,
        \\{"command":["-c","test \"$1\" = \"a b\" && test \"$MODE\" = image", "fixture", "a b"]}
    );
    defer alloc.free(encoded);
    // Follow the production SQL, registry query, HTTP writer, and local cache
    // boundaries before executing the resulting process arguments.
    const registry = @import("registry.zig");
    var sm = try @import("state_machine.zig").StateMachine.initMemory();
    defer sm.deinit();
    var sql: [sql_buffer_size]u8 = undefined;
    sm.apply(.{ .index = 1, .term = 1, .data = try registry.registerSql(&sql, "worker", "127.0.0.1", .{ .cpu_cores = 2, .memory_mb = 2048 }, 0) });
    sm.apply(.{ .index = 2, .term = 1, .data = try @import("scheduler.zig").assignmentSql(&sql, "assignment", "worker", .{ .image = "fixture", .command = encoded, .cpu_limit = 1500, .memory_limit_mb = 1024 }, 0) });
    const assignments = try registry.getAssignments(alloc, &sm.db, "worker");
    defer {
        for (assignments) |assignment| assignment.deinit(alloc);
        alloc.free(assignments);
    }
    try std.testing.expectEqual(@as(usize, 1), assignments.len);
    var response = std.Io.Writer.Allocating.init(alloc);
    defer response.deinit();
    try @import("../api/routes/cluster_agents/writers.zig").writeAssignmentJson(&response.writer, assignments[0]);
    const Fields = struct { command: []const u8, cpu_limit: i64, memory_limit_mb: i64 };
    const fields = try std.json.parseFromSlice(Fields, alloc, response.written(), .{ .ignore_unknown_fields = true });
    defer fields.deinit();
    const cache = @import("agent_store.zig");
    try cache.initTestDb();
    defer cache.closeDb();
    try cache.upsertAssignment(.{ .id = "assignment", .image = "fixture", .command = fields.value.command, .status = "pending", .cpu_limit = fields.value.cpu_limit, .memory_limit_mb = fields.value.memory_limit_mb, .synced_at = 0 });
    const cached = try cache.listPendingAssignments(alloc);
    defer {
        for (cached) |assignment| assignment.deinit(alloc);
        alloc.free(cached);
    }
    try std.testing.expectEqual(@as(usize, 1), cached.len);
    try std.testing.expectEqual(@as(i64, 1500), cached[0].cpu_limit);
    try std.testing.expectEqual(@as(i64, 1024), cached[0].memory_limit_mb);
    var decoded = try decode(alloc, cached[0].command);
    defer decoded.deinit();
    var resolved = try resolve(alloc, decoded.value, .{ .Entrypoint = &.{"sh"}, .Env = &.{ "MODE=image", "PATH=/bin" } }, &.{});
    defer resolved.deinit(alloc);
    const linux = std.os.linux;
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.ForkFailed;
    if (pid == 0) linux.exit_group(@import("../runtime/container/exec_runtime.zig").execCommand(resolved.command.command, resolved.command.args.items, resolved.env.items));
    const result = try @import("../runtime/process.zig").wait(@intCast(pid), false);
    try std.testing.expectEqual(@import("../runtime/process.zig").ExitStatus{ .exited = 0 }, result.status);
}

test "assignment resource limits reach actual kernel cgroup controls" {
    if (std.os.linux.geteuid() != 0) return error.SkipZigTest;
    const runtime = @import("../runtime/container.zig");
    const cgroups = @import("../runtime/cgroups.zig");
    var id: [12]u8 = undefined;
    try runtime.generateId(&id);
    const group = try cgroups.Cgroup.create(&id);
    defer group.destroy() catch {};
    for ([_]i64{ 1, 1500 }) |cpu| {
        const limits = try resourceLimits(cpu, 1024);
        try group.setLimits(limits);
        const actual = group.readAllMetrics();
        try std.testing.expectEqual(limits.cpu_max_usec, actual.cpu_max_usec);
        try std.testing.expectEqual(limits.cpu_max_period, actual.cpu_max_period.?);
        try std.testing.expectEqual(limits.memory_max, actual.memory_limit);
    }
}

test "training execution retains named mounts gpu settings and published ports" {
    const alloc = std.testing.allocator;
    const encoded = try fromWorkload(alloc,
        \\{"command":["python","train script.py"],"env":["DATA=one two"],"working_dir":"/work","gpus":4,"gpu_type":"H100","volumes":[{"source":"dataset","target":"/data","kind":"named"}],"ports":[{"host_port":9090,"container_port":8080}],"checkpoint":{"path":"/data/checkpoints","interval_secs":60,"keep":3}}
    );
    defer alloc.free(encoded);
    const enriched = try withVolumeDefinitions(alloc, encoded,
        \\{"volume_definitions":[{"name":"dataset","driver":{"nfs":{"server":"storage","path":"/dataset","options":"vers=4"}}}]}
    );
    defer alloc.free(enriched);
    const execution = try decode(alloc, enriched);
    defer execution.deinit();
    try std.testing.expectEqualStrings("train script.py", execution.value.argv[1]);
    try std.testing.expectEqualStrings("DATA=one two", execution.value.env[0]);
    try std.testing.expectEqualStrings("/work", execution.value.working_dir.?);
    try std.testing.expectEqual(@as(u32, 1), execution.value.gpu_count);
    try std.testing.expectEqualStrings("H100", execution.value.gpu_model.?);
    try std.testing.expectEqualStrings("/data", execution.value.volumes[0].target);
    try std.testing.expectEqualStrings("storage", execution.value.volume_definitions[0].driver.nfs.server);
    try std.testing.expectEqual(@as(u16, 9090), execution.value.ports[0].host_port);
    try std.testing.expectEqual(@as(u64, 60), execution.value.checkpoint.?.interval_secs);
}

test "assignment preserves service alert configuration" {
    const alloc = std.testing.allocator;
    const encoded = try fromWorkload(alloc,
        \\{"alerts":{"cpu_percent":90,"restart_count":3,"webhook":"https://example.com/hook"}}
    );
    defer alloc.free(encoded);
    var execution = try decode(alloc, encoded);
    defer execution.deinit();
    try std.testing.expectEqual(@as(f64, 90), execution.value.alerts.?.cpu_percent.?);
    try std.testing.expectEqualStrings("https://example.com/hook", execution.value.alerts.?.webhook.?);
}

test "service alert generation preserves execution metadata and defaults legacy assignments to zero" {
    const alloc = std.testing.allocator;
    const initial = try fromWorkload(alloc,
        \\{"command":["worker","argument with spaces"],"alerts":{"cpu_percent":80}}
    );
    defer alloc.free(initial);
    var legacy = try decode(alloc, initial);
    defer legacy.deinit();
    try std.testing.expectEqual(@as(u64, 0), legacy.value.alert_generation);
    const encoded = try withAlertGeneration(alloc, initial, 42);
    defer alloc.free(encoded);
    var execution = try decode(alloc, encoded);
    defer execution.deinit();
    try std.testing.expectEqual(@as(u64, 42), execution.value.alert_generation);
    try std.testing.expectEqualStrings("argument with spaces", execution.value.argv[1]);
    try std.testing.expectEqual(@as(f64, 80), execution.value.alerts.?.cpu_percent.?);
}
