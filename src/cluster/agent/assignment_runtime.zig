const std = @import("std");
const http_client = @import("../http_client.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const log = @import("../../lib/log.zig");
const container = @import("../../runtime/container.zig");
const image_registry = @import("../../image/registry.zig");
const image_layer = @import("../../image/layer.zig");
const image_spec = @import("../../image/spec.zig");
const manifest_health = @import("../../manifest/health.zig");
const manifest_spec = @import("../../manifest/spec.zig");
const store = @import("../../state/store.zig");
const logs = @import("../../runtime/logs.zig");
const api_endpoints = @import("../api_endpoints.zig");
const result_store = @import("result_store.zig");
const agent_store = @import("../agent_store.zig");
const assignment_spec = @import("../assignment_spec.zig");
const gpu_leases = @import("../../gpu/lease.zig");
const gpu_runtime = @import("../../manifest/gpu_runtime.zig");
const published_ports = @import("../../network/published_ports.zig");
const runtime_wait = @import("../../lib/runtime_wait.zig");

const extractJsonString = json_helpers.extractJsonString;
const numbers = @import("../../lib/json_numbers.zig");
const placement_numbers = @import("../placement_numbers.zig");

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

fn nowAwakeNanoseconds() i128 {
    return @intCast(std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds());
}

pub const GangInfo = struct {
    rank: u32,
    world_size: u32,
    master_addr: []const u8,
    master_port: u16,
};

const AssignmentMeta = struct {
    generation: i64 = 0,
    cpu_limit: i64 = 1000,
    memory_limit_mb: i64 = 256,
    app_name: ?[]const u8 = null,
    workload_kind: ?[]const u8 = null,
    workload_name: ?[]const u8 = null,
    health_check_json: ?[]const u8 = null,
};

/// Strings copied for an assignment worker. The tracking map owns the
/// assignment ID separately because it can outlive the worker.
const AssignmentInputs = struct {
    image: []const u8,
    command: []const u8,
    gang_info: ?GangInfo,
    meta: AssignmentMeta,

    fn init(
        alloc: std.mem.Allocator,
        image: []const u8,
        command: []const u8,
        gang_info: ?GangInfo,
        meta: AssignmentMeta,
    ) !AssignmentInputs {
        const image_copy = try alloc.dupe(u8, image);
        errdefer alloc.free(image_copy);
        const command_copy = try alloc.dupe(u8, command);
        errdefer alloc.free(command_copy);
        const app_name = try copyOptionalString(alloc, meta.app_name);
        errdefer if (app_name) |value| alloc.free(value);
        const workload_kind = try copyOptionalString(alloc, meta.workload_kind);
        errdefer if (workload_kind) |value| alloc.free(value);
        const workload_name = try copyOptionalString(alloc, meta.workload_name);
        errdefer if (workload_name) |value| alloc.free(value);
        const health_check_json = try copyOptionalString(alloc, meta.health_check_json);
        errdefer if (health_check_json) |value| alloc.free(value);
        const gang_copy: ?GangInfo = if (gang_info) |gang| .{
            .rank = gang.rank,
            .world_size = gang.world_size,
            .master_addr = try alloc.dupe(u8, gang.master_addr),
            .master_port = gang.master_port,
        } else null;

        return .{
            .image = image_copy,
            .command = command_copy,
            .gang_info = gang_copy,
            .meta = .{
                .generation = meta.generation,
                .cpu_limit = meta.cpu_limit,
                .memory_limit_mb = meta.memory_limit_mb,
                .app_name = app_name,
                .workload_kind = workload_kind,
                .workload_name = workload_name,
                .health_check_json = health_check_json,
            },
        };
    }

    fn deinit(self: AssignmentInputs, alloc: std.mem.Allocator) void {
        alloc.free(self.image);
        alloc.free(self.command);
        if (self.meta.app_name) |value| alloc.free(value);
        if (self.meta.workload_kind) |value| alloc.free(value);
        if (self.meta.workload_name) |value| alloc.free(value);
        if (self.meta.health_check_json) |value| alloc.free(value);
        if (self.gang_info) |gang| alloc.free(gang.master_addr);
    }
};

fn copyOptionalString(alloc: std.mem.Allocator, value: ?[]const u8) !?[]const u8 {
    return if (value) |text| try alloc.dupe(u8, text) else null;
}

const ServiceReadinessResult = enum {
    healthy,
    unhealthy,
    timeout,
    invalid,
};

pub fn reconcile(self: anytype) void {
    var resp = fetchAssignments(self) orelse return;
    defer resp.deinit(self.alloc);

    // Cancel work only after validating a successful assignment snapshot.
    // An error response does not mean the server removed every assignment.
    if (resp.status_code != 200) return;
    cancelRemovedAssignments(self, resp.body) catch return;
    retireResults(self, resp.body) catch return;

    const now = nowRealSeconds();
    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        const assignment_id = extractJsonString(obj, "id") orelse continue;
        const status = extractJsonString(obj, "status") orelse continue;
        const image = extractJsonString(obj, "image") orelse continue;
        const CommandField = struct { command: []const u8 = "" };
        const parsed_command = std.json.parseFromSlice(CommandField, self.alloc, obj, .{ .ignore_unknown_fields = true }) catch continue;
        defer parsed_command.deinit();
        const command = parsed_command.value.command;
        const numeric = numbers.parse(self.alloc, obj) catch continue;
        defer numeric.deinit();
        const cpu_limit = numbers.field(i64, numeric.value, "cpu_limit", 1, placement_numbers.max_cpu, 1000) catch continue;
        const memory_limit_mb = numbers.field(i64, numeric.value, "memory_limit_mb", 4, placement_numbers.max_memory_mb, 256) catch continue;
        const app_name = extractJsonString(obj, "app_name");
        const workload_kind = extractJsonString(obj, "workload_kind");
        const workload_name = extractJsonString(obj, "workload_name");
        const health_check_json = json_helpers.extractJsonObject(obj, "health_check");
        const generation = numbers.field(i64, numeric.value, "generation", 0, std.math.maxInt(i64), 0) catch continue;
        const gang_info = parseGang(numeric.value, extractJsonString(obj, "gang_master_addr")) catch continue;

        if (std.mem.eql(u8, status, "stopped") or std.mem.eql(u8, status, "failed")) {
            agent_store.removeAssignment(assignment_id) catch {};
            continue;
        }

        agent_store.upsertAssignment(.{
            .id = assignment_id,
            .image = image,
            .command = command,
            .status = status,
            .cpu_limit = cpu_limit,
            .memory_limit_mb = memory_limit_mb,
            .synced_at = now,
        }) catch {};

        if (std.mem.eql(u8, status, "pending")) {
            startPendingAssignment(self, assignment_id, image, command, gang_info, .{
                .generation = generation,
                .cpu_limit = cpu_limit,
                .memory_limit_mb = memory_limit_mb,
                .app_name = app_name,
                .workload_kind = workload_kind,
                .workload_name = workload_name,
                .health_check_json = health_check_json,
            }) catch {};
        }
    }
}

fn parseGang(object: std.json.Value, address: ?[]const u8) !?GangInfo {
    // The server emits null gang fields for ordinary assignments. A partially
    // populated gang is invalid, rather than silently becoming an ordinary task.
    var has_gang = address != null;
    for ([_][]const u8{ "gang_rank", "gang_world_size", "gang_master_port" }) |key| {
        if (object.object.get(key)) |value| {
            if (value != .null) has_gang = true;
        }
    }
    if (!has_gang) return null;
    const rank = (try numbers.optional(u32, object, "gang_rank", 0, std.math.maxInt(u32))) orelse return error.InvalidRequest;
    const world_size = (try numbers.optional(u32, object, "gang_world_size", 1, std.math.maxInt(u32))) orelse return error.InvalidRequest;
    const port = try numbers.field(u16, object, "gang_master_port", 1, std.math.maxInt(u16), 29500);
    if (rank >= world_size) return error.InvalidRequest;
    return .{ .rank = rank, .world_size = world_size, .master_addr = address orelse return error.InvalidRequest, .master_port = port };
}

fn cancelRemovedAssignments(self: anytype, body: []const u8) !void {
    const Desired = struct { id: []const u8, status: []const u8, generation: i64 = 0 };
    const parsed = try std.json.parseFromSlice([]Desired, self.alloc, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var desired = std.StringHashMap(i64).init(self.alloc);
    defer desired.deinit();
    for (parsed.value) |assignment| {
        if (std.mem.eql(u8, assignment.status, "pending") or std.mem.eql(u8, assignment.status, "running"))
            try desired.put(assignment.id, assignment.generation);
    }
    var retired: std.ArrayList([]const u8) = .empty;
    defer retired.deinit(self.alloc);
    {
        self.container_lock.lockUncancelable(std.Options.debug_io);
        defer self.container_lock.unlock(std.Options.debug_io);
        var it = self.local_containers.iterator();
        while (it.next()) |entry| {
            if (desired.get(entry.key_ptr.*) == null or desired.get(entry.key_ptr.*).? != entry.value_ptr.*.generation) {
                entry.value_ptr.*.canceled.store(true, .release);
                agent_store.removeAssignment(entry.key_ptr.*) catch {};
            }
            if (entry.value_ptr.*.canceled.load(.acquire) and entry.value_ptr.*.done.load(.acquire) and entry.value_ptr.*.pending_result == null)
                try retired.append(self.alloc, entry.key_ptr.*);
        }
        for (retired.items) |id| {
            const removed = self.local_containers.fetchRemove(id).?;
            self.alloc.destroy(removed.value);
            self.alloc.free(removed.key);
        }
    }
    // The cache can contain work from an earlier agent process. Remove obsolete
    // entries so a later server outage does not restart canceled assignments.
    const cached = try agent_store.listAssignments(self.alloc);
    defer {
        for (cached) |assignment| assignment.deinit(self.alloc);
        self.alloc.free(cached);
    }
    for (cached) |assignment| {
        if (!desired.contains(assignment.id)) try agent_store.removeAssignment(assignment.id);
    }
}

fn startPendingAssignment(
    self: anytype,
    id: []const u8,
    image: []const u8,
    command: []const u8,
    gang_info: ?GangInfo,
    meta: AssignmentMeta,
) !void {
    self.container_lock.lockUncancelable(std.Options.debug_io);
    const already_tracked = self.local_containers.contains(id);
    self.container_lock.unlock(std.Options.debug_io);
    if (already_tracked) return;
    if (!try result_store.claim(&self.id, id, meta.generation)) return;
    errdefer result_store.record(&self.id, id, meta.generation, "failed", "worker_start_failed") catch {};

    const id_copy = try self.alloc.dupe(u8, id);
    errdefer self.alloc.free(id_copy);
    const inputs = try AssignmentInputs.init(self.alloc, image, command, gang_info, meta);
    errdefer inputs.deinit(self.alloc);
    const owner = try self.alloc.create(@import("../agent.zig").LocalAssignment);
    errdefer self.alloc.destroy(owner);
    owner.* = .{ .generation = meta.generation };

    {
        self.container_lock.lockUncancelable(std.Options.debug_io);
        defer self.container_lock.unlock(std.Options.debug_io);
        try self.local_containers.put(id_copy, owner);
    }
    errdefer {
        self.container_lock.lockUncancelable(std.Options.debug_io);
        defer self.container_lock.unlock(std.Options.debug_io);
        _ = self.local_containers.remove(id_copy);
    }

    if (inputs.gang_info) |gang| {
        log.info("starting gang assignment {s} (image: {s}, rank {d}/{d})", .{ id_copy, inputs.image, gang.rank, gang.world_size });
    } else {
        log.info("starting assignment {s} (image: {s})", .{ id_copy, inputs.image });
    }

    // Successful spawning transfers the inputs to the worker. The map owns
    // the ID and progress record, which the worker borrows.
    self.assignment_workers.spawn(runAssignment, .{ self, owner, id_copy, inputs }) catch |err| {
        log.warn("failed to spawn thread for assignment {s}", .{id_copy});
        return err;
    };
}

fn fetchAssignments(self: anytype) ?http_client.Response {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/assignments", .{self.id}) catch return null;
    return api_endpoints.request(self, .get, path, "", self.worker_credential) catch return null;
}

const StopToken = struct {
    group: *const std.atomic.Value(bool),
    assignment: *const std.atomic.Value(bool),

    fn load(self: StopToken, comptime order: std.builtin.AtomicOrder) bool {
        return self.group.load(order) or self.assignment.load(order);
    }
};

fn runAssignment(
    group_stopping: *const std.atomic.Value(bool),
    self: anytype,
    owner: *@import("../agent.zig").LocalAssignment,
    assignment_id: []const u8,
    inputs: AssignmentInputs,
) void {
    // Defers run in reverse order. Release the inputs and finish the last cache
    // access before allowing the tracking map to free the ID and progress record.
    defer owner.done.store(true, .release);
    defer agent_store.removeAssignment(assignment_id) catch {};
    defer inputs.deinit(self.alloc);
    const stopping = StopToken{ .group = group_stopping, .assignment = &owner.canceled };
    const image = inputs.image;
    const command = inputs.command;
    const gang_info = inputs.gang_info;
    const meta = inputs.meta;

    if (stopping.load(.acquire)) {
        setContainerState(self, assignment_id, .stopped);
        reportStatus(self, assignment_id, meta.generation, "stopped", null);
        return;
    }

    var execution = assignment_spec.decode(self.alloc, command) catch {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "invalid_execution_spec");
        return;
    };
    defer execution.deinit();
    const limits = assignment_spec.resourceLimits(meta.cpu_limit, meta.memory_limit_mb) catch {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "invalid_resource_limits");
        return;
    };
    const ref = image_spec.parseImageRef(image);
    var threaded_io = std.Io.Threaded.init(self.alloc, .{});
    defer threaded_io.deinit();

    var pull_result = image_registry.pull(threaded_io.io(), self.alloc, ref) catch {
        log.warn("failed to pull image {s} for assignment {s}", .{ image, assignment_id });
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "image_pull_failed");
        return;
    };
    defer pull_result.deinit();
    var config_parsed = image_spec.parseImageConfig(self.alloc, pull_result.config_bytes) catch {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "invalid_image_config");
        return;
    };
    defer config_parsed.deinit();

    if (stopping.load(.acquire)) {
        setContainerState(self, assignment_id, .stopped);
        reportStatus(self, assignment_id, meta.generation, "stopped", null);
        return;
    }

    const layer_paths = image_layer.assembleRootfsDescriptors(self.alloc, pull_result.layers) catch {
        log.warn("failed to assemble rootfs for assignment {s}", .{assignment_id});
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "rootfs_assemble_failed");
        return;
    };
    defer {
        for (layer_paths) |path| self.alloc.free(path);
        self.alloc.free(layer_paths);
    }

    if (layer_paths.len == 0) {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "empty_image_rootfs");
        return;
    }
    const rootfs = layer_paths[layer_paths.len - 1];

    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf) catch {
        log.warn("failed to generate container ID for assignment {s}", .{assignment_id});
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "container_id_failed");
        return;
    };
    const container_id = id_buf[0..];

    var hostname_buf: [128]u8 = undefined;
    const hostname = buildAssignmentHostname(&hostname_buf, meta, gang_info);

    const gpu_count = if (execution.value.gpu_count == 0 and gang_info != null) 1 else execution.value.gpu_count;
    var gpus = gpu_leases.Lease.acquireWithMinimum(gpu_count, execution.value.gpu_model, execution.value.gpu_vram_min_mb) catch {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "gpu_unavailable");
        return;
    };
    defer gpus.deinit();
    var mesh_env: std.ArrayList([]const u8) = .empty;
    defer {
        for (mesh_env.items) |entry| self.alloc.free(entry);
        mesh_env.deinit(self.alloc);
    }
    prepareGpuEnv(self.alloc, &mesh_env, &gpus, gang_info) catch {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "gpu_environment_failed");
        return;
    };
    var mounts_arena = std.heap.ArenaAllocator.init(self.alloc);
    defer mounts_arena.deinit();
    const mount_runtime = @import("../../manifest/orchestrator/service_runtime.zig");
    const mounts = mount_runtime.resolveServiceVolumes(mounts_arena.allocator(), execution.value.volumes, execution.value.volume_definitions, meta.app_name orelse "") catch {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "volume_mount_failed");
        return;
    };
    if (mounts.bind_mounts.items.len != execution.value.volumes.len) {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "volume_mount_failed");
        return;
    }
    if (execution.value.ib_required and @import("../../gpu/mesh.zig").detectInfiniband().count == 0) {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "infiniband_unavailable");
        return;
    }
    if (execution.value.checkpoint) |ckpt| {
        const checkpoints = @import("../../manifest/checkpoint.zig");
        const resume_path = if (execution.value.resume_checkpoint)
            checkpoints.latestMountedCheckpoint(mounts_arena.allocator(), ckpt.path, mounts.bind_mounts.items) catch {
                setContainerState(self, assignment_id, .failed);
                reportStatus(self, assignment_id, meta.generation, "failed", "checkpoint_path_invalid");
                return;
            }
        else
            null;
        checkpoints.buildCheckpointEnv(self.alloc, &mesh_env, ckpt, resume_path) catch {
            setContainerState(self, assignment_id, .failed);
            reportStatus(self, assignment_id, meta.generation, "failed", "checkpoint_environment_failed");
            return;
        };
    }

    var resolved = assignment_spec.resolve(self.alloc, execution.value, config_parsed.value.config, mesh_env.items) catch {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "invalid_execution_spec");
        return;
    };
    defer resolved.deinit(self.alloc);

    store.save(.{
        .id = container_id,
        .rootfs = rootfs,
        .command = resolved.command.command,
        .hostname = hostname,
        .status = "created",
        .pid = null,
        .exit_code = null,
        .app_name = meta.app_name,
        .created_at = nowRealSeconds(),
    }) catch {
        log.warn("failed to save container record for assignment {s}", .{assignment_id});
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "container_record_failed");
        return;
    };

    var image_user: ?[]const u8 = null;
    if (config_parsed.value.config) |config| {
        if (config.User) |user| {
            if (user.len > 0) image_user = user;
        }
    }
    result_store.attachContainer(&self.id, assignment_id, meta.generation, container_id) catch {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "result_store_failed");
        cleanup(container_id);
        return;
    };
    var c = container.Container{
        .config = .{
            .id = container_id,
            .rootfs = rootfs,
            .command = resolved.command.command,
            .args = resolved.command.args.items,
            .working_dir = resolved.working_dir,
            .user = image_user,
            .limits = limits,
            .network = .{ .node_id = self.node_id },
            .mounts = mounts.bind_mounts.items,
            .gpu_indices = gpus.indices[0..gpus.count],
            .hostname = hostname,
            .lower_dirs = layer_paths,
            .env = resolved.env.items,
        },
        .status = .created,
        .pid = null,
        .exit_code = null,
        .created_at = nowRealSeconds(),
    };

    if (stopping.load(.acquire)) {
        setContainerState(self, assignment_id, .stopped);
        cleanup(container_id);
        return;
    }

    log.info("starting container {s} for assignment {s}", .{ container_id, assignment_id });
    c.start() catch {
        log.warn("container {s} failed to start for assignment {s}", .{ container_id, assignment_id });
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, meta.generation, "failed", "start_failed");
        cleanup(container_id);
        return;
    };

    if (gang_info) |gang| {
        if (gang.rank == 0) {
            const ports = [_]manifest_spec.PortMapping{.{ .host_port = gang.master_port, .container_port = gang.master_port }};
            published_ports.publishInstanceWithBootstrap(self.alloc, meta.app_name, hostname, container_id, &ports, gang.master_port) catch {
                _ = waitForAssignmentExit(&c, stopping, true);
                setContainerState(self, assignment_id, .failed);
                reportStatus(self, assignment_id, meta.generation, "failed", "rendezvous_port_failed");
                cleanup(container_id);
                return;
            };
        }
    }

    defer manifest_health.unregisterContainer(container_id);
    const readiness_result = waitForServiceReadiness(stopping, self.alloc, container_id, meta);
    switch (readiness_result) {
        .healthy => {},
        .unhealthy, .timeout, .invalid => {
            log.warn("service assignment {s} failed readiness gate", .{assignment_id});
            _ = waitForAssignmentExit(&c, stopping, true);
            if (stopping.load(.acquire)) {
                setContainerState(self, assignment_id, .stopped);
                reportStatus(self, assignment_id, meta.generation, "stopped", null);
                cleanup(container_id);
                return;
            }
            setContainerState(self, assignment_id, .failed);
            reportStatus(self, assignment_id, meta.generation, "failed", switch (readiness_result) {
                .healthy => unreachable,
                .unhealthy => "readiness_failed",
                .timeout => "readiness_timeout",
                .invalid => "readiness_invalid",
            });
            cleanup(container_id);
            return;
        },
    }

    if (meta.workload_kind != null and std.mem.eql(u8, meta.workload_kind.?, "service")) {
        const ports = servicePublishedPorts(self.alloc, execution.value.ports, gang_info) catch {
            _ = waitForAssignmentExit(&c, stopping, true);
            setContainerState(self, assignment_id, .failed);
            reportStatus(self, assignment_id, meta.generation, "failed", "invalid_published_ports");
            cleanup(container_id);
            return;
        };
        defer self.alloc.free(ports);
        const bootstrap_port: ?u16 = if (gang_info) |gang| if (gang.rank == 0) gang.master_port else null else null;
        published_ports.publishInstanceWithBootstrap(self.alloc, meta.app_name, hostname, container_id, ports, bootstrap_port) catch |err| {
            log.warn("assignment {s} could not publish service ports: {}", .{ assignment_id, err });
            _ = waitForAssignmentExit(&c, stopping, true);
            setContainerState(self, assignment_id, .failed);
            reportStatus(self, assignment_id, meta.generation, "failed", "published_port_failed");
            cleanup(container_id);
            return;
        };
    }
    const alert_registration = if (std.mem.eql(u8, meta.workload_kind orelse "", "service") and
        (execution.value.alerts != null or execution.value.alert_generation != 0))
        @import("../../manifest/alerts/runtime.zig").registerCluster(meta.app_name orelse "", meta.workload_name orelse container_id, execution.value.alerts orelse .{}, execution.value.alert_generation) catch |err| blk: {
            // an empty generation only suppresses thresholds from an older group.
            // it must not impose the alert limit on services without alerts.
            if (execution.value.alerts == null and err == error.TooManyAlertServices) break :blk null;
            c.forceStop() catch {};
            _ = c.wait() catch 255;
            cleanup(container_id);
            setContainerState(self, assignment_id, .failed);
            reportStatus(self, assignment_id, meta.generation, "failed", "alert_runtime_unavailable");
            return;
        }
    else
        null;
    defer if (alert_registration) |registration| registration.release();

    reportStatus(self, assignment_id, meta.generation, "running", null);
    setContainerState(self, assignment_id, .running);

    const exit_code = waitForAssignmentExit(&c, stopping, false);

    log.info("container {s} exited for assignment {s}", .{ container_id, assignment_id });
    if (meta.workload_kind != null and meta.workload_name != null and std.mem.eql(u8, meta.workload_kind.?, "service")) {
        manifest_health.unregisterContainer(container_id);
    }
    const is_training = meta.workload_kind != null and std.mem.eql(u8, meta.workload_kind.?, "training");
    const interrupted = stopping.load(.acquire);
    if ((interrupted and !is_training) or (!interrupted and exit_code == 0)) {
        setContainerState(self, assignment_id, .stopped);
        reportStatus(self, assignment_id, meta.generation, "stopped", null);
    } else {
        setContainerState(self, assignment_id, .failed);
        // an interrupted rank has not completed its training. operator pause
        // already removed its assignment; agent shutdown leaves it retryable.
        reportStatus(self, assignment_id, meta.generation, "failed", if (interrupted) "rank_interrupted" else "process_failed");
    }
    if (is_training) {
        // keep the stopped record and logs so remote training logs remain
        // available after a rank exits. its network and filesystem are gone.
        published_ports.removeInstance(self.alloc, container_id) catch |err| {
            log.warn("failed to release training ports for {s}: {}", .{ container_id, err });
        };
        container.cleanupContainerDirs(container_id);
    } else cleanup(container_id);
}

// one publication replaces every claim owned by this container. retain the
// rank-zero rendezvous port when adding the service's public ports.
fn servicePublishedPorts(alloc: std.mem.Allocator, service_ports: []const manifest_spec.PortMapping, gang: ?GangInfo) ![]manifest_spec.PortMapping {
    const rendezvous = if (gang) |group| if (group.rank == 0) group.master_port else null else null;
    if (rendezvous) |port| {
        for (service_ports) |existing| {
            if (existing.host_port != port) continue;
            if (existing.container_port != port) return error.PortCollision;
            return alloc.dupe(manifest_spec.PortMapping, service_ports);
        }
        const ports = try alloc.alloc(manifest_spec.PortMapping, service_ports.len + 1);
        @memcpy(ports[0..service_ports.len], service_ports);
        ports[service_ports.len] = .{ .host_port = port, .container_port = port };
        return ports;
    }
    return alloc.dupe(manifest_spec.PortMapping, service_ports);
}

/// Stop and reap the process on its assignment thread before releasing resources.
/// Give a canceled workload five seconds to exit, then force termination.
fn waitForAssignmentExit(c: anytype, stopping: anytype, stop_requested: bool) u8 {
    return waitForAssignmentExitWith(c, stopping, stop_requested, nowAwakeNanoseconds, runtime_wait.sleep);
}

fn waitForAssignmentExitWith(c: anytype, stopping: anytype, stop_requested: bool, comptime now: anytype, comptime sleep: anytype) u8 {
    var stop_deadline: ?i128 = if (stop_requested) now() + 5 * std.time.ns_per_s else null;
    if (stop_requested) c.stop() catch {};
    while (true) {
        c.poll() catch {
            c.forceStop() catch {};
            return c.wait() catch 255;
        };
        if (c.status == .stopped) return c.exit_code orelse 255;
        if (stop_deadline) |deadline| {
            if (now() >= deadline) {
                c.forceStop() catch {};
                return c.wait() catch 255;
            }
        } else if (stopping.load(.acquire)) {
            c.stop() catch {};
            stop_deadline = now() + 5 * std.time.ns_per_s;
        }
        if (!sleep(std.Io.Duration.fromMilliseconds(50), "assignment process wait")) {
            c.forceStop() catch {};
            return c.wait() catch 255;
        }
    }
}

fn waitForServiceReadiness(stopping: anytype, alloc: std.mem.Allocator, container_id: []const u8, meta: AssignmentMeta) ServiceReadinessResult {
    const workload_kind = meta.workload_kind orelse return .healthy;
    const service_name = meta.workload_name orelse return .healthy;
    if (!std.mem.eql(u8, workload_kind, "service")) return .healthy;
    const health_check_json = meta.health_check_json orelse return .healthy;

    const record = store.load(alloc, container_id) catch return .invalid;
    defer record.deinit(alloc);
    const ip_address = record.ip_address orelse return .invalid;
    const container_ip = @import("../../network/ip.zig").parseIp(ip_address) orelse return .invalid;
    const health_check = parseHealthCheckJson(alloc, health_check_json) orelse return .invalid;
    defer health_check.deinit(alloc);

    var id_buf: [12]u8 = undefined;
    if (container_id.len != id_buf.len) return .invalid;
    @memcpy(&id_buf, container_id[0..id_buf.len]);

    manifest_health.registerReplicaService(service_name, id_buf, container_ip, health_check) catch return .invalid;
    manifest_health.startChecker();

    const deadline_ns = nowAwakeNanoseconds() + (@as(i128, @intCast(estimateHealthStartupWindowSeconds(health_check))) * std.time.ns_per_s);
    defer {
        const final_status = manifest_health.getContainerStatus(container_id) orelse .starting;
        if (final_status != .healthy) manifest_health.unregisterContainer(container_id);
    }
    while (nowAwakeNanoseconds() < deadline_ns) {
        if (stopping.load(.acquire)) return .timeout;
        switch (manifest_health.getContainerStatus(container_id) orelse .starting) {
            .healthy => return .healthy,
            .unhealthy => return .unhealthy,
            .starting => if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(100), "assignment readiness wait")) return .timeout,
        }
    }
    return .timeout;
}

fn estimateHealthStartupWindowSeconds(health_check: manifest_spec.HealthCheck) u128 {
    const attempts: u128 = @max(@as(u32, 1), health_check.retries);
    return health_check.start_period + (attempts * (@as(u128, health_check.interval) + health_check.timeout)) + 2;
}

fn parseHealthCheckJson(alloc: std.mem.Allocator, json: []const u8) ?manifest_spec.HealthCheck {
    const kind = extractJsonString(json, "kind") orelse return null;
    const numeric = numbers.parse(alloc, json) catch return null;
    defer numeric.deinit();
    placement_numbers.validateHealth(numeric.value) catch return null;
    const interval = numbers.field(u32, numeric.value, "interval", 0, std.math.maxInt(u32), 10) catch return null;
    const timeout = numbers.field(u32, numeric.value, "timeout", 0, std.math.maxInt(u32), 5) catch return null;
    const retries = numbers.field(u32, numeric.value, "retries", 0, std.math.maxInt(u32), 3) catch return null;
    const start_period = numbers.field(u32, numeric.value, "start_period", 0, std.math.maxInt(u32), 0) catch return null;
    const port = numbers.field(u16, numeric.value, "port", 1, std.math.maxInt(u16), 0) catch return null;

    const check_type: manifest_spec.CheckType = if (std.mem.eql(u8, kind, "http")) .{
        .http = .{
            .path = alloc.dupe(u8, extractJsonString(json, "path") orelse return null) catch return null,
            .port = port,
        },
    } else if (std.mem.eql(u8, kind, "tcp")) .{
        .tcp = .{
            .port = port,
        },
    } else if (std.mem.eql(u8, kind, "grpc")) .{
        .grpc = .{
            .port = port,
            .service = if (extractJsonString(json, "service")) |service|
                alloc.dupe(u8, service) catch return null
            else
                null,
        },
    } else if (std.mem.eql(u8, kind, "exec")) .{
        .exec = .{
            .command = parseJsonStringArray(alloc, json, "command") orelse return null,
        },
    } else return null;

    return .{
        .check_type = check_type,
        .interval = interval,
        .timeout = timeout,
        .retries = retries,
        .start_period = start_period,
    };
}

fn parseJsonStringArray(alloc: std.mem.Allocator, json: []const u8, key: []const u8) ?[][]const u8 {
    const array_json = json_helpers.extractJsonArray(json, key) orelse return null;
    if (array_json.len < 2) return null;

    var items: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (items.items) |item| alloc.free(item);
        items.deinit(alloc);
    }

    var pos: usize = 1;
    while (pos < array_json.len - 1) {
        while (pos < array_json.len - 1 and (array_json[pos] == ' ' or array_json[pos] == '\n' or array_json[pos] == '\r' or array_json[pos] == '\t' or array_json[pos] == ',')) : (pos += 1) {}
        if (pos >= array_json.len - 1) break;
        if (array_json[pos] != '"') return null;
        pos += 1;
        const start = pos;

        while (pos < array_json.len - 1) : (pos += 1) {
            if (array_json[pos] == '\\') {
                pos += 1;
                if (pos >= array_json.len - 1) return null;
                continue;
            }
            if (array_json[pos] == '"') break;
        }
        if (pos >= array_json.len - 1) return null;

        const item = alloc.dupe(u8, array_json[start..pos]) catch return null;
        items.append(alloc, item) catch return null;
        pos += 1;
    }

    return items.toOwnedSlice(alloc) catch null;
}

fn prepareGpuEnv(alloc: std.mem.Allocator, env: *std.ArrayList([]const u8), gpus: *const gpu_leases.Lease, gang_info: ?GangInfo) !void {
    if (gpus.count > 0) {
        var gpu_buf: [4096]u8 = undefined;
        const data = try @import("../../gpu/passthrough.zig").generateGpuEnv(gpus.indices[0..gpus.count], &gpu_buf);
        try gpu_runtime.appendRequiredEnv(alloc, env, data);
    }
    if (gang_info) |gang| {
        const mesh = @import("../../gpu/mesh.zig");
        var mesh_buf: [1024]u8 = undefined;
        const address = if (gang.rank == 0) "0.0.0.0" else gang.master_addr;
        const data = try mesh.generateMeshEnv(&mesh_buf, mesh.detectInfiniband(), address, gang.master_port, gang.world_size, gang.rank, 0, null);
        try gpu_runtime.appendRequiredEnv(alloc, env, data);
        try gpu_runtime.appendRequiredEnv(alloc, env, "NCCL_SHM_DISABLE=1");
    }
}

fn buildAssignmentHostname(buf: []u8, meta: AssignmentMeta, gang_info: ?GangInfo) []const u8 {
    if (meta.workload_kind != null and meta.workload_name != null and std.mem.eql(u8, meta.workload_kind.?, "training")) {
        if (gang_info) |gang| {
            return std.fmt.bufPrint(buf, "{s}-rank-{d}", .{ meta.workload_name.?, gang.rank }) catch meta.workload_name.?;
        }
        return meta.workload_name.?;
    }
    if (meta.workload_name) |workload_name| return workload_name;
    return "agent";
}

fn reportStatus(self: anytype, assignment_id: []const u8, generation: i64, status: []const u8, reason: ?[]const u8) void {
    result_store.record(&self.id, assignment_id, generation, status, reason) catch |err| {
        log.err("could not persist assignment result {s}: {}", .{ assignment_id, err });
        // keep the completed owner until a later loop can persist its result.
        // a database failure must not turn completion into a duplicate start.
        self.container_lock.lockUncancelable(std.Options.debug_io);
        defer self.container_lock.unlock(std.Options.debug_io);
        if (self.local_containers.get(assignment_id)) |owner| {
            if (owner.generation != generation) return;
            owner.pending_result = .{ .state = std.meta.stringToEnum(@import("../agent.zig").ContainerState, status) orelse .failed };
            if (reason) |text| {
                const len = @min(text.len, owner.pending_result.?.reason.len);
                @memcpy(owner.pending_result.?.reason[0..len], text[0..len]);
                owner.pending_result.?.reason_len = len;
            }
        }
    };
}

// the loop owns network delivery. workers only persist their latest result, so
// failover cannot race an assignment thread reading the current api endpoint.
pub fn flushResults(self: anytype) void {
    flushResultsLimit(self, 8);
}

pub fn flushShutdownResults(self: anytype) void {
    flushResultsLimit(self, 1);
}

fn flushResultsLimit(self: anytype, limit: usize) void {
    {
        self.container_lock.lockUncancelable(std.Options.debug_io);
        defer self.container_lock.unlock(std.Options.debug_io);
        var owners = self.local_containers.iterator();
        while (owners.next()) |entry| {
            const owner = entry.value_ptr.*;
            if (owner.pending_result) |pending| {
                result_store.record(&self.id, entry.key_ptr.*, owner.generation, @tagName(pending.state), if (pending.reason_len > 0) pending.reason[0..pending.reason_len] else null) catch continue;
                owner.pending_result = null;
            }
        }
    }
    const results = result_store.list(self.alloc, &self.id) catch return;
    defer {
        for (results) |result| result.deinit(self.alloc);
        self.alloc.free(results);
    }
    var delivered: usize = 0;
    for (results) |result| {
        if (delivered == limit) break;
        self.container_lock.lockUncancelable(std.Options.debug_io);
        const owner = self.local_containers.get(result.assignment_id);
        const owned = if (owner) |value| value.generation == result.generation else false;
        self.container_lock.unlock(std.Options.debug_io);
        if (!result.terminal() and !owned) {
            delivered += 1;
            // a previous agent process cannot resume its worker thread. stop its
            // recorded cgroup before allowing the scheduler to replace it.
            recoverInterrupted(self, result) catch |err| log.warn("assignment recovery deferred for {s}: {}", .{ result.assignment_id, err });
            continue;
        }
        if (result.delivered != 0 or std.mem.eql(u8, result.status, "starting")) continue;
        delivered += 1;
        result_store.attempted(&self.id, result) catch return;
        var path_buffer: [192]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buffer, "/agents/{s}/assignments/{s}/status", .{ self.id, result.assignment_id }) catch continue;
        var body = std.Io.Writer.Allocating.init(self.alloc);
        defer body.deinit();
        body.writer.print("{{\"status\":\"{s}\",\"generation\":{d}", .{ result.status, result.generation }) catch return;
        if (result.reason) |reason| {
            body.writer.writeAll(",\"reason\":\"") catch return;
            json_helpers.writeJsonEscaped(&body.writer, reason) catch return;
            body.writer.writeByte('"') catch return;
        }
        body.writer.writeByte('}') catch return;
        var response = api_endpoints.request(self, .post, path, body.written(), self.worker_credential) catch break;
        defer response.deinit(self.alloc);
        if (response.status_code >= 500) break;
        if (response.status_code != 200 and response.status_code != 403) continue;
        const Receipt = struct { committed: bool = false, obsolete: bool = false, generation: i64 = -1 };
        const receipt = std.json.parseFromSlice(Receipt, self.alloc, response.body, .{ .ignore_unknown_fields = true }) catch continue;
        defer receipt.deinit();
        if (!receipt.value.committed or receipt.value.generation != result.generation) continue;
        if (response.status_code == 403 and !receipt.value.obsolete) continue;
        result_store.acknowledge(&self.id, result) catch return;
    }
}

fn recoverInterrupted(self: anytype, result: result_store.Result) !void {
    try recoverInterruptedWith(self, result, recoverContainer);
}

fn recoverInterruptedWith(self: anytype, result: result_store.Result, comptime stopContainer: anytype) !void {
    if (result.container_id) |id| try stopContainer(self.alloc, id);
    try result_store.record(&self.id, result.assignment_id, result.generation, "failed", "agent_restarted");
}

fn recoverContainer(alloc: std.mem.Allocator, id: []const u8) !void {
    const group = try @import("../../runtime/cgroups.zig").Cgroup.open(id);
    const exists = blk: {
        std.Io.Dir.cwd().access(std.Options.debug_io, group.path(), .{}) catch |err| {
            if (err == error.FileNotFound) break :blk false;
            return err;
        };
        break :blk true;
    };
    if (exists) try group.destroy();
    // the id was durably attached before c.start, so this cleanup never
    // chooses a process by a reused pid or a matching workload name.
    const record = store.load(alloc, id) catch |err| {
        if (err != error.NotFound) return err;
        return;
    };
    defer record.deinit(alloc);
    @import("../../runtime/cli/container/lifecycle_commands.zig").cleanupNetwork(id, record.ip_address, record.veth_host);
    try published_ports.removeInstance(alloc, id);
    container.cleanupContainerDirs(id);
    try store.updateStatus(id, "stopped", null, 255);
}

fn retireResults(self: anytype, snapshot: []const u8) !void {
    const Desired = struct { id: []const u8, status: []const u8, generation: i64 = 0 };
    const desired = try std.json.parseFromSlice([]Desired, self.alloc, snapshot, .{ .ignore_unknown_fields = true });
    defer desired.deinit();
    const results = try result_store.list(self.alloc, &self.id);
    defer {
        for (results) |result| result.deinit(self.alloc);
        self.alloc.free(results);
    }
    for (results) |result| {
        if (!result.terminal() or result.delivered == 0) continue;
        const still_desired = for (desired.value) |assignment| {
            if (std.mem.eql(u8, assignment.id, result.assignment_id) and assignment.generation == result.generation and
                (std.mem.eql(u8, assignment.status, "pending") or std.mem.eql(u8, assignment.status, "running"))) break true;
        } else false;
        if (!still_desired) try result_store.retire(&self.id, result);
    }
}

fn setContainerState(self: anytype, assignment_id: []const u8, state: anytype) void {
    self.container_lock.lockUncancelable(std.Options.debug_io);
    defer self.container_lock.unlock(std.Options.debug_io);
    if (self.local_containers.getPtr(assignment_id)) |container_state| {
        container_state.*.state = state;
    }
}

fn cleanup(container_id: []const u8) void {
    published_ports.removeInstance(std.heap.page_allocator, container_id) catch |err| {
        log.warn("failed to release published ports for {s}: {}", .{ container_id, err });
    };
    logs.deleteLogFile(container_id);
    container.cleanupContainerDirs(container_id);
    store.remove(container_id) catch {};
}

test "assignment startup releases owned inputs when worker admission fails" {
    const agent_mod = @import("../agent.zig");
    const RejectingWorkers = struct {
        fn spawn(_: *@This(), comptime _: anytype, _: anytype) !void {
            return error.Stopping;
        }
    };
    const Fixture = struct {
        id: [12]u8 = "fixtureagent".*,
        alloc: std.mem.Allocator,
        container_lock: std.Io.Mutex = .init,
        local_containers: std.StringHashMap(*agent_mod.LocalAssignment),
        assignment_workers: RejectingWorkers = .{},

        fn rejectAssignment(alloc: std.mem.Allocator, with_metadata: bool) !void {
            try agent_store.initTestDb();
            defer agent_store.closeDb();
            var fixture = @This(){
                .alloc = alloc,
                .local_containers = std.StringHashMap(*agent_mod.LocalAssignment).init(alloc),
            };
            defer fixture.local_containers.deinit();
            const gang: ?GangInfo = if (with_metadata) .{
                .rank = 1,
                .world_size = 2,
                .master_addr = "10.42.0.1",
                .master_port = 29500,
            } else null;
            const meta: AssignmentMeta = if (with_metadata) .{
                .app_name = "app",
                .workload_kind = "training",
                .workload_name = "worker",
                .health_check_json = "{\"kind\":\"tcp\",\"port\":8080}",
            } else .{};
            startPendingAssignment(&fixture, "assignment", "image", "/bin/sh", gang, meta) catch |err| {
                try std.testing.expectEqual(@as(u32, 0), fixture.local_containers.count());
                if (err == error.Stopping) return;
                return err;
            };
            return error.TestUnexpectedResult;
        }
    };

    // Exercise every allocation failure, including map insertion, before the
    // worker group rejects admission. No entry or copied input may remain.
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Fixture.rejectAssignment, .{true});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Fixture.rejectAssignment, .{false});
}

test "assignment inputs own copies of request strings" {
    const alloc = std.testing.allocator;
    var request_text = "request".*;
    const inputs = try AssignmentInputs.init(alloc, &request_text, &request_text, .{
        .rank = 1,
        .world_size = 2,
        .master_addr = &request_text,
        .master_port = 29500,
    }, .{
        .cpu_limit = 1500,
        .memory_limit_mb = 1024,
        .app_name = &request_text,
        .workload_kind = &request_text,
        .workload_name = &request_text,
        .health_check_json = &request_text,
    });
    defer inputs.deinit(alloc);
    @memset(&request_text, 0);

    for ([_][]const u8{
        inputs.image,
        inputs.command,
        inputs.gang_info.?.master_addr,
        inputs.meta.app_name.?,
        inputs.meta.workload_kind.?,
        inputs.meta.workload_name.?,
        inputs.meta.health_check_json.?,
    }) |text| try std.testing.expectEqualStrings("request", text);
    try std.testing.expectEqual(@as(i64, 1500), inputs.meta.cpu_limit);
    try std.testing.expectEqual(@as(i64, 1024), inputs.meta.memory_limit_mb);
    try std.testing.expectEqual(@as(u32, 1), inputs.gang_info.?.rank);
    try std.testing.expectEqual(@as(u32, 2), inputs.gang_info.?.world_size);
    try std.testing.expectEqual(@as(u16, 29500), inputs.gang_info.?.master_port);
}

test "parseHealthCheckJson parses http service checks" {
    const alloc = std.testing.allocator;
    const parsed = parseHealthCheckJson(
        alloc,
        "{\"kind\":\"http\",\"path\":\"/ready\",\"port\":8080,\"interval\":11,\"timeout\":6,\"retries\":4,\"start_period\":2}",
    ).?;
    defer parsed.deinit(alloc);

    switch (parsed.check_type) {
        .http => |http| {
            try std.testing.expectEqualStrings("/ready", http.path);
            try std.testing.expectEqual(@as(u16, 8080), http.port);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u32, 11), parsed.interval);
    try std.testing.expectEqual(@as(u32, 6), parsed.timeout);
    try std.testing.expectEqual(@as(u32, 4), parsed.retries);
    try std.testing.expectEqual(@as(u32, 2), parsed.start_period);
}

test "parseHealthCheckJson parses exec service checks" {
    const alloc = std.testing.allocator;
    const parsed = parseHealthCheckJson(
        alloc,
        "{\"kind\":\"exec\",\"command\":[\"/bin/sh\",\"-c\",\"echo ok\"],\"interval\":5,\"timeout\":3,\"retries\":2,\"start_period\":1}",
    ).?;
    defer parsed.deinit(alloc);

    switch (parsed.check_type) {
        .exec => |exec| {
            try std.testing.expectEqual(@as(usize, 3), exec.command.len);
            try std.testing.expectEqualStrings("/bin/sh", exec.command[0]);
            try std.testing.expectEqualStrings("-c", exec.command[1]);
            try std.testing.expectEqualStrings("echo ok", exec.command[2]);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "assignment worker ownership escalates uncooperative shutdown and reaps" {
    const Fixture = struct {
        status: enum { running, stopped } = .running,
        exit_code: ?u8 = null,
        terms: usize = 0,
        kills: usize = 0,
        reaped: bool = false,
        cooperative: bool = false,
        var clock: i128 = 0;

        fn poll(self: *@This()) !void {
            if (self.cooperative and self.terms != 0) {
                self.status = .stopped;
                self.exit_code = 0;
                self.reaped = true;
            }
        }
        fn stop(self: *@This()) !void {
            self.terms += 1;
        }
        fn forceStop(self: *@This()) !void {
            self.kills += 1;
        }
        fn wait(self: *@This()) !u8 {
            try std.testing.expectEqual(@as(usize, 1), self.kills);
            self.reaped = true;
            return 128;
        }
        fn now() i128 {
            return clock;
        }
        fn sleep(_: std.Io.Duration, _: []const u8) bool {
            clock += std.time.ns_per_s;
            return true;
        }
    };
    const stopping = std.atomic.Value(bool).init(true);
    var stubborn = Fixture{};
    Fixture.clock = 0;
    try std.testing.expectEqual(@as(u8, 128), waitForAssignmentExitWith(&stubborn, &stopping, false, Fixture.now, Fixture.sleep));
    try std.testing.expectEqual(@as(usize, 1), stubborn.terms);
    try std.testing.expect(stubborn.reaped);
    try std.testing.expect(Fixture.clock >= 5 * std.time.ns_per_s);
    var cooperative = Fixture{ .cooperative = true };
    Fixture.clock = 0;
    try std.testing.expectEqual(@as(u8, 0), waitForAssignmentExitWith(&cooperative, &stopping, false, Fixture.now, Fixture.sleep));
    try std.testing.expectEqual(@as(usize, 1), cooperative.terms);
    try std.testing.expectEqual(@as(usize, 0), cooperative.kills);
    try std.testing.expect(cooperative.reaped);
}

test "assignment removal cancels a real process and invalidates cached work" {
    const agent_mod = @import("../agent.zig");
    const process = @import("../../runtime/process.zig");
    const linux = std.os.linux;
    const Process = struct {
        pid: std.posix.pid_t,
        status: container.Status = .running,
        exit_code: ?u8 = null,
        fn poll(self: *@This()) !void {
            const result = try process.wait(self.pid, true);
            switch (result.status) {
                .running, .stopped => {},
                .exited => |code| {
                    self.status = .stopped;
                    self.exit_code = code;
                },
                .signaled => {
                    self.status = .stopped;
                    self.exit_code = 128;
                },
            }
        }
        fn stop(self: *@This()) !void {
            try process.terminate(self.pid);
        }
        fn forceStop(self: *@This()) !void {
            try process.kill(self.pid);
        }
        fn wait(self: *@This()) !u8 {
            _ = try process.wait(self.pid, false);
            self.status = .stopped;
            return 128;
        }
    };
    const Fixture = struct {
        id: [12]u8 = "fixtureagent".*,
        alloc: std.mem.Allocator = std.testing.allocator,
        container_lock: std.Io.Mutex = .init,
        local_containers: std.StringHashMap(*agent_mod.LocalAssignment),
    };
    try agent_store.initTestDb();
    defer agent_store.closeDb();
    for ([_][]const u8{ "[]", "[{\"id\":\"assignment\",\"status\":\"stopped\"}]", "[{\"id\":\"assignment\",\"status\":\"failed\"}]" }) |desired| {
        var owner = agent_mod.LocalAssignment{};
        var fixture = Fixture{ .local_containers = std.StringHashMap(*agent_mod.LocalAssignment).init(std.testing.allocator) };
        defer fixture.local_containers.deinit();
        try fixture.local_containers.put("assignment", &owner);
        try agent_store.upsertAssignment(.{ .id = "assignment", .image = "fixture", .command = "", .status = "pending", .cpu_limit = 1000, .memory_limit_mb = 256, .synced_at = 0 });
        const group_stopping = std.atomic.Value(bool).init(false);
        const token = StopToken{ .group = &group_stopping, .assignment = &owner.canceled };
        try cancelRemovedAssignments(&fixture, "[{\"id\":\"assignment\",\"status\":\"running\"}]");
        try std.testing.expect(!token.load(.acquire));
        try std.testing.expectError(error.UnexpectedToken, cancelRemovedAssignments(&fixture, "{"));
        try std.testing.expect(!token.load(.acquire));
        const pid = linux.fork();
        if (linux.errno(pid) != .SUCCESS) return error.ForkFailed;
        if (pid == 0) {
            while (true) _ = linux.syscall0(.pause);
        }
        var child = Process{ .pid = @intCast(pid) };
        defer if (child.status != .stopped) {
            child.forceStop() catch {};
            _ = child.wait() catch {};
        };
        try cancelRemovedAssignments(&fixture, desired);
        try std.testing.expect(token.load(.acquire));
        try std.testing.expect(!group_stopping.load(.acquire));
        _ = waitForAssignmentExit(&child, token, false);
        try std.testing.expectEqual(container.Status.stopped, child.status);
        const cached = try agent_store.listAssignments(std.testing.allocator);
        defer std.testing.allocator.free(cached);
        try std.testing.expectEqual(@as(usize, 0), cached.len);
    }
}

test "assignment cancellation retires completed owner when the same id becomes pending" {
    const agent_mod = @import("../agent.zig");
    const alloc = std.testing.allocator;
    const Fixture = struct {
        id: [12]u8 = "fixtureagent".*,
        alloc: std.mem.Allocator,
        container_lock: std.Io.Mutex = .init,
        local_containers: std.StringHashMap(*agent_mod.LocalAssignment),
    };
    try agent_store.initTestDb();
    defer agent_store.closeDb();
    var fixture = Fixture{ .alloc = alloc, .local_containers = std.StringHashMap(*agent_mod.LocalAssignment).init(alloc) };
    defer fixture.local_containers.deinit();
    const owner = try alloc.create(agent_mod.LocalAssignment);
    owner.* = .{};
    owner.canceled.store(true, .release);
    owner.done.store(true, .release);
    try fixture.local_containers.put(try alloc.dupe(u8, "assignment"), owner);
    try cancelRemovedAssignments(&fixture, "[{\"id\":\"assignment\",\"status\":\"pending\"}]");
    try std.testing.expectEqual(@as(u32, 0), fixture.local_containers.count());
}

test "placement numbers reject malformed gang and health metadata" {
    const alloc = std.testing.allocator;
    for ([_][]const u8{
        "{\"gang_rank\":4294967296,\"gang_world_size\":2}",
        "{\"gang_rank\":2,\"gang_world_size\":2}",
        "{\"gang_rank\":0,\"gang_world_size\":-1}",
        "{\"gang_rank\":0,\"gang_world_size\":2,\"gang_master_port\":65536}",
        "{\"gang_rank\":0,\"gang_world_size\":2.5}",
    }) |json| {
        const parsed = try numbers.parse(alloc, json);
        defer parsed.deinit();
        try std.testing.expectError(error.InvalidRequest, parseGang(parsed.value, "10.0.0.1"));
    }
    const ordinary = try numbers.parse(alloc, "{\"gang_rank\":null,\"gang_world_size\":null,\"gang_master_port\":null}");
    defer ordinary.deinit();
    try std.testing.expectEqual(@as(?GangInfo, null), try parseGang(ordinary.value, null));
    try std.testing.expect(parseHealthCheckJson(alloc, "{\"kind\":\"tcp\",\"port\":65536}") == null);
    try std.testing.expect(parseHealthCheckJson(alloc, "{\"kind\":\"tcp\",\"port\":80,\"retries\":null}") == null);
    const health = parseHealthCheckJson(alloc, "{\"kind\":\"tcp\",\"port\":65535,\"interval\":4294967295,\"timeout\":4294967295,\"retries\":4294967295,\"start_period\":4294967295}").?;
    defer health.deinit(alloc);
    try std.testing.expect(estimateHealthStartupWindowSeconds(health) > std.math.maxInt(u64));
}

test "service publication retains the assigned rank zero rendezvous port" {
    const alloc = std.testing.allocator;
    const service_ports = [_]manifest_spec.PortMapping{.{ .host_port = 8080, .container_port = 80 }};
    var gang: GangInfo = .{ .rank = 0, .world_size = 3, .master_addr = "10.0.0.1", .master_port = 29501 };
    const leader = try servicePublishedPorts(alloc, &service_ports, gang);
    defer alloc.free(leader);
    try std.testing.expectEqual(@as(usize, 2), leader.len);
    try std.testing.expectEqual(@as(u16, 29501), leader[1].host_port);
    gang.rank = 1;
    const follower = try servicePublishedPorts(alloc, &service_ports, gang);
    defer alloc.free(follower);
    try std.testing.expectEqual(@as(usize, 1), follower.len);
    gang.rank = 0;
    gang.master_port = 8080;
    try std.testing.expectError(error.PortCollision, servicePublishedPorts(alloc, &service_ports, gang));
    const duplicate = try servicePublishedPorts(alloc, &.{.{ .host_port = 8080, .container_port = 8080 }}, gang);
    defer alloc.free(duplicate);
    try std.testing.expectEqual(@as(usize, 1), duplicate.len);
}

test "agent recovery new generation cancels old worker before reusing its id" {
    const agent_mod = @import("../agent.zig");
    const alloc = std.testing.allocator;
    const Fixture = struct {
        alloc: std.mem.Allocator,
        container_lock: std.Io.Mutex = .init,
        local_containers: std.StringHashMap(*agent_mod.LocalAssignment),
    };
    try agent_store.initTestDb();
    defer agent_store.closeDb();
    var fixture = Fixture{ .alloc = alloc, .local_containers = std.StringHashMap(*agent_mod.LocalAssignment).init(alloc) };
    defer fixture.local_containers.deinit();
    const owner = try alloc.create(agent_mod.LocalAssignment);
    owner.* = .{ .generation = 2 };
    try fixture.local_containers.put(try alloc.dupe(u8, "assignment"), owner);
    const desired = "[{\"id\":\"assignment\",\"status\":\"pending\",\"generation\":3}]";
    try cancelRemovedAssignments(&fixture, desired);
    try std.testing.expect(owner.canceled.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), fixture.local_containers.count());
    owner.done.store(true, .release);
    try cancelRemovedAssignments(&fixture, desired);
    try std.testing.expectEqual(@as(u32, 0), fixture.local_containers.count());
}

test "agent recovery waits for owned container cleanup before reporting interruption" {
    const alloc = std.testing.allocator;
    try agent_store.initTestDb();
    defer agent_store.closeDb();
    const fixture: struct { alloc: std.mem.Allocator, id: [12]u8 } = .{ .alloc = alloc, .id = "worker000001".* };
    try std.testing.expect(try result_store.claim(&fixture.id, "assignment", 3));
    try result_store.attachContainer(&fixture.id, "assignment", 3, "abcdef012345");
    try result_store.record(&fixture.id, "assignment", 3, "running", null);
    const saved = try result_store.list(alloc, &fixture.id);
    defer {
        for (saved) |result| result.deinit(alloc);
        alloc.free(saved);
    }
    const Cleanup = struct {
        fn blocked(_: std.mem.Allocator, id: []const u8) !void {
            try std.testing.expectEqualStrings("abcdef012345", id);
            return error.DeleteFailed;
        }
        fn stopped(_: std.mem.Allocator, id: []const u8) !void {
            try std.testing.expectEqualStrings("abcdef012345", id);
        }
    };
    try std.testing.expectError(error.DeleteFailed, recoverInterruptedWith(&fixture, saved[0], Cleanup.blocked));
    const waiting = try result_store.list(alloc, &fixture.id);
    defer {
        for (waiting) |result| result.deinit(alloc);
        alloc.free(waiting);
    }
    try std.testing.expectEqualStrings("running", waiting[0].status);
    try std.testing.expect(!try result_store.claim(&fixture.id, "assignment", 3));
    try recoverInterruptedWith(&fixture, saved[0], Cleanup.stopped);
    const recovered = try result_store.list(alloc, &fixture.id);
    defer {
        for (recovered) |result| result.deinit(alloc);
        alloc.free(recovered);
    }
    try std.testing.expectEqualStrings("failed", recovered[0].status);
    try std.testing.expectEqualStrings("agent_restarted", recovered[0].reason.?);
}
