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
const agent_store = @import("../agent_store.zig");
const assignment_spec = @import("../assignment_spec.zig");
const runtime_wait = @import("../../lib/runtime_wait.zig");

const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

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
    cpu_limit: i64 = 1000,
    memory_limit_mb: i64 = 256,
    app_name: ?[]const u8 = null,
    workload_kind: ?[]const u8 = null,
    workload_name: ?[]const u8 = null,
    health_check_json: ?[]const u8 = null,
};

const ServiceReadinessResult = enum {
    healthy,
    unhealthy,
    timeout,
    invalid,
};

pub fn reconcile(self: anytype) void {
    var resp = fetchAssignments(self) orelse {
        reconcileFromCache(self);
        return;
    };
    defer resp.deinit(self.alloc);

    // Only a complete successful snapshot can remove desired work. A server
    // error or malformed response must never look like an empty assignment set.
    if (resp.status_code != 200) return;
    cancelRemovedAssignments(self, resp.body) catch return;

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
        const cpu_limit = extractJsonInt(obj, "cpu_limit") orelse 1000;
        const memory_limit_mb = extractJsonInt(obj, "memory_limit_mb") orelse 256;
        const app_name = extractJsonString(obj, "app_name");
        const workload_kind = extractJsonString(obj, "workload_kind");
        const workload_name = extractJsonString(obj, "workload_name");
        const health_check_json = json_helpers.extractJsonObject(obj, "health_check");
        const gang_rank = extractJsonInt(obj, "gang_rank");
        const gang_world_size = extractJsonInt(obj, "gang_world_size");
        const gang_master_addr = extractJsonString(obj, "gang_master_addr");
        const gang_master_port = extractJsonInt(obj, "gang_master_port");

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
            const gang_info: ?GangInfo = if (gang_rank != null and gang_world_size != null and gang_master_addr != null) .{
                .rank = @intCast(@max(0, gang_rank.?)),
                .world_size = @intCast(@max(0, gang_world_size.?)),
                .master_addr = gang_master_addr.?,
                .master_port = if (gang_master_port) |port| @intCast(@max(0, port)) else 29500,
            } else null;
            startPendingAssignment(self, assignment_id, image, command, gang_info, .{
                .cpu_limit = cpu_limit,
                .memory_limit_mb = memory_limit_mb,
                .app_name = app_name,
                .workload_kind = workload_kind,
                .workload_name = workload_name,
                .health_check_json = health_check_json,
            });
        }
    }
}

fn cancelRemovedAssignments(self: anytype, body: []const u8) !void {
    const Desired = struct { id: []const u8, status: []const u8 };
    const parsed = try std.json.parseFromSlice([]Desired, self.alloc, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var desired = std.StringHashMap(void).init(self.alloc);
    defer desired.deinit();
    for (parsed.value) |assignment| {
        if (std.mem.eql(u8, assignment.status, "pending") or std.mem.eql(u8, assignment.status, "running"))
            try desired.put(assignment.id, {});
    }
    var retired: std.ArrayList([]const u8) = .empty;
    defer retired.deinit(self.alloc);
    self.container_lock.lockUncancelable(std.Options.debug_io);
    defer self.container_lock.unlock(std.Options.debug_io);
    var it = self.local_containers.iterator();
    while (it.next()) |entry| {
        if (!desired.contains(entry.key_ptr.*)) {
            entry.value_ptr.*.canceled.store(true, .release);
            agent_store.removeAssignment(entry.key_ptr.*) catch {};
            if (entry.value_ptr.*.done.load(.acquire)) try retired.append(self.alloc, entry.key_ptr.*);
        }
    }
    for (retired.items) |id| {
        const removed = self.local_containers.fetchRemove(id).?;
        self.alloc.destroy(removed.value);
        self.alloc.free(removed.key);
    }
    // Cached work can predate this process. A successful desired-state snapshot
    // also invalidates those entries, preventing resurrection during an outage.
    const cached = try agent_store.listAssignments(self.alloc);
    defer {
        for (cached) |assignment| assignment.deinit(self.alloc);
        self.alloc.free(cached);
    }
    for (cached) |assignment| {
        if (!desired.contains(assignment.id)) try agent_store.removeAssignment(assignment.id);
    }
}

fn reconcileFromCache(self: anytype) void {
    const cached = agent_store.listPendingAssignments(self.alloc) catch return;
    defer {
        for (cached) |assignment| assignment.deinit(self.alloc);
        self.alloc.free(cached);
    }

    if (cached.len == 0) return;
    log.warn("server unreachable, reconciling from cache ({d} assignments)", .{cached.len});
    for (cached) |assignment| {
        startPendingAssignment(self, assignment.id, assignment.image, assignment.command, null, .{ .cpu_limit = assignment.cpu_limit, .memory_limit_mb = assignment.memory_limit_mb });
    }
}

fn startPendingAssignment(self: anytype, id: []const u8, image: []const u8, command: []const u8, gang_info: ?GangInfo, meta: AssignmentMeta) void {
    self.container_lock.lockUncancelable(std.Options.debug_io);
    const already_tracked = self.local_containers.contains(id);
    self.container_lock.unlock(std.Options.debug_io);
    if (already_tracked) return;

    const id_copy = self.alloc.dupe(u8, id) catch return;
    const image_copy = self.alloc.dupe(u8, image) catch {
        self.alloc.free(id_copy);
        return;
    };
    const command_copy = self.alloc.dupe(u8, command) catch {
        self.alloc.free(id_copy);
        self.alloc.free(image_copy);
        return;
    };
    const app_name_copy = if (meta.app_name) |app_name|
        self.alloc.dupe(u8, app_name) catch {
            self.alloc.free(id_copy);
            self.alloc.free(image_copy);
            self.alloc.free(command_copy);
            return;
        }
    else
        null;
    const workload_kind_copy = if (meta.workload_kind) |workload_kind|
        self.alloc.dupe(u8, workload_kind) catch {
            self.alloc.free(id_copy);
            self.alloc.free(image_copy);
            self.alloc.free(command_copy);
            if (app_name_copy) |app_name| self.alloc.free(app_name);
            return;
        }
    else
        null;
    const workload_name_copy = if (meta.workload_name) |workload_name|
        self.alloc.dupe(u8, workload_name) catch {
            self.alloc.free(id_copy);
            self.alloc.free(image_copy);
            self.alloc.free(command_copy);
            if (app_name_copy) |app_name| self.alloc.free(app_name);
            if (workload_kind_copy) |workload_kind| self.alloc.free(workload_kind);
            return;
        }
    else
        null;
    const health_check_json_copy = if (meta.health_check_json) |health_check_json|
        self.alloc.dupe(u8, health_check_json) catch {
            self.alloc.free(id_copy);
            self.alloc.free(image_copy);
            self.alloc.free(command_copy);
            if (app_name_copy) |app_name| self.alloc.free(app_name);
            if (workload_kind_copy) |workload_kind| self.alloc.free(workload_kind);
            if (workload_name_copy) |workload_name| self.alloc.free(workload_name);
            return;
        }
    else
        null;
    const gang_copy: ?GangInfo = if (gang_info) |gang| blk: {
        const addr_copy = self.alloc.dupe(u8, gang.master_addr) catch {
            self.alloc.free(id_copy);
            self.alloc.free(image_copy);
            self.alloc.free(command_copy);
            if (app_name_copy) |app_name| self.alloc.free(app_name);
            if (workload_kind_copy) |workload_kind| self.alloc.free(workload_kind);
            if (workload_name_copy) |workload_name| self.alloc.free(workload_name);
            if (health_check_json_copy) |health_check_json| self.alloc.free(health_check_json);
            return;
        };
        break :blk .{
            .rank = gang.rank,
            .world_size = gang.world_size,
            .master_addr = addr_copy,
            .master_port = gang.master_port,
        };
    } else null;

    const owner = self.alloc.create(@import("../agent.zig").LocalAssignment) catch {
        self.alloc.free(id_copy);
        self.alloc.free(image_copy);
        self.alloc.free(command_copy);
        if (app_name_copy) |name| self.alloc.free(name);
        if (workload_kind_copy) |kind| self.alloc.free(kind);
        if (workload_name_copy) |name| self.alloc.free(name);
        if (health_check_json_copy) |check| self.alloc.free(check);
        if (gang_copy) |gang| self.alloc.free(gang.master_addr);
        return;
    };
    owner.* = .{};
    self.container_lock.lockUncancelable(std.Options.debug_io);
    self.local_containers.put(id_copy, owner) catch {
        self.alloc.destroy(owner);
        self.container_lock.unlock(std.Options.debug_io);
        self.alloc.free(id_copy);
        self.alloc.free(image_copy);
        self.alloc.free(command_copy);
        if (app_name_copy) |app_name| self.alloc.free(app_name);
        if (workload_kind_copy) |workload_kind| self.alloc.free(workload_kind);
        if (workload_name_copy) |workload_name| self.alloc.free(workload_name);
        if (health_check_json_copy) |health_check_json| self.alloc.free(health_check_json);
        if (gang_copy) |gang| self.alloc.free(gang.master_addr);
        return;
    };
    self.container_lock.unlock(std.Options.debug_io);

    if (gang_copy) |gang| {
        log.info("starting gang assignment {s} (image: {s}, rank {d}/{d})", .{ id_copy, image_copy, gang.rank, gang.world_size });
    } else {
        log.info("starting assignment {s} (image: {s})", .{ id_copy, image_copy });
    }

    self.assignment_workers.spawn(runAssignment, .{ self, owner, id_copy, image_copy, command_copy, gang_copy, AssignmentMeta{
        .cpu_limit = meta.cpu_limit,
        .memory_limit_mb = meta.memory_limit_mb,
        .app_name = app_name_copy,
        .workload_kind = workload_kind_copy,
        .workload_name = workload_name_copy,
        .health_check_json = health_check_json_copy,
    } }) catch {
        log.warn("failed to spawn thread for assignment {s}", .{id_copy});
        self.container_lock.lockUncancelable(std.Options.debug_io);
        _ = self.local_containers.remove(id_copy);
        self.alloc.destroy(owner);
        self.container_lock.unlock(std.Options.debug_io);
        self.alloc.free(id_copy);
        self.alloc.free(image_copy);
        self.alloc.free(command_copy);
        if (app_name_copy) |app_name| self.alloc.free(app_name);
        if (workload_kind_copy) |workload_kind| self.alloc.free(workload_kind);
        if (workload_name_copy) |workload_name| self.alloc.free(workload_name);
        if (health_check_json_copy) |health_check_json| self.alloc.free(health_check_json);
        if (gang_copy) |gang| self.alloc.free(gang.master_addr);
    };
}

fn fetchAssignments(self: anytype) ?http_client.Response {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/assignments", .{self.id}) catch return null;
    return http_client.getWithAuth(self.alloc, self.server_addr, self.server_port, path, self.worker_credential) catch return null;
}

const StopToken = struct {
    group: *const std.atomic.Value(bool),
    assignment: *const std.atomic.Value(bool),

    fn load(self: StopToken, comptime order: std.builtin.AtomicOrder) bool {
        return self.group.load(order) or self.assignment.load(order);
    }
};

fn runAssignment(group_stopping: *const std.atomic.Value(bool), self: anytype, owner: *@import("../agent.zig").LocalAssignment, assignment_id: []const u8, image: []const u8, command: []const u8, gang_info: ?GangInfo, meta: AssignmentMeta) void {
    // Published only after the thread releases all borrowed assignment fields.
    defer owner.done.store(true, .release);
    const stopping = StopToken{ .group = group_stopping, .assignment = &owner.canceled };
    defer {
        self.alloc.free(image);
        self.alloc.free(command);
        if (meta.app_name) |app_name| self.alloc.free(app_name);
        if (meta.workload_kind) |workload_kind| self.alloc.free(workload_kind);
        if (meta.workload_name) |workload_name| self.alloc.free(workload_name);
        if (meta.health_check_json) |health_check_json| self.alloc.free(health_check_json);
        if (gang_info) |gang| self.alloc.free(gang.master_addr);
    }

    if (stopping.load(.acquire)) {
        setContainerState(self, assignment_id, .stopped);
        return;
    }

    var execution = assignment_spec.decode(self.alloc, command) catch {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed", "invalid_execution_spec");
        return;
    };
    defer execution.deinit();
    const limits = assignment_spec.resourceLimits(meta.cpu_limit, meta.memory_limit_mb) catch {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed", "invalid_resource_limits");
        return;
    };
    const ref = image_spec.parseImageRef(image);
    var threaded_io = std.Io.Threaded.init(self.alloc, .{});
    defer threaded_io.deinit();

    var pull_result = image_registry.pull(threaded_io.io(), self.alloc, ref) catch {
        log.warn("failed to pull image {s} for assignment {s}", .{ image, assignment_id });
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed", "image_pull_failed");
        return;
    };
    defer pull_result.deinit();
    var config_parsed = image_spec.parseImageConfig(self.alloc, pull_result.config_bytes) catch {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed", "invalid_image_config");
        return;
    };
    defer config_parsed.deinit();

    if (stopping.load(.acquire)) {
        setContainerState(self, assignment_id, .stopped);
        return;
    }

    const layer_paths = image_layer.assembleRootfs(self.alloc, pull_result.layer_digests) catch {
        log.warn("failed to assemble rootfs for assignment {s}", .{assignment_id});
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed", "rootfs_assemble_failed");
        return;
    };
    defer {
        for (layer_paths) |path| self.alloc.free(path);
        self.alloc.free(layer_paths);
    }

    if (layer_paths.len == 0) {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed", "empty_image_rootfs");
        return;
    }
    const rootfs = layer_paths[layer_paths.len - 1];

    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf) catch {
        log.warn("failed to generate container ID for assignment {s}", .{assignment_id});
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed", "container_id_failed");
        return;
    };
    const container_id = id_buf[0..];

    var hostname_buf: [128]u8 = undefined;
    const hostname = buildAssignmentHostname(&hostname_buf, meta, gang_info);

    const gpu_mesh = @import("../../gpu/mesh.zig");
    var mesh_env: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (mesh_env.items) |entry| self.alloc.free(entry);
        mesh_env.deinit(self.alloc);
    }
    if (gang_info) |gang| {
        const ib_result = gpu_mesh.detectInfiniband();
        var mesh_env_buf: [1024]u8 = undefined;
        if (gpu_mesh.generateMeshEnv(
            &mesh_env_buf,
            ib_result,
            gang.master_addr,
            gang.master_port,
            gang.world_size,
            gang.rank,
            gang.rank,
            null,
        )) |env_data| {
            var env_pos: usize = 0;
            while (env_pos < env_data.len) {
                const end = std.mem.indexOfScalarPos(u8, env_data, env_pos, 0) orelse env_data.len;
                if (end > env_pos) {
                    if (self.alloc.dupe(u8, env_data[env_pos..end])) |duped| {
                        mesh_env.append(self.alloc, duped) catch {};
                    } else |_| {}
                }
                env_pos = end + 1;
            }
        } else |_| {}
    }

    var resolved = assignment_spec.resolve(self.alloc, execution.value, config_parsed.value.config, mesh_env.items) catch {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed", "invalid_execution_spec");
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
        reportStatus(self, assignment_id, "failed", "container_record_failed");
        return;
    };

    var c = container.Container{
        .config = .{
            .id = container_id,
            .rootfs = rootfs,
            .command = resolved.command.command,
            .args = resolved.command.args.items,
            .working_dir = resolved.working_dir,
            .limits = limits,
            .network = .{ .node_id = self.node_id },
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
        reportStatus(self, assignment_id, "failed", "start_failed");
        cleanup(container_id);
        return;
    };

    const readiness_result = waitForServiceReadiness(stopping, self.alloc, container_id, meta);
    switch (readiness_result) {
        .healthy => {},
        .unhealthy, .timeout, .invalid => {
            log.warn("service assignment {s} failed readiness gate", .{assignment_id});
            _ = waitForAssignmentExit(&c, stopping, true);
            setContainerState(self, assignment_id, .failed);
            reportStatus(self, assignment_id, "failed", switch (readiness_result) {
                .healthy => unreachable,
                .unhealthy => "readiness_failed",
                .timeout => "readiness_timeout",
                .invalid => "readiness_invalid",
            });
            cleanup(container_id);
            return;
        },
    }

    reportStatus(self, assignment_id, "running", null);
    setContainerState(self, assignment_id, .running);

    const exit_code = waitForAssignmentExit(&c, stopping, false);
    agent_store.removeAssignment(assignment_id) catch {};

    log.info("container {s} exited for assignment {s}", .{ container_id, assignment_id });
    if (meta.workload_kind != null and meta.workload_name != null and std.mem.eql(u8, meta.workload_kind.?, "service")) {
        manifest_health.unregisterService(meta.workload_name.?);
    }
    if (stopping.load(.acquire) or exit_code == 0) {
        setContainerState(self, assignment_id, .stopped);
        reportStatus(self, assignment_id, "stopped", null);
    } else {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed", "process_failed");
    }
    cleanup(container_id);
}

/// Keep the container and its cleanup on the assignment thread. Shutdown first
/// asks the workload to exit, then kills it after a short grace period, so join
/// cannot leave a running workload borrowing the agent's state indefinitely.
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

    manifest_health.registerService(service_name, id_buf, container_ip, health_check) catch return .invalid;
    manifest_health.startChecker();

    const deadline_ns = nowAwakeNanoseconds() + (@as(i128, estimateHealthStartupWindowSeconds(health_check)) * std.time.ns_per_s);
    defer {
        const final_status = manifest_health.getStatus(service_name) orelse .starting;
        if (final_status != .healthy) manifest_health.unregisterService(service_name);
    }
    while (nowAwakeNanoseconds() < deadline_ns) {
        if (stopping.load(.acquire)) return .timeout;
        switch (manifest_health.getStatus(service_name) orelse .starting) {
            .healthy => return .healthy,
            .unhealthy => return .unhealthy,
            .starting => if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(100), "assignment readiness wait")) return .timeout,
        }
    }
    return .timeout;
}

fn estimateHealthStartupWindowSeconds(health_check: manifest_spec.HealthCheck) u32 {
    const attempts = @max(@as(u32, 1), health_check.retries);
    return health_check.start_period + (attempts * (health_check.interval + health_check.timeout)) + 2;
}

fn parseHealthCheckJson(alloc: std.mem.Allocator, json: []const u8) ?manifest_spec.HealthCheck {
    const kind = extractJsonString(json, "kind") orelse return null;
    const interval = intFieldAsU32(json, "interval", 10);
    const timeout = intFieldAsU32(json, "timeout", 5);
    const retries = intFieldAsU32(json, "retries", 3);
    const start_period = intFieldAsU32(json, "start_period", 0);

    const check_type: manifest_spec.CheckType = if (std.mem.eql(u8, kind, "http")) .{
        .http = .{
            .path = alloc.dupe(u8, extractJsonString(json, "path") orelse return null) catch return null,
            .port = intFieldAsU16(json, "port", 0),
        },
    } else if (std.mem.eql(u8, kind, "tcp")) .{
        .tcp = .{
            .port = intFieldAsU16(json, "port", 0),
        },
    } else if (std.mem.eql(u8, kind, "grpc")) .{
        .grpc = .{
            .port = intFieldAsU16(json, "port", 0),
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

fn intFieldAsU32(json: []const u8, key: []const u8, default_value: u32) u32 {
    return if (extractJsonInt(json, key)) |value| @intCast(@max(@as(i64, 0), value)) else default_value;
}

fn intFieldAsU16(json: []const u8, key: []const u8, default_value: u16) u16 {
    return if (extractJsonInt(json, key)) |value| @intCast(@max(@as(i64, 0), value)) else default_value;
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

fn reportStatus(self: anytype, assignment_id: []const u8, status: []const u8, reason: ?[]const u8) void {
    var path_buf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/assignments/{s}/status", .{ self.id, assignment_id }) catch return;

    var body_buf: [160]u8 = undefined;
    const body = if (reason) |status_reason|
        std.fmt.bufPrint(&body_buf, "{{\"status\":\"{s}\",\"reason\":\"{s}\"}}", .{ status, status_reason }) catch return
    else
        std.fmt.bufPrint(&body_buf, "{{\"status\":\"{s}\"}}", .{status}) catch return;

    var resp = http_client.postWithAuth(self.alloc, self.server_addr, self.server_port, path, body, self.worker_credential) catch {
        log.warn("failed to report status '{s}' for assignment {s}", .{ status, assignment_id });
        return;
    };
    resp.deinit(self.alloc);
}

fn setContainerState(self: anytype, assignment_id: []const u8, state: anytype) void {
    self.container_lock.lockUncancelable(std.Options.debug_io);
    defer self.container_lock.unlock(std.Options.debug_io);
    if (self.local_containers.getPtr(assignment_id)) |container_state| {
        container_state.*.state = state;
    }
}

fn cleanup(container_id: []const u8) void {
    logs.deleteLogFile(container_id);
    container.cleanupContainerDirs(container_id);
    store.remove(container_id) catch {};
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
        alloc: std.mem.Allocator = std.testing.allocator,
        container_lock: std.Io.Mutex = .init,
        local_containers: std.StringHashMap(*agent_mod.LocalAssignment),
    };
    try agent_store.initTestDb();
    defer agent_store.deinit();
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
