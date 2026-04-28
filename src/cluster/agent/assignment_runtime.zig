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

    const now = nowRealSeconds();
    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        const assignment_id = extractJsonString(obj, "id") orelse continue;
        const status = extractJsonString(obj, "status") orelse continue;
        const image = extractJsonString(obj, "image") orelse continue;
        const command = extractJsonString(obj, "command") orelse "";
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
                .app_name = app_name,
                .workload_kind = workload_kind,
                .workload_name = workload_name,
                .health_check_json = health_check_json,
            });
        }
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
        startPendingAssignment(self, assignment.id, assignment.image, assignment.command, null, .{});
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

    self.container_lock.lockUncancelable(std.Options.debug_io);
    self.local_containers.put(id_copy, .starting) catch {
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

    _ = std.Thread.spawn(.{}, runAssignment, .{ self, id_copy, image_copy, command_copy, gang_copy, AssignmentMeta{
        .app_name = app_name_copy,
        .workload_kind = workload_kind_copy,
        .workload_name = workload_name_copy,
        .health_check_json = health_check_json_copy,
    } }) catch {
        log.warn("failed to spawn thread for assignment {s}", .{id_copy});
        self.container_lock.lockUncancelable(std.Options.debug_io);
        _ = self.local_containers.remove(id_copy);
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
    return http_client.getWithAuth(self.alloc, self.server_addr, self.server_port, path, self.token) catch return null;
}

fn runAssignment(self: anytype, assignment_id: []const u8, image: []const u8, command: []const u8, gang_info: ?GangInfo, meta: AssignmentMeta) void {
    defer {
        self.alloc.free(image);
        self.alloc.free(command);
        if (meta.app_name) |app_name| self.alloc.free(app_name);
        if (meta.workload_kind) |workload_kind| self.alloc.free(workload_kind);
        if (meta.workload_name) |workload_name| self.alloc.free(workload_name);
        if (meta.health_check_json) |health_check_json| self.alloc.free(health_check_json);
        if (gang_info) |gang| self.alloc.free(gang.master_addr);
    }

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

    const rootfs = if (layer_paths.len > 0) layer_paths[layer_paths.len - 1] else "/";

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

    store.save(.{
        .id = container_id,
        .rootfs = rootfs,
        .command = if (command.len > 0) command else "/bin/sh",
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

    var c = container.Container{
        .config = .{
            .id = container_id,
            .rootfs = rootfs,
            .command = if (command.len > 0) command else "/bin/sh",
            .lower_dirs = layer_paths,
            .env = mesh_env.items,
        },
        .status = .created,
        .pid = null,
        .exit_code = null,
        .created_at = nowRealSeconds(),
    };

    log.info("starting container {s} for assignment {s}", .{ container_id, assignment_id });
    c.start() catch {
        log.warn("container {s} failed to start for assignment {s}", .{ container_id, assignment_id });
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed", "start_failed");
        cleanup(container_id);
        return;
    };

    const readiness_result = waitForServiceReadiness(self.alloc, container_id, meta);
    switch (readiness_result) {
        .healthy => {},
        .unhealthy, .timeout, .invalid => {
            log.warn("service assignment {s} failed readiness gate", .{assignment_id});
            _ = c.stop() catch {};
            _ = c.wait() catch 255;
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

    const exit_code = c.wait() catch 255;

    log.info("container {s} exited for assignment {s}", .{ container_id, assignment_id });
    if (meta.workload_kind != null and meta.workload_name != null and std.mem.eql(u8, meta.workload_kind.?, "service")) {
        manifest_health.unregisterService(meta.workload_name.?);
    }
    if (exit_code == 0) {
        setContainerState(self, assignment_id, .stopped);
        reportStatus(self, assignment_id, "stopped", null);
    } else {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed", "process_failed");
    }
    cleanup(container_id);
}

fn waitForServiceReadiness(alloc: std.mem.Allocator, container_id: []const u8, meta: AssignmentMeta) ServiceReadinessResult {
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

    var resp = http_client.postWithAuth(self.alloc, self.server_addr, self.server_port, path, body, self.token) catch {
        log.warn("failed to report status '{s}' for assignment {s}", .{ status, assignment_id });
        return;
    };
    resp.deinit(self.alloc);
}

fn setContainerState(self: anytype, assignment_id: []const u8, state: anytype) void {
    self.container_lock.lockUncancelable(std.Options.debug_io);
    defer self.container_lock.unlock(std.Options.debug_io);
    if (self.local_containers.getPtr(assignment_id)) |container_state| {
        container_state.* = state;
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
