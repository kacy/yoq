const std = @import("std");
const http_client = @import("../http_client.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const log = @import("../../lib/log.zig");
const container = @import("../../runtime/container.zig");
const image_registry = @import("../../image/registry.zig");
const image_layer = @import("../../image/layer.zig");
const image_spec = @import("../../image/spec.zig");
const store = @import("../../state/store.zig");
const logs = @import("../../runtime/logs.zig");
const agent_store = @import("../agent_store.zig");

const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

pub const GangInfo = struct {
    rank: u32,
    world_size: u32,
    master_addr: []const u8,
    master_port: u16,
};

pub fn reconcile(self: anytype) void {
    var resp = fetchAssignments(self) orelse {
        reconcileFromCache(self);
        return;
    };
    defer resp.deinit(self.alloc);

    const now = std.time.timestamp();
    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        const assignment_id = extractJsonString(obj, "id") orelse continue;
        const status = extractJsonString(obj, "status") orelse continue;
        const image = extractJsonString(obj, "image") orelse continue;
        const command = extractJsonString(obj, "command") orelse "";
        const cpu_limit = extractJsonInt(obj, "cpu_limit") orelse 1000;
        const memory_limit_mb = extractJsonInt(obj, "memory_limit_mb") orelse 256;
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
            startPendingAssignment(self, assignment_id, image, command, gang_info);
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
        startPendingAssignment(self, assignment.id, assignment.image, assignment.command, null);
    }
}

fn startPendingAssignment(self: anytype, id: []const u8, image: []const u8, command: []const u8, gang_info: ?GangInfo) void {
    self.container_lock.lock();
    const already_tracked = self.local_containers.contains(id);
    self.container_lock.unlock();
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
    const gang_copy: ?GangInfo = if (gang_info) |gang| blk: {
        const addr_copy = self.alloc.dupe(u8, gang.master_addr) catch {
            self.alloc.free(id_copy);
            self.alloc.free(image_copy);
            self.alloc.free(command_copy);
            return;
        };
        break :blk .{
            .rank = gang.rank,
            .world_size = gang.world_size,
            .master_addr = addr_copy,
            .master_port = gang.master_port,
        };
    } else null;

    self.container_lock.lock();
    self.local_containers.put(id_copy, .starting) catch {
        self.container_lock.unlock();
        self.alloc.free(id_copy);
        self.alloc.free(image_copy);
        self.alloc.free(command_copy);
        if (gang_copy) |gang| self.alloc.free(gang.master_addr);
        return;
    };
    self.container_lock.unlock();

    if (gang_copy) |gang| {
        log.info("starting gang assignment {s} (image: {s}, rank {d}/{d})", .{ id_copy, image_copy, gang.rank, gang.world_size });
    } else {
        log.info("starting assignment {s} (image: {s})", .{ id_copy, image_copy });
    }

    _ = std.Thread.spawn(.{}, runAssignment, .{ self, id_copy, image_copy, command_copy, gang_copy }) catch {
        log.warn("failed to spawn thread for assignment {s}", .{id_copy});
        self.container_lock.lock();
        _ = self.local_containers.remove(id_copy);
        self.container_lock.unlock();
        self.alloc.free(id_copy);
        self.alloc.free(image_copy);
        self.alloc.free(command_copy);
        if (gang_copy) |gang| self.alloc.free(gang.master_addr);
    };
}

fn fetchAssignments(self: anytype) ?http_client.Response {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/assignments", .{self.id}) catch return null;
    return http_client.getWithAuth(self.alloc, self.server_addr, self.server_port, path, self.token) catch return null;
}

fn runAssignment(self: anytype, assignment_id: []const u8, image: []const u8, command: []const u8, gang_info: ?GangInfo) void {
    defer {
        self.alloc.free(image);
        self.alloc.free(command);
        if (gang_info) |gang| self.alloc.free(gang.master_addr);
    }

    const ref = image_spec.parseImageRef(image);
    var pull_result = image_registry.pull(self.alloc, ref) catch {
        log.warn("failed to pull image {s} for assignment {s}", .{ image, assignment_id });
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed");
        return;
    };
    defer pull_result.deinit();

    const layer_paths = image_layer.assembleRootfs(self.alloc, pull_result.layer_digests) catch {
        log.warn("failed to assemble rootfs for assignment {s}", .{assignment_id});
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed");
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
        reportStatus(self, assignment_id, "failed");
        return;
    };
    const container_id = id_buf[0..];

    store.save(.{
        .id = container_id,
        .rootfs = rootfs,
        .command = if (command.len > 0) command else "/bin/sh",
        .hostname = "agent",
        .status = "created",
        .pid = null,
        .exit_code = null,
        .created_at = std.time.timestamp(),
    }) catch {
        log.warn("failed to save container record for assignment {s}", .{assignment_id});
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed");
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
        .created_at = std.time.timestamp(),
    };

    log.info("starting container {s} for assignment {s}", .{ container_id, assignment_id });
    c.start() catch {
        log.warn("container {s} failed to start for assignment {s}", .{ container_id, assignment_id });
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed");
        cleanup(container_id);
        return;
    };

    reportStatus(self, assignment_id, "running");
    setContainerState(self, assignment_id, .running);

    const exit_code = c.wait() catch 255;

    log.info("container {s} exited for assignment {s}", .{ container_id, assignment_id });
    if (exit_code == 0) {
        setContainerState(self, assignment_id, .stopped);
        reportStatus(self, assignment_id, "stopped");
    } else {
        setContainerState(self, assignment_id, .failed);
        reportStatus(self, assignment_id, "failed");
    }
    cleanup(container_id);
}

fn reportStatus(self: anytype, assignment_id: []const u8, status: []const u8) void {
    var path_buf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/assignments/{s}/status", .{ self.id, assignment_id }) catch return;

    var body_buf: [64]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"status\":\"{s}\"}}", .{status}) catch return;

    var resp = http_client.postWithAuth(self.alloc, self.server_addr, self.server_port, path, body, self.token) catch {
        log.warn("failed to report status '{s}' for assignment {s}", .{ status, assignment_id });
        return;
    };
    resp.deinit(self.alloc);
}

fn setContainerState(self: anytype, assignment_id: []const u8, state: anytype) void {
    self.container_lock.lock();
    defer self.container_lock.unlock();
    if (self.local_containers.getPtr(assignment_id)) |container_state| {
        container_state.* = state;
    }
}

fn cleanup(container_id: []const u8) void {
    logs.deleteLogFile(container_id);
    container.cleanupContainerDirs(container_id);
    store.remove(container_id) catch {};
}
