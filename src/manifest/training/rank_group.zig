// prepare rank resources once, start every rank, then poll them as a group.
// each container keeps its own network namespace and one selected gpu.
const std = @import("std");
const container = @import("../../runtime/container.zig");
const runtime = @import("../orchestrator/service_runtime.zig");
const execution = @import("../../cluster/assignment_spec.zig");
const spec = @import("../spec.zig");
const store = @import("../../state/store.zig");
const gpu_lease = @import("../../gpu/lease.zig");
const checkpoint = @import("../checkpoint.zig");
const gpu_mesh = @import("../../gpu/mesh.zig");
const gpu_env = @import("../../gpu/passthrough.zig");

pub const Group = struct {
    arena: *std.heap.ArenaAllocator,
    backing_alloc: std.mem.Allocator,
    image: runtime.ServiceImageConfig,
    volumes: runtime.ServiceVolumes,
    gpus: gpu_lease.Lease,
    ranks: []?container.Container,
    job: *const spec.TrainingJob,
    app_name: []const u8,
    resume_path: ?[]const u8,
    master_addr: []const u8 = "0.0.0.0",

    pub fn init(controller: anytype) !Group {
        const arena = try controller.alloc.create(std.heap.ArenaAllocator);
        errdefer controller.alloc.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(controller.alloc);
        errdefer arena.deinit();
        const alloc = arena.allocator();
        var gpus = try gpu_lease.Lease.acquire(controller.gpu_count, controller.job.gpu_type);
        errdefer gpus.deinit();
        var image = runtime.resolveServiceImage(alloc, controller.job.image) orelse return error.ImagePullFailed;
        errdefer image.deinit(alloc);
        const volumes = try runtime.resolveServiceVolumes(alloc, controller.job.volumes, controller.manifest_volumes, controller.app_name);
        if (volumes.bind_mounts.items.len != controller.job.volumes.len) return error.VolumeFailed;
        const ranks = try alloc.alloc(?container.Container, controller.gpu_count);
        @memset(ranks, null);
        return .{ .arena = arena, .backing_alloc = controller.alloc, .image = image, .volumes = volumes, .gpus = gpus, .ranks = ranks, .job = controller.job, .app_name = controller.app_name, .resume_path = controller.resume_path };
    }

    pub fn deinit(self: *Group) void {
        self.stopAll();
        for (self.ranks) |*rank| if (rank.*) |*c| container.cleanupContainerDirs(c.config.id);
        self.volumes.deinit(self.arena.allocator());
        self.image.deinit(self.arena.allocator());
        self.gpus.deinit();
        self.arena.deinit();
        self.backing_alloc.destroy(self.arena);
    }

    pub fn start(self: *Group, rank: usize) !void {
        const alloc = self.arena.allocator();
        const id = try alloc.create(container.ContainerId);
        try container.generateId(id);
        const hostname = try std.fmt.allocPrint(alloc, "{s}-rank-{d}", .{ self.job.name, rank });
        var env: std.ArrayList([]const u8) = .empty;
        const ib = gpu_mesh.detectInfiniband();
        if (self.job.resources.ib_required and ib.count == 0) return error.InfinibandRequired;
        var mesh_buf: [1024]u8 = undefined;
        const mesh = try gpu_mesh.generateMeshEnv(&mesh_buf, ib, self.master_addr, 29500, @intCast(self.ranks.len), @intCast(rank), 0, null);
        try appendEnv(alloc, &env, mesh);
        var gpu_buf: [4096]u8 = undefined;
        try appendEnv(alloc, &env, try gpu_env.generateGpuEnv(self.gpus.indices[rank .. rank + 1], &gpu_buf));
        // one visible gpu per container means local rank zero. disable shared
        // memory transport across the ranks' separate ipc namespaces.
        try env.append(alloc, "NCCL_SHM_DISABLE=1");
        if (self.job.checkpoint) |ckpt| try checkpoint.buildCheckpointEnv(alloc, &env, ckpt, self.resume_path);
        const image_config = if (self.image.config_parsed) |parsed| parsed.value.config else null;
        const resolved = try execution.resolve(alloc, .{ .argv = self.job.command, .env = self.job.env, .working_dir = self.job.working_dir }, image_config, env.items);
        const limits = try execution.resourceLimits(self.job.resources.cpu, @intCast(self.job.resources.memory_mb));
        self.ranks[rank] = .{
            .config = .{
                .id = id,
                .rootfs = self.image.rootfs,
                .command = resolved.command.command,
                .args = resolved.command.args.items,
                .env = resolved.env.items,
                .working_dir = resolved.working_dir,
                .user = self.image.user,
                .lower_dirs = self.image.layer_paths,
                .hostname = hostname,
                .mounts = self.volumes.bind_mounts.items,
                .gpu_indices = self.gpus.indices[rank .. rank + 1],
                .limits = limits,
                .network = .{},
            },
            .status = .created,
            .pid = null,
            .exit_code = null,
            .created_at = std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
        };
        const c = &self.ranks[rank].?;
        try store.save(.{ .id = id, .rootfs = self.image.rootfs, .command = resolved.command.command, .hostname = hostname, .status = "created", .pid = null, .exit_code = null, .app_name = self.app_name, .created_at = c.created_at });
        c.start() catch |err| {
            store.updateStatus(id, "stopped", null, 255) catch {};
            return err;
        };
        if (rank == 0) {
            const ip = (c.net_info orelse return error.MissingRankNetwork).ip;
            self.master_addr = try std.fmt.allocPrint(alloc, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
        }
    }

    pub fn poll(self: *Group, rank: usize) !?u8 {
        const c = &self.ranks[rank].?;
        try c.poll();
        return if (c.status == .stopped) c.exit_code orelse 255 else null;
    }

    pub fn stopAll(self: *Group) void {
        for (self.ranks) |*rank| if (rank.*) |*c| {
            if (c.status == .running) c.forceStop() catch {};
        };
        for (self.ranks) |*rank| if (rank.*) |*c| {
            if (c.pid != null) _ = c.wait() catch 255;
        };
    }
};

pub fn appendEnv(alloc: std.mem.Allocator, env: *std.ArrayList([]const u8), data: []const u8) !void {
    var entries = std.mem.splitScalar(u8, data, 0);
    while (entries.next()) |entry| {
        if (entry.len == 0) continue;
        const owned = try alloc.dupe(u8, entry);
        env.append(alloc, owned) catch |err| {
            alloc.free(owned);
            return err;
        };
    }
}
