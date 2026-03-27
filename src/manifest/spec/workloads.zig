const std = @import("std");
const shared_types = @import("shared_types.zig");

pub const TrainingJob = struct {
    name: []const u8,
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    working_dir: ?[]const u8,
    volumes: []const shared_types.VolumeMount,
    gpus: u32,
    gpu_type: ?[]const u8 = null,
    data: ?shared_types.DataSpec = null,
    checkpoint: ?shared_types.CheckpointSpec = null,
    resources: shared_types.TrainingResourceSpec = .{},
    fault_tolerance: shared_types.FaultToleranceSpec = .{},

    pub fn deinit(self: TrainingJob, alloc: std.mem.Allocator) void {
        freeCommonFields(alloc, self.name, self.image, self.command, self.env, self.working_dir, self.volumes);
        if (self.gpu_type) |gt| alloc.free(gt);
        if (self.data) |d| d.deinit(alloc);
        if (self.checkpoint) |c| c.deinit(alloc);
    }
};

pub const Service = struct {
    name: []const u8,
    image: []const u8,
    command: []const []const u8,
    ports: []const shared_types.PortMapping,
    env: []const []const u8,
    depends_on: []const []const u8,
    working_dir: ?[]const u8,
    volumes: []const shared_types.VolumeMount,
    health_check: ?shared_types.HealthCheck = null,
    restart: shared_types.RestartPolicy = .none,
    tls: ?shared_types.TlsConfig = null,
    http_proxy: ?shared_types.HttpProxyConfig = null,
    gpu: ?shared_types.GpuSpec = null,
    gpu_mesh: ?shared_types.GpuMeshSpec = null,
    alerts: ?shared_types.AlertSpec = null,

    pub fn deinit(self: Service, alloc: std.mem.Allocator) void {
        freeCommonFields(alloc, self.name, self.image, self.command, self.env, self.working_dir, self.volumes);
        for (self.depends_on) |dep| alloc.free(dep);
        alloc.free(self.depends_on);
        alloc.free(self.ports);
        if (self.health_check) |hc| hc.deinit(alloc);
        if (self.tls) |tc| tc.deinit(alloc);
        if (self.http_proxy) |proxy| proxy.deinit(alloc);
        if (self.gpu) |g| g.deinit(alloc);
        if (self.alerts) |a| a.deinit(alloc);
    }
};

pub const Worker = struct {
    name: []const u8,
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    depends_on: []const []const u8,
    working_dir: ?[]const u8,
    volumes: []const shared_types.VolumeMount,
    gpu: ?shared_types.GpuSpec = null,
    gpu_mesh: ?shared_types.GpuMeshSpec = null,

    pub fn deinit(self: Worker, alloc: std.mem.Allocator) void {
        freeCommonFields(alloc, self.name, self.image, self.command, self.env, self.working_dir, self.volumes);
        for (self.depends_on) |dep| alloc.free(dep);
        alloc.free(self.depends_on);
        if (self.gpu) |g| g.deinit(alloc);
    }
};

pub const Cron = struct {
    name: []const u8,
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    working_dir: ?[]const u8,
    volumes: []const shared_types.VolumeMount,
    every: u64,

    pub fn deinit(self: Cron, alloc: std.mem.Allocator) void {
        freeCommonFields(alloc, self.name, self.image, self.command, self.env, self.working_dir, self.volumes);
    }
};

fn freeCommonFields(
    alloc: std.mem.Allocator,
    name: []const u8,
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    working_dir: ?[]const u8,
    volumes: []const shared_types.VolumeMount,
) void {
    alloc.free(name);
    alloc.free(image);
    for (command) |cmd| alloc.free(cmd);
    alloc.free(command);
    for (env) |e| alloc.free(e);
    alloc.free(env);
    if (working_dir) |wd| alloc.free(wd);
    for (volumes) |vol| vol.deinit(alloc);
    alloc.free(volumes);
}
