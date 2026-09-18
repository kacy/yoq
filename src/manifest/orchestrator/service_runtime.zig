const std = @import("std");

const cli = @import("../../lib/cli.zig");
const spec = @import("../spec.zig");
const image_spec = @import("../../image/spec.zig");
const registry = @import("../../image/registry.zig");
const layer = @import("../../image/layer.zig");
const oci = @import("../../image/oci.zig");
const container = @import("../../runtime/container.zig");
const store = @import("../../state/store.zig");
const blob_store = @import("../../image/store.zig");
const log = @import("../../lib/log.zig");
const volumes_mod = @import("../../state/volumes.zig");
const logs = @import("../../runtime/logs.zig");

const writeErr = cli.writeErr;

pub const ServiceImageConfig = struct {
    rootfs: []const u8,
    entrypoint: []const []const u8 = &.{},
    default_cmd: []const []const u8 = &.{},
    image_env: []const []const u8 = &.{},
    working_dir: []const u8 = "/",
    user: ?[]const u8 = null,
    layer_paths: []const []const u8 = &.{},
    pull_result: ?registry.PullResult = null,
    config_parsed: ?image_spec.ParseResult(image_spec.ImageConfig) = null,
    img_record: ?store.ImageRecord = null,

    pub fn deinit(self: *ServiceImageConfig, alloc: std.mem.Allocator) void {
        if (self.pull_result) |*r| r.deinit();
        if (self.config_parsed) |*c| c.deinit();
        if (self.img_record) |img| img.deinit(alloc);
        for (self.layer_paths) |path| alloc.free(path);
        alloc.free(self.layer_paths);
    }
};

pub const ServiceVolumes = struct {
    bind_mounts: std.ArrayList(container.BindMount),
    resolved_sources: std.ArrayList([]const u8),

    pub fn deinit(self: *ServiceVolumes, alloc: std.mem.Allocator) void {
        for (self.resolved_sources.items) |source| alloc.free(source);
        self.resolved_sources.deinit(alloc);
        self.bind_mounts.deinit(alloc);
    }
};

pub const initial_backoff_ms: u64 = 1_000;
pub const max_backoff_ms: u64 = 30_000;
pub const healthy_run_threshold_ns: i128 = 10 * std.time.ns_per_s;

pub fn ensureImageAvailable(alloc: std.mem.Allocator, image: []const u8) bool {
    var threaded_io = std.Io.Threaded.init(alloc, .{});
    defer threaded_io.deinit();
    return ensureImageAvailableWithIo(threaded_io.io(), alloc, image);
}

pub fn ensureImageAvailableWithIo(io: std.Io, alloc: std.mem.Allocator, image: []const u8) bool {
    const ref = image_spec.parseImageRef(image);

    const existing = store.findImage(alloc, ref.repository, ref.reference);
    if (existing) |img| {
        img.deinit(alloc);
        return true;
    } else |_| {}

    var result = registry.pull(io, alloc, ref) catch return false;
    defer result.deinit();

    const layer_paths = layer.assembleRootfsDescriptors(alloc, result.layers) catch return false;
    defer {
        for (layer_paths) |path| alloc.free(path);
        alloc.free(layer_paths);
    }

    const cfg_computed = blob_store.computeDigest(result.config_bytes);
    var cfg_digest_buf: [71]u8 = undefined;
    const cfg_digest_str = cfg_computed.string(&cfg_digest_buf);
    oci.saveImageFromPull(
        ref,
        result.manifest_digest,
        result.manifest_bytes,
        result.config_bytes,
        cfg_digest_str,
        result.total_size,
    ) catch return false;

    return true;
}

pub fn resolveServiceImage(alloc: std.mem.Allocator, image: []const u8) ?ServiceImageConfig {
    var threaded_io = std.Io.Threaded.init(alloc, .{});
    defer threaded_io.deinit();
    return resolveServiceImageWithIo(threaded_io.io(), alloc, image);
}

pub fn resolveServiceImageWithIo(io: std.Io, alloc: std.mem.Allocator, image: []const u8) ?ServiceImageConfig {
    const ref = image_spec.parseImageRef(image);
    const img = store.findImage(alloc, ref.repository, ref.reference) catch return null;

    var result = ServiceImageConfig{ .rootfs = "/", .img_record = img };
    var resolved = false;
    defer if (!resolved) result.deinit(alloc);

    result.pull_result = registry.pull(io, alloc, ref) catch return null;
    result.config_parsed = image_spec.parseImageConfig(alloc, result.pull_result.?.config_bytes) catch return null;

    if (result.config_parsed.?.value.config) |cc| {
        if (cc.User) |user| {
            if (user.len > 0) result.user = user;
        }
        if (cc.Entrypoint) |ep| result.entrypoint = ep;
        if (cc.Cmd) |cmd| result.default_cmd = cmd;
        if (cc.Env) |env| result.image_env = env;
        if (cc.WorkingDir) |wd| {
            if (wd.len > 0) result.working_dir = wd;
        }
    }

    result.layer_paths = layer.assembleRootfsDescriptors(alloc, result.pull_result.?.layers) catch return null;
    if (result.layer_paths.len == 0) {
        log.err("image {s} has no extracted root filesystem", .{image});
        return null;
    }
    result.rootfs = result.layer_paths[result.layer_paths.len - 1];
    resolved = true;
    return result;
}

pub fn mergeServiceEnv(
    alloc: std.mem.Allocator,
    image_env: []const []const u8,
    manifest_env: []const []const u8,
) std.ArrayList([]const u8) {
    var merged: std.ArrayList([]const u8) = .empty;

    for (image_env) |img_var| {
        const img_key = envKey(img_var);
        var overridden = false;
        for (manifest_env) |manifest_var| {
            if (std.mem.eql(u8, envKey(manifest_var), img_key)) {
                overridden = true;
                break;
            }
        }
        if (!overridden) {
            merged.append(alloc, img_var) catch |err| {
                log.warn("failed to merge image env var: {}", .{err});
            };
        }
    }
    for (manifest_env) |manifest_var| {
        merged.append(alloc, manifest_var) catch |err| {
            log.warn("failed to merge manifest env var: {}", .{err});
        };
    }

    return merged;
}

pub fn resolveServiceVolumes(
    alloc: std.mem.Allocator,
    volumes: []const spec.VolumeMount,
    manifest_volumes: []const spec.Volume,
    app_name: []const u8,
) error{VolumeFailed}!ServiceVolumes {
    var result = ServiceVolumes{
        .bind_mounts = .empty,
        .resolved_sources = .empty,
    };

    errdefer result.deinit(alloc);
    for (volumes) |vol| {
        var path_buf: [4096]u8 = undefined;
        const source = switch (vol.kind) {
            .bind => blk: {
                const length = std.Io.Dir.cwd().realPathFile(std.Options.debug_io, vol.source, &path_buf) catch |err| {
                    log.err("cannot resolve required bind mount {s}: {}", .{ vol.source, err });
                    return error.VolumeFailed;
                };
                break :blk path_buf[0..length];
            },
            .named => blk: {
                const definition = findVolumeByName(manifest_volumes, vol.source) orelse {
                    log.err("named volume '{s}' not defined in manifest", .{vol.source});
                    return error.VolumeFailed;
                };
                const timestamp = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
                volumes_mod.createManaged(app_name, definition, timestamp, null) catch |err| {
                    log.err("failed to create volume '{s}': {}", .{ vol.source, err });
                    return error.VolumeFailed;
                };
                break :blk volumes_mod.resolveVolumePath(&path_buf, app_name, vol.source, definition.driver) catch |err| {
                    log.err("failed to resolve volume path '{s}': {}", .{ vol.source, err });
                    return error.VolumeFailed;
                };
            },
        };
        const owned = alloc.dupe(u8, source) catch return error.VolumeFailed;
        result.resolved_sources.append(alloc, owned) catch {
            alloc.free(owned);
            return error.VolumeFailed;
        };
        result.bind_mounts.append(alloc, .{ .source = owned, .target = vol.target }) catch return error.VolumeFailed;
    }

    return result;
}

pub fn findVolumeByName(manifest_volumes: []const spec.Volume, name: []const u8) ?spec.Volume {
    for (manifest_volumes) |vol| {
        if (std.mem.eql(u8, vol.name, name)) return vol;
    }
    return null;
}

pub fn runOneShot(
    alloc: std.mem.Allocator,
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    volumes: []const spec.VolumeMount,
    working_dir: ?[]const u8,
    hostname: []const u8,
    manifest_volumes: []const spec.Volume,
    app_name: []const u8,
) bool {
    var threaded_io = std.Io.Threaded.init(alloc, .{});
    defer threaded_io.deinit();
    return runOneShotWithIo(threaded_io.io(), alloc, image, command, env, volumes, working_dir, hostname, manifest_volumes, app_name);
}

pub fn runOneShotWithIo(
    io: std.Io,
    alloc: std.mem.Allocator,
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    volumes: []const spec.VolumeMount,
    working_dir: ?[]const u8,
    hostname: []const u8,
    manifest_volumes: []const spec.Volume,
    app_name: []const u8,
) bool {
    return runOneShotWithGpu(io, alloc, image, command, env, volumes, working_dir, hostname, manifest_volumes, app_name, null, null);
}

pub fn runCron(alloc: std.mem.Allocator, cron: spec.Cron, manifest_volumes: []const spec.Volume, app_name: []const u8, running: *const std.atomic.Value(bool)) bool {
    var threaded_io = std.Io.Threaded.init(alloc, .{});
    defer threaded_io.deinit();
    return runOneShotWithGpu(threaded_io.io(), alloc, cron.image, cron.command, cron.env, cron.volumes, cron.working_dir, cron.name, manifest_volumes, app_name, null, .{ .flag = running, .when = false });
}

pub fn validateLocalWorker(worker: spec.Worker) !void {
    if (worker.gpu_mesh != null) return error.UnsupportedLocalWorkerMesh;
}

pub fn runWorkerWithIo(io: std.Io, alloc: std.mem.Allocator, worker: spec.Worker, manifest_volumes: []const spec.Volume, app_name: []const u8) !bool {
    try validateLocalWorker(worker);
    return runOneShotWithGpu(io, alloc, worker.image, worker.command, worker.env, worker.volumes, worker.working_dir, worker.name, manifest_volumes, app_name, worker.gpu, null);
}

fn runOneShotWithGpu(
    io: std.Io,
    alloc: std.mem.Allocator,
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    volumes: []const spec.VolumeMount,
    working_dir: ?[]const u8,
    hostname: []const u8,
    manifest_volumes: []const spec.Volume,
    app_name: []const u8,
    gpu: ?spec.GpuSpec,
    cancellation: ?@import("../child_wait.zig").Cancellation,
) bool {
    if (if (cancellation) |token| token.requested() else false) return false;
    var gpu_lease = if (gpu) |config|
        @import("../../gpu/lease.zig").Lease.acquireWithMinimum(config.count, config.model, config.vram_min_mb) catch |err| {
            writeErr("failed to reserve worker gpus: {}\n", .{err});
            return false;
        }
    else
        @import("../../gpu/lease.zig").Lease{};
    defer gpu_lease.deinit();

    var img = resolveServiceImageWithIo(io, alloc, image) orelse {
        writeErr("failed to resolve image for worker {s}\n", .{hostname});
        return false;
    };
    defer img.deinit(alloc);

    var resolved = oci.resolveCommand(alloc, img.entrypoint, img.default_cmd, command) catch {
        writeErr("failed to resolve command for worker {s}\n", .{hostname});
        return false;
    };
    defer resolved.args.deinit(alloc);

    var merged_env = mergeServiceEnv(alloc, img.image_env, env);
    const owned_env_start = merged_env.items.len;
    defer {
        for (merged_env.items[owned_env_start..]) |entry| alloc.free(entry);
        merged_env.deinit(alloc);
    }
    if (gpu_lease.count > 0) {
        var gpu_env: [4096]u8 = undefined;
        const data = @import("../../gpu/passthrough.zig").generateGpuEnv(gpu_lease.indices[0..gpu_lease.count], &gpu_env) catch return false;
        @import("../gpu_runtime.zig").appendRequiredEnv(alloc, &merged_env, data) catch return false;
    }

    var wd = img.working_dir;
    if (working_dir) |working_dir_override| wd = working_dir_override;

    var vols = resolveServiceVolumes(alloc, volumes, manifest_volumes, app_name) catch {
        writeErr("failed to resolve volumes for worker {s}\n", .{hostname});
        return false;
    };
    defer vols.deinit(alloc);

    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf) catch {
        writeErr("failed to generate container ID for worker {s}\n", .{hostname});
        return false;
    };
    const id = id_buf[0..];

    store.save(.{
        .id = id,
        .rootfs = img.rootfs,
        .command = resolved.command,
        .hostname = hostname,
        .status = "created",
        .pid = null,
        .exit_code = null,
        .app_name = app_name,
        .created_at = std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
    }) catch return false;

    var c = container.Container{
        .config = .{
            .id = id,
            .rootfs = img.rootfs,
            .command = resolved.command,
            .args = resolved.args.items,
            .env = merged_env.items,
            .working_dir = wd,
            .user = img.user,
            .lower_dirs = img.layer_paths,
            .hostname = hostname,
            .mounts = vols.bind_mounts.items,
            .gpu_indices = gpu_lease.indices[0..gpu_lease.count],
        },
        .status = .created,
        .pid = null,
        .exit_code = null,
        .created_at = std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
    };

    if (if (cancellation) |token| token.requested() else false) {
        store.remove(id) catch {};
        return false;
    }

    c.start() catch {
        logs.deleteLogFile(id);
        container.cleanupContainerDirs(id);
        store.remove(id) catch {};
        return false;
    };

    const exit_code = @import("../child_wait.zig").wait(&c, cancellation);

    logs.deleteLogFile(id);
    container.cleanupContainerDirs(id);
    store.remove(id) catch {};

    return exit_code == 0;
}

pub fn envKey(env_var: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, env_var, '=')) |eq| {
        return env_var[0..eq];
    }
    return env_var;
}

test "local workers reject unsupported mesh execution" {
    const worker: spec.Worker = .{ .name = "mesh", .image = "scratch", .command = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{}, .gpu_mesh = .{ .world_size = 2 } };
    try std.testing.expectError(error.UnsupportedLocalWorkerMesh, validateLocalWorker(worker));
}

test "volume resolution releases earlier mounts when a required source is missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var source_buf: [4096]u8 = undefined;
    const length = try tmp.dir.realPathFile(std.Options.debug_io, ".", &source_buf);
    const missing = try std.fmt.allocPrint(std.testing.allocator, "{s}/missing", .{source_buf[0..length]});
    defer std.testing.allocator.free(missing);
    const mounts = [_]spec.VolumeMount{
        .{ .source = source_buf[0..length], .target = "/data", .kind = .bind },
        .{ .source = missing, .target = "/required", .kind = .bind },
    };
    try std.testing.expectError(error.VolumeFailed, resolveServiceVolumes(std.testing.allocator, &mounts, &.{}, "app"));
}

test "volume resolution fails rather than omitting a mount after allocation failure" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 2 });
    try std.testing.expectError(error.VolumeFailed, resolveServiceVolumes(failing.allocator(), &.{.{ .source = ".", .target = "/data", .kind = .bind }}, &.{}, "app"));
}
