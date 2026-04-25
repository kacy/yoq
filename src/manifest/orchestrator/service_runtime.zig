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
    layer_paths: []const []const u8 = &.{},
    pull_result: ?registry.PullResult = null,
    config_parsed: ?image_spec.ParseResult(image_spec.ImageConfig) = null,
    img_record: ?store.ImageRecord = null,

    pub fn deinit(self: *ServiceImageConfig, alloc: std.mem.Allocator) void {
        if (self.pull_result) |*r| r.deinit();
        if (self.config_parsed) |*c| c.deinit();
        if (self.img_record) |img| img.deinit(alloc);
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

    const layer_paths = layer.assembleRootfs(alloc, result.layer_digests) catch return false;
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

    result.pull_result = registry.pull(io, alloc, ref) catch return null;
    result.config_parsed = image_spec.parseImageConfig(alloc, result.pull_result.?.config_bytes) catch return null;

    if (result.config_parsed.?.value.config) |cc| {
        if (cc.Entrypoint) |ep| result.entrypoint = ep;
        if (cc.Cmd) |cmd| result.default_cmd = cmd;
        if (cc.Env) |env| result.image_env = env;
        if (cc.WorkingDir) |wd| {
            if (wd.len > 0) result.working_dir = wd;
        }
    }

    result.layer_paths = layer.assembleRootfs(alloc, result.pull_result.?.layer_digests) catch return null;
    if (result.layer_paths.len > 0) {
        result.rootfs = result.layer_paths[result.layer_paths.len - 1];
    }

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

    for (volumes) |vol| {
        switch (vol.kind) {
            .bind => {
                var resolve_buf: [4096]u8 = undefined;
                const abs_source_len = std.Io.Dir.cwd().realPathFile(std.Options.debug_io, vol.source, &resolve_buf) catch {
                    log.warn("failed to resolve bind mount source: {s}", .{vol.source});
                    continue;
                };
                const abs_source = resolve_buf[0..abs_source_len];

                const duped = alloc.dupe(u8, abs_source) catch {
                    log.warn("orchestrator: failed to allocate bind mount source: {s}", .{vol.source});
                    continue;
                };
                result.resolved_sources.append(alloc, duped) catch {
                    alloc.free(duped);
                    continue;
                };

                result.bind_mounts.append(alloc, .{
                    .source = duped,
                    .target = vol.target,
                }) catch |err| {
                    log.warn("failed to add bind mount for {s}: {}", .{ vol.target, err });
                };
            },
            .named => {
                const vol_def = findVolumeByName(manifest_volumes, vol.source) orelse {
                    log.err("named volume '{s}' not defined in manifest", .{vol.source});
                    return error.VolumeFailed;
                };

                const db = store.getDb() catch {
                    log.err("orchestrator: no database for volume creation", .{});
                    return error.VolumeFailed;
                };
                const timestamp = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
                volumes_mod.create(db, app_name, vol_def, timestamp, null) catch |err| {
                    log.err("failed to create volume '{s}': {}", .{ vol.source, err });
                    return error.VolumeFailed;
                };

                var path_buf: [4096]u8 = undefined;
                const vol_path = volumes_mod.resolveVolumePath(&path_buf, app_name, vol.source, vol_def.driver) catch |err| {
                    log.err("failed to resolve volume path '{s}': {}", .{ vol.source, err });
                    return error.VolumeFailed;
                };

                const duped = alloc.dupe(u8, vol_path) catch {
                    log.warn("orchestrator: failed to allocate volume path: {s}", .{vol.source});
                    continue;
                };
                result.resolved_sources.append(alloc, duped) catch {
                    alloc.free(duped);
                    continue;
                };

                result.bind_mounts.append(alloc, .{
                    .source = duped,
                    .target = vol.target,
                }) catch |err| {
                    log.warn("failed to add volume mount for {s}: {}", .{ vol.target, err });
                };
            },
        }
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
    defer merged_env.deinit(alloc);

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
        .app_name = null,
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
            .lower_dirs = img.layer_paths,
            .hostname = hostname,
            .mounts = vols.bind_mounts.items,
        },
        .status = .created,
        .pid = null,
        .exit_code = null,
        .created_at = std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
    };

    c.start() catch {
        logs.deleteLogFile(id);
        container.cleanupContainerDirs(id);
        store.remove(id) catch {};
        return false;
    };

    const exit_code = c.wait() catch 255;

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
