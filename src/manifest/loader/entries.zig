const std = @import("std");
const spec = @import("../spec.zig");
const toml = @import("../../lib/toml.zig");
const log = @import("../../lib/log.zig");
const common = @import("common.zig");
const fields = @import("fields.zig");

pub fn parseCommonFields(
    alloc: std.mem.Allocator,
    kind: []const u8,
    name: []const u8,
    table: *const toml.Table,
) common.LoadError!common.CommonFields {
    const image_raw = table.getString("image") orelse {
        log.err("manifest: {s} '{s}' is missing required field 'image'", .{ kind, name });
        return common.LoadError.MissingImage;
    };

    const command = try fields.parseStringArray(alloc, table.getArray("command"));
    errdefer {
        for (command) |cmd| alloc.free(cmd);
        alloc.free(command);
    }

    const env = try fields.parseEnvVars(alloc, table.getArray("env"));
    errdefer {
        for (env) |env_var| alloc.free(env_var);
        alloc.free(env);
    }

    const volume_mounts = try fields.parseVolumeMounts(alloc, table.getArray("volumes"));
    errdefer {
        for (volume_mounts) |volume_mount| volume_mount.deinit(alloc);
        alloc.free(volume_mounts);
    }

    const working_dir: ?[]const u8 = if (table.getString("working_dir")) |value|
        alloc.dupe(u8, value) catch return common.LoadError.OutOfMemory
    else
        null;

    return .{
        .image = alloc.dupe(u8, image_raw) catch return common.LoadError.OutOfMemory,
        .command = command,
        .env = env,
        .volumes = volume_mounts,
        .working_dir = working_dir,
    };
}

pub fn parseService(alloc: std.mem.Allocator, name: []const u8, table: *const toml.Table) common.LoadError!spec.Service {
    var parsed_common = try parseCommonFields(alloc, "service", name, table);
    errdefer parsed_common.deinit(alloc);

    const ports = try fields.parsePortMappings(alloc, table.getArray("ports"));
    errdefer alloc.free(ports);

    const depends_on = try fields.parseStringArray(alloc, table.getArray("depends_on"));
    errdefer {
        for (depends_on) |dep| alloc.free(dep);
        alloc.free(depends_on);
    }

    const health_check = try fields.parseHealthCheck(alloc, name, table.getTable("health_check"));
    errdefer if (health_check) |hc| hc.deinit(alloc);

    const restart = try fields.parseRestartPolicy(name, table.getString("restart"));

    const tls_config = try fields.parseTlsConfig(alloc, name, table.getTable("tls"));
    errdefer if (tls_config) |tls_config_value| tls_config_value.deinit(alloc);

    const http_routes = try fields.parseHttpProxyRoutes(alloc, name, table.getTable("http_proxy"), table.getTable("http_routes"));
    errdefer {
        for (http_routes) |route| route.deinit(alloc);
        alloc.free(http_routes);
    }

    const gpu_spec = try fields.parseGpuSpec(alloc, table.getTable("gpu"));
    errdefer if (gpu_spec) |gpu| gpu.deinit(alloc);

    const gpu_mesh_spec = try fields.parseGpuMeshSpec(table.getTable("gpu_mesh"));

    return .{
        .name = alloc.dupe(u8, name) catch return common.LoadError.OutOfMemory,
        .image = parsed_common.image,
        .command = parsed_common.command,
        .ports = ports,
        .env = parsed_common.env,
        .depends_on = depends_on,
        .working_dir = parsed_common.working_dir,
        .volumes = parsed_common.volumes,
        .health_check = health_check,
        .restart = restart,
        .tls = tls_config,
        .http_routes = http_routes,
        .gpu = gpu_spec,
        .gpu_mesh = gpu_mesh_spec,
    };
}

pub fn parseVolume(alloc: std.mem.Allocator, name: []const u8, table: *const toml.Table) common.LoadError!spec.Volume {
    const driver_str = table.getString("type") orelse table.getString("driver") orelse "local";

    const driver: spec.VolumeDriver = if (std.mem.eql(u8, driver_str, "host")) blk: {
        const path = table.getString("path") orelse {
            log.err("manifest: volume '{s}' with host driver requires 'path' field", .{name});
            return common.LoadError.InvalidVolumeConfig;
        };
        break :blk .{ .host = .{ .path = alloc.dupe(u8, path) catch return common.LoadError.OutOfMemory } };
    } else if (std.mem.eql(u8, driver_str, "nfs")) blk: {
        const server = table.getString("server") orelse {
            log.err("manifest: volume '{s}' with nfs driver requires 'server' field", .{name});
            return common.LoadError.InvalidVolumeConfig;
        };
        if (server.len == 0) {
            log.err("manifest: volume '{s}' nfs server must not be empty", .{name});
            return common.LoadError.InvalidVolumeConfig;
        }
        const path = table.getString("path") orelse {
            log.err("manifest: volume '{s}' with nfs driver requires 'path' field", .{name});
            return common.LoadError.InvalidVolumeConfig;
        };
        if (path.len == 0 or path[0] != '/') {
            log.err("manifest: volume '{s}' nfs path must be absolute (start with /)", .{name});
            return common.LoadError.InvalidVolumeConfig;
        }
        const options_str = table.getString("options");
        const server_dup = alloc.dupe(u8, server) catch return common.LoadError.OutOfMemory;
        errdefer alloc.free(server_dup);
        const path_dup = alloc.dupe(u8, path) catch return common.LoadError.OutOfMemory;
        errdefer alloc.free(path_dup);
        const options_dup = if (options_str) |options|
            (alloc.dupe(u8, options) catch return common.LoadError.OutOfMemory)
        else
            null;
        break :blk .{ .nfs = .{
            .server = server_dup,
            .path = path_dup,
            .options = options_dup,
        } };
    } else if (std.mem.eql(u8, driver_str, "parallel")) blk: {
        const path = table.getString("path") orelse {
            log.err("manifest: volume '{s}' with parallel driver requires 'path' field", .{name});
            return common.LoadError.InvalidVolumeConfig;
        };
        break :blk .{ .parallel = .{ .mount_path = alloc.dupe(u8, path) catch return common.LoadError.OutOfMemory } };
    } else .{ .local = .{} };

    return .{
        .name = alloc.dupe(u8, name) catch return common.LoadError.OutOfMemory,
        .driver = driver,
    };
}

pub fn parseWorker(alloc: std.mem.Allocator, name: []const u8, table: *const toml.Table) common.LoadError!spec.Worker {
    var parsed_common = try parseCommonFields(alloc, "worker", name, table);
    errdefer parsed_common.deinit(alloc);

    const depends_on = try fields.parseStringArray(alloc, table.getArray("depends_on"));
    errdefer {
        for (depends_on) |dep| alloc.free(dep);
        alloc.free(depends_on);
    }

    const gpu_spec = try fields.parseGpuSpec(alloc, table.getTable("gpu"));
    errdefer if (gpu_spec) |gpu| gpu.deinit(alloc);

    const gpu_mesh_spec = try fields.parseGpuMeshSpec(table.getTable("gpu_mesh"));

    return .{
        .name = alloc.dupe(u8, name) catch return common.LoadError.OutOfMemory,
        .image = parsed_common.image,
        .command = parsed_common.command,
        .env = parsed_common.env,
        .depends_on = depends_on,
        .working_dir = parsed_common.working_dir,
        .volumes = parsed_common.volumes,
        .gpu = gpu_spec,
        .gpu_mesh = gpu_mesh_spec,
    };
}

pub fn parseCron(alloc: std.mem.Allocator, name: []const u8, table: *const toml.Table) common.LoadError!spec.Cron {
    const every_str = table.getString("every") orelse {
        log.err("manifest: cron '{s}' is missing required field 'every'", .{name});
        return common.LoadError.InvalidSchedule;
    };

    const every = fields.parseDuration(every_str) orelse {
        log.err("manifest: cron '{s}' has invalid schedule '{s}' (expected e.g. '30s', '5m', '1h')", .{ name, every_str });
        return common.LoadError.InvalidSchedule;
    };

    var parsed_common = try parseCommonFields(alloc, "cron", name, table);
    errdefer parsed_common.deinit(alloc);

    return .{
        .name = alloc.dupe(u8, name) catch return common.LoadError.OutOfMemory,
        .image = parsed_common.image,
        .command = parsed_common.command,
        .env = parsed_common.env,
        .working_dir = parsed_common.working_dir,
        .volumes = parsed_common.volumes,
        .every = every,
    };
}

pub fn parseTrainingJob(alloc: std.mem.Allocator, name: []const u8, table: *const toml.Table) common.LoadError!spec.TrainingJob {
    var parsed_common = try parseCommonFields(alloc, "training", name, table);
    errdefer parsed_common.deinit(alloc);

    const gpus_raw = table.getInt("gpus") orelse {
        log.err("manifest: training '{s}' is missing required field 'gpus'", .{name});
        return common.LoadError.InvalidTrainingConfig;
    };
    if (gpus_raw < 1) {
        log.err("manifest: training '{s}' gpus must be >= 1", .{name});
        return common.LoadError.InvalidTrainingConfig;
    }

    const gpu_type_raw = table.getString("gpu_type");
    const gpu_type: ?[]const u8 = if (gpu_type_raw) |gpu_type_value|
        alloc.dupe(u8, gpu_type_value) catch return common.LoadError.OutOfMemory
    else
        null;
    errdefer if (gpu_type) |owned_gpu_type| alloc.free(owned_gpu_type);

    const data = try parseDataSpec(alloc, name, table.getTable("data"));
    errdefer if (data) |data_spec| data_spec.deinit(alloc);

    const checkpoint = try parseCheckpointSpec(alloc, name, table.getTable("checkpoint"));
    errdefer if (checkpoint) |checkpoint_spec| checkpoint_spec.deinit(alloc);

    const resources = parseTrainingResourceSpec(table.getTable("resources"));
    const fault_tolerance = parseFaultToleranceSpec(table.getTable("fault_tolerance"));

    return .{
        .name = alloc.dupe(u8, name) catch return common.LoadError.OutOfMemory,
        .image = parsed_common.image,
        .command = parsed_common.command,
        .env = parsed_common.env,
        .working_dir = parsed_common.working_dir,
        .volumes = parsed_common.volumes,
        .gpus = @intCast(gpus_raw),
        .gpu_type = gpu_type,
        .data = data,
        .checkpoint = checkpoint,
        .resources = resources,
        .fault_tolerance = fault_tolerance,
    };
}

fn parseDataSpec(alloc: std.mem.Allocator, name: []const u8, table: ?*const toml.Table) common.LoadError!?spec.DataSpec {
    const data_table = table orelse return null;

    const dataset_raw = data_table.getString("dataset") orelse {
        log.err("manifest: training '{s}' data section is missing required field 'dataset'", .{name});
        return common.LoadError.InvalidTrainingConfig;
    };

    const sharding_raw = data_table.getString("sharding") orelse "file";
    const preprocessing_raw = data_table.getString("preprocessing");
    const preprocessing: ?[]const u8 = if (preprocessing_raw) |value|
        alloc.dupe(u8, value) catch return common.LoadError.OutOfMemory
    else
        null;
    errdefer if (preprocessing) |owned| alloc.free(owned);

    const dataset = alloc.dupe(u8, dataset_raw) catch return common.LoadError.OutOfMemory;
    errdefer alloc.free(dataset);

    return .{
        .dataset = dataset,
        .sharding = alloc.dupe(u8, sharding_raw) catch return common.LoadError.OutOfMemory,
        .preprocessing = preprocessing,
    };
}

fn parseCheckpointSpec(alloc: std.mem.Allocator, name: []const u8, table: ?*const toml.Table) common.LoadError!?spec.CheckpointSpec {
    const ckpt_table = table orelse return null;

    const path_raw = ckpt_table.getString("path") orelse {
        log.err("manifest: training '{s}' checkpoint section is missing required field 'path'", .{name});
        return common.LoadError.InvalidTrainingConfig;
    };

    var interval_secs: u64 = 1800;
    if (ckpt_table.getString("interval")) |interval_str| {
        interval_secs = fields.parseDuration(interval_str) orelse {
            log.err("manifest: training '{s}' has invalid checkpoint interval '{s}' (expected e.g. '30m', '1h')", .{ name, interval_str });
            return common.LoadError.InvalidSchedule;
        };
    }

    const keep_raw = ckpt_table.getInt("keep");
    const keep: u32 = if (keep_raw) |k| @intCast(@max(1, k)) else 5;

    return .{
        .path = alloc.dupe(u8, path_raw) catch return common.LoadError.OutOfMemory,
        .interval_secs = interval_secs,
        .keep = keep,
    };
}

fn parseTrainingResourceSpec(table: ?*const toml.Table) spec.TrainingResourceSpec {
    const res_table = table orelse return .{};

    const cpu_raw = res_table.getInt("cpu");
    const cpu: u32 = if (cpu_raw) |cpu_value| @intCast(@max(100, cpu_value)) else 1000;

    const memory_mb_raw = res_table.getInt("memory_mb");
    const memory_mb: u64 = if (memory_mb_raw) |memory_value| @intCast(@max(256, memory_value)) else 65536;

    const ib_required = res_table.getBool("ib_required") orelse false;
    return .{
        .cpu = cpu,
        .memory_mb = memory_mb,
        .ib_required = ib_required,
    };
}

fn parseFaultToleranceSpec(table: ?*const toml.Table) spec.FaultToleranceSpec {
    const ft_table = table orelse return .{};

    const spare_ranks_raw = ft_table.getInt("spare_ranks");
    const spare_ranks: u32 = if (spare_ranks_raw) |spares| @intCast(@max(0, spares)) else 0;

    const auto_restart = ft_table.getBool("auto_restart") orelse true;

    const max_restarts_raw = ft_table.getInt("max_restarts");
    const max_restarts: u32 = if (max_restarts_raw) |restarts| @intCast(@max(0, restarts)) else 10;

    return .{
        .spare_ranks = spare_ranks,
        .auto_restart = auto_restart,
        .max_restarts = max_restarts,
    };
}
