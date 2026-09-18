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
    errdefer if (working_dir) |value| alloc.free(value);

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
    const rollout = try fields.parseRolloutPolicy(name, table.getTable("rollout"));

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

    const replicas_raw = table.getInt("replicas") orelse 1;
    if (replicas_raw < 1 or replicas_raw > spec.max_service_replicas) {
        log.err("manifest: service.{s}.replicas must be between 1 and {d}", .{ name, spec.max_service_replicas });
        return error.InvalidServiceConfig;
    }
    if (gpu_mesh_spec) |mesh| {
        if (@as(u64, @intCast(replicas_raw)) * mesh.world_size > spec.max_service_replicas) {
            log.err("manifest: service.{s} exceeds {d} service endpoints", .{ name, spec.max_service_replicas });
            return error.InvalidServiceConfig;
        }
    }
    const required_labels = try parseRequiredLabels(alloc, "service", name, table);
    errdefer alloc.free(required_labels);
    const alerts = try parseAlerts(alloc, name, table.getTable("alerts"));
    errdefer if (alerts) |config| config.deinit(alloc);

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
        .rollout = rollout,
        .tls = tls_config,
        .http_routes = http_routes,
        .gpu = gpu_spec,
        .gpu_mesh = gpu_mesh_spec,
        .replicas = @intCast(replicas_raw),
        .required_labels = required_labels,
        .alerts = alerts,
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
        const path = table.getString("mount_path") orelse table.getString("path") orelse {
            log.err("manifest: volume '{s}' with parallel driver requires 'path' field", .{name});
            return common.LoadError.InvalidVolumeConfig;
        };
        break :blk .{ .parallel = .{ .mount_path = alloc.dupe(u8, path) catch return common.LoadError.OutOfMemory } };
    } else if (std.mem.eql(u8, driver_str, "local")) .{ .local = .{} } else {
        log.err("manifest: volume.{s} has unknown driver '{s}'", .{ name, driver_str });
        return error.InvalidVolumeConfig;
    };
    errdefer driver.deinit(alloc);

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

    const required_labels = try parseRequiredLabels(alloc, "worker", name, table);
    errdefer alloc.free(required_labels);

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
        .required_labels = required_labels,
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

/// parse the optional top-level `[backup]` block. returns null when absent.
pub fn parseBackup(alloc: std.mem.Allocator, table: ?*const toml.Table) common.LoadError!?spec.BackupSpec {
    const backup_table = table orelse return null;

    const every_str = backup_table.getString("every") orelse {
        log.err("manifest: [backup] is missing required field 'every'", .{});
        return common.LoadError.InvalidSchedule;
    };
    const every = fields.parseDuration(every_str) orelse {
        log.err("manifest: [backup] has invalid schedule '{s}' (expected e.g. '30m', '24h')", .{every_str});
        return common.LoadError.InvalidSchedule;
    };

    const output_dir_raw = backup_table.getString("output_dir") orelse {
        log.err("manifest: [backup] is missing required field 'output_dir'", .{});
        return common.LoadError.InvalidVolumeConfig;
    };
    const output_dir = alloc.dupe(u8, output_dir_raw) catch return common.LoadError.OutOfMemory;
    errdefer alloc.free(output_dir);

    const keep_count = backup_table.getInt("keep_count") orelse 7;
    const max_bytes = backup_table.getInt("max_bytes") orelse 0;
    const max_age = if (backup_table.getString("max_age")) |value| @import("../backup_retention.zig").parseAge(value) orelse return error.InvalidSchedule else 0;
    if (keep_count < 1 or max_bytes < 0) return error.InvalidSchedule;

    return .{
        .every = every,
        .output_dir = output_dir,
        .encrypt = backup_table.getBool("encrypt") orelse true,
        .retention = .{ .keep_count = @intCast(keep_count), .max_age = max_age, .max_bytes = @intCast(max_bytes) },
    };
}

pub fn parseTrainingJob(alloc: std.mem.Allocator, name: []const u8, table: *const toml.Table) common.LoadError!spec.TrainingJob {
    if (table.getTable("data") != null) {
        log.err("manifest: training.{s}.data is unsupported; prepare datasets in the job command and mount them as volumes", .{name});
        return common.LoadError.InvalidTrainingConfig;
    }
    if (table.getTable("fault_tolerance")) |settings| {
        if ((settings.getInt("spare_ranks") orelse 0) != 0) {
            log.err("manifest: training.{s}.fault_tolerance.spare_ranks is unsupported; use zero", .{name});
            return common.LoadError.InvalidTrainingConfig;
        }
    }
    var parsed_common = try parseCommonFields(alloc, "training", name, table);
    errdefer parsed_common.deinit(alloc);

    const gpus_raw = table.getInt("gpus") orelse {
        log.err("manifest: training '{s}' is missing required field 'gpus'", .{name});
        return common.LoadError.InvalidTrainingConfig;
    };
    if (gpus_raw < 1 or gpus_raw > spec.max_training_ranks) {
        log.err("manifest: training.{s}.gpus must be between 1 and {d}", .{ name, spec.max_training_ranks });
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

    const interval_raw = ckpt_table.getInt("interval_secs") orelse 1800;
    if (interval_raw <= 0 or (ckpt_table.getInt("interval_secs") != null and ckpt_table.getString("interval") != null)) {
        log.err("manifest: training.{s}.checkpoint requires one positive interval", .{name});
        return error.InvalidTrainingConfig;
    }
    var interval_secs: u64 = @intCast(interval_raw);
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

fn parseRequiredLabels(alloc: std.mem.Allocator, kind: []const u8, name: []const u8, table: *const toml.Table) common.LoadError![]const u8 {
    const labels = table.getString("required_labels") orelse "";
    if (labels.len > 4096) return error.InvalidServiceConfig;
    if (labels.len > 0) {
        var parts = std.mem.splitScalar(u8, labels, ',');
        while (parts.next()) |part| {
            const pair = std.mem.trim(u8, part, " \t");
            const equals = std.mem.indexOfScalar(u8, pair, '=') orelse {
                log.err("manifest: {s}.{s}.required_labels requires comma-separated key=value pairs", .{ kind, name });
                return error.InvalidServiceConfig;
            };
            if (equals == 0 or equals == pair.len - 1) return error.InvalidServiceConfig;
        }
    }
    return alloc.dupe(u8, labels) catch return error.OutOfMemory;
}

fn parseAlerts(alloc: std.mem.Allocator, name: []const u8, table: ?*const toml.Table) common.LoadError!?spec.AlertSpec {
    const alerts = table orelse return null;
    var result: spec.AlertSpec = .{};
    inline for (.{ "cpu_percent", "memory_percent", "latency_p99_ms", "error_rate_percent" }) |field| {
        if (alerts.getFloat(field)) |value| {
            const maximum: f64 = if (std.mem.eql(u8, field, "latency_p99_ms")) 1e12 else 100;
            if (!std.math.isFinite(value) or value < 0 or value > maximum) {
                log.err("manifest: service.{s}.alerts.{s} must be between 0 and {d}", .{ name, field, maximum });
                return error.InvalidAlertConfig;
            }
            @field(result, field) = value;
        }
    }
    if (alerts.getInt("restart_count")) |count| {
        if (count < 0 or count > std.math.maxInt(u32)) return error.InvalidAlertConfig;
        result.restart_count = @intCast(count);
    }
    if (alerts.getString("webhook")) |url| {
        const uri = std.Uri.parse(url) catch return error.InvalidAlertConfig;
        if ((!std.mem.eql(u8, uri.scheme, "http") and !std.mem.eql(u8, uri.scheme, "https")) or uri.host == null) {
            log.err("manifest: service.{s}.alerts.webhook must be an absolute http or https url", .{name});
            return error.InvalidAlertConfig;
        }
        result.webhook = alloc.dupe(u8, url) catch return error.OutOfMemory;
    }
    return result;
}
