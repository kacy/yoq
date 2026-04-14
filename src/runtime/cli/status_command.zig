const std = @import("std");
const cli = @import("../../lib/cli.zig");
const json_out = @import("../../lib/json_output.zig");
const apply_release = @import("../../manifest/apply_release.zig");
const app_snapshot = @import("../../manifest/app_snapshot.zig");
const store = @import("../../state/store.zig");
const monitor = @import("../monitor.zig");
const cgroups = @import("../cgroups.zig");
const http_client = @import("../../cluster/http_client.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const health = @import("../../manifest/health.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;
const extractJsonFloat = json_helpers.extractJsonFloat;
const extractJsonArray = json_helpers.extractJsonArray;

const StatusError = error{
    InvalidArgument,
    ConnectionFailed,
    ServerError,
    StoreError,
    OutOfMemory,
};

pub fn status(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var verbose = false;
    var server: ?cli.ServerAddr = null;
    var app_mode = false;
    var target_name: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "--app")) {
            app_mode = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return StatusError.InvalidArgument;
            };
            server = cli.parseServerAddr(addr_str);
        } else {
            target_name = arg;
        }
    }

    if (!app_mode and target_name != null) {
        writeErr("usage: yoq status [--app [name]] [--verbose] [--server host:port]\n", .{});
        return StatusError.InvalidArgument;
    }

    if (app_mode) {
        const owned_app_name = if (target_name == null) try currentAppNameAlloc(alloc) else null;
        defer if (owned_app_name) |name| alloc.free(name);
        const app_name = target_name orelse owned_app_name.?;

        if (server) |s| {
            try statusRemoteApp(alloc, s.ip, s.port, app_name);
        } else {
            try statusLocalApp(alloc, app_name);
        }
        return;
    }

    if (server) |s| {
        try statusRemote(alloc, s.ip, s.port, verbose);
        return;
    }

    try statusLocal(alloc, verbose);
}

pub fn apps(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var server: ?cli.ServerAddr = null;
    var filters = AppListFilters{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return StatusError.InvalidArgument;
            };
            server = cli.parseServerAddr(addr_str);
        } else if (std.mem.eql(u8, arg, "--status")) {
            filters.status = args.next() orelse {
                writeErr("--status requires a rollout status\n", .{});
                return StatusError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--failed")) {
            filters.failed_only = true;
        } else if (std.mem.eql(u8, arg, "--in-progress")) {
            filters.in_progress_only = true;
        } else {
            writeErr("usage: yoq apps [--server host:port] [--json] [--status <status>] [--failed] [--in-progress]\n", .{});
            return StatusError.InvalidArgument;
        }
    }

    if (server) |s| {
        try appsRemote(alloc, s.ip, s.port, filters);
    } else {
        try appsLocal(alloc, filters);
    }
}

const AppListFilters = struct {
    status: ?[]const u8 = null,
    failed_only: bool = false,
    in_progress_only: bool = false,
};

fn statusLocal(alloc: std.mem.Allocator, verbose: bool) StatusError!void {
    var records = store.listAll(alloc) catch {
        writeErr("failed to list containers\n", .{});
        return StatusError.StoreError;
    };
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
    }

    if (records.items.len == 0) {
        write("no services running\n", .{});
        return;
    }

    var snapshots = monitor.collectSnapshots(alloc, &records) catch {
        writeErr("failed to collect service snapshots\n", .{});
        return StatusError.StoreError;
    };
    defer snapshots.deinit(alloc);

    printStatusTable(snapshots.items, verbose);
}

const AppStatusSnapshot = struct {
    app_name: []const u8,
    trigger: []const u8,
    release_id: []const u8,
    status: []const u8,
    rollout_state: []const u8 = "unknown",
    rollout_control_state: []const u8 = "active",
    manifest_hash: []const u8,
    created_at: i64,
    service_count: usize = 0,
    worker_count: usize = 0,
    cron_count: usize = 0,
    training_job_count: usize = 0,
    active_training_jobs: usize = 0,
    paused_training_jobs: usize = 0,
    failed_training_jobs: usize = 0,
    completed_targets: usize,
    failed_targets: usize,
    remaining_targets: usize,
    source_release_id: ?[]const u8 = null,
    previous_successful_release_id: ?[]const u8 = null,
    previous_successful_trigger: ?[]const u8 = null,
    previous_successful_status: ?[]const u8 = null,
    previous_successful_rollout_state: ?[]const u8 = null,
    previous_successful_rollout_control_state: ?[]const u8 = null,
    previous_successful_manifest_hash: ?[]const u8 = null,
    previous_successful_created_at: ?i64 = null,
    previous_successful_completed_targets: usize = 0,
    previous_successful_failed_targets: usize = 0,
    previous_successful_remaining_targets: usize = 0,
    previous_successful_source_release_id: ?[]const u8 = null,
    previous_successful_message: ?[]const u8 = null,
    previous_successful_failure_details_json: ?[]const u8 = null,
    previous_successful_rollout_targets_json: ?[]const u8 = null,
    message: ?[]const u8 = null,
    failure_details_json: ?[]const u8 = null,
    rollout_targets_json: ?[]const u8 = null,
};

fn statusLocalApp(alloc: std.mem.Allocator, app_name: []const u8) StatusError!void {
    const latest = store.getLatestDeploymentByApp(alloc, app_name) catch |err| switch (err) {
        error.NotFound => {
            write("no releases found for app {s}\n", .{app_name});
            return;
        },
        else => {
            writeErr("failed to read app status\n", .{});
            return StatusError.StoreError;
        },
    };
    defer latest.deinit(alloc);

    const previous_successful = loadPreviousSuccessfulDeployment(alloc, app_name, latest.id) catch {
        writeErr("failed to read app status\n", .{});
        return StatusError.StoreError;
    };
    defer if (previous_successful) |dep| dep.deinit(alloc);

    const snapshot = snapshotFromDeployments(latest, previous_successful);
    printAppStatus(snapshot);
}

fn statusRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16, verbose: bool) StatusError!void {
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, "/v1/status", token) catch {
        writeErr("failed to connect to server\n", .{});
        return StatusError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        return StatusError.ServerError;
    }

    var snapshots: std.ArrayList(monitor.ServiceSnapshot) = .empty;
    defer snapshots.deinit(alloc);

    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        const name = extractJsonString(obj, "name") orelse "?";
        const status_str = extractJsonString(obj, "status") orelse "unknown";
        const health_str = extractJsonString(obj, "health");

        const status_val: monitor.ServiceStatus = if (std.mem.eql(u8, status_str, "running"))
            .running
        else if (std.mem.eql(u8, status_str, "stopped"))
            .stopped
        else
            .mixed;

        const health_status: ?health.HealthStatus = if (health_str) |h| blk: {
            if (std.mem.eql(u8, h, "healthy")) break :blk .healthy;
            if (std.mem.eql(u8, h, "unhealthy")) break :blk .unhealthy;
            if (std.mem.eql(u8, h, "starting")) break :blk .starting;
            break :blk null;
        } else null;

        const psi_cpu = parsePsiFromJson(obj, "psi_cpu_some", "psi_cpu_full");
        const psi_mem = parsePsiFromJson(obj, "psi_mem_some", "psi_mem_full");

        const cpu_quota_pct: ?f64 = if (extractJsonFloat(obj, "cpu_quota_pct")) |v|
            (if (v > 0.0) v else null)
        else
            null;

        const mem_limit_raw = extractJsonInt(obj, "memory_limit");
        const memory_limit: ?u64 = if (mem_limit_raw) |v|
            (if (v > 0) @as(u64, @intCast(v)) else null)
        else
            null;

        snapshots.append(alloc, .{
            .name = name,
            .status = status_val,
            .health_status = health_status,
            .cpu_pct = extractJsonFloat(obj, "cpu_pct") orelse 0.0,
            .memory_bytes = @intCast(@max(0, extractJsonInt(obj, "memory_bytes") orelse 0)),
            .psi_cpu = psi_cpu,
            .psi_memory = psi_mem,
            .running_count = @intCast(@max(0, extractJsonInt(obj, "running") orelse 0)),
            .desired_count = @intCast(@max(0, extractJsonInt(obj, "desired") orelse 0)),
            .uptime_secs = extractJsonInt(obj, "uptime_secs") orelse 0,
            .memory_limit = memory_limit,
            .cpu_quota_pct = cpu_quota_pct,
        }) catch return StatusError.OutOfMemory;
    }

    if (snapshots.items.len == 0) {
        write("no services running\n", .{});
        return;
    }

    printStatusTable(snapshots.items, verbose);
}

fn statusRemoteApp(alloc: std.mem.Allocator, addr: [4]u8, port: u16, app_name: []const u8) StatusError!void {
    const path = std.fmt.allocPrint(alloc, "/apps/{s}/status", .{app_name}) catch return StatusError.OutOfMemory;
    defer alloc.free(path);

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, path, token) catch {
        writeErr("failed to connect to server\n", .{});
        return StatusError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code == 404) {
        write("no releases found for app {s}\n", .{app_name});
        return;
    }
    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        return StatusError.ServerError;
    }

    const snapshot = parseAppStatusResponse(resp.body);
    printAppStatus(snapshot);
}

fn appsLocal(alloc: std.mem.Allocator, filters: AppListFilters) StatusError!void {
    var latest = store.listLatestDeploymentsByApp(alloc) catch {
        writeErr("failed to read app list\n", .{});
        return StatusError.StoreError;
    };
    defer {
        for (latest.items) |dep| dep.deinit(alloc);
        latest.deinit(alloc);
    }

    var snapshots: std.ArrayList(AppStatusSnapshot) = .empty;
    defer snapshots.deinit(alloc);

    for (latest.items) |dep| {
        const previous_successful = loadPreviousSuccessfulDeployment(alloc, dep.app_name.?, dep.id) catch {
            writeErr("failed to read app list\n", .{});
            return StatusError.StoreError;
        };
        defer if (previous_successful) |prev| prev.deinit(alloc);

        const snapshot = snapshotFromDeployments(dep, previous_successful);
        if (appMatchesFilters(snapshot, filters)) {
            snapshots.append(alloc, snapshot) catch return StatusError.OutOfMemory;
        }
    }

    printAppStatuses(snapshots.items);
}

fn loadPreviousSuccessfulDeployment(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    exclude_release_id: []const u8,
) !?store.DeploymentRecord {
    return store.getPreviousSuccessfulDeploymentByApp(alloc, app_name, exclude_release_id) catch |err| switch (err) {
        error.NotFound => null,
        else => return err,
    };
}

fn appsRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16, filters: AppListFilters) StatusError!void {
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, "/apps", token) catch {
        writeErr("failed to connect to server\n", .{});
        return StatusError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        return StatusError.ServerError;
    }

    var snapshots: std.ArrayList(AppStatusSnapshot) = .empty;
    defer snapshots.deinit(alloc);

    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        const snapshot = parseAppStatusResponse(obj);
        if (appMatchesFilters(snapshot, filters)) {
            snapshots.append(alloc, snapshot) catch return StatusError.OutOfMemory;
        }
    }

    printAppStatuses(snapshots.items);
}

fn printAppStatus(snapshot: AppStatusSnapshot) void {
    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        writeAppStatusJsonObject(&w, snapshot);
        w.endObject();
        w.flush();
        return;
    }

    printAppStatusHeader();
    printAppStatusRow(snapshot);
}

fn printAppStatuses(snapshots: []const AppStatusSnapshot) void {
    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginArray();
        for (snapshots) |snapshot| {
            writeAppStatusJsonObject(&w, snapshot);
            w.endObject();
        }
        w.endArray();
        w.flush();
        return;
    }

    if (snapshots.len == 0) {
        write("no app releases found\n", .{});
        return;
    }

    printAppStatusHeader();
    for (snapshots) |snapshot| {
        printAppStatusRow(snapshot);
    }
}

fn printAppStatusHeader() void {
    write("{s:<14} {s:<14} {s:<14} {s:<11} {s:<10} {s:<11} {s:<22} {s:<18} {s:<14} {s}\n", .{
        "APP", "RELEASE", "STATUS", "ROLLOUT", "TRIGGER", "WORKLOADS", "TARGETS", "TRAINING", "PREV OK", "MESSAGE",
    });
}

fn printAppStatusRow(snapshot: AppStatusSnapshot) void {
    var message_buf: [160]u8 = undefined;
    const msg = formatStatusMessage(&message_buf, snapshot.message, snapshot.failure_details_json);

    var progress_buf: [64]u8 = undefined;
    const progress_str = formatAppProgress(&progress_buf, snapshot);
    var kinds_buf: [32]u8 = undefined;
    const kinds_str = std.fmt.bufPrint(&kinds_buf, "{d}/{d}/{d}/{d}", .{
        snapshot.service_count,
        snapshot.worker_count,
        snapshot.cron_count,
        snapshot.training_job_count,
    }) catch "?";
    var training_buf: [48]u8 = undefined;
    const training_str = formatTrainingRuntime(&training_buf, snapshot);

    const previous_successful = if (snapshot.previous_successful_release_id) |release_id|
        cli.truncate(release_id, 12)
    else
        "-";

    write("{s:<14} {s:<14} {s:<14} {s:<11} {s:<10} {s:<11} {s:<22} {s:<18} {s:<14} {s}\n", .{
        snapshot.app_name,
        cli.truncate(snapshot.release_id, 12),
        snapshot.status,
        snapshot.rollout_state,
        snapshot.trigger,
        kinds_str,
        progress_str,
        training_str,
        previous_successful,
        cli.truncate(msg, 48),
    });
}

fn formatStatusMessage(buf: []u8, message: ?[]const u8, failure_details_json: ?[]const u8) []const u8 {
    if (message == null or message.?.len == 0) {
        return json_helpers.summarizeFailureDetails(buf, failure_details_json) orelse "";
    }

    const prefix = std.fmt.bufPrint(buf, "{s}", .{message.?}) catch return message.?;
    if (failure_details_json == null) return prefix;

    const sep = std.fmt.bufPrint(buf[prefix.len..], " | ", .{}) catch return prefix;
    const summary = json_helpers.summarizeFailureDetails(buf[prefix.len + sep.len ..], failure_details_json) orelse return prefix;
    return buf[0 .. prefix.len + sep.len + summary.len];
}

fn formatAppProgress(buf: []u8, snapshot: AppStatusSnapshot) []const u8 {
    if (snapshot.failed_targets == 0 and snapshot.remaining_targets == 0) {
        return std.fmt.bufPrint(buf, "{d} ok", .{snapshot.completed_targets}) catch "?";
    }
    if (snapshot.remaining_targets == 0) {
        return std.fmt.bufPrint(buf, "{d} ok, {d} fail", .{
            snapshot.completed_targets,
            snapshot.failed_targets,
        }) catch "?";
    }
    return std.fmt.bufPrint(buf, "{d} ok, {d} fail, {d} left", .{
        snapshot.completed_targets,
        snapshot.failed_targets,
        snapshot.remaining_targets,
    }) catch "?";
}

fn formatTrainingRuntime(buf: []u8, snapshot: AppStatusSnapshot) []const u8 {
    if (snapshot.active_training_jobs == 0 and snapshot.paused_training_jobs == 0 and snapshot.failed_training_jobs == 0) {
        return "-";
    }
    return std.fmt.bufPrint(buf, "{d} act, {d} pause, {d} fail", .{
        snapshot.active_training_jobs,
        snapshot.paused_training_jobs,
        snapshot.failed_training_jobs,
    }) catch "?";
}

fn parseAppStatusResponse(json: []const u8) AppStatusSnapshot {
    return .{
        .app_name = extractJsonString(json, "app_name") orelse "?",
        .trigger = extractJsonString(json, "trigger") orelse "apply",
        .release_id = extractJsonString(json, "release_id") orelse "?",
        .status = extractJsonString(json, "status") orelse "unknown",
        .rollout_state = extractJsonString(json, "rollout_state") orelse "unknown",
        .rollout_control_state = extractJsonString(json, "rollout_control_state") orelse "active",
        .manifest_hash = extractJsonString(json, "manifest_hash") orelse "?",
        .created_at = extractJsonInt(json, "created_at") orelse 0,
        .service_count = @intCast(@max(0, extractJsonInt(json, "service_count") orelse 0)),
        .worker_count = @intCast(@max(0, extractJsonInt(json, "worker_count") orelse 0)),
        .cron_count = @intCast(@max(0, extractJsonInt(json, "cron_count") orelse 0)),
        .training_job_count = @intCast(@max(0, extractJsonInt(json, "training_job_count") orelse 0)),
        .active_training_jobs = @intCast(@max(0, extractJsonInt(json, "active_training_jobs") orelse 0)),
        .paused_training_jobs = @intCast(@max(0, extractJsonInt(json, "paused_training_jobs") orelse 0)),
        .failed_training_jobs = @intCast(@max(0, extractJsonInt(json, "failed_training_jobs") orelse 0)),
        .completed_targets = @intCast(@max(0, extractJsonInt(json, "completed_targets") orelse 0)),
        .failed_targets = @intCast(@max(0, extractJsonInt(json, "failed_targets") orelse 0)),
        .remaining_targets = @intCast(@max(0, extractJsonInt(json, "remaining_targets") orelse 0)),
        .source_release_id = extractJsonString(json, "source_release_id"),
        .previous_successful_release_id = extractJsonString(json, "previous_successful_release_id"),
        .previous_successful_trigger = extractJsonString(json, "previous_successful_trigger"),
        .previous_successful_status = extractJsonString(json, "previous_successful_status"),
        .previous_successful_rollout_state = extractJsonString(json, "previous_successful_rollout_state"),
        .previous_successful_rollout_control_state = extractJsonString(json, "previous_successful_rollout_control_state"),
        .previous_successful_manifest_hash = extractJsonString(json, "previous_successful_manifest_hash"),
        .previous_successful_created_at = extractJsonInt(json, "previous_successful_created_at"),
        .previous_successful_completed_targets = @intCast(@max(0, extractJsonInt(json, "previous_successful_completed_targets") orelse 0)),
        .previous_successful_failed_targets = @intCast(@max(0, extractJsonInt(json, "previous_successful_failed_targets") orelse 0)),
        .previous_successful_remaining_targets = @intCast(@max(0, extractJsonInt(json, "previous_successful_remaining_targets") orelse 0)),
        .previous_successful_source_release_id = extractJsonString(json, "previous_successful_source_release_id"),
        .previous_successful_message = extractJsonString(json, "previous_successful_message"),
        .previous_successful_failure_details_json = extractJsonArray(json, "previous_successful_failure_details"),
        .previous_successful_rollout_targets_json = extractJsonArray(json, "previous_successful_rollout_targets"),
        .message = extractJsonString(json, "message"),
        .failure_details_json = extractJsonArray(json, "failure_details"),
        .rollout_targets_json = extractJsonArray(json, "rollout_targets"),
    };
}

fn writeAppStatusJsonObject(w: *json_out.JsonWriter, snapshot: AppStatusSnapshot) void {
    w.beginObject();
    w.stringField("app_name", snapshot.app_name);
    w.stringField("trigger", snapshot.trigger);
    w.stringField("release_id", snapshot.release_id);
    w.stringField("status", snapshot.status);
    w.stringField("rollout_state", snapshot.rollout_state);
    w.stringField("rollout_control_state", snapshot.rollout_control_state);
    w.stringField("manifest_hash", snapshot.manifest_hash);
    w.intField("created_at", snapshot.created_at);
    w.uintField("service_count", snapshot.service_count);
    w.uintField("worker_count", snapshot.worker_count);
    w.uintField("cron_count", snapshot.cron_count);
    w.uintField("training_job_count", snapshot.training_job_count);
    w.uintField("active_training_jobs", snapshot.active_training_jobs);
    w.uintField("paused_training_jobs", snapshot.paused_training_jobs);
    w.uintField("failed_training_jobs", snapshot.failed_training_jobs);
    w.uintField("completed_targets", snapshot.completed_targets);
    w.uintField("failed_targets", snapshot.failed_targets);
    w.uintField("remaining_targets", snapshot.remaining_targets);
    if (snapshot.source_release_id) |source_release_id| w.stringField("source_release_id", source_release_id) else w.nullField("source_release_id");
    if (snapshot.previous_successful_release_id) |release_id| w.stringField("previous_successful_release_id", release_id) else w.nullField("previous_successful_release_id");
    if (snapshot.previous_successful_trigger) |trigger| w.stringField("previous_successful_trigger", trigger) else w.nullField("previous_successful_trigger");
    if (snapshot.previous_successful_status) |status_text| w.stringField("previous_successful_status", status_text) else w.nullField("previous_successful_status");
    if (snapshot.previous_successful_rollout_state) |state| w.stringField("previous_successful_rollout_state", state) else w.nullField("previous_successful_rollout_state");
    if (snapshot.previous_successful_rollout_control_state) |state| w.stringField("previous_successful_rollout_control_state", state) else w.nullField("previous_successful_rollout_control_state");
    if (snapshot.previous_successful_manifest_hash) |manifest_hash| w.stringField("previous_successful_manifest_hash", manifest_hash) else w.nullField("previous_successful_manifest_hash");
    if (snapshot.previous_successful_created_at) |created_at| w.intField("previous_successful_created_at", created_at) else w.nullField("previous_successful_created_at");
    w.uintField("previous_successful_completed_targets", snapshot.previous_successful_completed_targets);
    w.uintField("previous_successful_failed_targets", snapshot.previous_successful_failed_targets);
    w.uintField("previous_successful_remaining_targets", snapshot.previous_successful_remaining_targets);
    if (snapshot.previous_successful_source_release_id) |source_release_id| w.stringField("previous_successful_source_release_id", source_release_id) else w.nullField("previous_successful_source_release_id");
    if (snapshot.previous_successful_message) |message| w.stringField("previous_successful_message", message) else w.nullField("previous_successful_message");
    if (snapshot.previous_successful_failure_details_json) |failure_details| w.rawField("previous_successful_failure_details", failure_details) else w.nullField("previous_successful_failure_details");
    if (snapshot.previous_successful_rollout_targets_json) |targets| w.rawField("previous_successful_rollout_targets", targets) else w.nullField("previous_successful_rollout_targets");
    if (snapshot.message) |message| w.stringField("message", message) else w.nullField("message");
    if (snapshot.failure_details_json) |failure_details| w.rawField("failure_details", failure_details) else w.nullField("failure_details");
    if (snapshot.rollout_targets_json) |targets| w.rawField("rollout_targets", targets) else w.nullField("rollout_targets");
    w.beginObjectField("rollout");
    w.stringField("state", snapshot.rollout_state);
    w.stringField("control_state", snapshot.rollout_control_state);
    w.uintField("completed_targets", snapshot.completed_targets);
    w.uintField("failed_targets", snapshot.failed_targets);
    w.uintField("remaining_targets", snapshot.remaining_targets);
    if (snapshot.failure_details_json) |failure_details| w.rawField("failure_details", failure_details) else w.nullField("failure_details");
    if (snapshot.rollout_targets_json) |targets| w.rawField("targets", targets) else w.nullField("targets");
    w.endObject();
    w.beginObjectField("current_release");
    w.stringField("id", snapshot.release_id);
    w.stringField("trigger", snapshot.trigger);
    w.stringField("status", snapshot.status);
    w.stringField("rollout_state", snapshot.rollout_state);
    w.stringField("rollout_control_state", snapshot.rollout_control_state);
    w.stringField("manifest_hash", snapshot.manifest_hash);
    w.intField("created_at", snapshot.created_at);
    w.uintField("completed_targets", snapshot.completed_targets);
    w.uintField("failed_targets", snapshot.failed_targets);
    w.uintField("remaining_targets", snapshot.remaining_targets);
    if (snapshot.source_release_id) |source_release_id| w.stringField("source_release_id", source_release_id) else w.nullField("source_release_id");
    if (snapshot.message) |message| w.stringField("message", message) else w.nullField("message");
    if (snapshot.failure_details_json) |failure_details| w.rawField("failure_details", failure_details) else w.nullField("failure_details");
    if (snapshot.rollout_targets_json) |targets| w.rawField("rollout_targets", targets) else w.nullField("rollout_targets");
    w.beginObjectField("rollout");
    w.stringField("state", snapshot.rollout_state);
    w.stringField("control_state", snapshot.rollout_control_state);
    w.uintField("completed_targets", snapshot.completed_targets);
    w.uintField("failed_targets", snapshot.failed_targets);
    w.uintField("remaining_targets", snapshot.remaining_targets);
    if (snapshot.failure_details_json) |failure_details| w.rawField("failure_details", failure_details) else w.nullField("failure_details");
    if (snapshot.rollout_targets_json) |targets| w.rawField("targets", targets) else w.nullField("targets");
    w.endObject();
    w.endObject();
    if (snapshot.previous_successful_release_id) |release_id| {
        w.beginObjectField("previous_successful_release");
        w.stringField("id", release_id);
        w.stringField("trigger", snapshot.previous_successful_trigger orelse "apply");
        w.stringField("status", snapshot.previous_successful_status orelse "completed");
        w.stringField("rollout_state", snapshot.previous_successful_rollout_state orelse "unknown");
        w.stringField("rollout_control_state", snapshot.previous_successful_rollout_control_state orelse "active");
        if (snapshot.previous_successful_manifest_hash) |manifest_hash| w.stringField("manifest_hash", manifest_hash) else w.nullField("manifest_hash");
        if (snapshot.previous_successful_created_at) |created_at| w.intField("created_at", created_at) else w.nullField("created_at");
        w.uintField("completed_targets", snapshot.previous_successful_completed_targets);
        w.uintField("failed_targets", snapshot.previous_successful_failed_targets);
        w.uintField("remaining_targets", snapshot.previous_successful_remaining_targets);
        if (snapshot.previous_successful_source_release_id) |source_release_id| w.stringField("source_release_id", source_release_id) else w.nullField("source_release_id");
        if (snapshot.previous_successful_message) |message| w.stringField("message", message) else w.nullField("message");
        if (snapshot.previous_successful_failure_details_json) |failure_details| w.rawField("failure_details", failure_details) else w.nullField("failure_details");
        if (snapshot.previous_successful_rollout_targets_json) |targets| w.rawField("rollout_targets", targets) else w.nullField("rollout_targets");
        w.beginObjectField("rollout");
        w.stringField("state", snapshot.previous_successful_rollout_state orelse "unknown");
        w.stringField("control_state", snapshot.previous_successful_rollout_control_state orelse "active");
        w.uintField("completed_targets", snapshot.previous_successful_completed_targets);
        w.uintField("failed_targets", snapshot.previous_successful_failed_targets);
        w.uintField("remaining_targets", snapshot.previous_successful_remaining_targets);
        if (snapshot.previous_successful_failure_details_json) |failure_details| w.rawField("failure_details", failure_details) else w.nullField("failure_details");
        if (snapshot.previous_successful_rollout_targets_json) |targets| w.rawField("targets", targets) else w.nullField("targets");
        w.endObject();
        w.endObject();
    } else {
        w.nullField("previous_successful_release");
    }
    w.beginObjectField("workloads");
    w.uintField("services", snapshot.service_count);
    w.uintField("workers", snapshot.worker_count);
    w.uintField("crons", snapshot.cron_count);
    w.uintField("training_jobs", snapshot.training_job_count);
    w.endObject();
    w.beginObjectField("training_runtime");
    w.uintField("active", snapshot.active_training_jobs);
    w.uintField("paused", snapshot.paused_training_jobs);
    w.uintField("failed", snapshot.failed_training_jobs);
    w.endObject();
}

fn appStatusFromReports(
    report: apply_release.ApplyReport,
    previous_successful: ?apply_release.ApplyReport,
    summary: app_snapshot.Summary,
    training_summary: store.TrainingJobSummary,
) AppStatusSnapshot {
    return .{
        .app_name = report.app_name,
        .trigger = report.trigger.toString(),
        .release_id = report.release_id orelse "?",
        .status = report.status.toString(),
        .rollout_state = report.rolloutState(),
        .rollout_control_state = report.rollout_control_state.toString(),
        .manifest_hash = report.manifest_hash,
        .created_at = report.created_at,
        .service_count = summary.service_count,
        .worker_count = summary.worker_count,
        .cron_count = summary.cron_count,
        .training_job_count = summary.training_job_count,
        .active_training_jobs = training_summary.active,
        .paused_training_jobs = training_summary.paused,
        .failed_training_jobs = training_summary.failed,
        .completed_targets = report.completed_targets,
        .failed_targets = report.failed_targets,
        .remaining_targets = report.remainingTargets(),
        .source_release_id = report.source_release_id,
        .previous_successful_release_id = if (previous_successful) |prev| prev.release_id else null,
        .previous_successful_trigger = if (previous_successful) |prev| prev.trigger.toString() else null,
        .previous_successful_status = if (previous_successful) |prev| prev.status.toString() else null,
        .previous_successful_rollout_state = if (previous_successful) |prev| prev.rolloutState() else null,
        .previous_successful_rollout_control_state = if (previous_successful) |prev| prev.rollout_control_state.toString() else null,
        .previous_successful_manifest_hash = if (previous_successful) |prev| prev.manifest_hash else null,
        .previous_successful_created_at = if (previous_successful) |prev| prev.created_at else null,
        .previous_successful_completed_targets = if (previous_successful) |prev| prev.completed_targets else 0,
        .previous_successful_failed_targets = if (previous_successful) |prev| prev.failed_targets else 0,
        .previous_successful_remaining_targets = if (previous_successful) |prev| prev.remainingTargets() else 0,
        .previous_successful_source_release_id = if (previous_successful) |prev| prev.source_release_id else null,
        .previous_successful_message = if (previous_successful) |prev| prev.message else null,
        .previous_successful_failure_details_json = if (previous_successful) |prev| prev.failure_details_json else null,
        .previous_successful_rollout_targets_json = if (previous_successful) |prev| prev.rollout_targets_json else null,
        .message = report.message,
        .failure_details_json = report.failure_details_json,
        .rollout_targets_json = report.rollout_targets_json,
    };
}

fn snapshotFromDeployments(
    latest: store.DeploymentRecord,
    previous_successful: ?store.DeploymentRecord,
) AppStatusSnapshot {
    return appStatusFromReports(
        apply_release.reportFromDeployment(latest),
        if (previous_successful) |dep| apply_release.reportFromDeployment(dep) else null,
        app_snapshot.summarize(latest.config_snapshot),
        store.summarizeTrainingJobsByApp(latest.app_name.?) catch .{},
    );
}

fn currentAppNameAlloc(alloc: std.mem.Allocator) ![]u8 {
    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.fs.cwd().realpath(".", &cwd_buf) catch return StatusError.StoreError;
    return alloc.dupe(u8, std.fs.path.basename(cwd)) catch return StatusError.OutOfMemory;
}

fn appMatchesFilters(snapshot: AppStatusSnapshot, filters: AppListFilters) bool {
    if (filters.status) |status_filter| {
        if (!std.mem.eql(u8, snapshot.status, status_filter) and !std.mem.eql(u8, snapshot.rollout_state, status_filter)) return false;
    }
    if (filters.failed_only and !isFailedLikeRollout(snapshot.status, snapshot.rollout_state)) return false;
    if (filters.in_progress_only and !isInProgressRollout(snapshot.status, snapshot.rollout_state)) return false;
    return true;
}

fn isFailedLikeRollout(status_text: []const u8, rollout_state: []const u8) bool {
    return std.mem.eql(u8, status_text, "failed") or
        std.mem.eql(u8, status_text, "partially_failed") or
        std.mem.eql(u8, rollout_state, "blocked") or
        std.mem.eql(u8, rollout_state, "degraded");
}

fn isInProgressRollout(status_text: []const u8, rollout_state: []const u8) bool {
    return std.mem.eql(u8, status_text, "pending") or
        std.mem.eql(u8, status_text, "in_progress") or
        std.mem.eql(u8, rollout_state, "pending") or
        std.mem.eql(u8, rollout_state, "starting") or
        std.mem.eql(u8, rollout_state, "rolling");
}

fn printStatusTable(snapshots: []const monitor.ServiceSnapshot, verbose: bool) void {
    if (cli.output_mode == .json) {
        statusJson(snapshots);
        return;
    }

    write("{s:<12} {s:<10} {s:<11} {s:<10} {s:<11} {s:<13} {s}\n", .{
        "SERVICE", "STATUS", "HEALTH", "CPU", "MEMORY", "CONTAINERS", "UPTIME",
    });

    for (snapshots) |snap| {
        var cpu_buf: [16]u8 = undefined;
        const cpu_str = if (snap.cpu_pct > 0.0)
            std.fmt.bufPrint(&cpu_buf, "{d:.1}%", .{snap.cpu_pct}) catch "-"
        else
            @as([]const u8, "-");

        var mem_buf: [16]u8 = undefined;
        const mem_str = monitor.formatBytes(&mem_buf, snap.memory_bytes);

        var uptime_buf: [16]u8 = undefined;
        const uptime_str = monitor.formatUptime(&uptime_buf, snap.uptime_secs);

        var count_buf: [12]u8 = undefined;
        const count_str = std.fmt.bufPrint(&count_buf, "{d}/{d}", .{
            snap.running_count, snap.desired_count,
        }) catch "-";

        write("{s:<12} {s:<10} {s:<11} {s:<10} {s:<11} {s:<13} {s}\n", .{
            snap.name,
            monitor.formatStatus(snap.status),
            monitor.formatHealth(snap.health_status),
            cpu_str,
            mem_str,
            count_str,
            uptime_str,
        });

        if (verbose) {
            printVerboseDetails(snap);
        }
    }
}

fn printVerboseDetails(snap: monitor.ServiceSnapshot) void {
    if (snap.psi_cpu) |psi| {
        write("  cpu pressure:    some={d:.1}%  full={d:.1}%\n", .{ psi.some_avg10, psi.full_avg10 });
    }
    if (snap.psi_memory) |psi| {
        write("  memory pressure: some={d:.1}%  full={d:.1}%\n", .{ psi.some_avg10, psi.full_avg10 });
    }

    if (snap.memory_limit) |limit| {
        var limit_buf: [16]u8 = undefined;
        var usage_buf: [16]u8 = undefined;
        const limit_str = monitor.formatBytes(&limit_buf, limit);
        const usage_str = monitor.formatBytes(&usage_buf, snap.memory_bytes);
        if (limit > 0) {
            const pct = @as(f64, @floatFromInt(snap.memory_bytes)) / @as(f64, @floatFromInt(limit)) * 100.0;
            write("  memory limit:    {s} (using {s}, {d:.0}%)\n", .{ limit_str, usage_str, pct });
        }
    }
    if (snap.cpu_quota_pct) |quota| {
        write("  cpu quota:       {d:.0}%\n", .{quota});
    }

    var suggestion_buf: [256]u8 = undefined;
    if (monitor.suggestTuning(&suggestion_buf, snap)) |msg| {
        write("  {s}\n", .{msg});
    }
}

fn statusJson(snapshots: []const monitor.ServiceSnapshot) void {
    var w = json_out.JsonWriter{};
    w.beginArray();
    for (snapshots) |snap| {
        w.beginObject();
        w.stringField("name", snap.name);
        w.stringField("status", monitor.formatStatus(snap.status));
        w.stringField("health", monitor.formatHealth(snap.health_status));
        w.floatField("cpu_pct", snap.cpu_pct);
        w.uintField("memory_bytes", snap.memory_bytes);
        w.uintField("running", snap.running_count);
        w.uintField("desired", snap.desired_count);
        w.intField("uptime_secs", snap.uptime_secs);
        if (snap.memory_limit) |limit| w.uintField("memory_limit", limit) else w.nullField("memory_limit");
        if (snap.cpu_quota_pct) |quota| w.floatField("cpu_quota_pct", quota) else w.nullField("cpu_quota_pct");
        w.endObject();
    }
    w.endArray();
    w.flush();
}

fn parsePsiFromJson(json: []const u8, some_key: []const u8, full_key: []const u8) ?cgroups.PsiMetrics {
    const some = extractJsonFloat(json, some_key) orelse return null;
    const full = extractJsonFloat(json, full_key) orelse return null;
    return .{ .some_avg10 = some, .full_avg10 = full };
}

test "parseAppStatusResponse extracts app fields" {
    const snapshot = parseAppStatusResponse(
        \\{"app_name":"demo-app","trigger":"apply","release_id":"abc123def456","status":"completed","manifest_hash":"sha256:123","created_at":42,"service_count":2,"worker_count":1,"cron_count":3,"training_job_count":4,"active_training_jobs":2,"paused_training_jobs":1,"failed_training_jobs":1,"completed_targets":2,"failed_targets":0,"remaining_targets":0,"source_release_id":null,"message":null}
    );

    try std.testing.expectEqualStrings("demo-app", snapshot.app_name);
    try std.testing.expectEqualStrings("apply", snapshot.trigger);
    try std.testing.expectEqualStrings("abc123def456", snapshot.release_id);
    try std.testing.expectEqualStrings("completed", snapshot.status);
    try std.testing.expectEqualStrings("unknown", snapshot.rollout_state);
    try std.testing.expectEqualStrings("sha256:123", snapshot.manifest_hash);
    try std.testing.expectEqual(@as(i64, 42), snapshot.created_at);
    try std.testing.expectEqual(@as(usize, 2), snapshot.service_count);
    try std.testing.expectEqual(@as(usize, 1), snapshot.worker_count);
    try std.testing.expectEqual(@as(usize, 3), snapshot.cron_count);
    try std.testing.expectEqual(@as(usize, 4), snapshot.training_job_count);
    try std.testing.expectEqual(@as(usize, 2), snapshot.active_training_jobs);
    try std.testing.expectEqual(@as(usize, 1), snapshot.paused_training_jobs);
    try std.testing.expectEqual(@as(usize, 1), snapshot.failed_training_jobs);
    try std.testing.expectEqual(@as(usize, 2), snapshot.completed_targets);
    try std.testing.expectEqual(@as(usize, 0), snapshot.failed_targets);
    try std.testing.expectEqual(@as(usize, 0), snapshot.remaining_targets);
    try std.testing.expect(snapshot.source_release_id == null);
    try std.testing.expect(snapshot.previous_successful_release_id == null);
    try std.testing.expect(snapshot.previous_successful_manifest_hash == null);
    try std.testing.expect(snapshot.previous_successful_created_at == null);
    try std.testing.expect(snapshot.message == null);
}

test "appStatusFromReport matches remote app status shape" {
    const report = apply_release.ApplyReport{
        .app_name = "demo-app",
        .release_id = "dep-2",
        .status = .completed,
        .service_count = 2,
        .placed = 2,
        .failed = 0,
        .completed_targets = 2,
        .failed_targets = 0,
        .message = "all placements healthy",
        .manifest_hash = "sha256:222",
        .created_at = 200,
    };

    const local = appStatusFromReports(report, null, .{ .service_count = 2 }, .{});
    const remote = parseAppStatusResponse(
        \\{"app_name":"demo-app","trigger":"apply","release_id":"dep-2","status":"completed","rollout_state":"stable","manifest_hash":"sha256:222","created_at":200,"service_count":2,"completed_targets":2,"failed_targets":0,"remaining_targets":0,"source_release_id":null,"message":"all placements healthy"}
    );

    try std.testing.expectEqualStrings(local.app_name, remote.app_name);
    try std.testing.expectEqualStrings(local.trigger, remote.trigger);
    try std.testing.expectEqualStrings(local.release_id, remote.release_id);
    try std.testing.expectEqualStrings(local.status, remote.status);
    try std.testing.expectEqualStrings(local.rollout_state, remote.rollout_state);
    try std.testing.expectEqualStrings(local.manifest_hash, remote.manifest_hash);
    try std.testing.expectEqual(local.created_at, remote.created_at);
    try std.testing.expectEqual(local.service_count, remote.service_count);
    try std.testing.expectEqual(local.completed_targets, remote.completed_targets);
    try std.testing.expectEqual(local.failed_targets, remote.failed_targets);
    try std.testing.expectEqual(local.remaining_targets, remote.remaining_targets);
    try std.testing.expect(local.source_release_id == null);
    try std.testing.expect(local.previous_successful_release_id == null);
    try std.testing.expectEqualStrings(local.message.?, remote.message.?);
}

test "writeAppStatusJsonObject round-trips through remote parser" {
    const snapshot = AppStatusSnapshot{
        .app_name = "demo-app",
        .trigger = "rollback",
        .release_id = "dep-2",
        .status = "completed",
        .manifest_hash = "sha256:222",
        .created_at = 200,
        .service_count = 2,
        .worker_count = 1,
        .cron_count = 2,
        .training_job_count = 3,
        .active_training_jobs = 1,
        .paused_training_jobs = 1,
        .failed_training_jobs = 1,
        .completed_targets = 1,
        .failed_targets = 1,
        .remaining_targets = 0,
        .source_release_id = "dep-1",
        .previous_successful_release_id = "dep-0",
        .previous_successful_manifest_hash = "sha256:111",
        .previous_successful_created_at = 100,
        .message = "all placements healthy",
        .previous_successful_rollout_targets_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"state\":\"ready\",\"reason\":null}]",
        .rollout_targets_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"failed\",\"reason\":\"readiness_timeout\"}]",
    };

    var w = json_out.JsonWriter{};
    writeAppStatusJsonObject(&w, snapshot);

    const parsed = parseAppStatusResponse(w.getWritten());
    try std.testing.expectEqualStrings(snapshot.app_name, parsed.app_name);
    try std.testing.expectEqualStrings(snapshot.trigger, parsed.trigger);
    try std.testing.expectEqualStrings(snapshot.release_id, parsed.release_id);
    try std.testing.expectEqualStrings(snapshot.status, parsed.status);
    try std.testing.expectEqualStrings(snapshot.rollout_state, parsed.rollout_state);
    try std.testing.expectEqualStrings(snapshot.manifest_hash, parsed.manifest_hash);
    try std.testing.expectEqual(snapshot.created_at, parsed.created_at);
    try std.testing.expectEqual(snapshot.service_count, parsed.service_count);
    try std.testing.expectEqual(snapshot.worker_count, parsed.worker_count);
    try std.testing.expectEqual(snapshot.cron_count, parsed.cron_count);
    try std.testing.expectEqual(snapshot.training_job_count, parsed.training_job_count);
    try std.testing.expectEqual(snapshot.active_training_jobs, parsed.active_training_jobs);
    try std.testing.expectEqual(snapshot.paused_training_jobs, parsed.paused_training_jobs);
    try std.testing.expectEqual(snapshot.failed_training_jobs, parsed.failed_training_jobs);
    try std.testing.expectEqual(snapshot.completed_targets, parsed.completed_targets);
    try std.testing.expectEqual(snapshot.failed_targets, parsed.failed_targets);
    try std.testing.expectEqual(snapshot.remaining_targets, parsed.remaining_targets);
    try std.testing.expectEqualStrings(snapshot.source_release_id.?, parsed.source_release_id.?);
    try std.testing.expectEqualStrings(snapshot.previous_successful_release_id.?, parsed.previous_successful_release_id.?);
    try std.testing.expectEqualStrings(snapshot.previous_successful_manifest_hash.?, parsed.previous_successful_manifest_hash.?);
    try std.testing.expectEqual(snapshot.previous_successful_created_at.?, parsed.previous_successful_created_at.?);
    try std.testing.expectEqualStrings(snapshot.message.?, parsed.message.?);
    try std.testing.expect(parsed.previous_successful_rollout_targets_json != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed.previous_successful_rollout_targets_json.?, "\"workload_name\":\"db\"") != null);
    try std.testing.expect(parsed.rollout_targets_json != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed.rollout_targets_json.?, "\"workload_name\":\"web\"") != null);
}

test "writeAppStatusJsonObject includes nested release and workload views" {
    const snapshot = AppStatusSnapshot{
        .app_name = "demo-app",
        .trigger = "rollback",
        .release_id = "dep-2",
        .status = "completed",
        .manifest_hash = "sha256:222",
        .created_at = 200,
        .service_count = 2,
        .worker_count = 1,
        .cron_count = 2,
        .training_job_count = 3,
        .active_training_jobs = 1,
        .paused_training_jobs = 1,
        .failed_training_jobs = 1,
        .completed_targets = 1,
        .failed_targets = 1,
        .remaining_targets = 0,
        .source_release_id = "dep-1",
        .previous_successful_release_id = "dep-0",
        .previous_successful_manifest_hash = "sha256:111",
        .previous_successful_created_at = 100,
        .message = "all placements healthy",
        .rollout_targets_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"ready\",\"reason\":null}]",
    };

    var w = json_out.JsonWriter{};
    writeAppStatusJsonObject(&w, snapshot);
    const json = w.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, json, "\"current_release\":{\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_state\":\"unknown\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_targets\":[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"ready\",\"reason\":null}]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout\":{\"state\":\"unknown\",\"completed_targets\":1,\"failed_targets\":1,\"remaining_targets\":0,\"failure_details\":null,\"targets\":[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"ready\",\"reason\":null}]}") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"previous_successful_release\":{\"id\":\"dep-0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"workloads\":{\"services\":2,\"workers\":1,\"crons\":2,\"training_jobs\":3}") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"training_runtime\":{\"active\":1,\"paused\":1,\"failed\":1}") != null);
}

test "writeAppStatusJsonObject preserves failure details" {
    const snapshot = AppStatusSnapshot{
        .app_name = "demo-app",
        .trigger = "apply",
        .release_id = "dep-4",
        .status = "partially_failed",
        .manifest_hash = "sha256:444",
        .created_at = 400,
        .completed_targets = 1,
        .failed_targets = 1,
        .remaining_targets = 0,
        .message = "one or more rollout targets failed readiness checks",
        .failure_details_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"reason\":\"readiness_timeout\"}]",
    };

    var w = json_out.JsonWriter{};
    writeAppStatusJsonObject(&w, snapshot);
    const parsed = parseAppStatusResponse(w.getWritten());

    try std.testing.expect(parsed.failure_details_json != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed.failure_details_json.?, "\"reason\":\"readiness_timeout\"") != null);
}

test "writeAppStatusJsonObject preserves rollout control state" {
    const snapshot = AppStatusSnapshot{
        .app_name = "demo-app",
        .trigger = "apply",
        .release_id = "dep-5",
        .status = "in_progress",
        .rollout_state = "blocked",
        .rollout_control_state = "paused",
        .manifest_hash = "sha256:555",
        .created_at = 500,
        .completed_targets = 1,
        .failed_targets = 0,
        .remaining_targets = 1,
    };

    var w = json_out.JsonWriter{};
    writeAppStatusJsonObject(&w, snapshot);
    const json = w.getWritten();
    const parsed = parseAppStatusResponse(json);

    try std.testing.expectEqualStrings("paused", parsed.rollout_control_state);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_control_state\":\"paused\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"control_state\":\"paused\"") != null);
}

test "appMatchesFilters applies failed and in-progress filters" {
    const failed_snapshot = AppStatusSnapshot{
        .app_name = "demo-app",
        .trigger = "apply",
        .release_id = "dep-1",
        .status = "partially_failed",
        .rollout_state = "degraded",
        .manifest_hash = "sha256:111",
        .created_at = 100,
        .completed_targets = 1,
        .failed_targets = 1,
        .remaining_targets = 0,
        .source_release_id = null,
        .previous_successful_release_id = null,
        .previous_successful_manifest_hash = null,
        .previous_successful_created_at = null,
        .message = null,
    };
    const pending_snapshot = AppStatusSnapshot{
        .app_name = "demo-app",
        .trigger = "apply",
        .release_id = "dep-2",
        .status = "in_progress",
        .rollout_state = "rolling",
        .manifest_hash = "sha256:222",
        .created_at = 200,
        .completed_targets = 1,
        .failed_targets = 0,
        .remaining_targets = 1,
        .source_release_id = null,
        .previous_successful_release_id = null,
        .previous_successful_manifest_hash = null,
        .previous_successful_created_at = null,
        .message = null,
    };

    try std.testing.expect(appMatchesFilters(failed_snapshot, .{ .failed_only = true }));
    try std.testing.expect(!appMatchesFilters(failed_snapshot, .{ .in_progress_only = true }));
    try std.testing.expect(appMatchesFilters(failed_snapshot, .{ .status = "degraded" }));
    try std.testing.expect(appMatchesFilters(pending_snapshot, .{ .in_progress_only = true }));
    try std.testing.expect(appMatchesFilters(pending_snapshot, .{ .status = "rolling" }));
    try std.testing.expect(!appMatchesFilters(pending_snapshot, .{ .status = "completed" }));
}

test "appStatusFromReport preserves partially failed local release state" {
    const dep = store.DeploymentRecord{
        .id = "dep-3",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .manifest_hash = "sha256:333",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"},{\"name\":\"db\"}]}",
        .completed_targets = 1,
        .failed_targets = 1,
        .status = "partially_failed",
        .message = "one or more placements failed",
        .created_at = 300,
    };

    const previous_successful = apply_release.ApplyReport{
        .app_name = "demo-app",
        .release_id = "dep-2",
        .status = .completed,
        .service_count = 2,
        .placed = 2,
        .failed = 0,
        .completed_targets = 2,
        .failed_targets = 0,
        .manifest_hash = "sha256:222",
        .created_at = 200,
    };

    const local = appStatusFromReports(apply_release.reportFromDeployment(dep), previous_successful, .{ .service_count = 2 }, .{});
    const remote = parseAppStatusResponse(
        \\{"app_name":"demo-app","trigger":"apply","release_id":"dep-3","status":"partially_failed","manifest_hash":"sha256:333","created_at":300,"service_count":2,"completed_targets":1,"failed_targets":1,"remaining_targets":0,"source_release_id":null,"previous_successful_release_id":"dep-2","previous_successful_manifest_hash":"sha256:222","previous_successful_created_at":200,"message":"one or more placements failed"}
    );

    try std.testing.expectEqualStrings(local.app_name, remote.app_name);
    try std.testing.expectEqualStrings(local.trigger, remote.trigger);
    try std.testing.expectEqualStrings(local.release_id, remote.release_id);
    try std.testing.expectEqualStrings(local.status, remote.status);
    try std.testing.expectEqualStrings(local.manifest_hash, remote.manifest_hash);
    try std.testing.expectEqual(local.created_at, remote.created_at);
    try std.testing.expectEqual(local.service_count, remote.service_count);
    try std.testing.expectEqual(local.completed_targets, remote.completed_targets);
    try std.testing.expectEqual(local.failed_targets, remote.failed_targets);
    try std.testing.expectEqual(local.remaining_targets, remote.remaining_targets);
    try std.testing.expect(local.source_release_id == null);
    try std.testing.expectEqualStrings(local.previous_successful_release_id.?, remote.previous_successful_release_id.?);
    try std.testing.expectEqualStrings(local.previous_successful_manifest_hash.?, remote.previous_successful_manifest_hash.?);
    try std.testing.expectEqual(local.previous_successful_created_at.?, remote.previous_successful_created_at.?);
    try std.testing.expectEqualStrings(local.message.?, remote.message.?);
}

test "formatAppProgress summarizes in-flight and partial outcomes" {
    var buf: [64]u8 = undefined;

    const in_progress = AppStatusSnapshot{
        .app_name = "demo-app",
        .trigger = "apply",
        .release_id = "dep-2",
        .status = "in_progress",
        .manifest_hash = "sha256:222",
        .created_at = 200,
        .service_count = 4,
        .completed_targets = 1,
        .failed_targets = 1,
        .remaining_targets = 2,
        .source_release_id = null,
        .previous_successful_release_id = null,
        .previous_successful_manifest_hash = null,
        .previous_successful_created_at = null,
        .message = "apply in progress",
    };
    try std.testing.expectEqualStrings("1 ok, 1 fail, 2 left", formatAppProgress(&buf, in_progress));

    const partial = AppStatusSnapshot{
        .app_name = "demo-app",
        .trigger = "apply",
        .release_id = "dep-3",
        .status = "partially_failed",
        .manifest_hash = "sha256:333",
        .created_at = 300,
        .service_count = 2,
        .completed_targets = 1,
        .failed_targets = 1,
        .remaining_targets = 0,
        .source_release_id = null,
        .previous_successful_release_id = null,
        .previous_successful_manifest_hash = null,
        .previous_successful_created_at = null,
        .message = "one or more placements failed",
    };
    try std.testing.expectEqualStrings("1 ok, 1 fail", formatAppProgress(&buf, partial));

    const completed = AppStatusSnapshot{
        .app_name = "demo-app",
        .trigger = "apply",
        .release_id = "dep-4",
        .status = "completed",
        .manifest_hash = "sha256:444",
        .created_at = 400,
        .service_count = 2,
        .completed_targets = 2,
        .failed_targets = 0,
        .remaining_targets = 0,
        .source_release_id = null,
        .previous_successful_release_id = null,
        .previous_successful_manifest_hash = null,
        .previous_successful_created_at = null,
        .message = "apply completed",
    };
    try std.testing.expectEqualStrings("2 ok", formatAppProgress(&buf, completed));
}

test "formatStatusMessage appends failure detail summary" {
    var buf: [256]u8 = undefined;
    const text = formatStatusMessage(
        &buf,
        "one or more rollout targets failed readiness checks",
        "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"reason\":\"readiness_timeout\"}]",
    );

    try std.testing.expect(std.mem.indexOf(u8, text, "web: readiness_timeout") != null);
}

test "formatTrainingRuntime summarizes active paused and failed jobs" {
    var buf: [48]u8 = undefined;

    const empty = AppStatusSnapshot{
        .app_name = "demo-app",
        .trigger = "apply",
        .release_id = "dep-1",
        .status = "completed",
        .manifest_hash = "sha256:111",
        .created_at = 100,
        .completed_targets = 0,
        .failed_targets = 0,
        .remaining_targets = 0,
        .source_release_id = null,
        .previous_successful_release_id = null,
        .previous_successful_manifest_hash = null,
        .previous_successful_created_at = null,
        .message = null,
    };
    try std.testing.expectEqualStrings("-", formatTrainingRuntime(&buf, empty));

    const active = AppStatusSnapshot{
        .app_name = "demo-app",
        .trigger = "apply",
        .release_id = "dep-2",
        .status = "completed",
        .manifest_hash = "sha256:222",
        .created_at = 200,
        .active_training_jobs = 2,
        .paused_training_jobs = 1,
        .failed_training_jobs = 1,
        .completed_targets = 0,
        .failed_targets = 0,
        .remaining_targets = 0,
        .source_release_id = null,
        .previous_successful_release_id = null,
        .previous_successful_manifest_hash = null,
        .previous_successful_created_at = null,
        .message = null,
    };
    try std.testing.expectEqualStrings("2 act, 1 pause, 1 fail", formatTrainingRuntime(&buf, active));
}
