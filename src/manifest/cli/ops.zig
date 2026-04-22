const std = @import("std");
const platform = @import("platform");
const cli = @import("../../lib/cli.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const json_out = @import("../../lib/json_output.zig");
const apply_release = @import("../apply_release.zig");
const app_snapshot = @import("../app_snapshot.zig");
const rollback_snapshot = @import("../rollback_snapshot.zig");
const local_apply_backend = @import("../local_apply_backend.zig");
const manifest_loader = @import("../loader.zig");
const orchestrator = @import("../orchestrator.zig");
const release_history = @import("../release_history.zig");
const update = @import("../update.zig");
const store = @import("../../state/store.zig");
const http_client = @import("../../cluster/http_client.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const truncate = cli.truncate;

const OpsError = error{
    InvalidArgument,
    ManifestLoadFailed,
    DeploymentFailed,
    ConnectionFailed,
    StoreError,
    UnknownService,
};

pub fn rollback(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var target_name: ?[]const u8 = null;
    var app_mode = false;
    var server_addr: ?[]const u8 = null;
    var release_id: ?[]const u8 = null;
    var print_only = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--app")) {
            app_mode = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return OpsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--release")) {
            release_id = args.next() orelse {
                writeErr("--release requires a release id\n", .{});
                return OpsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--print")) {
            print_only = true;
        } else {
            target_name = arg;
        }
    }

    if (server_addr != null) {
        if (!app_mode) {
            writeErr("remote rollback currently requires --app [name]\n", .{});
            return OpsError.InvalidArgument;
        }
        const owned_app_name = if (target_name == null) try currentAppNameAlloc(alloc) else null;
        defer if (owned_app_name) |name| alloc.free(name);
        const app_name = target_name orelse owned_app_name.?;
        try rollbackRemoteApp(alloc, server_addr.?, app_name, release_id, print_only);
        return;
    }

    if (app_mode) {
        const owned_app_name = if (target_name == null) try currentAppNameAlloc(alloc) else null;
        defer if (owned_app_name) |name| alloc.free(name);
        const app_name = target_name orelse owned_app_name.?;
        try rollbackLocalApp(alloc, app_name, release_id, print_only);
        return;
    }

    const config = blk: {
        const service_name = target_name orelse {
            writeErr("usage: yoq rollback <service>\n", .{});
            writeErr("   or: yoq rollback --app [name] [--print] [--release <id>]\n", .{});
            writeErr("   or: yoq rollback --app [name] [--server host:port] [--release <id>] [--print]\n", .{});
            return OpsError.InvalidArgument;
        };

        break :blk update.rollback(alloc, service_name) catch |err| {
            switch (err) {
                update.UpdateError.NoPreviousDeployment => {
                    writeErr("no previous deployment found for {s}\n", .{service_name});
                },
                update.UpdateError.StoreFailed => {
                    writeErr("failed to read deployment history\n", .{});
                },
                else => {
                    writeErr("rollback failed\n", .{});
                },
            }
            return OpsError.StoreError;
        };
    };
    defer alloc.free(config);

    write("rollback config for {s}:\n{s}\n", .{ target_name.?, config });
    write("\nto apply this rollback, redeploy with this config using 'yoq up'\n", .{});
}

pub fn rollout(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    const action = args.next() orelse {
        writeErr("usage: yoq rollout <pause|resume|cancel> --app [name] [--server host:port]\n", .{});
        return OpsError.InvalidArgument;
    };

    var target_name: ?[]const u8 = null;
    var app_mode = false;
    var server_addr: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--app")) {
            app_mode = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return OpsError.InvalidArgument;
            };
        } else {
            target_name = arg;
        }
    }

    if (!app_mode) {
        writeErr("rollout control requires --app [name]\n", .{});
        return OpsError.InvalidArgument;
    }

    const control_state = if (std.mem.eql(u8, action, "pause"))
        "paused"
    else if (std.mem.eql(u8, action, "resume"))
        "active"
    else if (std.mem.eql(u8, action, "cancel"))
        "cancel_requested"
    else {
        writeErr("unknown rollout action: {s}\n", .{action});
        return OpsError.InvalidArgument;
    };

    const owned_app_name = if (target_name == null) try currentAppNameAlloc(alloc) else null;
    defer if (owned_app_name) |name| alloc.free(name);
    const app_name = target_name orelse owned_app_name.?;

    if (server_addr) |addr| {
        try rolloutRemoteApp(alloc, addr, app_name, action);
    } else {
        try rolloutLocalApp(alloc, app_name, action, control_state);
    }
}

const RollbackSummary = struct {
    app_name: []const u8,
    release_id: []const u8,
    trigger: []const u8,
    status: []const u8,
    rollout_state: []const u8 = "unknown",
    rollout_control_state: []const u8 = "active",
    completed_targets: usize,
    failed_targets: usize,
    remaining_targets: usize,
    source_release_id: ?[]const u8,
    resumed_from_release_id: ?[]const u8 = null,
    superseded_by_release_id: ?[]const u8 = null,
    message: ?[]const u8,
    failure_details_json: ?[]const u8 = null,
    rollout_targets_json: ?[]const u8 = null,
    rollout_checkpoint_json: ?[]const u8 = null,
    is_current: bool = false,
    is_previous_successful: bool = false,
};

fn rollbackLocalApp(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    release_id: ?[]const u8,
    print_only: bool,
) !void {
    const target = store.getRollbackTargetDeploymentByApp(alloc, app_name, release_id) catch {
        writeErr("no previous deployment found for app {s}\n", .{app_name});
        return OpsError.StoreError;
    };
    defer target.deinit(alloc);

    if (print_only) {
        write("rollback snapshot for app {s}:\n{s}\n", .{ app_name, target.config_snapshot });
        return;
    }

    var loaded = rollback_snapshot.loadLocalRollbackSnapshot(alloc, target.config_snapshot) catch |err| {
        writeErr("failed to load rollback snapshot: {}\n", .{err});
        return OpsError.StoreError;
    };
    defer loaded.deinit();

    var prepared = local_apply_backend.PreparedLocalApply.init(alloc, &loaded.manifest, &loaded.release, false) catch |err| {
        writeErr("failed to initialize rollback runtime: {}\n", .{err});
        return OpsError.DeploymentFailed;
    };
    defer prepared.deinit();
    prepared.beginRuntime();

    const apply_report = prepared.startRelease(.{
        .trigger = .rollback,
        .source_release_id = target.id,
    }) catch |err| {
        writeErr("rollback failed: {}\n", .{err});
        return OpsError.DeploymentFailed;
    };
    defer apply_report.deinit(alloc);

    printRollbackSummary(.{
        .app_name = app_name,
        .release_id = apply_report.release_id orelse "?",
        .trigger = apply_report.trigger.toString(),
        .status = apply_report.status.toString(),
        .rollout_state = apply_report.rolloutState(),
        .rollout_control_state = apply_report.rollout_control_state.toString(),
        .completed_targets = apply_report.completed_targets,
        .failed_targets = apply_report.failed_targets,
        .remaining_targets = apply_report.remainingTargets(),
        .source_release_id = apply_report.source_release_id,
        .resumed_from_release_id = apply_report.resumed_from_release_id,
        .message = apply_report.message,
    });

    if (loaded.release.resolvedServiceCount() == 0) {
        return;
    }

    writeErr("rollback applied. services running. press ctrl-c to stop.\n", .{});
    prepared.orch.waitForShutdown();
    writeErr("\nshutting down...\n", .{});
    prepared.orch.stopAll();
    writeErr("stopped\n", .{});
}

pub fn history(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var target_name: ?[]const u8 = null;
    var app_mode = false;
    var server_addr: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--app")) {
            app_mode = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return OpsError.InvalidArgument;
            };
        } else {
            target_name = arg;
        }
    }

    if (server_addr != null and !app_mode) {
        writeErr("remote history currently requires --app [name]\n", .{});
        return OpsError.InvalidArgument;
    }

    const owned_label = if (app_mode and target_name == null) try currentAppNameAlloc(alloc) else null;
    defer if (owned_label) |label| alloc.free(label);

    const label = if (app_mode)
        target_name orelse owned_label.?
    else
        target_name orelse {
            writeErr("usage: yoq history <service> [--json]\n", .{});
            writeErr("   or: yoq history --app [name] [--server host:port] [--json]\n", .{});
            return OpsError.InvalidArgument;
        };

    if (server_addr) |addr| {
        try printRemoteAppHistory(alloc, addr, label);
        return;
    }

    var deployments = if (app_mode)
        release_history.listAppReleases(alloc, label) catch |err| {
            writeErr("failed to read app release history: {}\n", .{err});
            return OpsError.StoreError;
        }
    else
        store.listDeployments(alloc, label) catch |err| {
            writeErr("failed to read deployment history: {}\n", .{err});
            return OpsError.StoreError;
        };
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginArray();
        const previous_successful_id = previousSuccessfulReleaseId(deployments.items);
        for (deployments.items, 0..) |dep, i| {
            var entry = historyEntryFromDeployment(dep);
            entry.is_current = i == 0;
            entry.is_previous_successful = previous_successful_id != null and std.mem.eql(u8, entry.id, previous_successful_id.?);
            writeHistoryJsonObject(&w, entry);
        }
        w.endArray();
        w.flush();
        return;
    }

    if (deployments.items.len == 0) {
        if (app_mode) {
            write("no releases found for app {s}\n", .{label});
        } else {
            write("no deployments found for {s}\n", .{label});
        }
        return;
    }

    writeHistoryHeader();

    const previous_successful_id = previousSuccessfulReleaseId(deployments.items);
    for (deployments.items, 0..) |dep, i| {
        var entry = historyEntryFromDeployment(dep);
        entry.is_current = i == 0;
        entry.is_previous_successful = previous_successful_id != null and std.mem.eql(u8, entry.id, previous_successful_id.?);
        writeHistoryRow(entry);
    }
}

fn currentAppNameAlloc(alloc: std.mem.Allocator) ![]u8 {
    var cwd_buf: [4096]u8 = undefined;
    const cwd = platform.cwd().realpath(".", &cwd_buf) catch return OpsError.StoreError;
    return alloc.dupe(u8, std.fs.path.basename(cwd)) catch return OpsError.StoreError;
}

fn printRemoteAppHistory(alloc: std.mem.Allocator, addr_str: []const u8, app_name: []const u8) !void {
    const server = cli.parseServerAddr(addr_str);
    const path = std.fmt.allocPrint(alloc, "/apps/{s}/history", .{app_name}) catch return OpsError.StoreError;
    defer alloc.free(path);

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, server.ip, server.port, path, token) catch |err| {
        writeErr("failed to connect to cluster server: {}\n", .{err});
        writeErr("hint: is the server running? try 'yoq serve' or 'yoq init-server'\n", .{});
        return OpsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("history failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return OpsError.StoreError;
    }

    if (cli.output_mode == .json) {
        write("{s}\n", .{resp.body});
        return;
    }

    var entries: std.ArrayList(HistoryEntryView) = .empty;
    defer entries.deinit(alloc);

    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        entries.append(alloc, parseHistoryObject(obj)) catch return OpsError.StoreError;
    }

    if (entries.items.len == 0) {
        write("no releases found for app {s}\n", .{app_name});
        return;
    }

    writeHistoryHeader();
    for (entries.items) |entry| {
        writeHistoryRow(entry);
    }
}

fn previousSuccessfulReleaseId(deployments: []const store.DeploymentRecord) ?[]const u8 {
    if (deployments.len == 0) return null;
    for (deployments[1..]) |dep| {
        if (std.mem.eql(u8, dep.status, "completed")) return dep.id;
    }
    return null;
}

const HistoryEntryView = struct {
    id: []const u8,
    app: ?[]const u8,
    service: []const u8,
    trigger: []const u8,
    status: []const u8,
    rollout_state: []const u8 = "unknown",
    rollout_control_state: []const u8 = "active",
    manifest_hash: []const u8,
    created_at: i64,
    service_count: usize = 0,
    worker_count: usize = 0,
    cron_count: usize = 0,
    training_job_count: usize = 0,
    completed_targets: usize,
    failed_targets: usize,
    remaining_targets: usize,
    source_release_id: ?[]const u8,
    resumed_from_release_id: ?[]const u8 = null,
    superseded_by_release_id: ?[]const u8 = null,
    message: ?[]const u8,
    failure_details_json: ?[]const u8 = null,
    rollout_targets_json: ?[]const u8 = null,
    rollout_checkpoint_json: ?[]const u8 = null,
    is_current: bool = false,
    is_previous_successful: bool = false,
};

fn historyEntryFromDeployment(dep: store.DeploymentRecord) HistoryEntryView {
    const report = apply_release.reportFromDeployment(dep);
    const summary = app_snapshot.summarize(dep.config_snapshot);
    return .{
        .id = report.release_id orelse dep.id,
        .app = dep.app_name,
        .service = dep.service_name,
        .trigger = report.trigger.toString(),
        .status = report.status.toString(),
        .rollout_state = report.rolloutState(),
        .rollout_control_state = report.rollout_control_state.toString(),
        .manifest_hash = report.manifest_hash,
        .created_at = report.created_at,
        .service_count = summary.service_count,
        .worker_count = summary.worker_count,
        .cron_count = summary.cron_count,
        .training_job_count = summary.training_job_count,
        .completed_targets = report.completed_targets,
        .failed_targets = report.failed_targets,
        .remaining_targets = report.remainingTargets(),
        .source_release_id = report.source_release_id,
        .resumed_from_release_id = report.resumed_from_release_id,
        .superseded_by_release_id = report.superseded_by_release_id,
        .message = report.message,
        .failure_details_json = report.failure_details_json,
        .rollout_targets_json = report.rollout_targets_json,
        .rollout_checkpoint_json = report.rollout_checkpoint_json,
        .is_current = false,
        .is_previous_successful = false,
    };
}

fn parseHistoryObject(obj: []const u8) HistoryEntryView {
    return .{
        .id = json_helpers.extractJsonString(obj, "id") orelse "?",
        .app = json_helpers.extractJsonString(obj, "app"),
        .service = json_helpers.extractJsonString(obj, "service") orelse "?",
        .trigger = json_helpers.extractJsonString(obj, "trigger") orelse "apply",
        .status = json_helpers.extractJsonString(obj, "status") orelse "?",
        .rollout_state = json_helpers.extractJsonString(obj, "rollout_state") orelse "unknown",
        .rollout_control_state = json_helpers.extractJsonString(obj, "rollout_control_state") orelse "active",
        .manifest_hash = json_helpers.extractJsonString(obj, "manifest_hash") orelse "?",
        .created_at = json_helpers.extractJsonInt(obj, "created_at") orelse 0,
        .service_count = @intCast(@max(0, json_helpers.extractJsonInt(obj, "service_count") orelse 0)),
        .worker_count = @intCast(@max(0, json_helpers.extractJsonInt(obj, "worker_count") orelse 0)),
        .cron_count = @intCast(@max(0, json_helpers.extractJsonInt(obj, "cron_count") orelse 0)),
        .training_job_count = @intCast(@max(0, json_helpers.extractJsonInt(obj, "training_job_count") orelse 0)),
        .completed_targets = @intCast(@max(0, json_helpers.extractJsonInt(obj, "completed_targets") orelse 0)),
        .failed_targets = @intCast(@max(0, json_helpers.extractJsonInt(obj, "failed_targets") orelse 0)),
        .remaining_targets = @intCast(@max(0, json_helpers.extractJsonInt(obj, "remaining_targets") orelse 0)),
        .source_release_id = json_helpers.extractJsonString(obj, "source_release_id"),
        .resumed_from_release_id = json_helpers.extractJsonString(obj, "resumed_from_release_id"),
        .superseded_by_release_id = json_helpers.extractJsonString(obj, "superseded_by_release_id"),
        .message = json_helpers.extractJsonString(obj, "message"),
        .failure_details_json = json_helpers.extractJsonArray(obj, "failure_details"),
        .rollout_targets_json = json_helpers.extractJsonArray(obj, "rollout_targets"),
        .rollout_checkpoint_json = json_helpers.extractJsonObject(obj, "rollout_checkpoint"),
        .is_current = json_helpers.extractJsonBool(obj, "is_current") orelse false,
        .is_previous_successful = json_helpers.extractJsonBool(obj, "is_previous_successful") orelse false,
    };
}

fn writeHistoryHeader() void {
    write("{s:<8} {s:<14} {s:<14} {s:<11} {s:<8} {s:<10} {s:<14} {s:<16} {s}\n", .{
        "MARK", "ID", "STATUS", "ROLLOUT", "CTRL", "TRIGGER", "HASH", "TARGETS", "MESSAGE",
    });
}

fn writeHistoryRow(entry: HistoryEntryView) void {
    var message_buf: [160]u8 = undefined;
    const message = formatHistoryMessage(&message_buf, entry.message, entry.failure_details_json);
    const mark = if (entry.is_current)
        "current"
    else if (entry.is_previous_successful)
        "prev-ok"
    else
        "";
    var progress_buf: [64]u8 = undefined;
    const progress = formatProgressCounts(&progress_buf, entry.completed_targets, entry.failed_targets, entry.remaining_targets);
    const control = formatRolloutControlState(entry.rollout_control_state);

    write("{s:<8} {s:<14} {s:<14} {s:<11} {s:<8} {s:<10} {s:<14} {s:<16} {s}\n", .{
        mark,
        truncate(entry.id, 12),
        entry.status,
        entry.rollout_state,
        control,
        entry.trigger,
        truncate(entry.manifest_hash, 12),
        progress,
        truncate(message, 36),
    });
}

fn formatHistoryMessage(buf: []u8, message: ?[]const u8, failure_details_json: ?[]const u8) []const u8 {
    if (message == null or message.?.len == 0) {
        return json_helpers.summarizeFailureDetails(buf, failure_details_json) orelse "";
    }

    const prefix = std.fmt.bufPrint(buf, "{s}", .{message.?}) catch return message.?;
    if (failure_details_json == null) return prefix;

    const sep = std.fmt.bufPrint(buf[prefix.len..], " | ", .{}) catch return prefix;
    const summary = json_helpers.summarizeFailureDetails(buf[prefix.len + sep.len ..], failure_details_json) orelse return prefix;
    return buf[0 .. prefix.len + sep.len + summary.len];
}

fn writeHistoryJsonObject(w: *json_out.JsonWriter, entry: HistoryEntryView) void {
    w.beginObject();
    w.stringField("id", entry.id);
    if (entry.app) |app_name| w.stringField("app", app_name) else w.nullField("app");
    w.stringField("service", entry.service);
    w.stringField("trigger", entry.trigger);
    w.stringField("status", entry.status);
    w.stringField("rollout_state", entry.rollout_state);
    w.stringField("rollout_control_state", entry.rollout_control_state);
    w.stringField("manifest_hash", entry.manifest_hash);
    w.intField("created_at", entry.created_at);
    w.uintField("service_count", entry.service_count);
    w.uintField("worker_count", entry.worker_count);
    w.uintField("cron_count", entry.cron_count);
    w.uintField("training_job_count", entry.training_job_count);
    w.uintField("completed_targets", entry.completed_targets);
    w.uintField("failed_targets", entry.failed_targets);
    w.uintField("remaining_targets", entry.remaining_targets);
    if (entry.source_release_id) |source_release_id| w.stringField("source_release_id", source_release_id) else w.nullField("source_release_id");
    if (entry.resumed_from_release_id) |release_id| w.stringField("resumed_from_release_id", release_id) else w.nullField("resumed_from_release_id");
    if (entry.superseded_by_release_id) |release_id| w.stringField("superseded_by_release_id", release_id) else w.nullField("superseded_by_release_id");
    if (entry.message) |message| w.stringField("message", message) else w.nullField("message");
    if (entry.failure_details_json) |failure_details| w.rawField("failure_details", failure_details) else w.nullField("failure_details");
    if (entry.rollout_targets_json) |rollout_targets| w.rawField("rollout_targets", rollout_targets) else w.nullField("rollout_targets");
    if (entry.rollout_checkpoint_json) |checkpoint| w.rawField("rollout_checkpoint", checkpoint) else w.nullField("rollout_checkpoint");
    w.beginObjectField("rollout");
    w.stringField("state", entry.rollout_state);
    w.stringField("control_state", entry.rollout_control_state);
    if (entry.resumed_from_release_id) |release_id| w.stringField("resumed_from_release_id", release_id) else w.nullField("resumed_from_release_id");
    if (entry.superseded_by_release_id) |release_id| w.stringField("superseded_by_release_id", release_id) else w.nullField("superseded_by_release_id");
    w.uintField("completed_targets", entry.completed_targets);
    w.uintField("failed_targets", entry.failed_targets);
    w.uintField("remaining_targets", entry.remaining_targets);
    if (entry.failure_details_json) |failure_details| w.rawField("failure_details", failure_details) else w.nullField("failure_details");
    if (entry.rollout_targets_json) |rollout_targets| w.rawField("targets", rollout_targets) else w.nullField("targets");
    if (entry.rollout_checkpoint_json) |checkpoint| w.rawField("checkpoint", checkpoint) else w.nullField("checkpoint");
    w.endObject();
    w.boolField("is_current", entry.is_current);
    w.boolField("is_previous_successful", entry.is_previous_successful);
    w.beginObjectField("release");
    w.stringField("id", entry.id);
    w.stringField("trigger", entry.trigger);
    w.stringField("status", entry.status);
    w.stringField("rollout_state", entry.rollout_state);
    w.stringField("rollout_control_state", entry.rollout_control_state);
    w.stringField("manifest_hash", entry.manifest_hash);
    w.intField("created_at", entry.created_at);
    w.uintField("completed_targets", entry.completed_targets);
    w.uintField("failed_targets", entry.failed_targets);
    w.uintField("remaining_targets", entry.remaining_targets);
    if (entry.source_release_id) |source_release_id| w.stringField("source_release_id", source_release_id) else w.nullField("source_release_id");
    if (entry.resumed_from_release_id) |release_id| w.stringField("resumed_from_release_id", release_id) else w.nullField("resumed_from_release_id");
    if (entry.superseded_by_release_id) |release_id| w.stringField("superseded_by_release_id", release_id) else w.nullField("superseded_by_release_id");
    if (entry.message) |message| w.stringField("message", message) else w.nullField("message");
    if (entry.failure_details_json) |failure_details| w.rawField("failure_details", failure_details) else w.nullField("failure_details");
    if (entry.rollout_targets_json) |rollout_targets| w.rawField("rollout_targets", rollout_targets) else w.nullField("rollout_targets");
    if (entry.rollout_checkpoint_json) |checkpoint| w.rawField("rollout_checkpoint", checkpoint) else w.nullField("rollout_checkpoint");
    w.beginObjectField("rollout");
    w.stringField("state", entry.rollout_state);
    w.stringField("control_state", entry.rollout_control_state);
    w.uintField("completed_targets", entry.completed_targets);
    w.uintField("failed_targets", entry.failed_targets);
    w.uintField("remaining_targets", entry.remaining_targets);
    if (entry.failure_details_json) |failure_details| w.rawField("failure_details", failure_details) else w.nullField("failure_details");
    if (entry.rollout_targets_json) |rollout_targets| w.rawField("targets", rollout_targets) else w.nullField("targets");
    if (entry.rollout_checkpoint_json) |checkpoint| w.rawField("checkpoint", checkpoint) else w.nullField("checkpoint");
    w.endObject();
    w.boolField("current", entry.is_current);
    w.boolField("previous_successful", entry.is_previous_successful);
    w.endObject();
    w.beginObjectField("workloads");
    w.uintField("services", entry.service_count);
    w.uintField("workers", entry.worker_count);
    w.uintField("crons", entry.cron_count);
    w.uintField("training_jobs", entry.training_job_count);
    w.endObject();
    w.endObject();
}

fn rollbackRemoteApp(
    alloc: std.mem.Allocator,
    addr_str: []const u8,
    app_name: []const u8,
    release_id: ?[]const u8,
    print_only: bool,
) !void {
    const server = cli.parseServerAddr(addr_str);
    const path = std.fmt.allocPrint(alloc, "/apps/{s}/rollback", .{app_name}) catch return OpsError.StoreError;
    defer alloc.free(path);
    const body = if (release_id) |id|
        std.fmt.allocPrint(alloc, "{{\"release_id\":\"{s}\",\"print\":{}}}", .{ id, print_only }) catch return OpsError.StoreError
    else
        std.fmt.allocPrint(alloc, "{{\"print\":{}}}", .{print_only}) catch return OpsError.StoreError;
    defer alloc.free(body);

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.postWithAuth(alloc, server.ip, server.port, path, body, token) catch |err| {
        writeErr("failed to connect to cluster server: {}\n", .{err});
        writeErr("hint: is the server running? try 'yoq serve' or 'yoq init-server'\n", .{});
        return OpsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("rollback failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return OpsError.StoreError;
    }

    if (print_only) {
        write("rollback snapshot for app {s}:\n{s}\n", .{ app_name, resp.body });
        return;
    }

    printRollbackSummary(parseRollbackSummary(resp.body));
}

fn rolloutContextFromDeployment(dep: store.DeploymentRecord) apply_release.ApplyContext {
    return .{
        .trigger = if (dep.trigger != null and std.mem.eql(u8, dep.trigger.?, "rollback")) .rollback else .apply,
        .source_release_id = dep.source_release_id,
        .resumed_from_release_id = dep.resumed_from_release_id,
    };
}

fn resumeLocalAppRollout(alloc: std.mem.Allocator, active: store.DeploymentRecord) !void {
    var loaded = rollback_snapshot.loadLocalRollbackSnapshot(alloc, active.config_snapshot) catch {
        writeErr("failed to load rollout snapshot for app {s}\n", .{active.app_name.?});
        return OpsError.StoreError;
    };
    defer loaded.deinit();

    var prepared = local_apply_backend.PreparedLocalApply.init(alloc, &loaded.manifest, &loaded.release, false) catch |err| {
        writeErr("failed to initialize rollout resume runtime: {}\n", .{err});
        return OpsError.DeploymentFailed;
    };
    defer prepared.deinit();
    prepared.beginRuntime();

    var context = rolloutContextFromDeployment(active);
    context.continue_release_id = active.id;
    const apply_report = prepared.startRelease(context) catch |err| {
        writeErr("rollout resume failed: {}\n", .{err});
        return OpsError.DeploymentFailed;
    };
    defer apply_report.deinit(alloc);

    write("rollout resumed for app {s}: {s}\n", .{ active.app_name.?, apply_report.release_id orelse active.id });
    write("status: {s} ({s})\n", .{ apply_report.status.toString(), apply_report.rolloutState() });

    if (loaded.release.resolvedServiceCount() == 0) return;

    writeErr("resumed services running. press ctrl-c to stop.\n", .{});
    prepared.orch.waitForShutdown();
    writeErr("\nshutting down...\n", .{});
    prepared.orch.stopAll();
    writeErr("stopped\n", .{});
}

fn rolloutLocalApp(alloc: std.mem.Allocator, app_name: []const u8, action: []const u8, control_state: []const u8) !void {
    const active = store.getActiveDeploymentByApp(alloc, app_name) catch {
        writeErr("no active rollout found for app {s}\n", .{app_name});
        return OpsError.StoreError;
    };
    defer active.deinit(alloc);

    if (std.mem.eql(u8, action, "resume") and
        std.mem.eql(u8, active.rollout_control_state orelse "active", "paused") and
        active.rollout_checkpoint_json != null)
    {
        return resumeLocalAppRollout(alloc, active);
    }

    store.updateDeploymentRolloutControlState(active.id, control_state) catch return OpsError.StoreError;
    write("rollout control updated for app {s}: {s} ({s})\n", .{ app_name, control_state, active.id });
}

fn rolloutRemoteApp(alloc: std.mem.Allocator, addr_str: []const u8, app_name: []const u8, action: []const u8) !void {
    const server = cli.parseServerAddr(addr_str);
    const path = std.fmt.allocPrint(alloc, "/apps/{s}/rollout/{s}", .{ app_name, action }) catch return OpsError.StoreError;
    defer alloc.free(path);

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.postWithAuth(alloc, server.ip, server.port, path, "{}", token) catch |err| {
        writeErr("failed to connect to cluster server: {}\n", .{err});
        return OpsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("rollout control failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return OpsError.StoreError;
    }

    write("{s}\n", .{resp.body});
}

fn parseRollbackSummary(json: []const u8) RollbackSummary {
    return .{
        .app_name = json_helpers.extractJsonString(json, "app_name") orelse "?",
        .release_id = json_helpers.extractJsonString(json, "release_id") orelse "?",
        .trigger = json_helpers.extractJsonString(json, "trigger") orelse "rollback",
        .status = json_helpers.extractJsonString(json, "status") orelse "unknown",
        .rollout_state = json_helpers.extractJsonString(json, "rollout_state") orelse "unknown",
        .rollout_control_state = json_helpers.extractJsonString(json, "rollout_control_state") orelse "active",
        .completed_targets = @intCast(@max(0, json_helpers.extractJsonInt(json, "completed_targets") orelse 0)),
        .failed_targets = @intCast(@max(0, json_helpers.extractJsonInt(json, "failed_targets") orelse 0)),
        .remaining_targets = @intCast(@max(0, json_helpers.extractJsonInt(json, "remaining_targets") orelse 0)),
        .source_release_id = json_helpers.extractJsonString(json, "source_release_id"),
        .resumed_from_release_id = json_helpers.extractJsonString(json, "resumed_from_release_id"),
        .message = json_helpers.extractJsonString(json, "message"),
    };
}

fn printRollbackSummary(summary: RollbackSummary) void {
    write("app: {s}\n", .{summary.app_name});
    write("release: {s}\n", .{summary.release_id});
    write("trigger: {s}\n", .{summary.trigger});
    write("source_release_id: {s}\n", .{summary.source_release_id orelse "-"});
    write("resumed_from_release_id: {s}\n", .{summary.resumed_from_release_id orelse "-"});
    write("status: {s}\n", .{summary.status});
    write("rollout_state: {s}\n", .{summary.rollout_state});
    write("rollout_control_state: {s}\n", .{formatRolloutControlState(summary.rollout_control_state)});

    var progress_buf: [64]u8 = undefined;
    const progress = formatProgressCounts(&progress_buf, summary.completed_targets, summary.failed_targets, summary.remaining_targets);
    write("targets: {s}\n", .{progress});

    if (summary.message) |message| {
        write("message: {s}\n", .{message});
    }
}

fn formatProgressCounts(buf: []u8, completed_targets: usize, failed_targets: usize, remaining_targets: usize) []const u8 {
    if (failed_targets == 0 and remaining_targets == 0) {
        return std.fmt.bufPrint(buf, "{d} ok", .{completed_targets}) catch "?";
    }
    if (remaining_targets == 0) {
        return std.fmt.bufPrint(buf, "{d} ok, {d} fail", .{ completed_targets, failed_targets }) catch "?";
    }
    return std.fmt.bufPrint(buf, "{d} ok, {d} fail, {d} left", .{
        completed_targets,
        failed_targets,
        remaining_targets,
    }) catch "?";
}

fn formatRolloutControlState(control_state: []const u8) []const u8 {
    if (std.mem.eql(u8, control_state, "active")) return "-";
    if (std.mem.eql(u8, control_state, "cancel_requested")) return "cancel";
    return control_state;
}

test "parseHistoryObject extracts app release fields" {
    const entry = parseHistoryObject(
        \\{"id":"dep-1","app":"demo-app","service":"demo-app","trigger":"apply","status":"completed","manifest_hash":"sha256:123","created_at":42,"service_count":2,"worker_count":1,"cron_count":3,"training_job_count":4,"completed_targets":0,"failed_targets":0,"remaining_targets":2,"source_release_id":null,"message":null}
    );

    try std.testing.expectEqualStrings("dep-1", entry.id);
    try std.testing.expectEqualStrings("demo-app", entry.app.?);
    try std.testing.expectEqualStrings("demo-app", entry.service);
    try std.testing.expectEqualStrings("apply", entry.trigger);
    try std.testing.expectEqualStrings("completed", entry.status);
    try std.testing.expectEqualStrings("sha256:123", entry.manifest_hash);
    try std.testing.expectEqual(@as(i64, 42), entry.created_at);
    try std.testing.expectEqual(@as(usize, 2), entry.service_count);
    try std.testing.expectEqual(@as(usize, 1), entry.worker_count);
    try std.testing.expectEqual(@as(usize, 3), entry.cron_count);
    try std.testing.expectEqual(@as(usize, 4), entry.training_job_count);
    try std.testing.expect(entry.source_release_id == null);
    try std.testing.expect(entry.message == null);
}

test "historyEntryFromDeployment matches remote app history shape" {
    const dep = store.DeploymentRecord{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .manifest_hash = "sha256:123",
        .config_snapshot = "{\"services\":[{\"name\":\"web\"}]}",
        .status = "completed",
        .message = "healthy",
        .created_at = 42,
    };

    const local = historyEntryFromDeployment(dep);
    var w = json_out.JsonWriter{};
    writeHistoryJsonObject(&w, local);
    const remote = parseHistoryObject(w.getWritten());

    try std.testing.expectEqualStrings(local.id, remote.id);
    try std.testing.expectEqualStrings(local.app.?, remote.app.?);
    try std.testing.expectEqualStrings(local.service, remote.service);
    try std.testing.expectEqualStrings(local.trigger, remote.trigger);
    try std.testing.expectEqualStrings(local.status, remote.status);
    try std.testing.expectEqualStrings(local.rollout_state, remote.rollout_state);
    try std.testing.expectEqualStrings(local.manifest_hash, remote.manifest_hash);
    try std.testing.expectEqual(local.created_at, remote.created_at);
    try std.testing.expectEqual(local.service_count, remote.service_count);
    try std.testing.expectEqual(local.completed_targets, remote.completed_targets);
    try std.testing.expectEqual(local.failed_targets, remote.failed_targets);
    try std.testing.expectEqual(local.remaining_targets, remote.remaining_targets);
    try std.testing.expect(local.source_release_id == null);
    try std.testing.expectEqualStrings(local.message.?, remote.message.?);
}

test "writeHistoryJsonObject round-trips through remote parser" {
    const entry = HistoryEntryView{
        .id = "dep-1",
        .app = "demo-app",
        .service = "demo-app",
        .trigger = "rollback",
        .status = "completed",
        .manifest_hash = "sha256:123",
        .created_at = 42,
        .service_count = 1,
        .worker_count = 2,
        .cron_count = 3,
        .training_job_count = 4,
        .completed_targets = 1,
        .failed_targets = 0,
        .remaining_targets = 0,
        .source_release_id = "dep-0",
        .resumed_from_release_id = "dep-paused",
        .superseded_by_release_id = "dep-next",
        .message = "healthy",
        .rollout_targets_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"ready\",\"reason\":null}]",
        .rollout_checkpoint_json = "{\"engine\":\"cluster\",\"phase\":\"cutover\",\"batch_start\":0,\"batch_end\":1,\"total_targets\":1,\"completed_targets\":1,\"failed_targets\":0,\"remaining_targets\":0,\"control_state\":\"active\"}",
    };

    var w = json_out.JsonWriter{};
    writeHistoryJsonObject(&w, entry);

    const parsed = parseHistoryObject(w.getWritten());
    try std.testing.expectEqualStrings(entry.id, parsed.id);
    try std.testing.expectEqualStrings(entry.app.?, parsed.app.?);
    try std.testing.expectEqualStrings(entry.service, parsed.service);
    try std.testing.expectEqualStrings(entry.trigger, parsed.trigger);
    try std.testing.expectEqualStrings(entry.status, parsed.status);
    try std.testing.expectEqualStrings(entry.rollout_state, parsed.rollout_state);
    try std.testing.expectEqualStrings(entry.manifest_hash, parsed.manifest_hash);
    try std.testing.expectEqual(entry.created_at, parsed.created_at);
    try std.testing.expectEqual(entry.service_count, parsed.service_count);
    try std.testing.expectEqual(entry.worker_count, parsed.worker_count);
    try std.testing.expectEqual(entry.cron_count, parsed.cron_count);
    try std.testing.expectEqual(entry.training_job_count, parsed.training_job_count);
    try std.testing.expectEqual(entry.completed_targets, parsed.completed_targets);
    try std.testing.expectEqual(entry.failed_targets, parsed.failed_targets);
    try std.testing.expectEqual(entry.remaining_targets, parsed.remaining_targets);
    try std.testing.expectEqualStrings(entry.source_release_id.?, parsed.source_release_id.?);
    try std.testing.expectEqualStrings(entry.resumed_from_release_id.?, parsed.resumed_from_release_id.?);
    try std.testing.expectEqualStrings(entry.superseded_by_release_id.?, parsed.superseded_by_release_id.?);
    try std.testing.expectEqualStrings(entry.message.?, parsed.message.?);
    try std.testing.expect(parsed.rollout_targets_json != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed.rollout_targets_json.?, "\"workload_name\":\"web\"") != null);
    try std.testing.expect(parsed.rollout_checkpoint_json != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed.rollout_checkpoint_json.?, "\"phase\":\"cutover\"") != null);
}

test "writeHistoryJsonObject includes nested release markers" {
    const entry = HistoryEntryView{
        .id = "dep-1",
        .app = "demo-app",
        .service = "demo-app",
        .trigger = "rollback",
        .status = "completed",
        .manifest_hash = "sha256:123",
        .created_at = 42,
        .service_count = 1,
        .worker_count = 2,
        .cron_count = 3,
        .training_job_count = 4,
        .completed_targets = 1,
        .failed_targets = 0,
        .remaining_targets = 0,
        .source_release_id = "dep-0",
        .message = "healthy",
        .rollout_targets_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"ready\",\"reason\":null}]",
        .rollout_checkpoint_json = "{\"engine\":\"cluster\",\"phase\":\"cutover\",\"batch_start\":0,\"batch_end\":1,\"total_targets\":1,\"completed_targets\":1,\"failed_targets\":0,\"remaining_targets\":0,\"control_state\":\"active\"}",
        .is_current = true,
        .is_previous_successful = false,
    };

    var w = json_out.JsonWriter{};
    writeHistoryJsonObject(&w, entry);
    const json = w.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, json, "\"is_current\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release\":{\"id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_state\":\"unknown\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_targets\":[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"ready\",\"reason\":null}]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_checkpoint\":{\"engine\":\"cluster\",\"phase\":\"cutover\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout\":{\"state\":\"unknown\",\"control_state\":\"active\",\"completed_targets\":1,\"failed_targets\":0,\"remaining_targets\":0,\"failure_details\":null,\"targets\":[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"ready\",\"reason\":null}],\"checkpoint\":{\"engine\":\"cluster\",\"phase\":\"cutover\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"current\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"workloads\":{\"services\":1,\"workers\":2,\"crons\":3,\"training_jobs\":4}") != null);
}

test "writeHistoryJsonObject preserves failure details" {
    const entry = HistoryEntryView{
        .id = "dep-9",
        .app = "demo-app",
        .service = "demo-app",
        .trigger = "apply",
        .status = "failed",
        .manifest_hash = "sha256:999",
        .created_at = 900,
        .completed_targets = 0,
        .failed_targets = 1,
        .remaining_targets = 0,
        .source_release_id = null,
        .message = "one or more placements failed",
        .failure_details_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"reason\":\"placement_failed\"}]",
    };

    var w = json_out.JsonWriter{};
    writeHistoryJsonObject(&w, entry);
    const parsed = parseHistoryObject(w.getWritten());

    try std.testing.expect(parsed.failure_details_json != null);
    try std.testing.expect(std.mem.indexOf(u8, parsed.failure_details_json.?, "\"reason\":\"placement_failed\"") != null);
}

test "writeHistoryJsonObject preserves rollout control state" {
    const entry = HistoryEntryView{
        .id = "dep-6",
        .app = "demo-app",
        .service = "demo-app",
        .trigger = "apply",
        .status = "in_progress",
        .rollout_state = "blocked",
        .rollout_control_state = "paused",
        .manifest_hash = "sha256:666",
        .created_at = 600,
        .completed_targets = 1,
        .failed_targets = 0,
        .remaining_targets = 1,
        .source_release_id = null,
        .message = "apply in progress",
    };

    var w = json_out.JsonWriter{};
    writeHistoryJsonObject(&w, entry);
    const json = w.getWritten();
    const parsed = parseHistoryObject(json);

    try std.testing.expectEqualStrings("paused", parsed.rollout_control_state);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_control_state\":\"paused\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"control_state\":\"paused\"") != null);
}

test "formatRolloutControlState shortens active and cancel states" {
    try std.testing.expectEqualStrings("-", formatRolloutControlState("active"));
    try std.testing.expectEqualStrings("paused", formatRolloutControlState("paused"));
    try std.testing.expectEqualStrings("cancel", formatRolloutControlState("cancel_requested"));
}

test "parseRollbackSummary extracts rollout control state" {
    const summary = parseRollbackSummary(
        \\{"app_name":"demo-app","release_id":"dep-7","trigger":"rollback","status":"in_progress","rollout_state":"blocked","rollout_control_state":"paused","completed_targets":1,"failed_targets":0,"remaining_targets":1,"source_release_id":"dep-3","resumed_from_release_id":"dep-paused","message":"rollback in progress"}
    );

    try std.testing.expectEqualStrings("demo-app", summary.app_name);
    try std.testing.expectEqualStrings("dep-7", summary.release_id);
    try std.testing.expectEqualStrings("blocked", summary.rollout_state);
    try std.testing.expectEqualStrings("paused", summary.rollout_control_state);
    try std.testing.expectEqualStrings("dep-paused", summary.resumed_from_release_id.?);
}

test "historyEntryFromDeployment preserves partially failed local release state" {
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

    const local = historyEntryFromDeployment(dep);
    var w = json_out.JsonWriter{};
    writeHistoryJsonObject(&w, local);
    const remote = parseHistoryObject(w.getWritten());

    try std.testing.expectEqualStrings(local.id, remote.id);
    try std.testing.expectEqualStrings(local.app.?, remote.app.?);
    try std.testing.expectEqualStrings(local.service, remote.service);
    try std.testing.expectEqualStrings(local.trigger, remote.trigger);
    try std.testing.expectEqualStrings(local.status, remote.status);
    try std.testing.expectEqualStrings(local.manifest_hash, remote.manifest_hash);
    try std.testing.expectEqual(local.created_at, remote.created_at);
    try std.testing.expectEqual(local.service_count, remote.service_count);
    try std.testing.expectEqual(local.completed_targets, remote.completed_targets);
    try std.testing.expectEqual(local.failed_targets, remote.failed_targets);
    try std.testing.expectEqual(local.remaining_targets, remote.remaining_targets);
    try std.testing.expect(local.source_release_id == null);
    try std.testing.expectEqualStrings(local.message.?, remote.message.?);
}

test "local app history marks current rollback and previous successful release across lifecycle" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();

    try store.saveDeployment(.{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:1","rollout":{"strategy":"blue_green","parallelism":2,"delay_between_batches":5,"failure_action":"pause","health_check_timeout":30}}],"workers":[{"name":"migrate","image":"postgres:16","command":["sh","-c","psql -f /m.sql"]}],"crons":[{"name":"nightly","image":"alpine:3","command":["sh","-c","echo nightly"],"every":3600}],"training_jobs":[{"name":"finetune","image":"trainer:v1","command":["torchrun","train.py"],"gpus":4,"gpu_type":"H100","cpu_limit":2000,"memory_limit_mb":131072,"ib_required":true,"spare_ranks":1,"auto_restart":false,"max_restarts":3}]}
        ,
        .completed_targets = 1,
        .failed_targets = 0,
        .status = "completed",
        .rollout_control_state = "active",
        .message = "apply completed",
        .created_at = 100,
    });
    try store.saveDeployment(.{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\",\"image\":\"nginx:2\"}],\"workers\":[],\"crons\":[],\"training_jobs\":[]}",
        .completed_targets = 1,
        .failed_targets = 0,
        .status = "completed",
        .rollout_control_state = "active",
        .message = "apply completed",
        .created_at = 200,
    });
    try store.saveDeployment(.{
        .id = "dep-3",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "rollback",
        .source_release_id = "dep-1",
        .manifest_hash = "sha256:111",
        .config_snapshot =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:1","rollout":{"strategy":"blue_green","parallelism":2,"delay_between_batches":5,"failure_action":"pause","health_check_timeout":30}}],"workers":[{"name":"migrate","image":"postgres:16","command":["sh","-c","psql -f /m.sql"]}],"crons":[{"name":"nightly","image":"alpine:3","command":["sh","-c","echo nightly"],"every":3600}],"training_jobs":[{"name":"finetune","image":"trainer:v1","command":["torchrun","train.py"],"gpus":4,"gpu_type":"H100","cpu_limit":2000,"memory_limit_mb":131072,"ib_required":true,"spare_ranks":1,"auto_restart":false,"max_restarts":3}]}
        ,
        .completed_targets = 1,
        .failed_targets = 0,
        .status = "completed",
        .rollout_control_state = "active",
        .message = "rollback completed",
        .created_at = 300,
    });

    var deployments = try release_history.listAppReleases(alloc, "demo-app");
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 3), deployments.items.len);
    try std.testing.expectEqualStrings("dep-3", deployments.items[0].id);
    try std.testing.expectEqualStrings("dep-2", deployments.items[1].id);
    try std.testing.expectEqualStrings("dep-1", deployments.items[2].id);

    const previous_successful_id = previousSuccessfulReleaseId(deployments.items);
    try std.testing.expect(previous_successful_id != null);
    try std.testing.expectEqualStrings("dep-2", previous_successful_id.?);

    var current = historyEntryFromDeployment(deployments.items[0]);
    current.is_current = true;
    current.is_previous_successful = previous_successful_id != null and std.mem.eql(u8, current.id, previous_successful_id.?);

    var previous_successful = historyEntryFromDeployment(deployments.items[1]);
    previous_successful.is_current = false;
    previous_successful.is_previous_successful = previous_successful_id != null and std.mem.eql(u8, previous_successful.id, previous_successful_id.?);

    try std.testing.expect(current.is_current);
    try std.testing.expect(!current.is_previous_successful);
    try std.testing.expectEqualStrings("rollback", current.trigger);
    try std.testing.expectEqualStrings("dep-1", current.source_release_id.?);
    try std.testing.expectEqual(@as(usize, 1), current.service_count);
    try std.testing.expectEqual(@as(usize, 1), current.worker_count);
    try std.testing.expectEqual(@as(usize, 1), current.cron_count);
    try std.testing.expectEqual(@as(usize, 1), current.training_job_count);

    try std.testing.expect(!previous_successful.is_current);
    try std.testing.expect(previous_successful.is_previous_successful);
    try std.testing.expectEqualStrings("apply", previous_successful.trigger);
    try std.testing.expect(previous_successful.source_release_id == null);
    try std.testing.expectEqual(@as(usize, 1), previous_successful.service_count);
    try std.testing.expectEqual(@as(usize, 0), previous_successful.worker_count);
    try std.testing.expectEqual(@as(usize, 0), previous_successful.cron_count);
    try std.testing.expectEqual(@as(usize, 0), previous_successful.training_job_count);
}

test "local app history preserves paused rollout current and previous successful release" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();

    try store.saveDeployment(.{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}],\"workers\":[],\"crons\":[],\"training_jobs\":[]}",
        .completed_targets = 1,
        .failed_targets = 0,
        .status = "completed",
        .rollout_control_state = "active",
        .message = "apply completed",
        .created_at = 100,
    });
    try store.saveDeployment(.{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"},{\"name\":\"db\"}],\"workers\":[],\"crons\":[],\"training_jobs\":[]}",
        .completed_targets = 1,
        .failed_targets = 0,
        .status = "in_progress",
        .rollout_control_state = "paused",
        .message = "rollout paused after first batch",
        .rollout_targets_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"ready\",\"reason\":null},{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"state\":\"starting\",\"reason\":null}]",
        .rollout_checkpoint_json = "{\"engine\":\"local\",\"phase\":\"batch\",\"batch_start\":1,\"batch_end\":2,\"total_targets\":2,\"completed_targets\":1,\"failed_targets\":0,\"remaining_targets\":1,\"control_state\":\"paused\"}",
        .created_at = 200,
    });

    var deployments = try release_history.listAppReleases(alloc, "demo-app");
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 2), deployments.items.len);
    try std.testing.expectEqualStrings("dep-2", deployments.items[0].id);
    try std.testing.expectEqualStrings("dep-1", deployments.items[1].id);

    const previous_successful_id = previousSuccessfulReleaseId(deployments.items);
    try std.testing.expect(previous_successful_id != null);
    try std.testing.expectEqualStrings("dep-1", previous_successful_id.?);

    var current = historyEntryFromDeployment(deployments.items[0]);
    current.is_current = true;
    current.is_previous_successful = previous_successful_id != null and std.mem.eql(u8, current.id, previous_successful_id.?);

    var previous_successful = historyEntryFromDeployment(deployments.items[1]);
    previous_successful.is_current = false;
    previous_successful.is_previous_successful = previous_successful_id != null and std.mem.eql(u8, previous_successful.id, previous_successful_id.?);

    try std.testing.expect(current.is_current);
    try std.testing.expect(!current.is_previous_successful);
    try std.testing.expectEqualStrings("in_progress", current.status);
    try std.testing.expectEqualStrings("blocked", current.rollout_state);
    try std.testing.expectEqualStrings("paused", current.rollout_control_state);
    try std.testing.expect(current.rollout_checkpoint_json != null);
    try std.testing.expect(current.rollout_targets_json != null);
    try std.testing.expect(std.mem.indexOf(u8, current.rollout_checkpoint_json.?, "\"control_state\":\"paused\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, current.rollout_targets_json.?, "\"workload_name\":\"db\",\"state\":\"starting\"") != null);

    try std.testing.expect(!previous_successful.is_current);
    try std.testing.expect(previous_successful.is_previous_successful);
    try std.testing.expectEqualStrings("completed", previous_successful.status);
    try std.testing.expectEqualStrings("stable", previous_successful.rollout_state);
}

test "local app history preserves exact partial failure details for current release" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();

    try store.saveDeployment(.{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}],\"workers\":[],\"crons\":[],\"training_jobs\":[]}",
        .completed_targets = 1,
        .failed_targets = 0,
        .status = "completed",
        .rollout_control_state = "active",
        .message = "apply completed",
        .created_at = 100,
    });
    try store.saveDeployment(.{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"},{\"name\":\"db\"}],\"workers\":[{\"name\":\"migrate\"}],\"crons\":[],\"training_jobs\":[]}",
        .completed_targets = 1,
        .failed_targets = 1,
        .status = "partially_failed",
        .rollout_control_state = "active",
        .message = "one or more rollout targets failed",
        .failure_details_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"reason\":\"placement_failed\"}]",
        .rollout_targets_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"ready\",\"reason\":null},{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"state\":\"failed\",\"reason\":\"placement_failed\"}]",
        .created_at = 200,
    });

    var deployments = try release_history.listAppReleases(alloc, "demo-app");
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 2), deployments.items.len);
    const previous_successful_id = previousSuccessfulReleaseId(deployments.items);
    try std.testing.expect(previous_successful_id != null);
    try std.testing.expectEqualStrings("dep-1", previous_successful_id.?);

    var current = historyEntryFromDeployment(deployments.items[0]);
    current.is_current = true;
    current.is_previous_successful = false;

    var previous_successful = historyEntryFromDeployment(deployments.items[1]);
    previous_successful.is_current = false;
    previous_successful.is_previous_successful = true;

    try std.testing.expect(current.is_current);
    try std.testing.expectEqualStrings("partially_failed", current.status);
    try std.testing.expectEqualStrings("degraded", current.rollout_state);
    try std.testing.expect(current.failure_details_json != null);
    try std.testing.expect(current.rollout_targets_json != null);
    try std.testing.expect(std.mem.indexOf(u8, current.failure_details_json.?, "\"workload_name\":\"db\",\"reason\":\"placement_failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, current.rollout_targets_json.?, "\"workload_name\":\"db\",\"state\":\"failed\",\"reason\":\"placement_failed\"") != null);
    try std.testing.expectEqual(@as(usize, 2), current.service_count);
    try std.testing.expectEqual(@as(usize, 1), current.worker_count);

    try std.testing.expect(previous_successful.is_previous_successful);
    try std.testing.expectEqualStrings("completed", previous_successful.status);
    try std.testing.expectEqualStrings("stable", previous_successful.rollout_state);
}

test "formatHistoryMessage appends failure detail summary" {
    var buf: [256]u8 = undefined;
    const text = formatHistoryMessage(
        &buf,
        "one or more placements failed",
        "[{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"reason\":\"placement_failed\"}]",
    );

    try std.testing.expect(std.mem.indexOf(u8, text, "db: placement_failed") != null);
}

pub fn runWorker(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var manifest_path: []const u8 = manifest_loader.default_filename;
    var worker_name: ?[]const u8 = null;
    var server_addr: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                return OpsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return OpsError.InvalidArgument;
            };
        } else {
            worker_name = arg;
        }
    }

    const name = worker_name orelse {
        writeErr("usage: yoq run-worker [-f manifest.toml] [--server host:port] <name>\n", .{});
        return OpsError.InvalidArgument;
    };

    if (server_addr) |addr_str| {
        const app_name = try currentAppNameAlloc(alloc);
        defer alloc.free(app_name);

        const server = cli.parseServerAddr(addr_str);
        const path = std.fmt.allocPrint(alloc, "/apps/{s}/workers/{s}/run", .{ app_name, name }) catch return OpsError.StoreError;
        defer alloc.free(path);

        var token_buf: [64]u8 = undefined;
        const token = cli.readApiToken(&token_buf);
        var resp = http_client.postWithAuth(alloc, server.ip, server.port, path, "{}", token) catch {
            writeErr("failed to connect to cluster server\n", .{});
            return OpsError.ConnectionFailed;
        };
        defer resp.deinit(alloc);

        if (resp.status_code != 200) {
            writeErr("worker run failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
            return OpsError.DeploymentFailed;
        }

        write("{s}\n", .{resp.body});
        return;
    }

    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
        writeErr("hint: create one with 'yoq init'\n", .{});
        return OpsError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    const worker = manifest.workerByName(name) orelse {
        writeErr("unknown worker: {s}\n", .{name});
        return OpsError.UnknownService;
    };

    writeErr("pulling {s}...\n", .{worker.image});
    if (!orchestrator.ensureImageAvailable(alloc, worker.image)) {
        writeErr("failed to pull image: {s}\n", .{worker.image});
        return OpsError.DeploymentFailed;
    }

    var cwd_buf: [4096]u8 = undefined;
    const cwd = platform.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    writeErr("running worker {s}...\n", .{name});
    if (orchestrator.runOneShot(alloc, worker.image, worker.command, worker.env, worker.volumes, worker.working_dir, name, manifest.volumes, app_name)) {
        writeErr("worker {s} completed successfully\n", .{name});
    } else {
        writeErr("worker {s} failed\n", .{name});
        return OpsError.DeploymentFailed;
    }
}
