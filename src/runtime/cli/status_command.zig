const std = @import("std");
const cli = @import("../../lib/cli.zig");
const json_out = @import("../../lib/json_output.zig");
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
    release_id: []const u8,
    status: []const u8,
    manifest_hash: []const u8,
    created_at: i64,
    service_count: usize,
    message: ?[]const u8,
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

    const snapshot: AppStatusSnapshot = .{
        .app_name = latest.app_name orelse latest.service_name,
        .release_id = latest.id,
        .status = latest.status,
        .manifest_hash = latest.manifest_hash,
        .created_at = latest.created_at,
        .service_count = countServices(latest.config_snapshot),
        .message = latest.message,
    };
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

fn printAppStatus(snapshot: AppStatusSnapshot) void {
    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginObject();
        w.stringField("app_name", snapshot.app_name);
        w.stringField("release_id", snapshot.release_id);
        w.stringField("status", snapshot.status);
        w.stringField("manifest_hash", snapshot.manifest_hash);
        w.intField("created_at", snapshot.created_at);
        w.uintField("service_count", snapshot.service_count);
        if (snapshot.message) |message| w.stringField("message", message) else w.nullField("message");
        w.endObject();
        w.flush();
        return;
    }

    write("{s:<14} {s:<14} {s:<14} {s:<20} {s:<14} {s}\n", .{
        "APP", "RELEASE", "STATUS", "TIMESTAMP", "SERVICES", "MESSAGE",
    });

    var ts_buf: [20]u8 = undefined;
    const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{snapshot.created_at}) catch "?";
    const msg = snapshot.message orelse "";

    var count_buf: [16]u8 = undefined;
    const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{snapshot.service_count}) catch "?";

    write("{s:<14} {s:<14} {s:<14} {s:<20} {s:<14} {s}\n", .{
        snapshot.app_name,
        cli.truncate(snapshot.release_id, 12),
        snapshot.status,
        ts_str,
        count_str,
        cli.truncate(msg, 40),
    });
}

fn parseAppStatusResponse(json: []const u8) AppStatusSnapshot {
    return .{
        .app_name = extractJsonString(json, "app_name") orelse "?",
        .release_id = extractJsonString(json, "release_id") orelse "?",
        .status = extractJsonString(json, "status") orelse "unknown",
        .manifest_hash = extractJsonString(json, "manifest_hash") orelse "?",
        .created_at = extractJsonInt(json, "created_at") orelse 0,
        .service_count = @intCast(@max(0, extractJsonInt(json, "service_count") orelse 0)),
        .message = extractJsonString(json, "message"),
    };
}

fn countServices(snapshot: []const u8) usize {
    const services = extractJsonArray(snapshot, "services") orelse return 0;
    var iter = json_helpers.extractJsonObjects(services);
    var count: usize = 0;
    while (iter.next() != null) count += 1;
    return count;
}

fn currentAppNameAlloc(alloc: std.mem.Allocator) ![]u8 {
    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.fs.cwd().realpath(".", &cwd_buf) catch return StatusError.StoreError;
    return alloc.dupe(u8, std.fs.path.basename(cwd)) catch return StatusError.OutOfMemory;
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
        \\{"app_name":"demo-app","release_id":"abc123def456","status":"completed","manifest_hash":"sha256:123","created_at":42,"service_count":2,"message":null}
    );

    try std.testing.expectEqualStrings("demo-app", snapshot.app_name);
    try std.testing.expectEqualStrings("abc123def456", snapshot.release_id);
    try std.testing.expectEqualStrings("completed", snapshot.status);
    try std.testing.expectEqualStrings("sha256:123", snapshot.manifest_hash);
    try std.testing.expectEqual(@as(i64, 42), snapshot.created_at);
    try std.testing.expectEqual(@as(usize, 2), snapshot.service_count);
    try std.testing.expect(snapshot.message == null);
}

test "countServices counts service objects in app snapshot" {
    const snapshot =
        \\{"app_name":"demo-app","services":[{"name":"web"},{"name":"db"},{"name":"worker"}]}
    ;
    try std.testing.expectEqual(@as(usize, 3), countServices(snapshot));
}
