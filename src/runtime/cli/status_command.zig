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

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return StatusError.InvalidArgument;
            };
            server = cli.parseServerAddr(addr_str);
        }
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
