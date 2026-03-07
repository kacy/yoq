// commands — status and metrics CLI commands
//
// extracted from main.zig for modularity. these handle both local
// (direct store/cgroup reads) and remote (API client) modes.

const std = @import("std");
const builtin = @import("builtin");
const cli = @import("../lib/cli.zig");
const json_out = @import("../lib/json_output.zig");
const store = @import("../state/store.zig");
const monitor = @import("monitor.zig");
const cgroups = @import("cgroups.zig");
const ebpf = if (builtin.os.tag == .linux) @import("../network/ebpf.zig") else struct {
    pub const PairEntry = struct {
        key: struct {
            src_ip: u32,
            dst_ip: u32,
            dst_port: u16,
        },
        value: struct {
            connections: u64,
            packets: u64,
            bytes: u64,
            errors: u64,
        },
    };

    pub const Metrics = struct {
        packets: u64 = 0,
        bytes: u64 = 0,
    };

    pub const Collector = struct {
        pub fn readMetrics(_: *const @This(), _: u32) ?Metrics {
            return null;
        }

        pub fn readPairMetrics(_: *const @This(), _: []PairEntry) usize {
            return 0;
        }
    };

    pub const MetricsCollector = Collector;

    pub fn getMetricsCollector() ?*Collector {
        return null;
    }

    pub fn ipToNetworkOrder(_: [4]u8) u32 {
        return 0;
    }
};
const ip = @import("../network/ip.zig");
const http_client = @import("../cluster/http_client.zig");
const json_helpers = @import("../lib/json_helpers.zig");
const health = @import("../manifest/health.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const formatCount = cli.formatCount;

const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;
const extractJsonFloat = json_helpers.extractJsonFloat;

const CommandsError = error{
    InvalidArgument,
    ConnectionFailed,
    ServerError,
    StoreError,
    OutOfMemory,
};

// -- status command --

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
                return CommandsError.InvalidArgument;
            };
            server = cli.parseServerAddr(addr_str);
        }
    }

    // cluster mode: query API endpoint
    if (server) |s| {
        statusRemote(alloc, s.ip, s.port, verbose) catch |e| return e;
        return;
    }

    // local mode: read directly from store and cgroups
    statusLocal(alloc, verbose) catch |e| return e;
}

fn statusLocal(alloc: std.mem.Allocator, verbose: bool) CommandsError!void {
    var records = store.listAll(alloc) catch {
        writeErr("failed to list containers\n", .{});
        return CommandsError.StoreError;
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
        return CommandsError.StoreError;
    };
    defer snapshots.deinit(alloc);

    printStatusTable(snapshots.items, verbose);
}

fn statusRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16, verbose: bool) CommandsError!void {
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, "/v1/status", token) catch {
        writeErr("failed to connect to server\n", .{});
        return CommandsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        return CommandsError.ServerError;
    }

    // parse JSON response into snapshots for display
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

        // parse PSI metrics if present in the response
        const psi_cpu = parsePsiFromJson(obj, "psi_cpu_some", "psi_cpu_full");
        const psi_mem = parsePsiFromJson(obj, "psi_mem_some", "psi_mem_full");

        // parse cpu quota percentage if present
        const cpu_quota_pct: ?f64 = if (extractJsonFloat(obj, "cpu_quota_pct")) |v|
            (if (v > 0.0) v else null)
        else
            null;

        // parse memory limit (0 or absent means unlimited)
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
            .memory_bytes = @intCast(extractJsonInt(obj, "memory_bytes") orelse 0),
            .psi_cpu = psi_cpu,
            .psi_memory = psi_mem,
            .running_count = @intCast(extractJsonInt(obj, "running") orelse 0),
            .desired_count = @intCast(extractJsonInt(obj, "desired") orelse 0),
            .uptime_secs = extractJsonInt(obj, "uptime_secs") orelse 0,
            .memory_limit = memory_limit,
            .cpu_quota_pct = cpu_quota_pct,
        }) catch return CommandsError.OutOfMemory;
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
    // PSI pressure metrics
    if (snap.psi_cpu) |psi| {
        write("  cpu pressure:    some={d:.1}%  full={d:.1}%\n", .{ psi.some_avg10, psi.full_avg10 });
    }
    if (snap.psi_memory) |psi| {
        write("  memory pressure: some={d:.1}%  full={d:.1}%\n", .{ psi.some_avg10, psi.full_avg10 });
    }

    // resource limits
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

    // auto-tuning suggestions with concrete numbers
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
        if (snap.memory_limit) |limit| {
            w.uintField("memory_limit", limit);
        } else {
            w.nullField("memory_limit");
        }
        if (snap.cpu_quota_pct) |quota| {
            w.floatField("cpu_quota_pct", quota);
        } else {
            w.nullField("cpu_quota_pct");
        }
        w.endObject();
    }
    w.endArray();
    w.flush();
}

/// parse PSI metrics from a JSON object's some/full fields.
/// returns null if neither field is present.
fn parsePsiFromJson(json: []const u8, some_key: []const u8, full_key: []const u8) ?cgroups.PsiMetrics {
    const some = extractJsonFloat(json, some_key) orelse return null;
    const full = extractJsonFloat(json, full_key) orelse return null;
    return .{ .some_avg10 = some, .full_avg10 = full };
}

// -- metrics command --

pub fn metrics(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var service_filter: ?[]const u8 = null;
    var server: ?cli.ServerAddr = null;
    var pairs_mode = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return CommandsError.InvalidArgument;
            };
            server = cli.parseServerAddr(addr_str);
        } else if (std.mem.eql(u8, arg, "--pairs")) {
            pairs_mode = true;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            service_filter = arg;
        }
    }

    if (pairs_mode) {
        if (server) |s| {
            metricsPairsRemote(alloc, s.ip, s.port) catch |e| return e;
        } else {
            metricsPairs(alloc) catch |e| return e;
        }
        return;
    }

    if (server) |s| {
        metricsRemote(alloc, s.ip, s.port, service_filter) catch |e| return e;
        return;
    }

    metricsLocal(alloc, service_filter) catch |e| return e;
}

fn metricsLocal(alloc: std.mem.Allocator, service_filter: ?[]const u8) CommandsError!void {
    var records = store.listAll(alloc) catch {
        writeErr("failed to list containers\n", .{});
        return CommandsError.StoreError;
    };
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
    }

    if (records.items.len == 0) {
        if (cli.output_mode == .json) {
            var w = json_out.JsonWriter{};
            w.beginArray();
            w.endArray();
            w.flush();
        } else {
            write("no services running\n", .{});
        }
        return;
    }

    const mc = ebpf.getMetricsCollector();

    if (cli.output_mode == .json) {
        metricsLocalJson(records.items, mc, service_filter);
        return;
    }

    write("{s:<12} {s:<10} {s:<16} {s:<12} {s}\n", .{
        "SERVICE", "CONTAINER", "IP", "PACKETS", "BYTES",
    });

    var found = false;
    for (records.items) |rec| {
        if (!std.mem.eql(u8, rec.status, "running")) continue;

        if (service_filter) |svc| {
            if (!std.mem.eql(u8, rec.hostname, svc)) continue;
        }

        const ip_str = rec.ip_address orelse continue;
        const short_id = if (rec.id.len >= 6) rec.id[0..6] else rec.id;

        var packets: u64 = 0;
        var bytes: u64 = 0;
        if (mc) |collector_const| {
            var collector: *ebpf.MetricsCollector = @constCast(collector_const);
            if (ip.parseIp(ip_str)) |addr| {
                const ip_net = ebpf.ipToNetworkOrder(addr);
                if (collector.readMetrics(ip_net)) |m| {
                    packets = m.packets;
                    bytes = m.bytes;
                }
            }
        }

        var bytes_buf: [16]u8 = undefined;
        const bytes_str = monitor.formatBytes(&bytes_buf, bytes);

        var pkt_buf: [16]u8 = undefined;
        const pkt_str = formatCount(&pkt_buf, packets);

        write("{s:<12} {s:<10} {s:<16} {s:<12} {s}\n", .{
            rec.hostname, short_id, ip_str, pkt_str, bytes_str,
        });
        found = true;
    }

    if (!found) {
        if (service_filter) |svc| {
            write("no running containers for service '{s}'\n", .{svc});
        } else {
            write("no running containers with network\n", .{});
        }
    }
}

fn metricsRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16, service_filter: ?[]const u8) CommandsError!void {
    // build path with optional query param
    var path_buf: [128]u8 = undefined;
    const path = if (service_filter) |svc|
        std.fmt.bufPrint(&path_buf, "/v1/metrics?service={s}", .{svc}) catch "/v1/metrics"
    else
        @as([]const u8, "/v1/metrics");

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, path, token) catch {
        writeErr("failed to connect to server\n", .{});
        return CommandsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        return CommandsError.ServerError;
    }

    // API already returns JSON — pass through directly
    if (cli.output_mode == .json) {
        write("{s}\n", .{resp.body});
        return;
    }

    write("{s:<12} {s:<10} {s:<16} {s:<12} {s}\n", .{
        "SERVICE", "CONTAINER", "IP", "PACKETS", "BYTES",
    });

    var found = false;
    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        const service = extractJsonString(obj, "service") orelse "?";
        const container_id = extractJsonString(obj, "container") orelse "?";
        const ip_str = extractJsonString(obj, "ip") orelse "?";
        const packets: u64 = @intCast(extractJsonInt(obj, "packets") orelse 0);
        const bytes: u64 = @intCast(extractJsonInt(obj, "bytes") orelse 0);

        var bytes_buf: [16]u8 = undefined;
        const bytes_str = monitor.formatBytes(&bytes_buf, bytes);

        var pkt_buf: [16]u8 = undefined;
        const pkt_str = formatCount(&pkt_buf, packets);

        write("{s:<12} {s:<10} {s:<16} {s:<12} {s}\n", .{
            service, container_id, ip_str, pkt_str, bytes_str,
        });
        found = true;
    }

    if (!found) {
        write("no metrics available\n", .{});
    }
}

fn metricsPairs(alloc: std.mem.Allocator) CommandsError!void {
    const mc = ebpf.getMetricsCollector() orelse {
        write("metrics collector not loaded (requires root)\n", .{});
        return;
    };

    var records = store.listAll(alloc) catch {
        writeErr("failed to list containers\n", .{});
        return CommandsError.StoreError;
    };
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
    }

    if (cli.output_mode == .json) {
        metricsPairsJson(records.items, mc);
        return;
    }

    var entries: [1024]ebpf.PairEntry = undefined;
    const count = mc.readPairMetrics(&entries);

    if (count == 0) {
        write("no pair metrics available\n", .{});
        return;
    }

    write("{s:<14} {s:<14} {s:<8} {s:<12} {s:<12} {s:<10} {s}\n", .{
        "FROM", "TO", "PORT", "CONNECTIONS", "PACKETS", "BYTES", "ERRORS",
    });

    for (entries[0..count]) |entry| {
        const src_name = resolveIpName(entry.key.src_ip, records.items);
        const dst_name = resolveIpName(entry.key.dst_ip, records.items);
        const port_val = std.mem.nativeTo(u16, entry.key.dst_port, .big);

        var conn_buf: [16]u8 = undefined;
        const conn_str = formatCount(&conn_buf, entry.value.connections);
        var pkt_buf: [16]u8 = undefined;
        const pkt_str = formatCount(&pkt_buf, entry.value.packets);
        var bytes_buf: [16]u8 = undefined;
        const bytes_str = monitor.formatBytes(&bytes_buf, entry.value.bytes);
        var err_buf: [16]u8 = undefined;
        const err_str = formatCount(&err_buf, entry.value.errors);

        write("{s:<14} {s:<14} {d:<8} {s:<12} {s:<12} {s:<10} {s}\n", .{
            src_name, dst_name, port_val, conn_str, pkt_str, bytes_str, err_str,
        });
    }
}

fn metricsPairsRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16) CommandsError!void {
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, "/v1/metrics?mode=pairs", token) catch {
        writeErr("failed to connect to server\n", .{});
        return CommandsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        return CommandsError.ServerError;
    }

    if (cli.output_mode == .json) {
        write("{s}\n", .{resp.body});
        return;
    }

    write("{s:<14} {s:<14} {s:<8} {s:<12} {s:<12} {s:<10} {s}\n", .{
        "FROM", "TO", "PORT", "CONNECTIONS", "PACKETS", "BYTES", "ERRORS",
    });

    var found = false;
    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        const from = extractJsonString(obj, "from") orelse "?";
        const to = extractJsonString(obj, "to") orelse "?";
        const obj_port: u64 = @intCast(extractJsonInt(obj, "port") orelse 0);
        const connections: u64 = @intCast(extractJsonInt(obj, "connections") orelse 0);
        const packets: u64 = @intCast(extractJsonInt(obj, "packets") orelse 0);
        const bytes: u64 = @intCast(extractJsonInt(obj, "bytes") orelse 0);
        const errors: u64 = @intCast(extractJsonInt(obj, "errors") orelse 0);

        var conn_buf: [16]u8 = undefined;
        const conn_str = formatCount(&conn_buf, connections);
        var pkt_buf: [16]u8 = undefined;
        const pkt_str = formatCount(&pkt_buf, packets);
        var bytes_buf: [16]u8 = undefined;
        const bytes_str = monitor.formatBytes(&bytes_buf, bytes);
        var err_buf: [16]u8 = undefined;
        const err_str = formatCount(&err_buf, errors);

        write("{s:<14} {s:<14} {d:<8} {s:<12} {s:<12} {s:<10} {s}\n", .{
            from, to, obj_port, conn_str, pkt_str, bytes_str, err_str,
        });
        found = true;
    }

    if (!found) {
        write("no pair metrics available\n", .{});
    }
}

fn metricsLocalJson(records: []const store.ContainerRecord, mc: ?*const ebpf.MetricsCollector, service_filter: ?[]const u8) void {
    var w = json_out.JsonWriter{};
    w.beginArray();
    for (records) |rec| {
        if (!std.mem.eql(u8, rec.status, "running")) continue;
        if (service_filter) |svc| {
            if (!std.mem.eql(u8, rec.hostname, svc)) continue;
        }
        const ip_str = rec.ip_address orelse continue;
        const short_id = if (rec.id.len >= 6) rec.id[0..6] else rec.id;

        var packets: u64 = 0;
        var bytes: u64 = 0;
        if (mc) |collector| {
            if (ip.parseIp(ip_str)) |addr| {
                const ip_net = ebpf.ipToNetworkOrder(addr);
                if (collector.readMetrics(ip_net)) |m| {
                    packets = m.packets;
                    bytes = m.bytes;
                }
            }
        }

        w.beginObject();
        w.stringField("service", rec.hostname);
        w.stringField("container", short_id);
        w.stringField("ip", ip_str);
        w.uintField("packets", packets);
        w.uintField("bytes", bytes);
        w.endObject();
    }
    w.endArray();
    w.flush();
}

fn metricsPairsJson(records: []const store.ContainerRecord, mc: *const ebpf.MetricsCollector) void {
    var entries: [1024]ebpf.PairEntry = undefined;
    const count = @constCast(mc).readPairMetrics(&entries);

    var w = json_out.JsonWriter{};
    w.beginArray();
    for (entries[0..count]) |entry| {
        const src_name = resolveIpName(entry.key.src_ip, records);
        const dst_name = resolveIpName(entry.key.dst_ip, records);
        const port_val = std.mem.nativeTo(u16, entry.key.dst_port, .big);

        w.beginObject();
        w.stringField("from", src_name);
        w.stringField("to", dst_name);
        w.uintField("port", port_val);
        w.uintField("connections", entry.value.connections);
        w.uintField("packets", entry.value.packets);
        w.uintField("bytes", entry.value.bytes);
        w.uintField("errors", entry.value.errors);
        w.endObject();
    }
    w.endArray();
    w.flush();
}

/// resolve a network-order IP (u32) to a service hostname.
fn resolveIpName(ip_net: u32, records: []const store.ContainerRecord) []const u8 {
    const ip_bytes = std.mem.asBytes(&ip_net);
    for (records) |rec| {
        if (!std.mem.eql(u8, rec.status, "running")) continue;
        const rec_ip_str = rec.ip_address orelse continue;
        if (ip.parseIp(rec_ip_str)) |addr| {
            if (std.mem.eql(u8, &addr, ip_bytes[0..4])) return rec.hostname;
        }
    }
    return "unknown";
}
