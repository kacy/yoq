// commands — status and metrics CLI commands
//
// extracted from main.zig for modularity. these handle both local
// (direct store/cgroup reads) and remote (API client) modes.

const std = @import("std");
const cli = @import("../lib/cli.zig");
const store = @import("../state/store.zig");
const monitor = @import("monitor.zig");
const cgroups = @import("cgroups.zig");
const ebpf = @import("../network/ebpf.zig");
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

// -- status command --

pub fn status(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var verbose = false;
    var server: ?cli.ServerAddr = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                std.process.exit(1);
            };
            server = cli.parseServerAddr(addr_str);
        }
    }

    // cluster mode: query API endpoint
    if (server) |s| {
        statusRemote(alloc, s.ip, s.port, verbose);
        return;
    }

    // local mode: read directly from store and cgroups
    statusLocal(alloc, verbose);
}

fn statusLocal(alloc: std.mem.Allocator, verbose: bool) void {
    var records = store.listAll(alloc) catch {
        writeErr("failed to list containers\n", .{});
        std.process.exit(1);
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
        std.process.exit(1);
    };
    defer snapshots.deinit(alloc);

    printStatusTable(snapshots.items, verbose);
}

fn statusRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16, verbose: bool) void {
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, "/v1/status", token) catch {
        writeErr("failed to connect to server\n", .{});
        std.process.exit(1);
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        std.process.exit(1);
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
        }) catch {
            writeErr("failed to parse status response\n", .{});
            std.process.exit(1);
        };
    }

    if (snapshots.items.len == 0) {
        write("no services running\n", .{});
        return;
    }

    printStatusTable(snapshots.items, verbose);
}

fn printStatusTable(snapshots: []const monitor.ServiceSnapshot, verbose: bool) void {
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

    // auto-tuning suggestions based on PSI
    if (snap.psi_memory) |psi| {
        if (psi.some_avg10 > 25.0) {
            write("  \xe2\x9a\xa0 memory pressure high \xe2\x80\x94 consider increasing memory limit\n", .{});
        }
    }
    if (snap.psi_cpu) |psi| {
        if (psi.some_avg10 > 50.0) {
            write("  \xe2\x9a\xa0 cpu pressure high \xe2\x80\x94 consider increasing cpu allocation\n", .{});
        }
    }
}

/// parse PSI metrics from a JSON object's some/full fields.
/// returns null if neither field is present.
fn parsePsiFromJson(json: []const u8, some_key: []const u8, full_key: []const u8) ?cgroups.PsiMetrics {
    const some = extractJsonFloat(json, some_key) orelse return null;
    const full = extractJsonFloat(json, full_key) orelse return null;
    return .{ .some_avg10 = some, .full_avg10 = full };
}

// -- metrics command --

pub fn metrics(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    var service_filter: ?[]const u8 = null;
    var server: ?cli.ServerAddr = null;
    var pairs_mode = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                std.process.exit(1);
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
            metricsPairsRemote(alloc, s.ip, s.port);
        } else {
            metricsPairs(alloc);
        }
        return;
    }

    if (server) |s| {
        metricsRemote(alloc, s.ip, s.port, service_filter);
        return;
    }

    metricsLocal(alloc, service_filter);
}

fn metricsLocal(alloc: std.mem.Allocator, service_filter: ?[]const u8) void {
    var records = store.listAll(alloc) catch {
        writeErr("failed to list containers\n", .{});
        std.process.exit(1);
    };
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
    }

    if (records.items.len == 0) {
        write("no services running\n", .{});
        return;
    }

    const mc = ebpf.getMetricsCollector();

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
        if (mc) |collector| {
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

fn metricsRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16, service_filter: ?[]const u8) void {
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
        std.process.exit(1);
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        std.process.exit(1);
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

fn metricsPairs(alloc: std.mem.Allocator) void {
    const mc = ebpf.getMetricsCollector() orelse {
        write("metrics collector not loaded (requires root)\n", .{});
        return;
    };

    var records = store.listAll(alloc) catch {
        writeErr("failed to list containers\n", .{});
        std.process.exit(1);
    };
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
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

fn metricsPairsRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16) void {
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, "/v1/metrics?mode=pairs", token) catch {
        writeErr("failed to connect to server\n", .{});
        std.process.exit(1);
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        std.process.exit(1);
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
