const std = @import("std");
const builtin = @import("builtin");
const cli = @import("../../lib/cli.zig");
const json_out = @import("../../lib/json_output.zig");
const store = @import("../../state/store.zig");
const monitor = @import("../monitor.zig");
const ip = @import("../../network/ip.zig");
const http_client = @import("../../cluster/http_client.zig");
const json_helpers = @import("../../lib/json_helpers.zig");

const ebpf = if (builtin.os.tag == .linux) @import("../../network/ebpf.zig") else struct {
    pub const PairEntry = struct {
        key: struct { src_ip: u32, dst_ip: u32, dst_port: u16 },
        value: struct { connections: u64, packets: u64, bytes: u64, errors: u64 },
    };
    pub const Metrics = struct { packets: u64 = 0, bytes: u64 = 0 };
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

const write = cli.write;
const writeErr = cli.writeErr;
const formatCount = cli.formatCount;
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

const MetricsError = error{
    InvalidArgument,
    ConnectionFailed,
    ServerError,
    StoreError,
};

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
                return MetricsError.InvalidArgument;
            };
            server = cli.parseServerAddr(addr_str);
        } else if (std.mem.eql(u8, arg, "--pairs")) {
            pairs_mode = true;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            service_filter = arg;
        }
    }

    if (pairs_mode) {
        if (server) |s| try metricsPairsRemote(alloc, s.ip, s.port) else try metricsPairs(alloc);
        return;
    }

    if (server) |s| {
        try metricsRemote(alloc, s.ip, s.port, service_filter);
        return;
    }

    try metricsLocal(alloc, service_filter);
}

fn metricsLocal(alloc: std.mem.Allocator, service_filter: ?[]const u8) MetricsError!void {
    var records = store.listAll(alloc) catch {
        writeErr("failed to list containers\n", .{});
        return MetricsError.StoreError;
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
        const short_id = cli.truncate(rec.id, 6);

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
        if (service_filter) |svc| write("no running containers for service '{s}'\n", .{svc}) else write("no running containers with network\n", .{});
    }
}

fn metricsRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16, service_filter: ?[]const u8) MetricsError!void {
    var path_buf: [128]u8 = undefined;
    const path = if (service_filter) |svc|
        std.fmt.bufPrint(&path_buf, "/v1/metrics?service={s}", .{svc}) catch "/v1/metrics"
    else
        @as([]const u8, "/v1/metrics");

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, path, token) catch {
        writeErr("failed to connect to server\n", .{});
        return MetricsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        return MetricsError.ServerError;
    }

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
        const packets: u64 = @intCast(@max(0, extractJsonInt(obj, "packets") orelse 0));
        const bytes: u64 = @intCast(@max(0, extractJsonInt(obj, "bytes") orelse 0));

        var bytes_buf: [16]u8 = undefined;
        const bytes_str = monitor.formatBytes(&bytes_buf, bytes);
        var pkt_buf: [16]u8 = undefined;
        const pkt_str = formatCount(&pkt_buf, packets);

        write("{s:<12} {s:<10} {s:<16} {s:<12} {s}\n", .{
            service, container_id, ip_str, pkt_str, bytes_str,
        });
        found = true;
    }

    if (!found) write("no metrics available\n", .{});
}

fn metricsPairs(alloc: std.mem.Allocator) MetricsError!void {
    const mc = ebpf.getMetricsCollector() orelse {
        write("metrics collector not loaded (requires root)\n", .{});
        return;
    };

    var records = store.listAll(alloc) catch {
        writeErr("failed to list containers\n", .{});
        return MetricsError.StoreError;
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

fn metricsPairsRemote(alloc: std.mem.Allocator, addr: [4]u8, port: u16) MetricsError!void {
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, addr, port, "/v1/metrics?mode=pairs", token) catch {
        writeErr("failed to connect to server\n", .{});
        return MetricsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        return MetricsError.ServerError;
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
        const packets: u64 = @intCast(@max(0, extractJsonInt(obj, "packets") orelse 0));
        const bytes: u64 = @intCast(@max(0, extractJsonInt(obj, "bytes") orelse 0));
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

    if (!found) write("no pair metrics available\n", .{});
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
        const short_id = cli.truncate(rec.id, 6);

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
