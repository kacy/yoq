const std = @import("std");
const cli = @import("../../lib/cli.zig");
const AppContext = @import("../../lib/app_context.zig").AppContext;
const networks = @import("../../network/local_networks.zig");
const ip = @import("../../network/ip.zig");

pub fn network(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    dispatch(args, ctx.alloc) catch |err| {
        switch (err) {
            error.InUse => cli.writeErr("network is referenced by a container; remove the container first\n", .{}),
            error.NotFound => cli.writeErr("network not found\n", .{}),
            error.InvalidName => cli.writeErr("network names must be DNS labels of at most 63 characters; default and none are reserved\n", .{}),
            error.SubnetInUse => cli.writeErr("subnet overlaps an existing network or host route\n", .{}),
            error.InvalidSubnet => cli.writeErr("subnet must be an aligned private IPv4 /24 outside 10.42.0.0/16\n", .{}),
            error.InvalidArgument => cli.writeErr("usage: yoq network create [--subnet CIDR] <name> | ls [--json] | inspect [--json] <name> | rm <name>\n", .{}),
            else => cli.writeErr("network operation failed: {}\n", .{err}),
        }
        return err;
    };
}

fn dispatch(args: anytype, alloc: std.mem.Allocator) !void {
    const action = args.next() orelse return error.InvalidArgument;
    if (std.mem.eql(u8, action, "create")) {
        var name: ?[]const u8 = null;
        var subnet: ?[]const u8 = null;
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--subnet")) {
                if (subnet != null) return error.InvalidArgument;
                subnet = args.next() orelse return error.InvalidArgument;
            } else if (std.mem.startsWith(u8, arg, "-") or name != null) return error.InvalidArgument else name = arg;
        }
        const record = try networks.create(alloc, name orelse return error.InvalidArgument, subnet);
        defer record.deinit(alloc);
        cli.write("{s}\n", .{record.name});
    } else if (std.mem.eql(u8, action, "ls")) {
        const json = if (args.next()) |arg| blk: {
            if (!std.mem.eql(u8, arg, "--json") or args.next() != null) return error.InvalidArgument;
            break :blk true;
        } else false;
        const records = try networks.list(alloc);
        defer {
            for (records) |record| record.deinit(alloc);
            alloc.free(records);
        }
        if (json) {
            var arena = std.heap.ArenaAllocator.init(alloc);
            defer arena.deinit();
            const values = try arena.allocator().alloc(JsonNetwork, records.len);
            for (records, values) |record, *value| value.* = try jsonNetwork(arena.allocator(), record, false);
            return writeJson(arena.allocator(), values);
        }
        cli.write("NAME  DRIVER  SUBNET  REFERENCES\n", .{});
        for (records) |record| {
            var buf: [16]u8 = undefined;
            cli.write("{s}  bridge  {s}/24  {d}\n", .{ record.name, ip.formatIp(record.subnet.base, &buf), record.references });
        }
    } else if (std.mem.eql(u8, action, "inspect")) {
        var name: ?[]const u8 = null;
        var json = false;
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--json") and !json) json = true else if (std.mem.startsWith(u8, arg, "-") or name != null) return error.InvalidArgument else name = arg;
        }
        const selected = name orelse return error.InvalidArgument;
        const record = try networks.inspect(alloc, selected);
        defer record.deinit(alloc);
        if (json) {
            var arena = std.heap.ArenaAllocator.init(alloc);
            defer arena.deinit();
            return writeJson(arena.allocator(), try jsonNetwork(arena.allocator(), record, true));
        }
        var subnet_buf: [16]u8 = undefined;
        var gateway_buf: [16]u8 = undefined;
        cli.write("name: {s}\ndriver: bridge\nbridge: {s}\nsubnet: {s}/24\ngateway: {s}\nreferences: {d}\ncreated: {d}\n", .{ record.name, record.bridge_name, ip.formatIp(record.subnet.base, &subnet_buf), ip.formatIp(record.subnet.gateway, &gateway_buf), record.references, record.created_at });
        const refs = try networks.attachments(alloc, selected);
        defer {
            for (refs) |ref| ref.deinit(alloc);
            alloc.free(refs);
        }
        for (refs) |ref| cli.write("container: {s}  name: {s}  address: {s}\n", .{ ref.container_id, ref.dns_name, ref.address orelse "stopped" });
    } else if (std.mem.eql(u8, action, "rm")) {
        const name = args.next() orelse return error.InvalidArgument;
        if (args.next() != null) return error.InvalidArgument;
        try networks.remove(name);
        cli.write("{s}\n", .{name});
    } else return error.InvalidArgument;
}

const JsonPort = struct {
    host_ip: []const u8,
    host_port: u16,
    container_port: u16,
    protocol: []const u8,
};
const JsonContainer = struct {
    id: []const u8,
    name: []const u8,
    address: ?[]const u8,
    aliases: []const []const u8,
    ports: []const JsonPort,
};
const JsonNetwork = struct {
    name: []const u8,
    driver: []const u8 = "bridge",
    bridge: []const u8,
    subnet: []const u8,
    gateway: []const u8,
    references: u64,
    created_at: i64,
    containers: ?[]const JsonContainer,
};

// The caller owns an arena so the complete report survives until serialization.
fn jsonNetwork(alloc: std.mem.Allocator, record: networks.Record, details: bool) !JsonNetwork {
    var address_buf: [16]u8 = undefined;
    var result: JsonNetwork = .{
        .name = record.name,
        .bridge = record.bridge_name,
        .subnet = try std.fmt.allocPrint(alloc, "{s}/24", .{ip.formatIp(record.subnet.base, &address_buf)}),
        .gateway = try alloc.dupe(u8, ip.formatIp(record.subnet.gateway, &address_buf)),
        .references = record.references,
        .created_at = record.created_at,
        .containers = null,
    };
    if (!details) return result;
    const refs = try networks.attachments(alloc, record.name);
    const containers = try alloc.alloc(JsonContainer, refs.len);
    for (refs, containers) |ref, *value| {
        value.* = .{ .id = ref.container_id, .name = ref.dns_name, .address = ref.address, .aliases = try networks.aliases(alloc, ref.container_id), .ports = &.{} };
        const config = @import("../run_state.zig").loadConfig(alloc, ref.container_id) catch |err| switch (err) {
            error.NotFound => continue,
            else => return err,
        };
        const ports = try alloc.alloc(JsonPort, config.port_maps.len);
        for (config.port_maps, ports) |port, *published| published.* = .{
            .host_ip = try alloc.dupe(u8, ip.formatIp(port.bindIp() orelse .{ 0, 0, 0, 0 }, &address_buf)),
            .host_port = port.host_port,
            .container_port = port.container_port,
            .protocol = @tagName(port.protocol),
        };
        value.ports = ports;
    }
    result.containers = containers;
    return result;
}

fn writeJson(alloc: std.mem.Allocator, value: anytype) !void {
    const output = try std.json.Stringify.valueAlloc(alloc, value, .{});
    defer alloc.free(output);
    cli.write("{s}\n", .{output});
}

test "network JSON reports use textual addresses and explicit reference counts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const record: networks.Record = .{ .name = "app-net", .bridge_name = "yoqn-fixture", .subnet = .{ .node_id = 0, .base = .{ 172, 30, 2, 0 }, .gateway = .{ 172, 30, 2, 1 }, .prefix_len = 24, .range_start = .{ 172, 30, 2, 2 }, .range_end = .{ 172, 30, 2, 254 } }, .references = 3, .provisioned = true, .created_at = 1 };
    const json = try std.json.Stringify.valueAlloc(alloc, try jsonNetwork(alloc, record, false), .{});
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json, .{});
    try std.testing.expectEqualStrings("172.30.2.0/24", parsed.value.object.get("subnet").?.string);
    try std.testing.expectEqualStrings("172.30.2.1", parsed.value.object.get("gateway").?.string);
    try std.testing.expectEqual(@as(i64, 3), parsed.value.object.get("references").?.integer);
    try std.testing.expect(parsed.value.object.get("containers").? == .null);
}
