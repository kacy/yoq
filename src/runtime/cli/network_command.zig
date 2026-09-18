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
            error.InvalidArgument => cli.writeErr("usage: yoq network create [--subnet CIDR] <name> | ls | inspect <name> | rm <name>\n", .{}),
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
        if (args.next() != null) return error.InvalidArgument;
        const records = try networks.list(alloc);
        defer {
            for (records) |record| record.deinit(alloc);
            alloc.free(records);
        }
        cli.write("NAME  DRIVER  SUBNET  REFERENCES\n", .{});
        for (records) |record| {
            var buf: [16]u8 = undefined;
            cli.write("{s}  bridge  {s}/24  {d}\n", .{ record.name, ip.formatIp(record.subnet.base, &buf), record.references });
        }
    } else if (std.mem.eql(u8, action, "inspect")) {
        const name = args.next() orelse return error.InvalidArgument;
        if (args.next() != null) return error.InvalidArgument;
        const record = try networks.inspect(alloc, name);
        defer record.deinit(alloc);
        var subnet_buf: [16]u8 = undefined;
        var gateway_buf: [16]u8 = undefined;
        cli.write("name: {s}\ndriver: bridge\nbridge: {s}\nsubnet: {s}/24\ngateway: {s}\nreferences: {d}\ncreated: {d}\n", .{ record.name, record.bridge_name, ip.formatIp(record.subnet.base, &subnet_buf), ip.formatIp(record.subnet.gateway, &gateway_buf), record.references, record.created_at });
        const refs = try networks.attachments(alloc, name);
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
