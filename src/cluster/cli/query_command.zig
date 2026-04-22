const std = @import("std");
const cli = @import("../../lib/cli.zig");
const http_client = @import("../http_client.zig");
const json_helpers = @import("../../lib/json_helpers.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const readApiToken = cli.readApiToken;
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

const QueryError = error{
    InvalidArgument,
    ConnectionFailed,
    ServerError,
};

pub fn cluster(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var subcommand: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else {
            subcommand = arg;
        }
    }

    const subcmd = subcommand orelse {
        writeErr("usage: yoq cluster <status>\n", .{});
        return QueryError.InvalidArgument;
    };

    if (std.mem.eql(u8, subcmd, "status")) {
        clusterStatus(alloc);
    } else {
        writeErr("unknown cluster subcommand: {s}\n", .{subcmd});
        return QueryError.InvalidArgument;
    }
}

fn clusterStatus(alloc: std.mem.Allocator) void {
    var token_buf: [64]u8 = undefined;
    const token = readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, .{ 127, 0, 0, 1 }, 7700, "/cluster/status", token) catch |err| {
        writeErr("cannot connect to API server at localhost:7700: {}\n", .{err});
        writeErr("hint: start the server with 'yoq serve' or 'yoq init-server'\n", .{});
        return;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("cluster status failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return;
    }

    write("{s}\n", .{resp.body});
}

pub fn nodes(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var server: cli.ServerAddr = .{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return QueryError.InvalidArgument;
            };
            server = cli.parseServerAddr(addr_str);
        }
    }
    const server_addr = server.ip;
    const server_port = server.port;

    var token_buf: [64]u8 = undefined;
    const token = readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, server_addr, server_port, "/agents", token) catch |err| {
        writeErr("failed to connect to server: {}\n", .{err});
        writeErr("hint: start the server with 'yoq serve' or 'yoq init-server'\n", .{});
        return QueryError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        return QueryError.ServerError;
    }

    if (cli.output_mode == .json) {
        write("{s}\n", .{resp.body});
        return;
    }

    write("{s:<14} {s:<10} {s:<12} {s:<16} {s}\n", .{ "ID", "STATUS", "CPU", "MEMORY", "CONTAINERS" });
    write("{s:->14} {s:->10} {s:->12} {s:->16} {s:->10}\n", .{ "", "", "", "", "" });

    var pos: usize = 0;
    while (pos < resp.body.len) {
        const obj_start = std.mem.indexOfPos(u8, resp.body, pos, "{\"id\":\"") orelse break;
        const obj_end = std.mem.indexOfPos(u8, resp.body, obj_start + 1, "}") orelse break;
        const obj = resp.body[obj_start .. obj_end + 1];

        const id = extractJsonString(obj, "id") orelse "?";
        const status = extractJsonString(obj, "status") orelse "?";
        const cpu_cores = extractJsonInt(obj, "cpu_cores") orelse 0;
        const cpu_used = extractJsonInt(obj, "cpu_used") orelse 0;
        const memory_mb = extractJsonInt(obj, "memory_mb") orelse 0;
        const memory_used = extractJsonInt(obj, "memory_used_mb") orelse 0;
        const containers = extractJsonInt(obj, "containers") orelse 0;

        var cpu_buf: [24]u8 = undefined;
        const cpu_str = std.fmt.bufPrint(&cpu_buf, "{d}/{d}", .{ cpu_used, cpu_cores * 1000 }) catch "?";
        var mem_buf: [24]u8 = undefined;
        const mem_str = std.fmt.bufPrint(&mem_buf, "{d}/{d}MB", .{ memory_used, memory_mb }) catch "?";
        var cnt_buf: [12]u8 = undefined;
        const cnt_str = std.fmt.bufPrint(&cnt_buf, "{d}", .{containers}) catch "?";

        write("{s:<14} {s:<10} {s:<12} {s:<16} {s}\n", .{ id, status, cpu_str, mem_str, cnt_str });
        pos = obj_end + 1;
    }
}

pub fn drain(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var node_id: ?[]const u8 = null;
    var server: cli.ServerAddr = .{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return QueryError.InvalidArgument;
            };
            server = cli.parseServerAddr(addr_str);
        } else {
            node_id = arg;
        }
    }
    const server_addr = server.ip;
    const server_port = server.port;

    const id = node_id orelse {
        writeErr("usage: yoq drain <node-id> [--server host:port]\n", .{});
        return QueryError.InvalidArgument;
    };

    var path_buf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/drain", .{id}) catch {
        writeErr("node ID too long\n", .{});
        return QueryError.InvalidArgument;
    };

    var token_buf: [64]u8 = undefined;
    const token = readApiToken(&token_buf);

    var resp = http_client.postWithAuth(alloc, server_addr, server_port, path, "", token) catch |err| {
        writeErr("failed to connect to server: {}\n", .{err});
        writeErr("hint: start the server with 'yoq serve' or 'yoq init-server'\n", .{});
        return QueryError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code == 200) {
        write("node {s} marked for draining\n", .{id});
    } else {
        writeErr("drain failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return QueryError.ServerError;
    }
}
