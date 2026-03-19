const std = @import("std");
const cli = @import("../../lib/cli.zig");
const cluster_config = @import("../config.zig");
const cluster_agent = @import("../agent.zig");
const http_client = @import("../http_client.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const ip = @import("../../network/ip.zig");
const net_setup = @import("../../network/setup.zig");
const orchestrator = @import("../../manifest/orchestrator.zig");

const writeErr = cli.writeErr;

const MembershipError = error{
    InvalidArgument,
    ConnectionFailed,
    ServerStartFailed,
};

pub fn join(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var server_host: ?[]const u8 = null;
    var token: ?[]const u8 = null;
    var api_port: u16 = 7700;
    var role: cluster_config.NodeRole = .both;
    var region: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--token")) {
            token = args.next() orelse {
                writeErr("--token requires a join token\n", .{});
                return MembershipError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--port")) {
            const port_str = args.next() orelse {
                writeErr("--port requires a port number\n", .{});
                return MembershipError.InvalidArgument;
            };
            api_port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid port: {s}\n", .{port_str});
                return MembershipError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--role")) {
            const role_str = args.next() orelse {
                writeErr("--role requires a value (server, agent, or both)\n", .{});
                return MembershipError.InvalidArgument;
            };
            role = cluster_config.NodeRole.fromString(role_str) orelse {
                writeErr("invalid role: {s} (expected server, agent, or both)\n", .{role_str});
                return MembershipError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--region")) {
            region = args.next() orelse {
                writeErr("--region requires a region name\n", .{});
                return MembershipError.InvalidArgument;
            };
        } else {
            server_host = arg;
        }
    }

    const host = server_host orelse {
        writeErr("usage: yoq join <server-host> --token <token> [--port <api-port>]\n", .{});
        return MembershipError.InvalidArgument;
    };

    const join_token = token orelse {
        writeErr("--token is required\n", .{});
        return MembershipError.InvalidArgument;
    };

    const server_addr = ip.parseIp(host) orelse {
        writeErr("invalid server address: {s}\n", .{host});
        return MembershipError.InvalidArgument;
    };

    writeErr("joining cluster at {s}:{d} (role={s})...\n", .{ host, api_port, role.toString() });

    var agent = try cluster_agent.Agent.initOwned(alloc, server_addr, api_port, join_token);
    defer agent.deinit();
    agent.role = role;
    agent.region = region;

    agent.register() catch |err| {
        writeErr("failed to register with server: {}\n", .{err});
        writeErr("hint: check that the server is running and the token is correct\n", .{});
        return MembershipError.ConnectionFailed;
    };

    writeErr("joined cluster as agent {s}\n", .{agent.id});

    if (agent.node_id != null and agent.wg_keypair != null and agent.overlay_ip != null) {
        setupAgentWireguard(&agent, alloc);
    }
    agent.start() catch |err| {
        writeErr("failed to start agent loop: {}\n", .{err});
        return MembershipError.ServerStartFailed;
    };

    orchestrator.installSignalHandlers();
    agent.wait();

    writeErr("agent stopped\n", .{});
}

fn setupAgentWireguard(agent: *cluster_agent.Agent, alloc: std.mem.Allocator) void {
    const node_id = agent.node_id orelse return;
    const kp = agent.wg_keypair orelse return;
    const overlay_ip = agent.overlay_ip orelse return;

    var peers_buf: [16]net_setup.PeerInfo = undefined;
    var peer_count: usize = 0;

    var resp = http_client.getWithAuth(
        alloc,
        agent.server_addr,
        agent.server_port,
        "/wireguard/peers",
        agent.token,
    ) catch |err| {
        writeErr("warning: failed to fetch wireguard peers: {}\n", .{err});
        net_setup.setupClusterNetworking(.{
            .node_id = node_id,
            .private_key = &kp.private_key,
            .listen_port = agent.wg_listen_port,
            .overlay_ip = overlay_ip,
            .peers = &.{},
            .role = agent.role,
        }) catch |err2| {
            writeErr("warning: failed to set up wireguard interface: {}\n", .{err2});
        };
        return;
    };
    defer resp.deinit(alloc);

    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        if (peer_count >= peers_buf.len) break;

        const pub_key = json_helpers.extractJsonString(obj, "public_key") orelse continue;
        const overlay_str = json_helpers.extractJsonString(obj, "overlay_ip") orelse continue;
        const node_id_val = json_helpers.extractJsonInt(obj, "node_id") orelse continue;
        const endpoint = json_helpers.extractJsonString(obj, "endpoint") orelse "";

        if (node_id_val == node_id) continue;

        const peer_node: u16 = if (node_id_val >= 1 and node_id_val <= 65534)
            @intCast(node_id_val)
        else
            continue;

        peers_buf[peer_count] = .{
            .public_key = pub_key,
            .endpoint = endpoint,
            .overlay_ip = if (peer_node <= 254)
                [4]u8{ 10, 40, 0, @intCast(peer_node) }
            else
                [4]u8{ 10, 40, @intCast(peer_node >> 8), @intCast(peer_node & 0xFF) },
            .container_subnet_node = peer_node,
            .is_hub = agent.role == .agent,
        };

        if (ip.parseIp(overlay_str)) |ip_bytes| {
            peers_buf[peer_count].overlay_ip = ip_bytes;
        }

        peer_count += 1;
    }

    net_setup.setupClusterNetworking(.{
        .node_id = node_id,
        .private_key = &kp.private_key,
        .listen_port = agent.wg_listen_port,
        .overlay_ip = overlay_ip,
        .peers = peers_buf[0..peer_count],
        .role = agent.role,
    }) catch |err| {
        writeErr("warning: failed to set up wireguard interface: {}\n", .{err});
        return;
    };

    writeErr("wireguard mesh active (node_id={d}, {d} peers)\n", .{ node_id, peer_count });
}
