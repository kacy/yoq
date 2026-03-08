// cluster commands — serve, init-server, join, cluster, nodes, drain
//
// extracted from main.zig. these are the CLI entry points for cluster
// management. internal helpers (setupAgentWireguard, parseIpv4Bytes,
// clusterStatus) stay private.

const std = @import("std");
const cli = @import("../lib/cli.zig");
const api_server = @import("../api/server.zig");
const routes = @import("../api/routes.zig");
const cluster_node = @import("node.zig");
const cluster_config = @import("config.zig");
const cluster_agent = @import("agent.zig");
const http_client = @import("http_client.zig");
const json_helpers = @import("../lib/json_helpers.zig");
const ip = @import("../network/ip.zig");
const net_setup = @import("../network/setup.zig");
const dns = @import("../network/dns.zig");
const orchestrator = @import("../manifest/orchestrator.zig");
const paths = @import("../lib/paths.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const readApiToken = cli.readApiToken;
const generateAndSaveToken = cli.generateAndSaveToken;
const isValidApiToken = cli.isValidApiToken;
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

const ClusterCommandsError = error{
    InvalidArgument,
    ServerStartFailed,
    ConfigFailed,
    ConnectionFailed,
    ServerError,
    Unauthorized,
    NetworkError,
    OutOfMemory,
};

pub fn serve(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var port: u16 = 7700;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            const port_str = args.next() orelse {
                writeErr("--port requires a port number\n", .{});
                return ClusterCommandsError.InvalidArgument;
            };
            port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid port: {s}\n", .{port_str});
                return ClusterCommandsError.InvalidArgument;
            };
        }
    }

    // generate or load API token for authentication.
    // even in single-node mode (localhost-only), require auth so that
    // any process on the machine can't silently manage containers.
    var token_buf: [64]u8 = undefined;
    const token: ?[]const u8 = readApiToken(&token_buf) orelse generateAndSaveToken(&token_buf);

    if (token) |t| {
        routes.api_token = t;

        var path_buf: [paths.max_path]u8 = undefined;
        const token_path = paths.dataPath(&path_buf, "api_token") catch "~/.local/share/yoq/api_token";
        writeErr("API token: {s}\n", .{token_path});
    } else {
        writeErr("failed to set up API token; refusing to run without auth\n", .{});
        return ClusterCommandsError.ServerStartFailed;
    }
    defer routes.api_token = null;

    var server = api_server.Server.init(alloc, port, .{ 127, 0, 0, 1 }) catch |err| {
        writeErr("failed to start server on port {d}: {}\n", .{ port, err });
        return ClusterCommandsError.ServerStartFailed;
    };
    defer server.deinit();

    orchestrator.installSignalHandlers();
    server.run();
}

pub fn initServer(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var node_id: u64 = 1;
    var raft_port: u16 = 9700;
    var api_port: u16 = 7700;
    var peers_str: []const u8 = "";
    var join_token: ?[]const u8 = null;
    var api_token_arg: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--id")) {
            const id_str = args.next() orelse {
                writeErr("--id requires a node ID\n", .{});
                return ClusterCommandsError.InvalidArgument;
            };
            node_id = std.fmt.parseInt(u64, id_str, 10) catch {
                writeErr("invalid node id: {s}\n", .{id_str});
                return ClusterCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--port")) {
            const port_str = args.next() orelse {
                writeErr("--port requires a port number\n", .{});
                return ClusterCommandsError.InvalidArgument;
            };
            raft_port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid port: {s}\n", .{port_str});
                return ClusterCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--api-port")) {
            const port_str = args.next() orelse {
                writeErr("--api-port requires a port number\n", .{});
                return ClusterCommandsError.InvalidArgument;
            };
            api_port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid port: {s}\n", .{port_str});
                return ClusterCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--peers")) {
            peers_str = args.next() orelse {
                writeErr("--peers requires peer list\n", .{});
                return ClusterCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--token")) {
            join_token = args.next() orelse {
                writeErr("--token requires a join token\n", .{});
                return ClusterCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--api-token")) {
            api_token_arg = args.next() orelse {
                writeErr("--api-token requires a 64-character hex token\n", .{});
                return ClusterCommandsError.InvalidArgument;
            };
        }
    }

    // resolve data directory
    var data_dir_buf: [paths.max_path]u8 = undefined;
    const data_dir = cluster_config.defaultDataDir(&data_dir_buf) catch |err| {
        writeErr("failed to create cluster data directory: {}\n", .{err});
        return ClusterCommandsError.ConfigFailed;
    };

    // parse peers
    const peers = cluster_config.parsePeers(alloc, peers_str) catch |err| {
        writeErr("invalid peers format: {} (expected id@host:port,id@host:port)\n", .{err});
        return ClusterCommandsError.InvalidArgument;
    };
    defer alloc.free(peers);

    if (join_token == null) {
        writeErr("cluster mode requires --token for join authentication and raft transport auth\n", .{});
        return ClusterCommandsError.InvalidArgument;
    }

    // derive a shared key from the join token for raft transport authentication.
    // uses HMAC-SHA256 as a simple KDF: HMAC(key=token, data="yoq-raft-transport-key").
    // this ensures cluster comms are always authenticated when a token is set.
    var shared_key: ?[32]u8 = null;
    if (join_token) |t| {
        const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
        var derived: [32]u8 = undefined;
        HmacSha256.create(&derived, "yoq-raft-transport-key", t);
        shared_key = derived;
    }

    var api_token_buf: [64]u8 = undefined;
    const api_token = blk: {
        if (api_token_arg) |provided| {
            if (!isValidApiToken(provided)) {
                writeErr("--api-token must be a 64-character lowercase hex token\n", .{});
                return ClusterCommandsError.InvalidArgument;
            }
            break :blk provided;
        }

        const from_file = readApiToken(&api_token_buf) orelse {
            writeErr("cluster mode requires an API token. provide --api-token or create ~/.local/share/yoq/api_token with 0o600 permissions\n", .{});
            return ClusterCommandsError.InvalidArgument;
        };
        break :blk from_file;
    };

    writeErr("starting server node {d} on :{d} (api :{d}) with {d} peers\n", .{
        node_id, raft_port, api_port, peers.len,
    });

    // initialize raft node with shared key
    var node = cluster_node.Node.init(alloc, .{
        .id = node_id,
        .port = raft_port,
        .peers = peers,
        .data_dir = data_dir,
        .shared_key = shared_key,
    }) catch |err| {
        writeErr("failed to initialize raft node: {}\n", .{err});
        return ClusterCommandsError.ServerStartFailed;
    };
    defer node.deinit();

    if (peers.len > 0 and node.transport.shared_key == null) {
        writeErr("cluster mode requires raft transport authentication when peers are configured\n", .{});
        return ClusterCommandsError.InvalidArgument;
    }

    node.start() catch |err| {
        writeErr("failed to start raft node: {}\n", .{err});
        return ClusterCommandsError.ServerStartFailed;
    };

    // set cluster node and join token for API routes
    routes.cluster = &node;
    routes.join_token = join_token;
    defer {
        routes.cluster = null;
        routes.join_token = null;
    }

    // enable cluster-wide DNS resolution. the server's DNS resolver
    // will fall through to the replicated service_names table for
    // names not found in the local in-memory registry. this lets
    // containers on any node resolve service names cluster-wide.
    dns.setClusterDb(node.stateMachineDb());
    defer dns.setClusterDb(null);

    // start API server — cluster mode binds to all interfaces since
    // agents on other nodes need to reach this server.
    // set api_token so all endpoints (except health/version) require auth.
    routes.api_token = api_token;
    defer routes.api_token = null;

    var server = api_server.Server.init(alloc, api_port, .{ 0, 0, 0, 0 }) catch |err| {
        writeErr("failed to start API server on port {d}: {}\n", .{ api_port, err });
        return ClusterCommandsError.ServerStartFailed;
    };
    defer server.deinit();

    orchestrator.installSignalHandlers();
    server.run();

    node.stop();
}

pub fn join(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var server_host: ?[]const u8 = null;
    var token: ?[]const u8 = null;
    var api_port: u16 = 7700;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--token")) {
            token = args.next() orelse {
                writeErr("--token requires a join token\n", .{});
                return ClusterCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--port")) {
            const port_str = args.next() orelse {
                writeErr("--port requires a port number\n", .{});
                return ClusterCommandsError.InvalidArgument;
            };
            api_port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid port: {s}\n", .{port_str});
                return ClusterCommandsError.InvalidArgument;
            };
        } else {
            server_host = arg;
        }
    }

    const host = server_host orelse {
        writeErr("usage: yoq join <server-host> --token <token> [--port <api-port>]\n", .{});
        return ClusterCommandsError.InvalidArgument;
    };

    const join_token = token orelse {
        writeErr("--token is required\n", .{});
        return ClusterCommandsError.InvalidArgument;
    };

    // parse server address
    const server_addr = ip.parseIp(host) orelse {
        writeErr("invalid server address: {s}\n", .{host});
        return ClusterCommandsError.InvalidArgument;
    };

    writeErr("joining cluster at {s}:{d}...\n", .{ host, api_port });

    var agent = cluster_agent.Agent.init(alloc, server_addr, api_port, join_token);

    // register with server
    agent.register() catch |err| {
        writeErr("failed to register with server: {}\n", .{err});
        writeErr("hint: check that the server is running and the token is correct\n", .{});
        return ClusterCommandsError.ConnectionFailed;
    };

    writeErr("joined cluster as agent {s}\n", .{agent.id});

    // set up wireguard mesh networking if the server assigned a node_id.
    // this creates the wg-yoq interface, assigns our overlay IP, and adds
    // any existing peers so cross-node container traffic can flow immediately.
    if (agent.node_id != null and agent.wg_keypair != null and agent.overlay_ip != null) {
        setupAgentWireguard(&agent, alloc);
    }
    defer {
        // tear down wireguard on exit — the kernel cleans up peers and routes
        // when the interface is deleted, so this is a single operation.
        if (agent.node_id != null) {
            net_setup.teardownClusterNetworking();
        }
    }

    // start heartbeat loop
    agent.start() catch |err| {
        writeErr("failed to start agent loop: {}\n", .{err});
        return ClusterCommandsError.ServerStartFailed;
    };

    // install signal handlers for graceful shutdown
    orchestrator.installSignalHandlers();

    // block until shutdown signal
    agent.wait();

    writeErr("agent stopped\n", .{});
}

/// fetch the peer list from the server and set up the wireguard mesh.
/// called once during join after the agent has registered and received
/// its node_id, overlay IP, and wireguard keypair. any failure here is
/// non-fatal — the agent will still function, and the reconcilePeers loop
/// in the heartbeat cycle will retry peer setup.
fn setupAgentWireguard(agent: *cluster_agent.Agent, alloc: std.mem.Allocator) void {
    const node_id = agent.node_id orelse return;
    const kp = agent.wg_keypair orelse return;
    const overlay_ip = agent.overlay_ip orelse return;

    // fetch the current peer list from the server
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
        // still set up the interface with no peers — they'll be added
        // on the first heartbeat cycle via reconcilePeers
        net_setup.setupClusterNetworking(.{
            .node_id = node_id,
            .private_key = &kp.private_key,
            .listen_port = agent.wg_listen_port,
            .overlay_ip = overlay_ip,
            .peers = &.{},
        }) catch |err2| {
            writeErr("warning: failed to set up wireguard interface: {}\n", .{err2});
        };
        return;
    };
    defer resp.deinit(alloc);

    // parse peer objects from the response
    var iter = json_helpers.extractJsonObjects(resp.body);
    while (iter.next()) |obj| {
        if (peer_count >= peers_buf.len) break;

        const pub_key = json_helpers.extractJsonString(obj, "public_key") orelse continue;
        const overlay_str = json_helpers.extractJsonString(obj, "overlay_ip") orelse continue;
        const node_id_val = json_helpers.extractJsonInt(obj, "node_id") orelse continue;
        const endpoint = json_helpers.extractJsonString(obj, "endpoint") orelse "";

        // skip ourselves
        if (node_id_val == node_id) continue;

        const peer_node: u8 = if (node_id_val >= 1 and node_id_val <= 254)
            @intCast(node_id_val)
        else
            continue;

        peers_buf[peer_count] = .{
            .public_key = pub_key,
            .endpoint = endpoint,
            .overlay_ip = .{ 10, 40, 0, peer_node },
            .container_subnet_node = peer_node,
        };

        // also parse the actual overlay IP from the string
        if (parseIpv4Bytes(overlay_str)) |ip_bytes| {
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
    }) catch |err| {
        writeErr("warning: failed to set up wireguard interface: {}\n", .{err});
        return;
    };

    writeErr("wireguard mesh active (node_id={d}, {d} peers)\n", .{ node_id, peer_count });
}

/// parse a dotted-quad IPv4 string into 4 bytes. returns null on failure.
fn parseIpv4Bytes(str: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var start: usize = 0;

    for (str, 0..) |c, i| {
        if (c == '.') {
            if (octet_idx >= 3) return null;
            result[octet_idx] = std.fmt.parseInt(u8, str[start..i], 10) catch return null;
            octet_idx += 1;
            start = i + 1;
        }
    }

    if (octet_idx != 3) return null;
    result[3] = std.fmt.parseInt(u8, str[start..], 10) catch return null;
    return result;
}

pub fn cluster(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
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
        return ClusterCommandsError.InvalidArgument;
    };

    if (std.mem.eql(u8, subcmd, "status")) {
        clusterStatus(alloc);
    } else {
        writeErr("unknown cluster subcommand: {s}\n", .{subcmd});
        return ClusterCommandsError.InvalidArgument;
    }
}

fn clusterStatus(alloc: std.mem.Allocator) void {
    // query the local API server for cluster status
    const fd = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch |err| {
        writeErr("failed to create socket: {}\n", .{err});
        return;
    };
    defer std.posix.close(fd);

    const timeout = std.posix.timeval{ .sec = 2, .usec = 0 };
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 7700);
    std.posix.connect(fd, &addr.any, addr.getOsSockLen()) catch |err| {
        writeErr("cannot connect to API server at localhost:7700: {}\n", .{err});
        writeErr("hint: start the server with 'yoq serve' or 'yoq init-server'\n", .{});
        return;
    };

    const request = "GET /cluster/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    _ = std.posix.write(fd, request) catch |err| {
        writeErr("failed to send request: {}\n", .{err});
        return;
    };

    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }

    // find body (after \r\n\r\n)
    const response = buf[0..total];
    if (std.mem.indexOf(u8, response, "\r\n\r\n")) |body_start| {
        write("{s}\n", .{response[body_start + 4 ..]});
    } else {
        writeErr("invalid response from server\n", .{});
    }

    _ = alloc;
}

pub fn nodes(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var server: cli.ServerAddr = .{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return ClusterCommandsError.InvalidArgument;
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
        return ClusterCommandsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("server returned status {d}\n", .{resp.status_code});
        return ClusterCommandsError.ServerError;
    }

    // API already returns JSON — pass through directly
    if (cli.output_mode == .json) {
        write("{s}\n", .{resp.body});
        return;
    }

    // parse and display agent list as a table
    // response is a JSON array: [{"id":"...","status":"...","cpu_cores":N,...},...]
    write("{s:<14} {s:<10} {s:<12} {s:<16} {s}\n", .{ "ID", "STATUS", "CPU", "MEMORY", "CONTAINERS" });
    write("{s:->14} {s:->10} {s:->12} {s:->16} {s:->10}\n", .{ "", "", "", "", "" });

    // simple parser: walk through JSON array finding each object
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

        // format CPU as "used/total" in millicores
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

pub fn drain(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var node_id: ?[]const u8 = null;
    var server: cli.ServerAddr = .{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--server")) {
            const addr_str = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return ClusterCommandsError.InvalidArgument;
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
        return ClusterCommandsError.InvalidArgument;
    };

    // POST /agents/{id}/drain
    var path_buf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/agents/{s}/drain", .{id}) catch {
        writeErr("node ID too long\n", .{});
        return ClusterCommandsError.InvalidArgument;
    };

    var token_buf: [64]u8 = undefined;
    const token = readApiToken(&token_buf);

    var resp = http_client.postWithAuth(alloc, server_addr, server_port, path, "", token) catch |err| {
        writeErr("failed to connect to server: {}\n", .{err});
        writeErr("hint: start the server with 'yoq serve' or 'yoq init-server'\n", .{});
        return ClusterCommandsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code == 200) {
        write("node {s} marked for draining\n", .{id});
    } else {
        writeErr("drain failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return ClusterCommandsError.ServerError;
    }
}
