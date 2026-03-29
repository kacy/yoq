const std = @import("std");
const cli = @import("../../lib/cli.zig");
const api_server = @import("../../api/server.zig");
const routes = @import("../../api/routes.zig");
const cluster_node = @import("../node.zig");
const cluster_config = @import("../config.zig");
const orchestrator = @import("../../manifest/orchestrator.zig");
const paths = @import("../../lib/paths.zig");
const log = @import("../../lib/log.zig");
const ip = @import("../../network/ip.zig");
const service_rollout = @import("../../network/service_rollout.zig");
const service_reconciler = @import("../../network/service_reconciler.zig");
const proxy_control_plane = @import("../../network/proxy/control_plane.zig");
const listener_runtime = @import("../../network/proxy/listener_runtime.zig");

const writeErr = cli.writeErr;
const readApiToken = cli.readApiToken;
const generateAndSaveToken = cli.generateAndSaveToken;
const isValidApiToken = cli.isValidApiToken;

const ServerCommandError = error{
    InvalidArgument,
    ServerStartFailed,
    ConfigFailed,
};

pub fn serve(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var port: u16 = 7700;
    var http_proxy_bind: [4]u8 = listener_runtime.default_bind_addr;
    var http_proxy_port: u16 = listener_runtime.default_listen_port;
    var log_fmt: log.LogFormat = .json;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            const port_str = args.next() orelse {
                writeErr("--port requires a port number\n", .{});
                return ServerCommandError.InvalidArgument;
            };
            port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid port: {s}\n", .{port_str});
                return ServerCommandError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--http-proxy-bind")) {
            const bind_str = args.next() orelse {
                writeErr("--http-proxy-bind requires an IPv4 address\n", .{});
                return ServerCommandError.InvalidArgument;
            };
            http_proxy_bind = ip.parseIp(bind_str) orelse {
                writeErr("invalid http proxy bind address: {s}\n", .{bind_str});
                return ServerCommandError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--http-proxy-port")) {
            const port_str = args.next() orelse {
                writeErr("--http-proxy-port requires a port number\n", .{});
                return ServerCommandError.InvalidArgument;
            };
            http_proxy_port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid http proxy port: {s}\n", .{port_str});
                return ServerCommandError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--log-format")) {
            const fmt_str = args.next() orelse {
                writeErr("--log-format requires text or json\n", .{});
                return ServerCommandError.InvalidArgument;
            };
            if (std.mem.eql(u8, fmt_str, "text")) {
                log_fmt = .text;
            } else if (std.mem.eql(u8, fmt_str, "json")) {
                log_fmt = .json;
            } else {
                writeErr("invalid log format: {s} (expected text or json)\n", .{fmt_str});
                return ServerCommandError.InvalidArgument;
            }
        }
    }

    log.setFormat(log_fmt);
    listener_runtime.configure(http_proxy_bind, http_proxy_port);
    service_rollout.logStartupSummary();
    service_reconciler.ensureDataPlaneReadyIfEnabled();
    service_reconciler.bootstrapIfEnabled();
    service_reconciler.startAuditLoopIfEnabled();
    listener_runtime.setStateChangeHook(proxy_control_plane.refreshIfEnabled);
    defer listener_runtime.setStateChangeHook(null);
    listener_runtime.startIfEnabled(alloc);
    defer listener_runtime.stop();
    proxy_control_plane.startSyncLoopIfEnabled();
    defer proxy_control_plane.stopSyncLoop();

    var token_buf: [64]u8 = undefined;
    const token: ?[]const u8 = readApiToken(&token_buf) orelse generateAndSaveToken(&token_buf);

    if (token) |t| {
        routes.api_token = t;

        var path_buf: [paths.max_path]u8 = undefined;
        const token_path = paths.dataPath(&path_buf, "api_token") catch "~/.local/share/yoq/api_token";
        writeErr("API token: {s}\n", .{token_path});
    } else {
        writeErr("failed to set up API token; refusing to run without auth\n", .{});
        return ServerCommandError.ServerStartFailed;
    }
    defer routes.api_token = null;

    var server = api_server.Server.init(alloc, port, .{ 127, 0, 0, 1 }) catch |err| {
        writeErr("failed to start server on port {d}: {}\n", .{ port, err });
        return ServerCommandError.ServerStartFailed;
    };
    defer server.deinit();

    orchestrator.installSignalHandlers();
    server.run();
}

pub fn initServer(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var node_id: u64 = 1;
    var raft_port: u16 = 9700;
    var api_port: u16 = 7700;
    var http_proxy_bind: [4]u8 = .{ 0, 0, 0, 0 };
    var http_proxy_port: u16 = listener_runtime.default_listen_port;
    var peers_str: []const u8 = "";
    var join_token: ?[]const u8 = null;
    var api_token_arg: ?[]const u8 = null;
    var log_fmt: log.LogFormat = .json;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--id")) {
            const id_str = args.next() orelse {
                writeErr("--id requires a node ID\n", .{});
                return ServerCommandError.InvalidArgument;
            };
            node_id = std.fmt.parseInt(u64, id_str, 10) catch {
                writeErr("invalid node id: {s}\n", .{id_str});
                return ServerCommandError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--port")) {
            const port_str = args.next() orelse {
                writeErr("--port requires a port number\n", .{});
                return ServerCommandError.InvalidArgument;
            };
            raft_port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid port: {s}\n", .{port_str});
                return ServerCommandError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--api-port")) {
            const port_str = args.next() orelse {
                writeErr("--api-port requires a port number\n", .{});
                return ServerCommandError.InvalidArgument;
            };
            api_port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid port: {s}\n", .{port_str});
                return ServerCommandError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--http-proxy-bind")) {
            const bind_str = args.next() orelse {
                writeErr("--http-proxy-bind requires an IPv4 address\n", .{});
                return ServerCommandError.InvalidArgument;
            };
            http_proxy_bind = ip.parseIp(bind_str) orelse {
                writeErr("invalid http proxy bind address: {s}\n", .{bind_str});
                return ServerCommandError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--http-proxy-port")) {
            const port_str = args.next() orelse {
                writeErr("--http-proxy-port requires a port number\n", .{});
                return ServerCommandError.InvalidArgument;
            };
            http_proxy_port = std.fmt.parseInt(u16, port_str, 10) catch {
                writeErr("invalid http proxy port: {s}\n", .{port_str});
                return ServerCommandError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--peers")) {
            peers_str = args.next() orelse {
                writeErr("--peers requires peer list\n", .{});
                return ServerCommandError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--token")) {
            join_token = args.next() orelse {
                writeErr("--token requires a join token\n", .{});
                return ServerCommandError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--api-token")) {
            api_token_arg = args.next() orelse {
                writeErr("--api-token requires a 64-character hex token\n", .{});
                return ServerCommandError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--log-format")) {
            const fmt_str = args.next() orelse {
                writeErr("--log-format requires text or json\n", .{});
                return ServerCommandError.InvalidArgument;
            };
            if (std.mem.eql(u8, fmt_str, "text")) {
                log_fmt = .text;
            } else if (std.mem.eql(u8, fmt_str, "json")) {
                log_fmt = .json;
            } else {
                writeErr("invalid log format: {s} (expected text or json)\n", .{fmt_str});
                return ServerCommandError.InvalidArgument;
            }
        }
    }

    log.setFormat(log_fmt);
    listener_runtime.configure(http_proxy_bind, http_proxy_port);
    service_rollout.logStartupSummary();
    service_reconciler.ensureDataPlaneReadyIfEnabled();
    service_reconciler.bootstrapIfEnabled();
    service_reconciler.startAuditLoopIfEnabled();
    listener_runtime.setStateChangeHook(proxy_control_plane.refreshIfEnabled);
    defer listener_runtime.setStateChangeHook(null);
    listener_runtime.startIfEnabled(alloc);
    defer listener_runtime.stop();
    proxy_control_plane.startSyncLoopIfEnabled();
    defer proxy_control_plane.stopSyncLoop();

    var data_dir_buf: [paths.max_path]u8 = undefined;
    const data_dir = cluster_config.defaultDataDir(&data_dir_buf) catch |err| {
        writeErr("failed to create cluster data directory: {}\n", .{err});
        return ServerCommandError.ConfigFailed;
    };

    const peers = cluster_config.parsePeers(alloc, peers_str) catch |err| {
        writeErr("invalid peers format: {} (expected id@host:port,id@host:port)\n", .{err});
        return ServerCommandError.InvalidArgument;
    };
    defer alloc.free(peers);

    if (join_token == null) {
        writeErr("cluster mode requires --token for join authentication and raft transport auth\n", .{});
        return ServerCommandError.InvalidArgument;
    }

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
                return ServerCommandError.InvalidArgument;
            }
            break :blk provided;
        }

        const from_file = readApiToken(&api_token_buf) orelse {
            writeErr("cluster mode requires an API token. provide --api-token or create ~/.local/share/yoq/api_token with 0o600 permissions\n", .{});
            return ServerCommandError.InvalidArgument;
        };
        break :blk from_file;
    };

    writeErr("starting server node {d} on :{d} (api :{d}) with {d} peers\n", .{
        node_id, raft_port, api_port, peers.len,
    });

    var node = cluster_node.Node.init(alloc, .{
        .id = node_id,
        .port = raft_port,
        .api_port = api_port,
        .peers = peers,
        .data_dir = data_dir,
        .shared_key = shared_key,
    }) catch |err| {
        writeErr("failed to initialize raft node: {}\n", .{err});
        return ServerCommandError.ServerStartFailed;
    };
    defer node.deinit();

    if (peers.len > 0 and node.transport.shared_key == null) {
        writeErr("cluster mode requires raft transport authentication when peers are configured\n", .{});
        return ServerCommandError.InvalidArgument;
    }

    node.start() catch |err| {
        writeErr("failed to start raft node: {}\n", .{err});
        return ServerCommandError.ServerStartFailed;
    };

    routes.cluster = &node;
    routes.join_token = join_token;
    defer {
        routes.cluster = null;
        routes.join_token = null;
    }

    const dns = @import("../../network/dns.zig");
    dns.setClusterDb(node.stateMachineDb());
    defer dns.setClusterDb(null);
    service_reconciler.bootstrapIfEnabled();

    routes.api_token = api_token;
    defer routes.api_token = null;

    var server = api_server.Server.init(alloc, api_port, .{ 0, 0, 0, 0 }) catch |err| {
        writeErr("failed to start API server on port {d}: {}\n", .{ api_port, err });
        return ServerCommandError.ServerStartFailed;
    };
    defer server.deinit();

    orchestrator.installSignalHandlers();
    server.run();

    node.stop();
}
