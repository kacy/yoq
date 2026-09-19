// privileged integration tests — networking
//
// tests bridge creation, container networking, and port mapping.
// requires root and a working yoq binary at zig-out/bin/yoq.
//
// run with: sudo zig build test-privileged
//       or: sudo make test-privileged

const std = @import("std");
const helpers = @import("helpers");
const runtime_preflight = @import("runtime_preflight");

const alloc = std.testing.allocator;
const service_port: u16 = 8080;

fn trimOutput(output: []const u8) []const u8 {
    return std.mem.trim(u8, output, " \n\r\t");
}

fn isIpv4Output(output: []const u8) bool {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        const trimmed = trimOutput(line);
        if (trimmed.len == 0) continue;

        var parts = std.mem.splitScalar(u8, trimmed, '.');
        var count: usize = 0;
        var valid = true;
        while (parts.next()) |part| : (count += 1) {
            _ = std.fmt.parseUnsigned(u8, part, 10) catch {
                valid = false;
                break;
            };
        }
        if (valid and count == 4) return true;
    }
    return false;
}

fn stopAndRemoveContainer(env: *helpers.TestEnv, name: []const u8) void {
    if (env.runYoq(&.{ "stop", name })) |result| {
        var stop = result;
        stop.deinit();
    } else |_| {}

    if (env.runYoq(&.{ "rm", name })) |result| {
        var rm = result;
        rm.deinit();
    } else |_| {}
}

fn removeContainer(env: *helpers.TestEnv, name: []const u8) void {
    if (env.runYoq(&.{ "rm", name })) |result| {
        var rm = result;
        rm.deinit();
    } else |_| {}
}

fn waitForContainerRunning(env: *helpers.TestEnv, name: []const u8) !void {
    var attempt: usize = 0;
    while (attempt < 40) : (attempt += 1) {
        var ps = try env.runYoq(&.{"ps"});
        defer ps.deinit();

        if (ps.exit_code == 0 and
            std.mem.indexOf(u8, ps.stdout, name) != null and
            std.mem.indexOf(u8, ps.stdout, "running") != null)
        {
            return;
        }
        std.Io.sleep(std.testing.io, std.Io.Duration.fromNanoseconds(@intCast(250 * std.time.ns_per_ms)), .awake) catch unreachable;
    }

    std.debug.print("timed out waiting for container {s} to reach running state\n", .{name});
    return error.TestExpectedContains;
}

fn initNetworkingFixture() !struct { env: helpers.TestEnv, rootfs: helpers.RootfsFixture } {
    try runtime_preflight.requireRuntimeNetwork();
    return .{
        .env = try helpers.TestEnv.init(alloc),
        .rootfs = try helpers.createNetworkingRootfs(alloc),
    };
}

fn waitForHostHttpBody(env: *helpers.TestEnv, port: u16, expected: []const u8) !void {
    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/", .{port});
    defer alloc.free(url);

    var attempt: usize = 0;
    while (attempt < 20) : (attempt += 1) {
        var curl = try env.run(&.{
            "curl", "-fsS", "--connect-timeout", "1", url,
        });
        defer curl.deinit();

        if (curl.exit_code == 0 and std.mem.indexOf(u8, curl.stdout, expected) != null) return;
        std.Io.sleep(std.testing.io, std.Io.Duration.fromNanoseconds(@intCast(250 * std.time.ns_per_ms)), .awake) catch unreachable;
    }

    std.debug.print("timed out waiting for host HTTP body containing '{s}' on port {d}\n", .{ expected, port });
    return error.TestExpectedContains;
}

fn waitForServiceDiscoveryHttpBody(env: *helpers.TestEnv, rootfs_path: []const u8, server_name: []const u8, expected: []const u8) !void {
    const port_str = try std.fmt.allocPrint(alloc, "{d}", .{service_port});
    defer alloc.free(port_str);

    var attempt: usize = 0;
    while (attempt < 20) : (attempt += 1) {
        const client_name = try helpers.uniqueName(alloc, "test-client-http");
        defer alloc.free(client_name);

        var client = try env.runYoq(&.{
            "run", "--name", client_name, rootfs_path, "/bin/yoq-test-net-probe", "http-get", server_name, port_str, "/",
        });
        defer client.deinit();
        removeContainer(env, client_name);

        if (client.exit_code == 0 and std.mem.indexOf(u8, client.stdout, expected) != null) return;
        std.Io.sleep(std.testing.io, std.Io.Duration.fromNanoseconds(@intCast(250 * std.time.ns_per_ms)), .awake) catch unreachable;
    }

    std.debug.print("timed out waiting for service discovery HTTP body containing '{s}' from {s}\n", .{ expected, server_name });
    return error.TestExpectedContains;
}

fn waitForServiceDiscoveryHttpFailure(env: *helpers.TestEnv, rootfs_path: []const u8, server_name: []const u8) !void {
    const port_str = try std.fmt.allocPrint(alloc, "{d}", .{service_port});
    defer alloc.free(port_str);

    var attempt: usize = 0;
    while (attempt < 20) : (attempt += 1) {
        const client_name = try helpers.uniqueName(alloc, "test-client-fail");
        defer alloc.free(client_name);

        var client = try env.runYoq(&.{
            "run", "--name", client_name, rootfs_path, "/bin/yoq-test-net-probe", "http-get", server_name, port_str, "/",
        });
        defer client.deinit();
        removeContainer(env, client_name);

        if (client.exit_code != 0) return;
        std.Io.sleep(std.testing.io, std.Io.Duration.fromNanoseconds(@intCast(250 * std.time.ns_per_ms)), .awake) catch unreachable;
    }

    std.debug.print("service discovery for {s} never stopped resolving\n", .{server_name});
    return error.TestExpectedContains;
}

fn waitForServiceDiscoveryResolution(env: *helpers.TestEnv, rootfs_path: []const u8, server_name: []const u8) !void {
    var last_stdout: ?[]u8 = null;
    defer if (last_stdout) |buf| alloc.free(buf);
    var last_stderr: ?[]u8 = null;
    defer if (last_stderr) |buf| alloc.free(buf);

    var attempt: usize = 0;
    while (attempt < 20) : (attempt += 1) {
        const client_name = try helpers.uniqueName(alloc, "test-client-resolve");
        defer alloc.free(client_name);

        var client = try env.runYoq(&.{
            "run", "--name", client_name, rootfs_path, "/bin/yoq-test-net-probe", "resolve", server_name,
        });
        defer client.deinit();
        removeContainer(env, client_name);

        if (last_stdout) |buf| alloc.free(buf);
        last_stdout = try alloc.dupe(u8, client.stdout);
        if (last_stderr) |buf| alloc.free(buf);
        last_stderr = try alloc.dupe(u8, client.stderr);

        if (client.exit_code == 0 and isIpv4Output(client.stdout)) return;
        std.Io.sleep(std.testing.io, std.Io.Duration.fromNanoseconds(@intCast(250 * std.time.ns_per_ms)), .awake) catch unreachable;
    }

    std.debug.print("timed out waiting for service discovery resolution for {s}\n", .{server_name});
    if (last_stdout) |buf| std.debug.print("last client stdout:\n{s}\n", .{buf});
    if (last_stderr) |buf| std.debug.print("last client stderr:\n{s}\n", .{buf});
    if (env.runYoq(&.{"ps"})) |result| {
        var ps = result;
        defer ps.deinit();
        std.debug.print("yoq ps at failure:\n{s}\n", .{ps.stdout});
    } else |_| {}
    return error.TestExpectedContains;
}

fn startLocalHttpServer(env: *helpers.TestEnv, rootfs_path: []const u8, name: []const u8, host_port: ?u16, body: []const u8) !void {
    const port_str = try std.fmt.allocPrint(alloc, "{d}", .{service_port});
    defer alloc.free(port_str);

    if (host_port) |port| {
        const port_map = try std.fmt.allocPrint(alloc, "{d}:{d}", .{ port, service_port });
        defer alloc.free(port_map);

        var run_result = try env.runYoq(&.{
            "run", "-d", "--name", name, "-p", port_map, rootfs_path, "/bin/yoq-test-http-server", port_str, body,
        });
        defer run_result.deinit();
        try run_result.expectExitCode(0);
        try std.testing.expect(trimOutput(run_result.stdout).len > 0);
        try waitForContainerRunning(env, name);
        return;
    }

    var run_result = try env.runYoq(&.{
        "run", "-d", "--name", name, rootfs_path, "/bin/yoq-test-http-server", port_str, body,
    });
    defer run_result.deinit();
    try run_result.expectExitCode(0);
    try std.testing.expect(trimOutput(run_result.stdout).len > 0);
    try waitForContainerRunning(env, name);
}

fn requireExternalNetworkTests() !void {
    const environ = std.Io.Dir.cwd().readFileAlloc(std.testing.io, "/proc/self/environ", alloc, .limited(64 * 1024)) catch return error.SkipZigTest;
    defer alloc.free(environ);

    var entries = std.mem.splitScalar(u8, environ, 0);
    while (entries.next()) |entry| {
        if (std.mem.eql(u8, entry, "YOQ_REQUIRE_NETWORK_TESTS=1")) return;
    }
    return error.SkipZigTest;
}

test "container gets an IP address" {
    var fixture = try initNetworkingFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const name = try helpers.uniqueName(alloc, "test-net-ip");
    defer alloc.free(name);
    defer stopAndRemoveContainer(&fixture.env, name);

    try startLocalHttpServer(&fixture.env, fixture.rootfs.rootfs_path, name, null, "ip-check");

    var ps = try fixture.env.runYoq(&.{"ps"});
    defer ps.deinit();

    try std.testing.expect(ps.exit_code == 0);
    const id = trimOutput(ps.stdout);
    try std.testing.expect(id.len > 0);
    try helpers.expectContains(ps.stdout, "10.42.");
    try helpers.expectContains(ps.stdout, name);
}

test "container can reach the internet when external network tests are enabled" {
    try requireExternalNetworkTests();

    var fixture = try initNetworkingFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const name = try helpers.uniqueName(alloc, "test-net-ping");
    defer alloc.free(name);
    defer removeContainer(&fixture.env, name);

    var result = try fixture.env.runYoq(&.{
        "run", "--name", name, fixture.rootfs.rootfs_path, "/bin/yoq-test-net-probe", "http-get", "example.com", "80", "/",
    });
    defer result.deinit();

    try std.testing.expect(result.exit_code == 0);
}

test "port mapping makes container reachable from host" {
    var fixture = try initNetworkingFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const name = try helpers.uniqueName(alloc, "test-net-port");
    defer alloc.free(name);
    defer stopAndRemoveContainer(&fixture.env, name);

    try startLocalHttpServer(&fixture.env, fixture.rootfs.rootfs_path, name, 18080, "hello-from-port-map");
    try waitForHostHttpBody(&fixture.env, 18080, "hello-from-port-map");
}

test "containers discover each other by name" {
    var fixture = try initNetworkingFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const server_name = try helpers.uniqueName(alloc, "test-server");
    defer alloc.free(server_name);
    defer stopAndRemoveContainer(&fixture.env, server_name);

    try startLocalHttpServer(&fixture.env, fixture.rootfs.rootfs_path, server_name, null, "resolve-me");
    try waitForServiceDiscoveryResolution(&fixture.env, fixture.rootfs.rootfs_path, server_name);
}

test "http service is reachable from host port and by service name" {
    var fixture = try initNetworkingFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const server_name = try helpers.uniqueName(alloc, "test-http-svc");
    defer alloc.free(server_name);
    defer stopAndRemoveContainer(&fixture.env, server_name);

    try startLocalHttpServer(&fixture.env, fixture.rootfs.rootfs_path, server_name, 18081, "hello-from-host-and-peer");

    try waitForHostHttpBody(&fixture.env, 18081, "hello-from-host-and-peer");
    try waitForServiceDiscoveryHttpBody(&fixture.env, fixture.rootfs.rootfs_path, server_name, "hello-from-host-and-peer");
}

test "service discovery stops resolving after backend removal" {
    var fixture = try initNetworkingFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const server_name = try helpers.uniqueName(alloc, "test-http-remove");
    defer alloc.free(server_name);
    defer stopAndRemoveContainer(&fixture.env, server_name);

    try startLocalHttpServer(&fixture.env, fixture.rootfs.rootfs_path, server_name, null, "hello-before-remove");
    try waitForServiceDiscoveryHttpBody(&fixture.env, fixture.rootfs.rootfs_path, server_name, "hello-before-remove");

    stopAndRemoveContainer(&fixture.env, server_name);
    try waitForServiceDiscoveryHttpFailure(&fixture.env, fixture.rootfs.rootfs_path, server_name);
}

test "service discovery recovers after backend replacement" {
    var fixture = try initNetworkingFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const server_name = try helpers.uniqueName(alloc, "test-http-recover");
    defer alloc.free(server_name);
    defer stopAndRemoveContainer(&fixture.env, server_name);

    try startLocalHttpServer(&fixture.env, fixture.rootfs.rootfs_path, server_name, null, "first-generation");
    try waitForServiceDiscoveryHttpBody(&fixture.env, fixture.rootfs.rootfs_path, server_name, "first-generation");

    stopAndRemoveContainer(&fixture.env, server_name);
    try waitForServiceDiscoveryHttpFailure(&fixture.env, fixture.rootfs.rootfs_path, server_name);

    try startLocalHttpServer(&fixture.env, fixture.rootfs.rootfs_path, server_name, null, "second-generation");
    try waitForServiceDiscoveryHttpBody(&fixture.env, fixture.rootfs.rootfs_path, server_name, "second-generation");
}

test "standalone policy owners reject unenforced configured workloads" {
    try runtime_preflight.requireRuntimeNetwork();
    var result = try helpers.run(alloc, &.{ "python3", "scripts/required-policy-smoke.py" });
    defer result.deinit();
    if (result.exit_code != 0) std.debug.print("required policy fixture failed:\n{s}\n{s}\n", .{ result.stdout, result.stderr });
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
}

fn removeNamedNetwork(env: *helpers.TestEnv, name: []const u8) void {
    if (env.runYoq(&.{ "network", "rm", name })) |result| {
        var removed = result;
        removed.deinit();
    } else |_| {}
}

test "named networks scope DNS aliases and retain stopped attachments" {
    var fixture = try initNetworkingFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();
    const first_network = try helpers.uniqueName(alloc, "named-one");
    defer alloc.free(first_network);
    const second_network = try helpers.uniqueName(alloc, "named-two");
    defer alloc.free(second_network);
    defer removeNamedNetwork(&fixture.env, first_network);
    defer removeNamedNetwork(&fixture.env, second_network);
    const first_server = try helpers.uniqueName(alloc, "server-one");
    defer alloc.free(first_server);
    const second_server = try helpers.uniqueName(alloc, "server-two");
    defer alloc.free(second_server);
    defer stopAndRemoveContainer(&fixture.env, first_server);
    defer stopAndRemoveContainer(&fixture.env, second_server);

    for ([_][]const u8{ first_network, second_network }, [_][]const u8{ first_server, second_server }, [_][]const u8{ "first-scope", "second-scope" }) |network, server, body| {
        var created = try fixture.env.runYoq(&.{ "network", "create", network });
        defer created.deinit();
        try created.expectExitCode(0);
        var started = try fixture.env.runYoq(&.{ "run", "-d", "--name", server, "--network", network, "--network-alias", "shared", fixture.rootfs.rootfs_path, "/bin/yoq-test-http-server", "8080", body });
        defer started.deinit();
        try started.expectExitCode(0);
        try waitForContainerRunning(&fixture.env, server);
    }
    for ([_][]const u8{ first_network, second_network }, [_][]const u8{ "first-scope", "second-scope" }) |network, body| {
        var response = try fixture.env.runYoq(&.{ "run", "--rm", "--network", network, fixture.rootfs.rootfs_path, "/bin/yoq-test-net-probe", "http-get", "shared", "8080", "/" });
        defer response.deinit();
        try response.expectExitCode(0);
        try helpers.expectContains(response.stdout, body);
    }
    var inspected = try fixture.env.runYoq(&.{ "network", "inspect", "--json", first_network });
    defer inspected.deinit();
    try inspected.expectExitCode(0);
    const report = try std.json.parseFromSlice(std.json.Value, alloc, inspected.stdout, .{});
    defer report.deinit();
    try std.testing.expectEqual(@as(i64, 1), report.value.object.get("references").?.integer);
    const member = report.value.object.get("containers").?.array.items[0].object;
    try std.testing.expectEqualStrings("shared", member.get("aliases").?.array.items[0].string);
    try std.testing.expectEqual(@as(usize, 0), member.get("ports").?.array.items.len);
    var other_scope = try fixture.env.runYoq(&.{ "run", "--rm", "--network", second_network, fixture.rootfs.rootfs_path, "/bin/yoq-test-net-probe", "resolve", first_server });
    defer other_scope.deinit();
    try std.testing.expect(other_scope.exit_code != 0);
    var stopped = try fixture.env.runYoq(&.{ "stop", first_server });
    defer stopped.deinit();
    try stopped.expectExitCode(0);
    var refused = try fixture.env.runYoq(&.{ "network", "rm", first_network });
    defer refused.deinit();
    try std.testing.expect(refused.exit_code != 0);
    try helpers.expectContains(refused.stderr, "referenced");
    var removed = try fixture.env.runYoq(&.{ "rm", first_server });
    defer removed.deinit();
    try removed.expectExitCode(0);
    var network_removed = try fixture.env.runYoq(&.{ "network", "rm", first_network });
    defer network_removed.deinit();
    try network_removed.expectExitCode(0);
}

fn inspectedPublishedPort(env: *helpers.TestEnv, name: []const u8, protocol: []const u8) !u16 {
    var result = try env.runYoq(&.{ "container", "inspect", name });
    defer result.deinit();
    try result.expectExitCode(0);
    const document = try std.json.parseFromSlice(std.json.Value, alloc, result.stdout, .{});
    defer document.deinit();
    const config = document.value.object.get("config").?.object;
    const mappings = config.get("port_maps").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), mappings.len);
    const mapping = mappings[0].object;
    try std.testing.expectEqualStrings(protocol, mapping.get("protocol").?.string);
    try std.testing.expectEqualStrings("127.0.0.1", mapping.get("host_ip").?.string);
    const port = mapping.get("host_port").?.integer;
    try std.testing.expect(port > 0 and port <= 65535);
    return @intCast(port);
}

fn probePublishedPort(env: *helpers.TestEnv, address: []const u8, port: []const u8, protocol: []const u8, success: bool) !void {
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        var result = if (std.mem.eql(u8, protocol, "udp"))
            try env.run(&.{ "zig-out/bin/yoq-test-net-probe", "udp-get", address, port, "published-response" })
        else blk: {
            const url = try std.fmt.allocPrint(alloc, "http://{s}:{s}/", .{ address, port });
            defer alloc.free(url);
            break :blk try env.run(&.{ "curl", "--noproxy", "*", "-fsS", "--connect-timeout", "1", "--max-time", "2", url });
        };
        defer result.deinit();
        if (success and result.exit_code != 0 and attempt < 19) {
            try std.Io.sleep(std.testing.io, .fromMilliseconds(50), .awake);
            continue;
        }
        if (success) {
            try result.expectExitCode(0);
            try helpers.expectContains(result.stdout, "published-response");
        } else try std.testing.expect(result.exit_code != 0);
        return;
    }
}

test "loopback tcp and udp ephemeral ports survive restart and retain stopped reservations" {
    var fixture = try initNetworkingFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();
    for ([_][]const u8{ "tcp", "udp" }) |protocol| {
        const name = try helpers.uniqueName(alloc, "ephemeral-port");
        defer alloc.free(name);
        defer stopAndRemoveContainer(&fixture.env, name);
        const mapping = try std.fmt.allocPrint(alloc, "127.0.0.1:0:8080/{s}", .{protocol});
        defer alloc.free(mapping);
        var started = if (std.mem.eql(u8, protocol, "udp"))
            try fixture.env.runYoq(&.{ "run", "-d", "--name", name, "-p", mapping, fixture.rootfs.rootfs_path, "/bin/yoq-test-net-probe", "udp-serve", "8080" })
        else
            try fixture.env.runYoq(&.{ "run", "-d", "--name", name, "-p", mapping, fixture.rootfs.rootfs_path, "/bin/yoq-test-http-server", "8080", "published-response" });
        defer started.deinit();
        try started.expectExitCode(0);
        try waitForContainerRunning(&fixture.env, name);
        const assigned = try inspectedPublishedPort(&fixture.env, name, protocol);
        const port = try std.fmt.allocPrint(alloc, "{d}", .{assigned});
        defer alloc.free(port);
        try probePublishedPort(&fixture.env, "127.0.0.1", port, protocol, true);
        try probePublishedPort(&fixture.env, "127.0.0.2", port, protocol, false);
        var held = try fixture.env.run(&.{ "zig-out/bin/yoq-test-net-probe", "bind-probe", "127.0.0.1", port, protocol });
        defer held.deinit();
        try std.testing.expect(held.exit_code != 0);
        var restarted = try fixture.env.runYoq(&.{ "restart", name });
        defer restarted.deinit();
        try restarted.expectExitCode(0);
        try std.testing.expectEqual(assigned, try inspectedPublishedPort(&fixture.env, name, protocol));
        try probePublishedPort(&fixture.env, "127.0.0.1", port, protocol, true);
        var stopped = try fixture.env.runYoq(&.{ "stop", name });
        defer stopped.deinit();
        try stopped.expectExitCode(0);
        var released_socket = try fixture.env.run(&.{ "zig-out/bin/yoq-test-net-probe", "bind-probe", "127.0.0.1", port, protocol });
        defer released_socket.deinit();
        try released_socket.expectExitCode(0);
        const same_mapping = try std.fmt.allocPrint(alloc, "127.0.0.1:{s}:8080/{s}", .{ port, protocol });
        defer alloc.free(same_mapping);
        var conflict = try fixture.env.runYoq(&.{ "create", "-p", same_mapping, fixture.rootfs.rootfs_path, "/bin/sh" });
        defer conflict.deinit();
        try std.testing.expect(conflict.exit_code != 0);
        var removed = try fixture.env.runYoq(&.{ "rm", name });
        defer removed.deinit();
        try removed.expectExitCode(0);
        var reused = try fixture.env.runYoq(&.{ "create", "--name", name, "-p", same_mapping, fixture.rootfs.rootfs_path, "/bin/sh" });
        defer reused.deinit();
        try reused.expectExitCode(0);
    }
}
