// privileged integration tests — networking
//
// tests bridge creation, container networking, and port mapping.
// requires root and a working yoq binary at zig-out/bin/yoq.
//
// run with: sudo zig build test-privileged
//       or: sudo make test-privileged

const std = @import("std");
const helpers = @import("helpers");

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
        std.Thread.sleep(250 * std.time.ns_per_ms);
    }

    std.debug.print("timed out waiting for container {s} to reach running state\n", .{name});
    return error.TestExpectedContains;
}

fn initNetworkingFixture() !struct { env: helpers.TestEnv, rootfs: helpers.RootfsFixture } {
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
        std.Thread.sleep(250 * std.time.ns_per_ms);
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
        std.Thread.sleep(250 * std.time.ns_per_ms);
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
        std.Thread.sleep(250 * std.time.ns_per_ms);
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
        std.Thread.sleep(250 * std.time.ns_per_ms);
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
        try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);
        try std.testing.expect(trimOutput(run_result.stdout).len > 0);
        try waitForContainerRunning(env, name);
        return;
    }

    var run_result = try env.runYoq(&.{
        "run", "-d", "--name", name, rootfs_path, "/bin/yoq-test-http-server", port_str, body,
    });
    defer run_result.deinit();
    try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);
    try std.testing.expect(trimOutput(run_result.stdout).len > 0);
    try waitForContainerRunning(env, name);
}

fn requireExternalNetworkTests() !void {
    const raw = std.process.getEnvVarOwned(alloc, "YOQ_REQUIRE_NETWORK_TESTS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer alloc.free(raw);

    const enabled = std.mem.trim(u8, raw, " \n\r\t");
    if (!std.mem.eql(u8, enabled, "1")) return error.SkipZigTest;
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
