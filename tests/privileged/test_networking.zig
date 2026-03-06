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

// -- bridge tests --

test "container gets an IP address" {
    // run a container and check it got an IP via ps
    var run_result = try helpers.runYoq(alloc, &.{
        "run", "-d", "--name", "test-net-ip", "busybox:latest", "sleep", "30",
    });
    defer run_result.deinit();
    if (run_result.exit_code != 0) {
        std.debug.print("run failed: {s}\n", .{run_result.stderr});
        return error.RunFailed;
    }

    // ps should show an IP for the container
    var ps = try helpers.runYoq(alloc, &.{"ps"});
    defer ps.deinit();

    try std.testing.expect(ps.exit_code == 0);
    // containers get IPs from 10.42.0.0/16
    try helpers.expectContains(ps.stdout, "10.42.");

    // cleanup
    var stop = try helpers.runYoq(alloc, &.{ "stop", "test-net-ip" });
    defer stop.deinit();
    var rm = try helpers.runYoq(alloc, &.{ "rm", "test-net-ip" });
    defer rm.deinit();
}

test "container can reach the internet" {
    // run a container that pings an external host
    var result = try helpers.runYoq(alloc, &.{
        "run", "--name", "test-net-ping", "busybox:latest",
        "ping", "-c", "1", "-W", "5", "8.8.8.8",
    });
    defer result.deinit();

    // should succeed if networking is configured
    try std.testing.expect(result.exit_code == 0);
    try helpers.expectContains(result.stdout, "1 packets transmitted");

    // cleanup
    var rm = try helpers.runYoq(alloc, &.{ "rm", "test-net-ping" });
    defer rm.deinit();
}

test "port mapping makes container reachable from host" {
    // start nginx with port mapping
    var run_result = try helpers.runYoq(alloc, &.{
        "run", "-d", "--name", "test-net-port",
        "-p", "18080:80",
        "busybox:latest", "httpd", "-f", "-p", "80",
    });
    defer run_result.deinit();
    if (run_result.exit_code != 0) {
        std.debug.print("run failed: {s}\n", .{run_result.stderr});
        return error.RunFailed;
    }

    // give the httpd a moment to start
    std.Thread.sleep(500 * std.time.ns_per_ms);

    // curl the mapped port
    var curl = try helpers.run(alloc, &.{
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "--connect-timeout", "3", "http://127.0.0.1:18080/",
    });
    defer curl.deinit();

    // we expect some HTTP response (even 404 is fine — it means port mapping works)
    try std.testing.expect(curl.exit_code == 0);
    const code = std.mem.trim(u8, curl.stdout, " \n\r\t");
    try std.testing.expect(code.len == 3); // HTTP status code

    // cleanup
    var stop = try helpers.runYoq(alloc, &.{ "stop", "test-net-port" });
    defer stop.deinit();
    var rm = try helpers.runYoq(alloc, &.{ "rm", "test-net-port" });
    defer rm.deinit();
}

// -- service discovery --

test "containers discover each other by name" {
    // start a "server" container
    var server = try helpers.runYoq(alloc, &.{
        "run", "-d", "--name", "test-server",
        "busybox:latest", "httpd", "-f", "-p", "80",
    });
    defer server.deinit();
    if (server.exit_code != 0) return error.RunFailed;

    std.Thread.sleep(500 * std.time.ns_per_ms);

    // start a "client" container that resolves the server by name
    var client = try helpers.runYoq(alloc, &.{
        "run", "--name", "test-client",
        "busybox:latest", "nslookup", "test-server",
    });
    defer client.deinit();

    // nslookup should resolve the name to an IP in the 10.42.x.x range
    try std.testing.expect(client.exit_code == 0);
    try helpers.expectContains(client.stdout, "10.42.");

    // cleanup
    var stop = try helpers.runYoq(alloc, &.{ "stop", "test-server" });
    defer stop.deinit();
    var rm_server = try helpers.runYoq(alloc, &.{ "rm", "test-server" });
    defer rm_server.deinit();
    var rm_client = try helpers.runYoq(alloc, &.{ "rm", "test-client" });
    defer rm_client.deinit();
}
