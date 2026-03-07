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

fn trimOutput(output: []const u8) []const u8 {
    return std.mem.trim(u8, output, " \n\r\t");
}

fn pullBusybox(env: *helpers.TestEnv) !void {
    var pull = try env.runYoq(&.{ "pull", "busybox:latest" });
    defer pull.deinit();

    if (pull.exit_code != 0) {
        std.debug.print("pull failed: {s}\n", .{pull.stderr});
        return error.PullFailed;
    }
}

test "container gets an IP address" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();
    try pullBusybox(&env);

    const name = try helpers.uniqueName(alloc, "test-net-ip");
    defer alloc.free(name);

    var run_result = try env.runYoq(&.{
        "run", "-d", "--name", name, "busybox:latest", "sleep", "30",
    });
    defer run_result.deinit();
    try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);

    const id = trimOutput(run_result.stdout);
    try std.testing.expect(id.len > 0);

    var ps = try env.runYoq(&.{"ps"});
    defer ps.deinit();

    try std.testing.expect(ps.exit_code == 0);
    try helpers.expectContains(ps.stdout, id);
    try helpers.expectContains(ps.stdout, "10.42.");

    var stop = try env.runYoq(&.{ "stop", name });
    defer stop.deinit();
    var rm = try env.runYoq(&.{ "rm", name });
    defer rm.deinit();
}

test "container can reach the internet" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();
    try pullBusybox(&env);

    const name = try helpers.uniqueName(alloc, "test-net-ping");
    defer alloc.free(name);

    var result = try env.runYoq(&.{
        "run",  "--name",  name, "busybox:latest",
        "ping", "-c",      "1",  "-W",
        "5",    "8.8.8.8",
    });
    defer result.deinit();

    // should succeed if networking is configured
    try std.testing.expect(result.exit_code == 0);
    try helpers.expectContains(result.stdout, "1 packets transmitted");

    var rm = try env.runYoq(&.{ "rm", name });
    defer rm.deinit();
}

test "port mapping makes container reachable from host" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();
    try pullBusybox(&env);

    const name = try helpers.uniqueName(alloc, "test-net-port");
    defer alloc.free(name);

    var run_result = try env.runYoq(&.{
        "run", "-d",       "--name",         name,
        "-p",  "18080:80", "busybox:latest", "httpd",
        "-f",  "-p",       "80",
    });
    defer run_result.deinit();
    try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);

    std.Thread.sleep(500 * std.time.ns_per_ms);

    var curl = try env.run(&.{
        "curl",              "-s", "-o",                      "/dev/null", "-w", "%{http_code}",
        "--connect-timeout", "3",  "http://127.0.0.1:18080/",
    });
    defer curl.deinit();

    try std.testing.expect(curl.exit_code == 0);
    const code = std.mem.trim(u8, curl.stdout, " \n\r\t");
    try std.testing.expect(code.len == 3); // HTTP status code

    var stop = try env.runYoq(&.{ "stop", name });
    defer stop.deinit();
    var rm = try env.runYoq(&.{ "rm", name });
    defer rm.deinit();
}

test "containers discover each other by name" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();
    try pullBusybox(&env);

    const server_name = try helpers.uniqueName(alloc, "test-server");
    defer alloc.free(server_name);
    const client_name = try helpers.uniqueName(alloc, "test-client");
    defer alloc.free(client_name);

    var server = try env.runYoq(&.{
        "run",            "-d",    "--name", server_name,
        "busybox:latest", "httpd", "-f",     "-p",
        "80",
    });
    defer server.deinit();
    try std.testing.expectEqual(@as(u8, 0), server.exit_code);

    std.Thread.sleep(500 * std.time.ns_per_ms);

    var client = try env.runYoq(&.{
        "run",            "--name",   client_name,
        "busybox:latest", "nslookup", server_name,
    });
    defer client.deinit();

    try std.testing.expect(client.exit_code == 0);
    try helpers.expectContains(client.stdout, "10.42.");

    var stop = try env.runYoq(&.{ "stop", server_name });
    defer stop.deinit();
    var rm_server = try env.runYoq(&.{ "rm", server_name });
    defer rm_server.deinit();
    var rm_client = try env.runYoq(&.{ "rm", client_name });
    defer rm_client.deinit();
}
