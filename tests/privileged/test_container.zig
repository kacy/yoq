// privileged integration tests — container lifecycle
//
// tests the full container lifecycle: run, ps, logs, stop, rm.
// requires root and a working yoq binary at zig-out/bin/yoq.
//
// run with: sudo zig build test-privileged
//       or: sudo make test-privileged

const std = @import("std");
const helpers = @import("helpers");

const alloc = std.testing.allocator;

// -- lifecycle tests --

test "run a container and verify it appears in ps" {
    // pull a tiny image first
    var pull = try helpers.runYoq(alloc, &.{ "pull", "busybox:latest" });
    defer pull.deinit();
    if (pull.exit_code != 0) {
        std.debug.print("pull failed: {s}\n", .{pull.stderr});
        return error.PullFailed;
    }

    // run a short-lived container
    var run_result = try helpers.runYoq(alloc, &.{
        "run", "--name", "test-lifecycle", "busybox:latest", "echo", "hello from yoq",
    });
    defer run_result.deinit();

    try std.testing.expect(run_result.exit_code == 0);
    try helpers.expectContains(run_result.stdout, "hello from yoq");
}

test "ps shows running containers" {
    // start a long-running container in background
    var run_result = try helpers.runYoq(alloc, &.{
        "run", "-d", "--name", "test-ps", "busybox:latest", "sleep", "60",
    });
    defer run_result.deinit();
    if (run_result.exit_code != 0) {
        std.debug.print("run -d failed: {s}\n", .{run_result.stderr});
        return error.RunFailed;
    }

    // verify it shows in ps
    var ps = try helpers.runYoq(alloc, &.{"ps"});
    defer ps.deinit();

    try std.testing.expect(ps.exit_code == 0);
    try helpers.expectContains(ps.stdout, "test-ps");

    // cleanup
    var stop = try helpers.runYoq(alloc, &.{ "stop", "test-ps" });
    defer stop.deinit();
    var rm = try helpers.runYoq(alloc, &.{ "rm", "test-ps" });
    defer rm.deinit();
}

test "stop and rm container" {
    // start a container
    var run_result = try helpers.runYoq(alloc, &.{
        "run", "-d", "--name", "test-stop", "busybox:latest", "sleep", "60",
    });
    defer run_result.deinit();
    if (run_result.exit_code != 0) return error.RunFailed;

    // stop it
    var stop = try helpers.runYoq(alloc, &.{ "stop", "test-stop" });
    defer stop.deinit();
    try std.testing.expect(stop.exit_code == 0);

    // it should no longer appear as running in ps
    var ps = try helpers.runYoq(alloc, &.{"ps"});
    defer ps.deinit();
    try helpers.expectNotContains(ps.stdout, "running");

    // remove it
    var rm = try helpers.runYoq(alloc, &.{ "rm", "test-stop" });
    defer rm.deinit();
    try std.testing.expect(rm.exit_code == 0);
}

test "logs captures container output" {
    // run a container that produces known output
    var run_result = try helpers.runYoq(alloc, &.{
        "run", "--name", "test-logs", "busybox:latest", "echo", "log-test-output",
    });
    defer run_result.deinit();
    if (run_result.exit_code != 0) return error.RunFailed;

    // check logs contain the expected output
    var logs = try helpers.runYoq(alloc, &.{ "logs", "test-logs" });
    defer logs.deinit();

    try std.testing.expect(logs.exit_code == 0);
    try helpers.expectContains(logs.stdout, "log-test-output");

    // cleanup
    var rm = try helpers.runYoq(alloc, &.{ "rm", "test-logs" });
    defer rm.deinit();
}

// -- json output --

test "ps --json produces valid json" {
    var run_result = try helpers.runYoq(alloc, &.{
        "run", "-d", "--name", "test-json", "busybox:latest", "sleep", "30",
    });
    defer run_result.deinit();
    if (run_result.exit_code != 0) return error.RunFailed;

    var ps = try helpers.runYoq(alloc, &.{ "ps", "--json" });
    defer ps.deinit();

    try std.testing.expect(ps.exit_code == 0);
    // json output should start with [ and end with ]
    const trimmed = std.mem.trim(u8, ps.stdout, " \n\r\t");
    try std.testing.expect(trimmed.len > 0);
    try std.testing.expect(trimmed[0] == '[');
    try std.testing.expect(trimmed[trimmed.len - 1] == ']');

    // cleanup
    var stop = try helpers.runYoq(alloc, &.{ "stop", "test-json" });
    defer stop.deinit();
    var rm = try helpers.runYoq(alloc, &.{ "rm", "test-json" });
    defer rm.deinit();
}

test "version --json produces valid json" {
    var result = try helpers.runYoq(alloc, &.{ "version", "--json" });
    defer result.deinit();

    try std.testing.expect(result.exit_code == 0);
    try helpers.expectContains(result.stdout, "\"version\"");
}

// -- error handling --

test "run with nonexistent image fails gracefully" {
    var result = try helpers.runYoq(alloc, &.{
        "run", "nonexistent-image-that-does-not-exist:v999",
    });
    defer result.deinit();

    try std.testing.expect(result.exit_code != 0);
    try std.testing.expect(result.stderr.len > 0);
}

test "stop nonexistent container fails gracefully" {
    var result = try helpers.runYoq(alloc, &.{ "stop", "nonexistent-container-id" });
    defer result.deinit();

    try std.testing.expect(result.exit_code != 0);
}
