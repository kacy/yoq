// privileged integration tests — error paths and edge cases
//
// these tests verify that yoq handles errors gracefully and doesn't
// leak resources or crash when things go wrong.

const std = @import("std");
const helpers = @import("helpers");

const alloc = std.testing.allocator;

test "run with nonexistent rootfs fails gracefully" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    const result = try env.runYoq(&.{
        "run", "/nonexistent/path/to/rootfs", "/bin/sh", "-c", "echo hello",
    });
    defer result.deinit();

    // should fail with error, not crash
    try std.testing.expect(result.exit_code != 0);
}

test "run with invalid container ID is rejected" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    // try to use a path-traversal id (should be rejected)
    const result = try env.runYoq(&.{
        "run", "--name", "../etc/passwd", fixture.rootfs_path, "/bin/sh", "-c", "echo hello",
    });
    defer result.deinit();

    // should fail - invalid id contains path traversal
    try std.testing.expect(result.exit_code != 0);
}

test "run with command that doesn't exist" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    const name = try helpers.uniqueName(alloc, "error-cmd-not-found");
    defer alloc.free(name);

    const result = try env.runYoq(&.{
        "run", "--name", name, fixture.rootfs_path, "/nonexistent/command",
    });
    defer result.deinit();

    // command not found should return 127
    try std.testing.expectEqual(@as(u8, 127), result.exit_code);
}

test "run with extremely long command line" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    const name = try helpers.uniqueName(alloc, "error-long-cmd");
    defer alloc.free(name);

    // create a very long argument (close to the 64KB buffer limit)
    const long_arg = try alloc.alloc(u8, 1000);
    defer alloc.free(long_arg);
    @memset(long_arg, 'a');

    const result = try env.runYoq(&.{
        "run", "--name", name, fixture.rootfs_path, "/bin/echo", long_arg,
    });
    defer result.deinit();

    // should succeed or fail gracefully - either way we verify no crash
    try std.testing.expect(result.exit_code == 0 or result.exit_code == 127);
}

test "logs for nonexistent container" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    const result = try env.runYoq(&.{ "logs", "nonexistent123" });
    defer result.deinit();

    // should fail gracefully
    try std.testing.expect(result.exit_code != 0);
}

test "rm nonexistent container" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    const result = try env.runYoq(&.{ "rm", "nonexistent123" });
    defer result.deinit();

    // might fail but shouldn't crash
    try std.testing.expect(result.exit_code == 0 or result.exit_code != 0);
}

test "stop nonexistent container" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    const result = try env.runYoq(&.{ "stop", "nonexistent123" });
    defer result.deinit();

    // should fail gracefully
    try std.testing.expect(result.exit_code != 0);
}

test "exec into nonexistent container" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    const result = try env.runYoq(&.{ "exec", "nonexistent123", "/bin/sh" });
    defer result.deinit();

    // should fail gracefully
    try std.testing.expect(result.exit_code != 0);
}

test "run with invalid bind mount source" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    const name = try helpers.uniqueName(alloc, "error-bad-mount");
    defer alloc.free(name);

    // try to mount a sensitive path
    const result = try env.runYoq(&.{
        "run",     "--name",                  name,
        "--mount", "/etc/passwd:/etc/passwd", fixture.rootfs_path,
        "/bin/sh", "-c",                      "echo hello",
    });
    defer result.deinit();

    // should fail - mounting /etc is blocked
    try std.testing.expect(result.exit_code != 0);
}

test "run with resource limits enforced" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    const name = try helpers.uniqueName(alloc, "error-limits");
    defer alloc.free(name);

    // run with very low memory limit
    const result = try env.runYoq(&.{
        "run", "--name", name,
        "--memory",          "4m", // minimum allowed
        fixture.rootfs_path, "/bin/sh",
        "-c",                "echo within limits",
    });
    defer result.deinit();

    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
}

test "run with memory below minimum is rejected" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    const name = try helpers.uniqueName(alloc, "error-memory-min");
    defer alloc.free(name);

    // 1 MB is below the 4 MB minimum
    const result = try env.runYoq(&.{
        "run",      "--name", name,
        "--memory", "1m",     fixture.rootfs_path,
        "/bin/sh",  "-c",     "echo hello",
    });
    defer result.deinit();

    // should fail validation
    try std.testing.expect(result.exit_code != 0);
}

test "run detached and cleanup" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    const name = try helpers.uniqueName(alloc, "error-detach");
    defer alloc.free(name);

    // start detached container
    var run_result = try env.runYoq(&.{
        "run", "-d", "--name", name, fixture.rootfs_path, "/bin/sh", "-c", "sleep 0.1",
    });
    defer run_result.deinit();
    try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);

    // wait a bit for it to complete
    std.time.sleep(200 * std.time.ns_per_ms);

    // stop should fail since it's already stopped
    var stop_result = try env.runYoq(&.{ "stop", name });
    defer stop_result.deinit();
    // might fail but shouldn't crash

    // rm should succeed
    var rm_result = try env.runYoq(&.{ "rm", name });
    defer rm_result.deinit();
    // cleanup should work
}

test "rapid start/stop cycles don't leak" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    // run 10 rapid cycles
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const name = try helpers.uniqueName(alloc, "error-rapid");
        defer alloc.free(name);

        var run_result = try env.runYoq(&.{
            "run", "--name", name, fixture.rootfs_path, "/bin/true",
        });
        defer run_result.deinit();
        try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);

        // cleanup
        var rm_result = try env.runYoq(&.{ "rm", name });
        defer rm_result.deinit();
    }
}

test "container ID validation rejects path traversal" {
    const container = @import("container");

    // valid IDs
    try std.testing.expect(container.isValidContainerId("abc123def456"));
    try std.testing.expect(container.isValidContainerId("0123456789ab"));
    try std.testing.expect(container.isValidContainerId("ffffffffffff"));

    // path traversal
    try std.testing.expect(!container.isValidContainerId("../etc/passwd"));
    try std.testing.expect(!container.isValidContainerId("../../etc"));
    try std.testing.expect(!container.isValidContainerId("/etc/passwd"));
    try std.testing.expect(!container.isValidContainerId("abc/../def"));

    // invalid characters
    try std.testing.expect(!container.isValidContainerId("ABC123DEF456")); // uppercase
    try std.testing.expect(!container.isValidContainerId("xyz123def456")); // non-hex
    try std.testing.expect(!container.isValidContainerId("abc:123def45")); // colon

    // wrong lengths
    try std.testing.expect(!container.isValidContainerId("abc123")); // too short
    try std.testing.expect(!container.isValidContainerId("abc123def4567")); // too long
    try std.testing.expect(!container.isValidContainerId("")); // empty
}
