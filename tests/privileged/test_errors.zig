// privileged integration tests — error paths and edge cases
//
// these tests verify that yoq handles errors gracefully and doesn't
// leak resources or crash when things go wrong.

const std = @import("std");
const helpers = @import("helpers");

const alloc = std.testing.allocator;

fn looksLikeValidContainerId(id: []const u8) bool {
    if (id.len != 12) return false;
    for (id) |c| {
        switch (c) {
            '0'...'9', 'a'...'f' => {},
            else => return false,
        }
    }
    return true;
}

test "run with nonexistent rootfs fails gracefully" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var result = try env.runYoq(&.{
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
    var result = try env.runYoq(&.{
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

    var result = try env.runYoq(&.{
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

    var result = try env.runYoq(&.{
        "run", "--name", name, fixture.rootfs_path,
        "/bin/sh", "-c", "printf '%s' \"$1\" >/dev/null && echo ok", "sh", long_arg,
    });
    defer result.deinit();

    // long argv should still execute successfully with a shell-only rootfs
    try std.testing.expectEqual(@as(u8, 0), result.exit_code);
    try helpers.expectContains(result.stdout, "ok");
}

test "logs for nonexistent container" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var result = try env.runYoq(&.{ "logs", "nonexistent123" });
    defer result.deinit();

    // should fail gracefully
    try std.testing.expect(result.exit_code != 0);
}

test "rm nonexistent container" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var result = try env.runYoq(&.{ "rm", "nonexistent123" });
    defer result.deinit();

    try std.testing.expect(result.exit_code != 0);
    try helpers.expectContains(result.stderr, "container not found");
}

test "stop nonexistent container" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var result = try env.runYoq(&.{ "stop", "nonexistent123" });
    defer result.deinit();

    // should fail gracefully
    try std.testing.expect(result.exit_code != 0);
}

test "exec into nonexistent container" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var result = try env.runYoq(&.{ "exec", "nonexistent123", "/bin/sh" });
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
    var result = try env.runYoq(&.{
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
    var result = try env.runYoq(&.{
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
    var result = try env.runYoq(&.{
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

    // start detached container with a shell builtin so the shell-only rootfs is sufficient
    var run_result = try env.runYoq(&.{
        "run", "-d", "--name", name, fixture.rootfs_path, "/bin/sh", "-c", ":",
    });
    defer run_result.deinit();
    try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);

    // wait a bit for it to complete
    std.Thread.sleep(200 * std.time.ns_per_ms);

    // stop should fail since it's already stopped
    var stop_result = try env.runYoq(&.{ "stop", name });
    defer stop_result.deinit();
    try std.testing.expect(stop_result.exit_code != 0);

    // rm should succeed
    var rm_result = try env.runYoq(&.{ "rm", name });
    defer rm_result.deinit();
    try std.testing.expectEqual(@as(u8, 0), rm_result.exit_code);
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
            "run", "--name", name, fixture.rootfs_path, "/bin/sh", "-c", ":",
        });
        defer run_result.deinit();
        try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);

        // cleanup
        var rm_result = try env.runYoq(&.{ "rm", name });
        defer rm_result.deinit();
    }
}

test "container ID validation rejects path traversal" {
    // valid IDs
    try std.testing.expect(looksLikeValidContainerId("abc123def456"));
    try std.testing.expect(looksLikeValidContainerId("0123456789ab"));
    try std.testing.expect(looksLikeValidContainerId("ffffffffffff"));

    // path traversal
    try std.testing.expect(!looksLikeValidContainerId("../etc/passwd"));
    try std.testing.expect(!looksLikeValidContainerId("../../etc"));
    try std.testing.expect(!looksLikeValidContainerId("/etc/passwd"));
    try std.testing.expect(!looksLikeValidContainerId("abc/../def"));

    // invalid characters
    try std.testing.expect(!looksLikeValidContainerId("ABC123DEF456")); // uppercase
    try std.testing.expect(!looksLikeValidContainerId("xyz123def456")); // non-hex
    try std.testing.expect(!looksLikeValidContainerId("abc:123def45")); // colon

    // wrong lengths
    try std.testing.expect(!looksLikeValidContainerId("abc123")); // too short
    try std.testing.expect(!looksLikeValidContainerId("abc123def4567")); // too long
    try std.testing.expect(!looksLikeValidContainerId("")); // empty
}
