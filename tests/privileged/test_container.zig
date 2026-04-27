// privileged integration tests — container lifecycle
//
// these use a local rootfs fixture and isolated yoq state per test so the
// lifecycle checks are deterministic and do not depend on registry access.

const std = @import("std");
const helpers = @import("helpers");
const runtime_preflight = @import("runtime_preflight");

const alloc = std.testing.allocator;

fn trimOutput(output: []const u8) []const u8 {
    return std.mem.trim(u8, output, " \n\r\t");
}

fn initTestEnv() !helpers.TestEnv {
    try runtime_preflight.requireRuntimeCore();
    return helpers.TestEnv.init(alloc);
}

fn initLifecycleFixture() !struct { env: helpers.TestEnv, rootfs: helpers.RootfsFixture } {
    try runtime_preflight.requireRuntimeCore();
    return .{
        .env = try helpers.TestEnv.init(alloc),
        .rootfs = try helpers.createShellRootfs(alloc),
    };
}

test "run local rootfs command and capture stdout" {
    var fixture = try initLifecycleFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const name = try helpers.uniqueName(alloc, "lifecycle-run");
    defer alloc.free(name);

    var run_result = try fixture.env.runYoq(&.{
        "run", "--name", name, fixture.rootfs.rootfs_path, "/bin/sh", "-c", "echo hello from yoq",
    });
    defer run_result.deinit();

    try std.testing.expect(run_result.exit_code == 0);
    try helpers.expectContains(run_result.stdout, "hello from yoq");
}

test "logs captures local rootfs output" {
    var fixture = try initLifecycleFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const name = try helpers.uniqueName(alloc, "lifecycle-logs");
    defer alloc.free(name);

    var run_result = try fixture.env.runYoq(&.{
        "run", "--name", name, fixture.rootfs.rootfs_path, "/bin/sh", "-c", "echo log-test-output",
    });
    defer run_result.deinit();

    // check logs contain the expected output
    var logs = try fixture.env.runYoq(&.{ "logs", name });
    defer logs.deinit();

    try std.testing.expect(logs.exit_code == 0);
    try helpers.expectContains(logs.stdout, "log-test-output");

    // cleanup
    var rm = try fixture.env.runYoq(&.{ "rm", name });
    defer rm.deinit();
}

test "ps --json produces valid json" {
    var fixture = try initLifecycleFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const name = try helpers.uniqueName(alloc, "lifecycle-json");
    defer alloc.free(name);

    var run_result = try fixture.env.runYoq(&.{
        "run",                      "-d",      "--name", name,
        fixture.rootfs.rootfs_path, "/bin/sh", "-c",     "while :; do :; done",
    });
    defer run_result.deinit();
    try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);

    const id = trimOutput(run_result.stdout);
    try std.testing.expect(id.len > 0);

    var ps = try fixture.env.runYoq(&.{ "ps", "--json" });
    defer ps.deinit();

    try std.testing.expect(ps.exit_code == 0);
    const trimmed = std.mem.trim(u8, ps.stdout, " \n\r\t");
    try std.testing.expect(trimmed.len > 0);
    try std.testing.expect(trimmed[0] == '[');
    try std.testing.expect(trimmed[trimmed.len - 1] == ']');
    try helpers.expectContains(trimmed, id);

    var stop = try fixture.env.runYoq(&.{ "stop", name });
    defer stop.deinit();
    var rm = try fixture.env.runYoq(&.{ "rm", name });
    defer rm.deinit();
}

test "version --json produces valid json" {
    var env = try initTestEnv();
    defer env.deinit();

    var result = try env.runYoq(&.{ "version", "--json" });
    defer result.deinit();

    try std.testing.expect(result.exit_code == 0);
    try helpers.expectContains(result.stdout, "\"version\"");
}

test "stop followed by rm is deterministic for detached rootfs containers" {
    var fixture = try initLifecycleFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const name = try helpers.uniqueName(alloc, "lifecycle-stop-rm");
    defer alloc.free(name);

    var run_result = try fixture.env.runYoq(&.{
        "run",                      "-d",      "--name", name,
        fixture.rootfs.rootfs_path, "/bin/sh", "-c",     "while :; do :; done",
    });
    defer run_result.deinit();
    try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);

    const id = trimOutput(run_result.stdout);
    try std.testing.expect(id.len > 0);

    var stop = try fixture.env.runYoq(&.{ "stop", name });
    defer stop.deinit();
    try std.testing.expectEqual(@as(u8, 0), stop.exit_code);

    var rm = try fixture.env.runYoq(&.{ "rm", name });
    defer rm.deinit();
    try std.testing.expectEqual(@as(u8, 0), rm.exit_code);

    var ps = try fixture.env.runYoq(&.{"ps"});
    defer ps.deinit();
    try helpers.expectNotContains(ps.stdout, id);
}

test "name based lifecycle works for detached rootfs containers" {
    var fixture = try initLifecycleFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const name = try helpers.uniqueName(alloc, "lifecycle-name");
    defer alloc.free(name);

    var run_result = try fixture.env.runYoq(&.{
        "run",                      "-d",      "--name", name,
        fixture.rootfs.rootfs_path, "/bin/sh", "-c",     "while :; do :; done",
    });
    defer run_result.deinit();
    try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);

    const id = trimOutput(run_result.stdout);
    try std.testing.expect(id.len > 0);

    var ps = try fixture.env.runYoq(&.{"ps"});
    defer ps.deinit();
    try helpers.expectContains(ps.stdout, id);

    var stop = try fixture.env.runYoq(&.{ "stop", name });
    defer stop.deinit();
    try std.testing.expectEqual(@as(u8, 0), stop.exit_code);

    var rm = try fixture.env.runYoq(&.{ "rm", name });
    defer rm.deinit();
    try std.testing.expectEqual(@as(u8, 0), rm.exit_code);
}

test "rm running container fails gracefully without corrupting state" {
    var fixture = try initLifecycleFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const name = try helpers.uniqueName(alloc, "lifecycle-rm-running");
    defer alloc.free(name);

    var run_result = try fixture.env.runYoq(&.{
        "run",                      "-d",      "--name", name,
        fixture.rootfs.rootfs_path, "/bin/sh", "-c",     "while :; do :; done",
    });
    defer run_result.deinit();
    try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);

    var rm = try fixture.env.runYoq(&.{ "rm", name });
    defer rm.deinit();
    try std.testing.expect(rm.exit_code != 0);
    try helpers.expectContains(rm.stderr, "cannot remove running container");

    var stop = try fixture.env.runYoq(&.{ "stop", name });
    defer stop.deinit();
    var cleanup = try fixture.env.runYoq(&.{ "rm", name });
    defer cleanup.deinit();
}

test "run with nonexistent image fails gracefully" {
    var env = try initTestEnv();
    defer env.deinit();

    var result = try env.runYoq(&.{ "run", "nonexistent-image-that-does-not-exist:v999" });
    defer result.deinit();

    try std.testing.expect(result.exit_code != 0);
    try std.testing.expect(result.stderr.len > 0);
}

test "stop nonexistent container fails gracefully" {
    var env = try initTestEnv();
    defer env.deinit();

    var result = try env.runYoq(&.{ "stop", "nonexistent-container-id" });
    defer result.deinit();

    try std.testing.expect(result.exit_code != 0);
}
