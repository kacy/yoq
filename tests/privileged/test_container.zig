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

test "detached supervisor inherits process environment and exposes container json" {
    var fixture = try initLifecycleFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    const name = try helpers.uniqueName(alloc, "lifecycle-json");
    defer alloc.free(name);

    try fixture.env.env_map.put("YOQ_TEST_SUPERVISOR_MARKER", "inherited-through-entrypoint");
    defer {
        if (fixture.env.runYoq(&.{ "stop", name })) |value| {
            var result = value;
            result.deinit();
        } else |_| {}
        if (fixture.env.runYoq(&.{ "rm", name })) |value| {
            var result = value;
            result.deinit();
        } else |_| {}
    }

    var run_result = try fixture.env.runYoq(&.{
        "run",                      "-d",      "--name", name,
        fixture.rootfs.rootfs_path, "/bin/sh", "-c",     "while :; do :; done",
    });
    defer run_result.deinit();
    try run_result.expectExitCode(0);

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

    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, trimmed, .{});
    defer parsed.deinit();
    const pid = parsed.value.array.items[0].object.get("pid").?.integer;
    const status_path = try std.fmt.allocPrint(alloc, "/proc/{d}/status", .{pid});
    defer alloc.free(status_path);
    var status = try fixture.env.run(&.{ "/bin/cat", status_path });
    defer status.deinit();
    try std.testing.expectEqual(@as(u8, 0), status.exit_code);
    var lines = std.mem.splitScalar(u8, status.stdout, '\n');
    const supervisor_pid = while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "PPid:")) {
            break try std.fmt.parseInt(u32, std.mem.trim(u8, line[5..], " \t"), 10);
        }
    } else return error.TestUnexpectedResult;
    const environ_path = try std.fmt.allocPrint(alloc, "/proc/{d}/environ", .{supervisor_pid});
    defer alloc.free(environ_path);
    var environ = try fixture.env.run(&.{ "/bin/cat", environ_path });
    defer environ.deinit();
    try std.testing.expectEqual(@as(u8, 0), environ.exit_code);
    for ([_][]const u8{ "HOME", "PATH", "YOQ_TEST_SUPERVISOR_MARKER" }) |key| {
        const expected = try std.fmt.allocPrint(alloc, "{s}={s}\x00", .{ key, fixture.env.env_map.get(key).? });
        defer alloc.free(expected);
        try std.testing.expect(std.mem.indexOf(u8, environ.stdout, expected) != null);
    }
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
    try run_result.expectExitCode(0);

    const id = trimOutput(run_result.stdout);
    try std.testing.expect(id.len > 0);

    var stop = try fixture.env.runYoq(&.{ "stop", name });
    defer stop.deinit();
    try stop.expectExitCode(0);

    var rm = try fixture.env.runYoq(&.{ "rm", name });
    defer rm.deinit();
    try rm.expectExitCode(0);

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
    try run_result.expectExitCode(0);

    const id = trimOutput(run_result.stdout);
    try std.testing.expect(id.len > 0);

    var ps = try fixture.env.runYoq(&.{"ps"});
    defer ps.deinit();
    try helpers.expectContains(ps.stdout, id);

    var stop = try fixture.env.runYoq(&.{ "stop", name });
    defer stop.deinit();
    try stop.expectExitCode(0);

    var rm = try fixture.env.runYoq(&.{ "rm", name });
    defer rm.deinit();
    try rm.expectExitCode(0);
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
    try run_result.expectExitCode(0);

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

test "detached startup accepts fast exits independently of exit code" {
    var fixture = try initLifecycleFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();

    for ([_]u8{ 0, 1, 255 }) |exit_code| {
        const command = try std.fmt.allocPrint(alloc, "exit {d}", .{exit_code});
        defer alloc.free(command);
        var launched = try fixture.env.runYoq(&.{ "run", "-d", fixture.rootfs.rootfs_path, "/bin/sh", "-c", command });
        defer launched.deinit();
        try std.testing.expectEqual(@as(u8, 0), launched.exit_code);
        const id = trimOutput(launched.stdout);
        try std.testing.expect(id.len > 0);
        defer {
            if (fixture.env.runYoq(&.{ "rm", id })) |value| {
                var result = value;
                result.deinit();
            } else |_| {}
        }

        var completed = false;
        for (0..100) |_| {
            var ps = try fixture.env.runYoq(&.{ "ps", "--json" });
            defer ps.deinit();
            const parsed = try std.json.parseFromSlice(std.json.Value, alloc, trimOutput(ps.stdout), .{});
            defer parsed.deinit();
            for (parsed.value.array.items) |entry| {
                if (!std.mem.eql(u8, entry.object.get("id").?.string, id)) continue;
                if (std.mem.eql(u8, entry.object.get("status").?.string, "stopped") and entry.object.get("pid").? == .null) {
                    completed = true;
                }
            }
            if (completed) break;
            try std.Io.sleep(std.testing.io, .fromMilliseconds(50), .awake);
        }
        try std.testing.expect(completed);
    }
}

test "detached startup rejects a genuine filesystem preparation failure" {
    var fixture = try initLifecycleFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();
    const proc_path = try std.fmt.allocPrint(alloc, "{s}/proc", .{fixture.rootfs.rootfs_path});
    defer alloc.free(proc_path);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = proc_path, .data = "not a mount directory" });
    var launched = try fixture.env.runYoq(&.{ "run", "-d", fixture.rootfs.rootfs_path, "/bin/sh", "-c", ":" });
    defer launched.deinit();
    try std.testing.expect(launched.exit_code != 0);
    try std.testing.expectEqualStrings("", trimOutput(launched.stdout));
}
