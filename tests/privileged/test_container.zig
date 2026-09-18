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
            var ps = try fixture.env.runYoq(&.{ "ps", "-a", "--json" });
            defer ps.deinit();
            try ps.expectExitCode(0);
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

const ImageFixture = struct {
    env: helpers.TestEnv,
    rootfs: helpers.RootfsFixture,
    // A registry lookup would fail: this fixture is built entirely from local files.
    const tag = "127.0.0.1:1/parity:fixture";

    fn init() !ImageFixture {
        try runtime_preflight.requireRuntimeCore();
        var env = try helpers.TestEnv.init(alloc);
        errdefer env.deinit();
        var rootfs = try helpers.createRootfsWithBinaries(alloc, &.{
            .{ .host_path = "/bin/sh", .dest_path = "/bin/sh" },
            .{ .host_path = "/bin/sleep", .dest_path = "/bin/sleep" },
        });
        errdefer rootfs.deinit();
        for ([_][]const u8{ "work", "data" }) |name| {
            const path = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ rootfs.rootfs_path, name });
            defer alloc.free(path);
            try std.Io.Dir.cwd().createDirPath(std.testing.io, path);
        }
        try helpers.writeFile(rootfs.rootfs_path, "data/seed", "image-seed\n");
        try helpers.writeFile(rootfs.tmp.slice(), "Dockerfile", "FROM scratch\nCOPY rootfs/ /\nENV PATH=/bin\nENV FIXTURE_ENV=image-value\nWORKDIR /work\nCMD [\"/bin/sh\", \"-c\", \"printf offline\"]\n");
        var built = try env.runYoq(&.{ "build", "-t", tag, rootfs.tmp.slice() });
        defer built.deinit();
        try built.expectExitCode(0);
        return .{ .env = env, .rootfs = rootfs };
    }

    fn deinit(self: *ImageFixture) void {
        self.rootfs.deinit();
        self.env.deinit();
    }
};

fn cleanupContainer(env: *helpers.TestEnv, name: []const u8) void {
    for ([_][]const u8{ "stop", "rm" }) |command| {
        if (env.runYoq(&.{ command, name })) |value| {
            var result = value;
            result.deinit();
        } else |_| {}
    }
}

fn expectCommand(env: *helpers.TestEnv, args: []const []const u8) !void {
    var result = try env.runYoq(args);
    defer result.deinit();
    try result.expectExitCode(0);
}

fn expectExecOutput(env: *helpers.TestEnv, name: []const u8, command: []const u8, expected: []const u8) !void {
    var result = try env.runYoq(&.{ "exec", name, "sh", "-c", command });
    defer result.deinit();
    try result.expectExitCode(0);
    try std.testing.expectEqualStrings(expected, result.stdout);
}

fn waitRemoved(env: *helpers.TestEnv, name: []const u8) !void {
    for (0..100) |_| {
        var result = try env.runYoq(&.{ "container", "inspect", name });
        defer result.deinit();
        if (result.exit_code != 0) return;
        try std.Io.sleep(std.testing.io, .fromMilliseconds(50), .awake);
    }
    return error.ContainerNotRemoved;
}

test "local parity builds offline and preserves raw streams and process configuration" {
    var fixture = try ImageFixture.init();
    defer fixture.deinit();
    var defaults = try fixture.env.runYoq(&.{ "run", "--no-net", "--rm", ImageFixture.tag });
    defer defaults.deinit();
    try defaults.expectExitCode(0);
    try std.testing.expectEqualStrings("offline", defaults.stdout);
    defer cleanupContainer(&fixture.env, "raw-streams");
    var raw = try fixture.env.runYoq(&.{ "run", "--no-net", "--name", "raw-streams", ImageFixture.tag, "sh", "-c", "printf 'prompt>\\000\\r'; printf error-tail >&2; exit 23" });
    defer raw.deinit();
    try raw.expectExitCode(23);
    try std.testing.expectEqualStrings("prompt>\x00\r", raw.stdout);
    try std.testing.expectEqualStrings("error-tail", raw.stderr);

    defer cleanupContainer(&fixture.env, "effective-process");
    var started = try fixture.env.runYoq(&.{ "run", "--no-net", "--pull", "never", "-d", "--name", "effective-process", "-e", "FIXTURE_ENV=cli-value", ImageFixture.tag, "sleep", "60" });
    defer started.deinit();
    try started.expectExitCode(0);
    try expectExecOutput(&fixture.env, "effective-process", "printf '%s|%s|%s' \"$FIXTURE_ENV\" \"$PATH\" \"$PWD\"", "cli-value|/bin|/work");
    var signaled = try fixture.env.runYoq(&.{ "exec", "effective-process", "sh", "-c", "kill -TERM $$" });
    defer signaled.deinit();
    try signaled.expectExitCode(143);
    var terminal = try fixture.env.runYoq(&.{ "exec", "-t", "effective-process", "sh", "-c", "test -t 0 && test -t 1 && test -t 2 && printf terminal" });
    defer terminal.deinit();
    try terminal.expectExitCode(0);
    try std.testing.expectEqualStrings("terminal", terminal.stdout);

    var tail = try fixture.env.runYoq(&.{ "logs", "raw-streams", "--tail", "0" });
    defer tail.deinit();
    try tail.expectExitCode(0);
    try std.testing.expectEqualStrings("", tail.stdout);
}

test "local parity preserves image writable files through stop start restart and copy" {
    var fixture = try ImageFixture.init();
    defer fixture.deinit();
    defer cleanupContainer(&fixture.env, "durable-files");
    var launched = try fixture.env.runYoq(&.{ "run", "--no-net", "-d", "--name", "durable-files", ImageFixture.tag, "sleep", "60" });
    defer launched.deinit();
    try launched.expectExitCode(0);
    const id = trimOutput(launched.stdout);
    try expectExecOutput(&fixture.env, "durable-files", "printf original > /work/marker", "");
    try expectCommand(&fixture.env, &.{ "stop", "durable-files" });
    const host_source = try std.fmt.allocPrint(alloc, "{s}/copy-in", .{fixture.env.tmp.slice()});
    defer alloc.free(host_source);
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = host_source, .data = "copied while stopped\n" });
    try expectCommand(&fixture.env, &.{ "cp", host_source, "durable-files:/work/copied" });
    const host_destination = try std.fmt.allocPrint(alloc, "{s}/copy-out", .{fixture.env.tmp.slice()});
    defer alloc.free(host_destination);
    try expectCommand(&fixture.env, &.{ "cp", "durable-files:/work/copied", host_destination });
    const copied = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, host_destination, alloc, .limited(100));
    defer alloc.free(copied);
    try std.testing.expectEqualStrings("copied while stopped\n", copied);

    try expectCommand(&fixture.env, &.{ "start", "durable-files" });
    try expectExecOutput(&fixture.env, "durable-files", "IFS= read -r marker < /work/marker; printf '%s' \"$marker\"", "original");
    try expectCommand(&fixture.env, &.{ "restart", "durable-files" });
    try expectExecOutput(&fixture.env, "durable-files", "IFS= read -r marker < /work/marker; printf '%s' \"$marker\"", "original");
    var changes = try fixture.env.runYoq(&.{ "diff", "durable-files" });
    defer changes.deinit();
    try changes.expectExitCode(0);
    try helpers.expectContains(changes.stdout, "A /work/marker\n");
    try helpers.expectContains(changes.stdout, "A /work/copied\n");
    try expectCommand(&fixture.env, &.{ "stop", "durable-files" });
    try expectCommand(&fixture.env, &.{ "rm", "durable-files" });
    const storage = try std.fmt.allocPrint(alloc, "{s}/.local/share/yoq/containers/{s}", .{ fixture.env.home, id });
    defer alloc.free(storage);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(std.testing.io, storage, .{}));
}

test "local parity manual stop suppresses always restart and automatic removal clears state" {
    var fixture = try ImageFixture.init();
    defer fixture.deinit();
    defer cleanupContainer(&fixture.env, "always-stop");
    try expectCommand(&fixture.env, &.{ "run", "--no-net", "-d", "--name", "always-stop", "--restart", "always", ImageFixture.tag, "sleep", "60" });
    try expectCommand(&fixture.env, &.{ "stop", "always-stop" });
    // Observe beyond the first automatic-restart backoff.
    try std.Io.sleep(std.testing.io, .fromMilliseconds(1300), .awake);
    var state = try fixture.env.runYoq(&.{ "container", "inspect", "always-stop" });
    defer state.deinit();
    try state.expectExitCode(0);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, state.stdout, .{});
    defer parsed.deinit();
    try std.testing.expect(!parsed.value.object.get("desired_running").?.bool);
    const record = parsed.value.object.get("state").?.object;
    try std.testing.expectEqualStrings("stopped", record.get("status").?.string);
    try std.testing.expect(record.get("pid").? == .null);
    var running = try fixture.env.runYoq(&.{ "ps", "--json" });
    defer running.deinit();
    try running.expectExitCode(0);
    try helpers.expectNotContains(running.stdout, "always-stop");
    var all = try fixture.env.runYoq(&.{ "ps", "-a", "--json" });
    defer all.deinit();
    try all.expectExitCode(0);
    try helpers.expectContains(all.stdout, "always-stop");

    var automatic = try fixture.env.runYoq(&.{ "run", "--no-net", "--rm", "--name", "remove-on-exit", ImageFixture.tag, "sh", "-c", "printf removed-output" });
    defer automatic.deinit();
    try automatic.expectExitCode(0);
    try std.testing.expectEqualStrings("removed-output", automatic.stdout);
    try waitRemoved(&fixture.env, "remove-on-exit");
}

test "local parity initializes named and anonymous volumes without overwriting retained data" {
    var fixture = try ImageFixture.init();
    defer fixture.deinit();
    const read_seed = "IFS= read -r seed < /data/seed; printf '%s' \"$seed\"";
    var named = try fixture.env.runYoq(&.{ "run", "--no-net", "--rm", "--name", "named-first", "--mount", "type=volume,source=parity-data,target=/data", ImageFixture.tag, "sh", "-c", "IFS= read -r seed < /data/seed; printf '%s' \"$seed\"; printf retained > /data/seed" });
    defer named.deinit();
    try named.expectExitCode(0);
    try std.testing.expectEqualStrings("image-seed", named.stdout);
    try waitRemoved(&fixture.env, "named-first");
    var kept = try fixture.env.runYoq(&.{ "volume", "inspect", "parity-data" });
    defer kept.deinit();
    try kept.expectExitCode(0);
    try helpers.expectContains(kept.stdout, "kind: named\n");
    try helpers.expectContains(kept.stdout, "references: 0\n");
    var reused = try fixture.env.runYoq(&.{ "run", "--no-net", "--rm", "--name", "named-second", "--mount", "type=volume,source=parity-data,target=/data", ImageFixture.tag, "sh", "-c", read_seed });
    defer reused.deinit();
    try reused.expectExitCode(0);
    try std.testing.expectEqualStrings("retained", reused.stdout);
    try waitRemoved(&fixture.env, "named-second");

    defer cleanupContainer(&fixture.env, "anonymous-owner");
    try expectCommand(&fixture.env, &.{ "run", "--no-net", "-d", "--name", "anonymous-owner", "--mount", "type=volume,target=/data", ImageFixture.tag, "sleep", "60" });
    try expectExecOutput(&fixture.env, "anonymous-owner", read_seed, "image-seed");
    try expectExecOutput(&fixture.env, "anonymous-owner", "printf anonymous-data > /data/seed", "");
    var inspected = try fixture.env.runYoq(&.{ "container", "inspect", "anonymous-owner" });
    defer inspected.deinit();
    try inspected.expectExitCode(0);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, inspected.stdout, .{});
    defer parsed.deinit();
    const mounts = parsed.value.object.get("config").?.object.get("mounts").?.array.items;
    const source = for (mounts) |mount| {
        if (std.mem.eql(u8, mount.object.get("target").?.string, "/data")) break mount.object.get("source").?.string;
    } else return error.VolumeMountMissing;
    const volume_name = std.fs.path.basename(source);
    try expectCommand(&fixture.env, &.{ "stop", "anonymous-owner" });
    try expectCommand(&fixture.env, &.{ "start", "anonymous-owner" });
    try expectExecOutput(&fixture.env, "anonymous-owner", read_seed, "anonymous-data");
    try expectCommand(&fixture.env, &.{ "stop", "anonymous-owner" });
    try expectCommand(&fixture.env, &.{ "rm", "anonymous-owner" });
    var retained = try fixture.env.runYoq(&.{ "volume", "inspect", volume_name });
    defer retained.deinit();
    try retained.expectExitCode(0);
    try helpers.expectContains(retained.stdout, "kind: anonymous\n");
    try helpers.expectContains(retained.stdout, "references: 0\n");
    try expectCommand(&fixture.env, &.{ "volume", "rm", volume_name });

    var automatic = try fixture.env.runYoq(&.{ "run", "--no-net", "--rm", "--name", "anonymous-auto", "--mount", "type=volume,target=/data", ImageFixture.tag, "sh", "-c", read_seed });
    defer automatic.deinit();
    try automatic.expectExitCode(0);
    try std.testing.expectEqualStrings("image-seed", automatic.stdout);
    try waitRemoved(&fixture.env, "anonymous-auto");
    var volumes = try fixture.env.runYoq(&.{ "volume", "ls" });
    defer volumes.deinit();
    try volumes.expectExitCode(0);
    try helpers.expectContains(volumes.stdout, "parity-data");
    try helpers.expectNotContains(volumes.stdout, "anonymous");
}

test "local parity forwards piped stdin through foreground run exec and attach" {
    var fixture = try initLifecycleFixture();
    defer fixture.env.deinit();
    defer fixture.rootfs.deinit();
    const executable = try std.fmt.allocPrint(alloc, "{s}/zig-out/bin/yoq", .{fixture.env.cwd});
    defer alloc.free(executable);
    const script = "printf 'one\\ntwo\\n' | \"$1\" run --no-net --rm -i \"$2\" /bin/sh -c 'while IFS= read -r line; do printf \"<%s>\" \"$line\"; done'";
    var foreground = try fixture.env.run(&.{ "/bin/sh", "-c", script, "stdin-fixture", executable, fixture.rootfs.rootfs_path });
    defer foreground.deinit();
    try foreground.expectExitCode(0);
    try std.testing.expectEqualStrings("<one><two>", foreground.stdout);

    defer cleanupContainer(&fixture.env, "pipe-attach");
    try expectCommand(&fixture.env, &.{ "run", "--no-net", "-d", "-i", "--name", "pipe-attach", fixture.rootfs.rootfs_path, "/bin/sh", "-c", "while IFS= read -r line; do printf '<%s>' \"$line\"; done" });
    var executed = try fixture.env.run(&.{ "/bin/sh", "-c", "printf 'exec-input\\n' | \"$1\" exec -i pipe-attach /bin/sh -c 'IFS= read -r value; printf \"%s\" \"$value\"'", "exec-stdin", executable });
    defer executed.deinit();
    try executed.expectExitCode(0);
    try std.testing.expectEqualStrings("exec-input", executed.stdout);
    var attached = try fixture.env.run(&.{ "/bin/sh", "-c", "printf 'attached-input\\n' | \"$1\" attach pipe-attach", "attach-stdin", executable });
    defer attached.deinit();
    try attached.expectExitCode(0);
    try std.testing.expectEqualStrings("<attached-input>", attached.stdout);
}

fn waitHealth(env: *helpers.TestEnv, name: []const u8, expected: []const u8, exit_code: u8) !void {
    for (0..100) |_| {
        var result = try env.runYoq(&.{ "container", "inspect", name });
        defer result.deinit();
        try result.expectExitCode(0);
        const parsed = try std.json.parseFromSlice(std.json.Value, alloc, result.stdout, .{});
        defer parsed.deinit();
        if (parsed.value.object.get("health")) |health| {
            if (health == .object and std.mem.eql(u8, health.object.get("status").?.string, expected)) {
                const last_exit = health.object.get("last_exit").?;
                if (last_exit == .integer and last_exit.integer == exit_code) return;
            }
        }
        try std.Io.sleep(std.testing.io, .fromMilliseconds(50), .awake);
    }
    return error.HealthStatusNotReached;
}

fn activeHealthGroup(id: []const u8) ![]const u8 {
    const prefix = try std.fmt.allocPrint(alloc, "health-{s}-", .{id});
    defer alloc.free(prefix);
    for (0..100) |_| {
        var directory = try std.Io.Dir.cwd().openDir(std.testing.io, "/sys/fs/cgroup/yoq", .{ .iterate = true });
        defer directory.close(std.testing.io);
        var iterator = directory.iterate();
        while (try iterator.next(std.testing.io)) |entry| {
            if (entry.kind != .directory or !std.mem.startsWith(u8, entry.name, prefix)) continue;
            const path = try std.fmt.allocPrint(alloc, "/sys/fs/cgroup/yoq/{s}/cgroup.procs", .{entry.name});
            defer alloc.free(path);
            const processes = std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, alloc, .limited(4096)) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
            defer alloc.free(processes);
            // The helper and its child must both have joined before cancellation.
            var lines = std.mem.tokenizeScalar(u8, processes, '\n');
            _ = lines.next() orelse continue;
            _ = lines.next() orelse continue;
            return std.fmt.allocPrint(alloc, "/sys/fs/cgroup/yoq/{s}", .{entry.name});
        }
        try std.Io.sleep(std.testing.io, .fromMilliseconds(20), .awake);
    }
    return error.HealthCheckNotRunning;
}

test "local parity health transitions and stop cleans up an active timed check" {
    var fixture = try ImageFixture.init();
    defer fixture.deinit();
    defer cleanupContainer(&fixture.env, "health-owner");
    const check = "test \"$FIXTURE_ENV\" = image-value && test \"$PWD\" = /work || exit 9; if test -f /work/timeout; then sleep 30 & wait; fi";
    var started = try fixture.env.runYoq(&.{ "run", "--no-net", "-d", "--name", "health-owner", "--health-cmd", check, "--health-interval", "100ms", "--health-timeout", "500ms", "--health-retries", "1", ImageFixture.tag, "sleep", "60" });
    defer started.deinit();
    try started.expectExitCode(0);
    const id = trimOutput(started.stdout);
    try waitHealth(&fixture.env, "health-owner", "healthy", 0);
    try expectExecOutput(&fixture.env, "health-owner", ": > /work/timeout", "");
    try waitHealth(&fixture.env, "health-owner", "unhealthy", 124);
    const group = try activeHealthGroup(id);
    defer alloc.free(group);
    const process_file = try std.fmt.allocPrint(alloc, "{s}/cgroup.procs", .{group});
    defer alloc.free(process_file);
    const processes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, process_file, alloc, .limited(4096));
    defer alloc.free(processes);
    try expectCommand(&fixture.env, &.{ "stop", "health-owner" });
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(std.testing.io, group, .{}));
    var lines = std.mem.tokenizeScalar(u8, processes, '\n');
    while (lines.next()) |pid| {
        const proc_path = try std.fmt.allocPrint(alloc, "/proc/{s}", .{pid});
        defer alloc.free(proc_path);
        try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(std.testing.io, proc_path, .{}));
    }
}
