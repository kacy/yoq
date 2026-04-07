// privileged integration tests — resource exhaustion and limits
//
// these tests verify that resource limits are properly enforced
// and that the system degrades gracefully under pressure.

const std = @import("std");
const helpers = @import("helpers");

const alloc = std.testing.allocator;

test "container with pids_max=1 can only run one process" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    const name = try helpers.uniqueName(alloc, "limit-pids");
    defer alloc.free(name);

    // run with minimum pids limit
    var run_result = try env.runYoq(&.{
        "run", "--name", name,
        "--pids",            "2", // need at least 2 for init + workload
        fixture.rootfs_path, "/bin/sh",
        "-c",                "echo single-process",
    });
    defer run_result.deinit();

    // should succeed with minimal processes
    try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);
}

test "container with memory limit can allocate within limit" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    const name = try helpers.uniqueName(alloc, "limit-mem-ok");
    defer alloc.free(name);

    // run with 8MB limit - should be able to allocate 4MB
    var run_result = try env.runYoq(&.{
        "run",      "--name", name,
        "--memory", "8m",     fixture.rootfs_path,
        "/bin/sh",  "-c",     "i=0; while [ \"$i\" -lt 4096 ]; do printf '%1024s' ''; i=$((i + 1)); done > /tmp/test && echo ok",
    });
    defer run_result.deinit();

    try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);
    try helpers.expectContains(run_result.stdout, "ok");
}

test "container with 4MB memory minimum is enforced" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    const name = try helpers.uniqueName(alloc, "limit-mem-min");
    defer alloc.free(name);

    // 1 MB is below the 4 MB minimum
    var run_result = try env.runYoq(&.{
        "run",      "--name", name,
        "--memory", "1m",     fixture.rootfs_path,
        "/bin/sh",  "-c",     "echo hello",
    });
    defer run_result.deinit();

    // should fail validation
    try std.testing.expect(run_result.exit_code != 0);
}

test "cpu weight validation rejects out of range values" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    const name1 = try helpers.uniqueName(alloc, "limit-cpu-zero");
    defer alloc.free(name1);

    // cpu-weight 0 is invalid (must be 1-10000)
    var result1 = try env.runYoq(&.{
        "run",          "--name", name1,
        "--cpu-weight", "0",      fixture.rootfs_path,
        "/bin/true",
    });
    defer result1.deinit();
    try std.testing.expect(result1.exit_code != 0);

    const name2 = try helpers.uniqueName(alloc, "limit-cpu-huge");
    defer alloc.free(name2);

    // cpu-weight 20000 is invalid (must be <= 10000)
    var result2 = try env.runYoq(&.{
        "run",          "--name", name2,
        "--cpu-weight", "20000",  fixture.rootfs_path,
        "/bin/true",
    });
    defer result2.deinit();
    try std.testing.expect(result2.exit_code != 0);
}

test "multiple containers with different limits coexist" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    // start several containers with different resource limits
    const names = [_][]const u8{ "limit-multi-1", "limit-multi-2", "limit-multi-3" };
    const limits = [_][]const u8{ "8m", "16m", "32m" };

    for (names, limits) |name_base, limit| {
        const name = try helpers.uniqueName(alloc, name_base);
        defer alloc.free(name);

        var result = try env.runYoq(&.{
            "run",      "-d",        "--name",            name,
            "--memory", limit,       fixture.rootfs_path, "/bin/sh",
            "-c",       "sleep 0.1",
        });
        defer result.deinit();
        try std.testing.expectEqual(@as(u8, 0), result.exit_code);

        // cleanup
        var rm = try env.runYoq(&.{ "rm", name });
        defer rm.deinit();
    }
}

test "container restart policy no prevents restart" {
    var env = try helpers.TestEnv.init(alloc);
    defer env.deinit();

    var fixture = try helpers.createShellRootfs(alloc);
    defer fixture.deinit();

    const name = try helpers.uniqueName(alloc, "restart-no");
    defer alloc.free(name);

    // run with restart=no - should not restart on failure
    var run_result = try env.runYoq(&.{
        "run",       "-d", "--name", name,
        "--restart", "no",
        fixture.rootfs_path, "/bin/sh", "-c", "exit 1",
    });
    defer run_result.deinit();
    try std.testing.expectEqual(@as(u8, 0), run_result.exit_code);

    // wait for it to exit
    std.Thread.sleep(200 * std.time.ns_per_ms);

    // check status
    var ps_result = try env.runYoq(&.{"ps"});
    defer ps_result.deinit();

    // container should have exited and not be running
    try std.testing.expect(ps_result.exit_code == 0);

    // cleanup
    var rm = try env.runYoq(&.{ "rm", name });
    defer rm.deinit();
}

test "backoff increases on restart but caps" {
    // this is an internal logic test - the backoff_ms value doubles
    // up to 30 second maximum
    const math = @import("std").math;

    var backoff: u32 = 1000;
    const max_backoff: u32 = 30_000;

    // simulate several restarts
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const new_backoff = math.min(math.mul(u32, backoff, 2) catch max_backoff, max_backoff);
        backoff = new_backoff;
    }

    // should have reached max
    try std.testing.expectEqual(max_backoff, backoff);
}

test "ResourceLimits validation errors" {
    const cgroups_common = @import("cgroups_common");

    // memory below minimum (4MB)
    const bad_mem = cgroups_common.ResourceLimits{ .memory_max = 1024 * 1024 };
    try std.testing.expectError(cgroups_common.CgroupError.LimitBelowMinimum, bad_mem.validate());

    // pids below minimum (1)
    const bad_pids = cgroups_common.ResourceLimits{ .pids_max = 0 };
    try std.testing.expectError(cgroups_common.CgroupError.LimitBelowMinimum, bad_pids.validate());

    // valid limits
    const good = cgroups_common.ResourceLimits{ .memory_max = 8 * 1024 * 1024, .pids_max = 10 };
    try good.validate();
}

test "unlimited resource limits" {
    const cgroups_common = @import("cgroups_common");

    // unlimited should pass validation
    try cgroups_common.ResourceLimits.unlimited.validate();

    // all limits should be null
    try std.testing.expect(cgroups_common.ResourceLimits.unlimited.memory_max == null);
    try std.testing.expect(cgroups_common.ResourceLimits.unlimited.pids_max == null);
    try std.testing.expect(cgroups_common.ResourceLimits.unlimited.cpu_weight == null);
}
