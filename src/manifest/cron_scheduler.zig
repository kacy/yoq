// cron scheduler
//
// runs recurring tasks one at a time on a dedicated thread. each
// interval starts when the previous run finishes. while waiting for
// a task, the thread checks for shutdown every second.
//
// usage:
//   var sched = try CronScheduler.init(alloc, manifest.crons, manifest.volumes, app_name);
//   sched.start();
//   // ... later ...
//   sched.stop();
//   sched.deinit();

const std = @import("std");
const spec = @import("spec.zig");
const orchestrator = @import("orchestrator.zig");
const cli = @import("../lib/cli.zig");
const runtime_wait = @import("../lib/runtime_wait.zig");

const writeErr = cli.writeErr;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

fn nextRunIndex(next_runs: []const i64) ?usize {
    var earliest_idx: ?usize = null;
    var earliest_time: i64 = std.math.maxInt(i64);
    for (next_runs, 0..) |next, i| {
        // keep the first cron on ties; the maximum timestamp is a sentinel.
        if (next < earliest_time) {
            earliest_time = next;
            earliest_idx = i;
        }
    }
    return earliest_idx;
}

pub const CronScheduler = struct {
    alloc: std.mem.Allocator,
    crons: []const spec.Cron,
    manifest_volumes: []const spec.Volume,
    app_name: []const u8,
    next_runs: []i64,
    thread: ?std.Thread,
    running: std.atomic.Value(bool),

    pub fn init(alloc: std.mem.Allocator, crons: []const spec.Cron, manifest_volumes: []const spec.Volume, app_name: []const u8) !CronScheduler {
        const next_runs = try alloc.alloc(i64, crons.len);

        // wait a full interval before each cron's first run.
        const now = nowRealSeconds();
        for (crons, 0..) |c, i| {
            next_runs[i] = now + @as(i64, @intCast(c.every));
        }

        return .{
            .alloc = alloc,
            .crons = crons,
            .manifest_volumes = manifest_volumes,
            .app_name = app_name,
            .next_runs = next_runs,
            .thread = null,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    /// start the scheduler thread if it is not already running.
    pub fn start(self: *CronScheduler) void {
        if (self.running.load(.acquire)) return;
        self.running.store(true, .release);

        self.thread = std.Thread.spawn(.{}, schedulerLoop, .{self}) catch |e| {
            writeErr("failed to start cron scheduler: {}\n", .{e});
            self.running.store(false, .release);
            return;
        };
    }

    /// stop the scheduler thread and wait for it to finish.
    pub fn stop(self: *CronScheduler) void {
        self.running.store(false, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    pub fn deinit(self: *CronScheduler) void {
        self.alloc.free(self.next_runs);
    }

    fn schedulerLoop(self: *CronScheduler) void {
        while (self.running.load(.acquire)) {
            const now = nowRealSeconds();

            const idx = nextRunIndex(self.next_runs) orelse {
                // no scheduled runs. check again after the idle wait.
                if (!runtime_wait.sleep(std.Io.Duration.fromSeconds(1), "cron scheduler idle wait")) return;
                continue;
            };
            const earliest_time = self.next_runs[idx];

            // check for shutdown each second while waiting for the next run.
            if (earliest_time > now) {
                var remaining = earliest_time - now;
                while (remaining > 0 and self.running.load(.acquire)) {
                    if (!runtime_wait.sleep(std.Io.Duration.fromSeconds(1), "cron scheduler due wait")) return;
                    remaining -= 1;
                }
                if (!self.running.load(.acquire)) break;
            }

            self.runCron(idx);
        }
    }

    fn runCron(self: *CronScheduler, idx: usize) void {
        const cron = self.crons[idx];
        writeErr("cron: running {s}...\n", .{cron.name});

        _ = orchestrator.ensureImageAvailable(self.alloc, cron.image);

        const success = orchestrator.runOneShot(
            self.alloc,
            cron.image,
            cron.command,
            cron.env,
            cron.volumes,
            cron.working_dir,
            cron.name,
            self.manifest_volumes,
            self.app_name,
        );

        if (success) {
            writeErr("cron: {s} completed\n", .{cron.name});
        } else {
            writeErr("cron: {s} failed\n", .{cron.name});
        }

        // start the next interval after this attempt finishes, even if it failed.
        self.next_runs[idx] = nowRealSeconds() + @as(i64, @intCast(cron.every));
    }
};

// -- tests --

test "nextRunIndex keeps the first cron when run times match" {
    try std.testing.expectEqual(@as(?usize, 1), nextRunIndex(&.{ 30, 10, 10, 20 }));
}

test "nextRunIndex skips the sentinel and accepts negative timestamps" {
    const unscheduled = std.math.maxInt(i64);
    try std.testing.expectEqual(@as(?usize, null), nextRunIndex(&.{}));
    try std.testing.expectEqual(@as(?usize, null), nextRunIndex(&.{ unscheduled, unscheduled }));
    try std.testing.expectEqual(@as(?usize, 2), nextRunIndex(&.{ unscheduled, 0, -10 }));
    try std.testing.expectEqual(@as(?usize, 1), nextRunIndex(&.{ unscheduled, unscheduled - 1 }));
}

test "CronScheduler init sets next_runs" {
    const alloc = std.testing.allocator;

    const crons = [_]spec.Cron{
        .{
            .name = "backup",
            .image = "postgres:15",
            .command = &.{},
            .env = &.{},
            .working_dir = null,
            .volumes = &.{},
            .every = 3600,
        },
        .{
            .name = "cleanup",
            .image = "alpine:latest",
            .command = &.{},
            .env = &.{},
            .working_dir = null,
            .volumes = &.{},
            .every = 60,
        },
    };

    var sched = try CronScheduler.init(alloc, &crons, &.{}, "test");
    defer sched.deinit();

    // each first run is one interval after initialization.
    const now = nowRealSeconds();
    try std.testing.expect(sched.next_runs[0] >= now);
    try std.testing.expect(sched.next_runs[0] <= now + 3600);
    try std.testing.expect(sched.next_runs[1] >= now);
    try std.testing.expect(sched.next_runs[1] <= now + 60);

    // cleanup's shorter interval puts it before backup.
    try std.testing.expect(sched.next_runs[1] < sched.next_runs[0]);
}

test "CronScheduler starts and stops" {
    const alloc = std.testing.allocator;

    const crons = [_]spec.Cron{
        .{
            .name = "test",
            .image = "scratch",
            .command = &.{},
            .env = &.{},
            .working_dir = null,
            .volumes = &.{},
            .every = 999999, // keep the cron from running during this test.
        },
    };

    var sched = try CronScheduler.init(alloc, &crons, &.{}, "test");
    defer sched.deinit();

    // keep the scheduler in its wait loop until shutdown.
    sched.next_runs[0] = nowRealSeconds() + 999999;

    sched.start();
    try std.testing.expect(sched.running.load(.acquire));

    sched.stop();
    try std.testing.expect(!sched.running.load(.acquire));
    try std.testing.expect(sched.thread == null);
}
