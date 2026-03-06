// cron scheduler — runs recurring tasks on a fixed interval
//
// spawns a single thread that sleeps until the next cron is due,
// runs it via runOneShot, and reschedules. checks for shutdown
// every second while sleeping.
//
// usage:
//   var sched = CronScheduler.init(alloc, manifest.crons);
//   sched.start();
//   // ... later ...
//   sched.stop();
//   sched.deinit();

const std = @import("std");
const spec = @import("spec.zig");
const orchestrator = @import("orchestrator.zig");
const cli = @import("../lib/cli.zig");

const writeErr = cli.writeErr;

pub const CronScheduler = struct {
    alloc: std.mem.Allocator,
    crons: []const spec.Cron,
    next_runs: []i64,
    thread: ?std.Thread,
    running: std.atomic.Value(bool),

    pub fn init(alloc: std.mem.Allocator, crons: []const spec.Cron) !CronScheduler {
        const next_runs = try alloc.alloc(i64, crons.len);

        // schedule first run of each cron at now + interval
        const now = std.time.timestamp();
        for (crons, 0..) |c, i| {
            next_runs[i] = now + @as(i64, @intCast(c.every));
        }

        return .{
            .alloc = alloc,
            .crons = crons,
            .next_runs = next_runs,
            .thread = null,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    /// start the scheduler thread. idempotent — does nothing if already running.
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
            const now = std.time.timestamp();

            // find the soonest cron that's due
            var earliest_idx: ?usize = null;
            var earliest_time: i64 = std.math.maxInt(i64);
            for (self.next_runs, 0..) |next, i| {
                if (next < earliest_time) {
                    earliest_time = next;
                    earliest_idx = i;
                }
            }

            const idx = earliest_idx orelse {
                // no crons — shouldn't happen but sleep and retry
                std.Thread.sleep(1 * std.time.ns_per_s);
                continue;
            };

            // sleep until the cron is due, checking shutdown every second
            if (earliest_time > now) {
                var remaining = earliest_time - now;
                while (remaining > 0 and self.running.load(.acquire)) {
                    std.Thread.sleep(1 * std.time.ns_per_s);
                    remaining -= 1;
                }
                if (!self.running.load(.acquire)) break;
            }

            // run the cron
            const cron = self.crons[idx];
            writeErr("cron: running {s}...\n", .{cron.name});

            // pull image if needed
            _ = orchestrator.ensureImageAvailable(self.alloc, cron.image);

            const success = orchestrator.runOneShot(
                self.alloc,
                cron.image,
                cron.command,
                cron.env,
                cron.volumes,
                cron.working_dir,
                cron.name,
            );

            if (success) {
                writeErr("cron: {s} completed\n", .{cron.name});
            } else {
                writeErr("cron: {s} failed\n", .{cron.name});
            }

            // reschedule
            self.next_runs[idx] = std.time.timestamp() + @as(i64, @intCast(cron.every));
        }
    }
};

// -- tests --

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

    var sched = try CronScheduler.init(alloc, &crons);
    defer sched.deinit();

    // next_runs should be set to now + interval
    const now = std.time.timestamp();
    try std.testing.expect(sched.next_runs[0] >= now);
    try std.testing.expect(sched.next_runs[0] <= now + 3600);
    try std.testing.expect(sched.next_runs[1] >= now);
    try std.testing.expect(sched.next_runs[1] <= now + 60);

    // cleanup (60s) should be scheduled before backup (3600s)
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
            .every = 999999, // far future — won't actually run
        },
    };

    var sched = try CronScheduler.init(alloc, &crons);
    defer sched.deinit();

    // set next_run far in the future so the loop just sleeps
    sched.next_runs[0] = std.time.timestamp() + 999999;

    sched.start();
    try std.testing.expect(sched.running.load(.acquire));

    sched.stop();
    try std.testing.expect(!sched.running.load(.acquire));
    try std.testing.expect(sched.thread == null);
}
