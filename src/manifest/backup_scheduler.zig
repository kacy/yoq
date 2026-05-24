// backup scheduler — runs database backups on a fixed interval
//
// spawns a single thread that sleeps until the next backup is due, writes a
// timestamped artifact into the configured output directory via the internal
// backup path, and reschedules. checks for shutdown every second while
// sleeping. mirrors cron_scheduler, but runs yoq's own backup rather than a
// container.
//
// usage:
//   var sched = BackupScheduler.init(alloc, manifest.backup.?);
//   sched.start();
//   // ... later ...
//   sched.stop();
//   sched.deinit();

const std = @import("std");
const spec = @import("spec.zig");
const backup_mod = @import("../state/backup.zig");
const linux_platform = @import("linux_platform");
const cli = @import("../lib/cli.zig");
const runtime_wait = @import("../lib/runtime_wait.zig");

const writeErr = cli.writeErr;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

pub const BackupScheduler = struct {
    alloc: std.mem.Allocator,
    spec: spec.BackupSpec,
    next_run: i64,
    thread: ?std.Thread,
    running: std.atomic.Value(bool),

    pub fn init(alloc: std.mem.Allocator, backup_spec: spec.BackupSpec) BackupScheduler {
        return .{
            .alloc = alloc,
            .spec = backup_spec,
            .next_run = nowRealSeconds() + @as(i64, @intCast(backup_spec.every)),
            .thread = null,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    /// start the scheduler thread. idempotent — does nothing if already running.
    pub fn start(self: *BackupScheduler) void {
        if (self.running.load(.acquire)) return;
        self.running.store(true, .release);

        self.thread = std.Thread.spawn(.{}, schedulerLoop, .{self}) catch |e| {
            writeErr("failed to start backup scheduler: {}\n", .{e});
            self.running.store(false, .release);
            return;
        };
    }

    /// stop the scheduler thread and wait for it to finish.
    pub fn stop(self: *BackupScheduler) void {
        self.running.store(false, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    pub fn deinit(self: *BackupScheduler) void {
        _ = self; // the spec is owned by the manifest; nothing to free here.
    }

    fn schedulerLoop(self: *BackupScheduler) void {
        while (self.running.load(.acquire)) {
            const now = nowRealSeconds();

            // sleep until the next backup is due, checking shutdown every second.
            if (self.next_run > now) {
                var remaining = self.next_run - now;
                while (remaining > 0 and self.running.load(.acquire)) {
                    if (!runtime_wait.sleep(std.Io.Duration.fromSeconds(1), "backup scheduler due wait")) return;
                    remaining -= 1;
                }
                if (!self.running.load(.acquire)) break;
            }

            self.runBackupOnce();
            self.next_run = nowRealSeconds() + @as(i64, @intCast(self.spec.every));
        }
    }

    fn runBackupOnce(self: *BackupScheduler) void {
        linux_platform.cwd().makePath(self.spec.output_dir) catch |e| {
            writeErr("backup: cannot create output dir {s}: {}\n", .{ self.spec.output_dir, e });
            return;
        };

        const ts = nowRealSeconds();
        const ext = if (self.spec.encrypt) "yoqbackup" else "db";
        const path = std.fmt.allocPrintSentinel(self.alloc, "{s}/yoq-backup-{d}.{s}", .{ self.spec.output_dir, ts, ext }, 0) catch {
            writeErr("backup: out of memory building output path\n", .{});
            return;
        };
        defer self.alloc.free(path);

        backup_mod.backup(self.alloc, path, self.spec.encrypt) catch |e| {
            writeErr("backup: scheduled backup failed: {}\n", .{e});
            return;
        };
        writeErr("backup: wrote {s}\n", .{path});
    }
};

// -- tests --

test "BackupScheduler init schedules the first run after the interval" {
    const sched = BackupScheduler.init(std.testing.allocator, .{
        .every = 3600,
        .output_dir = "/tmp/yoq-backups",
        .encrypt = true,
    });

    const now = nowRealSeconds();
    try std.testing.expect(sched.next_run > now);
    try std.testing.expect(sched.next_run <= now + 3600);
}

test "BackupScheduler starts and stops" {
    var sched = BackupScheduler.init(std.testing.allocator, .{
        .every = 999999, // far future — won't actually run
        .output_dir = "/tmp/yoq-backups",
        .encrypt = true,
    });
    defer sched.deinit();

    sched.start();
    try std.testing.expect(sched.running.load(.acquire));

    sched.stop();
    try std.testing.expect(!sched.running.load(.acquire));
    try std.testing.expect(sched.thread == null);
}
