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
const retention = @import("backup_retention.zig");
const backup_metrics = @import("backup_metrics.zig");
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
    metrics: *backup_metrics.Metrics = &backup_metrics.global,

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
            _ = self.metrics.failures.fetchAdd(1, .monotonic);
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
        self.runOnceWith(nowRealSeconds(), backup_mod.backup) catch |err| {
            writeErr("backup: scheduled backup failed: {}\n", .{err});
        };
    }

    fn runOnceWith(self: *BackupScheduler, now: i64, comptime writeBackup: anytype) !void {
        errdefer _ = self.metrics.failures.fetchAdd(1, .monotonic);
        try linux_platform.cwd().makePath(self.spec.output_dir);
        var dir = try std.Io.Dir.cwd().openDir(std.Options.debug_io, self.spec.output_dir, .{ .iterate = true });
        defer dir.close(std.Options.debug_io);
        // Serialize scheduled writers/pruning in this output directory. A
        // concurrent scheduler skips this attempt instead of blocking stop().
        const linux = std.os.linux;
        const rc = linux.openat(dir.handle, ".yoq-backup.lock", .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o600);
        if (linux.errno(rc) != .SUCCESS) return error.LockFailed;
        const lock_fd: std.posix.fd_t = @intCast(rc);
        defer linux_platform.posix.close(lock_fd);
        if (linux.errno(linux.flock(lock_fd, 2 | 4)) != .SUCCESS) return error.BackupBusy; // LOCK_EX | LOCK_NB

        var random: [16]u8 = undefined;
        linux_platform.randomBytes(&random);
        const ext = if (self.spec.encrypt) "yoqbackup" else "db";
        const path = try std.fmt.allocPrintSentinel(self.alloc, "{s}/yoq-backup-{d}-{s}.{s}", .{ self.spec.output_dir, now, std.fmt.bytesToHex(random, .lower), ext }, 0);
        defer self.alloc.free(path);
        try writeBackup(self.alloc, path, self.spec.encrypt);
        _ = self.metrics.successes.fetchAdd(1, .monotonic);
        self.metrics.last_success.store(now, .release);

        // A failed or disk-full backup never removes an older recovery point.
        retention.prune(self.alloc, dir, std.fs.path.basename(path), now, self.spec.retention) catch |err| {
            _ = self.metrics.retention_failures.fetchAdd(1, .monotonic);
            writeErr("backup: artifact saved, but retention failed: {}\n", .{err});
        };
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

test "backup scheduler preserves recovery points on disk full and prunes only after success" {
    const Fixture = struct {
        fn full(_: std.mem.Allocator, _: [:0]const u8, _: bool) !void {
            return error.NoSpaceLeft;
        }
        fn complete(_: std.mem.Allocator, path: [:0]const u8, _: bool) !void {
            try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = path, .data = "complete backup" });
        }
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "yoq-backup-10.db", .data = "old valid backup" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "yoq-backup-15.db.partial", .data = "in progress" });
    var path: [4096]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &path);
    var metrics: backup_metrics.Metrics = .{};
    var scheduler = BackupScheduler.init(std.testing.allocator, .{ .every = 100, .output_dir = path[0..len], .encrypt = false, .retention = .{ .keep_count = 1 } });
    scheduler.metrics = &metrics;
    try std.testing.expectError(error.NoSpaceLeft, scheduler.runOnceWith(20, Fixture.full));
    try tmp.dir.access(std.testing.io, "yoq-backup-10.db", .{});
    try std.testing.expectEqual(@as(u64, 1), metrics.failures.load(.monotonic));
    try std.testing.expectEqual(@as(i64, 0), metrics.last_success.load(.acquire));
    try scheduler.runOnceWith(30, Fixture.complete);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, "yoq-backup-10.db", .{}));
    try tmp.dir.access(std.testing.io, "yoq-backup-15.db.partial", .{});
    try std.testing.expectEqual(@as(u64, 1), metrics.successes.load(.monotonic));
    try std.testing.expectEqual(@as(i64, 30), metrics.last_success.load(.acquire));
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try metrics.writePrometheus(&out.writer, 45);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "yoq_backup_last_success_age_seconds 15\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "yoq_backup_failures_total 1\n") != null);
}
