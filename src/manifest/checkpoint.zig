// checkpoint — checkpoint lifecycle management for training jobs
//
// scans checkpoint directories for new snapshots, records them in the
// database, and enforces keep-N retention policy. checkpoints are
// identified by step number extracted from directory naming convention:
// {checkpoint_path}/step_{N}/ or {checkpoint_path}/checkpoint-{N}/
//
// the training process writes checkpoints; this module discovers and
// tracks them. on resume, it provides the latest checkpoint path so
// the training container can restore from it.

const std = @import("std");
const store = @import("../state/store.zig");
const spec = @import("spec.zig");

pub const CheckpointError = error{
    ScanFailed,
    StoreFailed,
    PathTooLong,
};

/// a step directory found during a scan. `name` is a single directory entry
/// name, never a path.
pub const CheckpointEntry = struct {
    step: i64,
    name: []const u8,
};

pub fn freeEntries(alloc: std.mem.Allocator, entries: []CheckpointEntry) void {
    for (entries) |entry| alloc.free(entry.name);
    alloc.free(entries);
}

/// list the step directories directly inside `dir`, sorted by step
/// ascending. symlinked entries are skipped. free with freeEntries.
pub fn scanCheckpointDir(alloc: std.mem.Allocator, dir: std.Io.Dir) ![]CheckpointEntry {
    var entries: std.ArrayList(CheckpointEntry) = .empty;
    errdefer {
        for (entries.items) |entry| alloc.free(entry.name);
        entries.deinit(alloc);
    }

    var iter = dir.iterate();
    while (try iter.next(std.Options.debug_io)) |entry| {
        if (entry.kind != .directory) continue;
        const step = parseStepFromName(entry.name) orelse continue;
        const name = try alloc.dupe(u8, entry.name);
        errdefer alloc.free(name);
        try entries.append(alloc, .{ .step = step, .name = name });
    }

    const sorted = try entries.toOwnedSlice(alloc);
    std.mem.sort(CheckpointEntry, sorted, {}, stepLessThan);
    return sorted;
}

fn stepLessThan(_: void, a: CheckpointEntry, b: CheckpointEntry) bool {
    return a.step < b.step;
}

/// extract step number from checkpoint directory name.
/// supports: step_123, checkpoint-123, ckpt_123, step123
fn parseStepFromName(name: []const u8) ?i64 {
    const prefixes = [_][]const u8{ "step", "checkpoint", "ckpt" };
    inline for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) {
            const rest = name[prefix.len..];
            const num_start = if (rest.len > 0 and (rest[0] == '_' or rest[0] == '-')) rest[1..] else rest;
            return std.fmt.parseInt(i64, num_start, 10) catch null;
        }
    }
    return null;
}

/// record newly discovered checkpoints in the database and enforce
/// keep-N retention. `dir` is the opened checkpoint directory and
/// `checkpoint_path` is its path inside the container, which is what gets
/// recorded. returns the number of new checkpoints recorded.
pub fn syncCheckpoints(alloc: std.mem.Allocator, job_id: []const u8, checkpoint_path: []const u8, dir: std.Io.Dir, keep: u32) !u32 {
    return syncCheckpointsWithDelete(alloc, job_id, checkpoint_path, dir, keep, deleteCheckpointDirectory);
}

fn syncCheckpointsWithDelete(alloc: std.mem.Allocator, job_id: []const u8, checkpoint_path: []const u8, dir: std.Io.Dir, keep: u32, comptime delete_directory: anytype) !u32 {
    const entries = scanCheckpointDir(alloc, dir) catch return error.ScanFailed;
    defer freeEntries(alloc, entries);
    if (entries.len == 0) return 0;

    // load existing checkpoints from db (newest-first)
    var existing = store.listCheckpoints(alloc, job_id) catch return error.StoreFailed;
    defer {
        for (existing.items) |rec| rec.deinit(alloc);
        existing.deinit(alloc);
    }

    // find which steps are already recorded and save new ones
    var new_count: u32 = 0;
    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();

    for (entries) |entry| {
        var found = false;
        for (existing.items) |rec| {
            if (rec.step == entry.step) {
                found = true;
                break;
            }
        }
        if (!found) {
            const recorded = std.fs.path.join(alloc, &.{ checkpoint_path, entry.name }) catch return error.StoreFailed;
            defer alloc.free(recorded);
            store.saveCheckpoint(job_id, entry.step, recorded, 0, now) catch return error.StoreFailed;
            new_count += 1;
        }
    }

    // include this scan's inserts before selecting the oldest steps. a newly
    // discovered directory may be older than every recorded checkpoint.
    if (keep > 0) {
        var current = store.listCheckpoints(alloc, job_id) catch return error.StoreFailed;
        defer {
            for (current.items) |record| record.deinit(alloc);
            current.deinit(alloc);
        }
        const retained = @min(@as(usize, keep), current.items.len);
        for (current.items[retained..]) |old| {
            // only the last component of a recorded path is trusted, and only
            // relative to the directory opened for this scan. older rows held
            // absolute host paths; they resolve the same way.
            const name = std.fs.path.basename(old.path);
            if (parseStepFromName(name) == null) return error.ScanFailed;
            // retain the record when deletion fails so the next scan can retry.
            try delete_directory(dir, name);
            store.deleteCheckpoint(old.id) catch return error.StoreFailed;
        }
    }

    return new_count;
}

fn deleteCheckpointDirectory(dir: std.Io.Dir, name: []const u8) !void {
    try dir.deleteTree(std.Options.debug_io, name);
}

/// get the path to the latest checkpoint for a job.
/// returns null if no checkpoints exist.
pub fn getLatestCheckpointPath(alloc: std.mem.Allocator, job_id: []const u8) ?[]const u8 {
    const rec = store.getLatestCheckpoint(alloc, job_id) catch return null;
    if (rec) |r| {
        defer alloc.free(r.job_id);
        // caller owns the path
        return r.path;
    }
    return null;
}

/// build environment variables for checkpoint-aware training.
/// injects YOQ_CHECKPOINT_DIR, YOQ_CHECKPOINT_INTERVAL, and
/// optionally YOQ_RESUME_FROM if a prior checkpoint exists.
pub fn buildCheckpointEnv(
    alloc: std.mem.Allocator,
    env: *std.ArrayListUnmanaged([]const u8),
    ckpt: spec.CheckpointSpec,
    resume_path: ?[]const u8,
) !void {
    try appendEnv(alloc, env, "YOQ_CHECKPOINT_DIR={s}", .{ckpt.path});
    try appendEnv(alloc, env, "YOQ_CHECKPOINT_INTERVAL={d}", .{ckpt.interval_secs});
    try appendEnv(alloc, env, "YOQ_CHECKPOINT_KEEP={d}", .{ckpt.keep});
    if (resume_path) |path| try appendEnv(alloc, env, "YOQ_RESUME_FROM={s}", .{path});
}

// checkpoint paths belong to the container. open the directory behind the
// longest matching bind mount and return a path the resumed process can open.
pub fn latestMountedCheckpoint(alloc: std.mem.Allocator, checkpoint_path: []const u8, mounts: []const @import("../runtime/container.zig").BindMount) !?[]const u8 {
    var dir = try openMountedDirectory(checkpoint_path, mounts) orelse return null;
    defer dir.close(std.Options.debug_io);
    const entries = try scanCheckpointDir(alloc, dir);
    defer freeEntries(alloc, entries);
    if (entries.len == 0) return null;
    return try std.fs.path.join(alloc, &.{ checkpoint_path, entries[entries.len - 1].name });
}

/// where a container path lives on the host: a bind mount source and the
/// relative path below it.
const MountedLocation = struct {
    source: []const u8,
    suffix: []const u8,
};

fn mountedLocation(path: []const u8, mounts: []const @import("../runtime/container.zig").BindMount) !?MountedLocation {
    if (!std.fs.path.isAbsolute(path)) return error.InvalidCheckpointPath;
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| if (std.mem.eql(u8, component, "..")) return error.InvalidCheckpointPath;
    var selected: ?@import("../runtime/container.zig").BindMount = null;
    for (mounts) |mount| {
        const target = std.mem.trimEnd(u8, mount.target, "/");
        if (!std.mem.startsWith(u8, path, target)) continue;
        if (path.len > target.len and path[target.len] != '/') continue;
        if (selected == null or target.len > std.mem.trimEnd(u8, selected.?.target, "/").len) selected = mount;
    }
    const mount = selected orelse return null;
    const suffix = std.mem.trim(u8, path[std.mem.trimEnd(u8, mount.target, "/").len..], "/");
    return .{ .source = mount.source, .suffix = suffix };
}

/// open the host directory behind a container checkpoint path, or null when
/// no mount covers it or it does not exist yet.
///
/// the container controls everything below the mount source, so the walk
/// from the source to the checkpoint directory refuses symlinks and cannot
/// leave the source. otherwise a planted link could point retention at any
/// host directory.
pub fn openMountedDirectory(path: []const u8, mounts: []const @import("../runtime/container.zig").BindMount) !?std.Io.Dir {
    const location = try mountedLocation(path, mounts) orelse return null;
    var source = std.Io.Dir.cwd().openDir(std.Options.debug_io, location.source, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer source.close(std.Options.debug_io);

    const platform = @import("linux_platform").posix;
    const fd = platform.openat2(
        source.handle,
        if (location.suffix.len == 0) "." else location.suffix,
        .{ .DIRECTORY = true, .CLOEXEC = true },
        .{ .beneath = true, .no_symlinks = true, .no_magiclinks = true },
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        error.PathEscapes => return error.CheckpointPathRejected,
        else => return error.ScanFailed,
    };
    return .{ .handle = fd };
}

fn appendEnv(alloc: std.mem.Allocator, env: *std.ArrayListUnmanaged([]const u8), comptime format: []const u8, args: anytype) !void {
    const entry = try std.fmt.allocPrint(alloc, format, args);
    errdefer alloc.free(entry);
    try env.append(alloc, entry);
}

// -- tests --

test "parseStepFromName parses step_N" {
    try std.testing.expectEqual(@as(?i64, 1000), parseStepFromName("step_1000"));
    try std.testing.expectEqual(@as(?i64, 0), parseStepFromName("step_0"));
    try std.testing.expectEqual(@as(?i64, 42), parseStepFromName("step-42"));
    try std.testing.expectEqual(@as(?i64, 5), parseStepFromName("step5"));
}

test "parseStepFromName parses checkpoint-N" {
    try std.testing.expectEqual(@as(?i64, 100), parseStepFromName("checkpoint-100"));
    try std.testing.expectEqual(@as(?i64, 200), parseStepFromName("checkpoint_200"));
}

test "parseStepFromName parses ckpt_N" {
    try std.testing.expectEqual(@as(?i64, 50), parseStepFromName("ckpt_50"));
    try std.testing.expectEqual(@as(?i64, 75), parseStepFromName("ckpt-75"));
}

test "parseStepFromName returns null for unrecognized" {
    try std.testing.expect(parseStepFromName("model_weights") == null);
    try std.testing.expect(parseStepFromName("latest") == null);
    try std.testing.expect(parseStepFromName("") == null);
}

test "buildCheckpointEnv adds env vars" {
    const alloc = std.testing.allocator;

    var env: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (env.items) |e| alloc.free(e);
        env.deinit(alloc);
    }

    const ckpt = spec.CheckpointSpec{
        .path = "/mnt/checkpoints",
        .interval_secs = 900,
        .keep = 3,
    };

    try buildCheckpointEnv(alloc, &env, ckpt, null);

    try std.testing.expectEqual(@as(usize, 3), env.items.len);
    try std.testing.expectEqualStrings("YOQ_CHECKPOINT_DIR=/mnt/checkpoints", env.items[0]);
    try std.testing.expectEqualStrings("YOQ_CHECKPOINT_INTERVAL=900", env.items[1]);
    try std.testing.expectEqualStrings("YOQ_CHECKPOINT_KEEP=3", env.items[2]);
}

test "buildCheckpointEnv adds resume path" {
    const alloc = std.testing.allocator;

    var env: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (env.items) |e| alloc.free(e);
        env.deinit(alloc);
    }

    const ckpt = spec.CheckpointSpec{
        .path = "/mnt/ckpt",
        .interval_secs = 1800,
        .keep = 5,
    };

    try buildCheckpointEnv(alloc, &env, ckpt, "/mnt/ckpt/step_500");

    try std.testing.expectEqual(@as(usize, 4), env.items.len);
    try std.testing.expectEqualStrings("YOQ_RESUME_FROM=/mnt/ckpt/step_500", env.items[3]);
}

test "checkpoint store round-trip" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;

    // save a training job first (for FK)
    try store.saveTrainingJob(.{
        .id = "job-1",
        .name = "test-train",
        .app_name = "myapp",
        .state = "running",
        .image = "train:v1",
        .gpus = 4,
        .checkpoint_path = "/mnt/ckpt",
        .checkpoint_interval = 900,
        .checkpoint_keep = 3,
        .restart_count = 0,
        .created_at = 1000,
        .updated_at = 1000,
    });

    // save checkpoints
    try store.saveCheckpoint("job-1", 100, "/mnt/ckpt/step_100", 1024, 2000);
    try store.saveCheckpoint("job-1", 200, "/mnt/ckpt/step_200", 2048, 3000);
    try store.saveCheckpoint("job-1", 300, "/mnt/ckpt/step_300", 4096, 4000);

    // get latest
    const latest = try store.getLatestCheckpoint(alloc, "job-1");
    try std.testing.expect(latest != null);
    const l = latest.?;
    defer l.deinit(alloc);
    try std.testing.expectEqual(@as(i64, 300), l.step);
    try std.testing.expectEqualStrings("/mnt/ckpt/step_300", l.path);

    // list all
    var all = try store.listCheckpoints(alloc, "job-1");
    defer {
        for (all.items) |rec| rec.deinit(alloc);
        all.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 3), all.items.len);
    // newest first
    try std.testing.expectEqual(@as(i64, 300), all.items[0].step);
    try std.testing.expectEqual(@as(i64, 200), all.items[1].step);

    // delete oldest
    try store.deleteCheckpoint(all.items[2].id);

    var remaining = try store.listCheckpoints(alloc, "job-1");
    defer {
        for (remaining.items) |rec| rec.deinit(alloc);
        remaining.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 2), remaining.items.len);
}

test "training job store round-trip" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;

    try store.saveTrainingJob(.{
        .id = "tj-1",
        .name = "llm-train",
        .app_name = "myapp",
        .state = "running",
        .image = "train:v2",
        .gpus = 8,
        .checkpoint_path = "/data/ckpt",
        .checkpoint_interval = 1800,
        .checkpoint_keep = 5,
        .restart_count = 0,
        .created_at = 1000,
        .updated_at = 1000,
    });

    // find by app+name
    const found = try store.findTrainingJob(alloc, "myapp", "llm-train");
    try std.testing.expect(found != null);
    const f = found.?;
    defer f.deinit(alloc);
    try std.testing.expectEqualStrings("tj-1", f.id);
    try std.testing.expectEqualStrings("running", f.state);
    try std.testing.expectEqual(@as(i64, 8), f.gpus);

    // update state
    try store.updateTrainingJobState("tj-1", "paused", 2000);
    const updated = try store.getTrainingJob(alloc, "tj-1");
    defer updated.deinit(alloc);
    try std.testing.expectEqualStrings("paused", updated.state);
    try std.testing.expectEqual(@as(i64, 2000), updated.updated_at);

    // increment restarts
    try store.incrementTrainingJobRestarts("tj-1", 3000);
    const restarted = try store.getTrainingJob(alloc, "tj-1");
    defer restarted.deinit(alloc);
    try std.testing.expectEqual(@as(i64, 1), restarted.restart_count);
}

test "training checkpoint resume maps the most specific mount into container paths" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDir(std.Options.debug_io, "step_20", .default_dir);
    try tmp.dir.createDir(std.Options.debug_io, "step_3", .default_dir);
    const host = try tmp.dir.realPathFileAlloc(std.Options.debug_io, ".", alloc);
    defer alloc.free(host);
    const mounts = [_]@import("../runtime/container.zig").BindMount{
        .{ .source = "/missing", .target = "/data" },
        .{ .source = host, .target = "/data/checkpoints" },
    };
    const latest = (try latestMountedCheckpoint(alloc, "/data/checkpoints", &mounts)).?;
    defer alloc.free(latest);
    try std.testing.expectEqualStrings("/data/checkpoints/step_20", latest);
    try std.testing.expect((try mountedLocation("/database", &mounts)) == null);
    try std.testing.expectError(error.InvalidCheckpointPath, mountedLocation("/data/../etc", &mounts));
}

fn seedRetentionJob() !void {
    try store.saveTrainingJob(.{
        .id = "retention-job",
        .name = "train",
        .app_name = "retention",
        .state = "running",
        .image = "scratch",
        .gpus = 1,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 0,
        .created_at = 1,
        .updated_at = 1,
    });
}

fn expectRetainedSteps(expected: []const i64) !void {
    const alloc = std.testing.allocator;
    var records = try store.listCheckpoints(alloc, "retention-job");
    defer {
        for (records.items) |record| record.deinit(alloc);
        records.deinit(alloc);
    }
    try std.testing.expectEqual(expected.len, records.items.len);
    for (expected, records.items) |step, record| try std.testing.expectEqual(step, record.step);
}

test "training checkpoint retention prunes the first discovered batch" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();
    try seedRetentionJob();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmp.dir.realPathFileAlloc(std.Options.debug_io, ".", alloc);
    defer alloc.free(path);
    for ([_][]const u8{ "step_100", "step_200", "step_300", "step_400" }) |name|
        try tmp.dir.createDir(std.Options.debug_io, name, .default_dir);
    try std.testing.expectEqual(@as(u32, 4), try syncCheckpoints(alloc, "retention-job", "/ckpt", tmp.dir, 2));
    try expectRetainedSteps(&.{ 400, 300 });
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.Options.debug_io, "step_100", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.Options.debug_io, "step_200", .{}));
    try tmp.dir.access(std.Options.debug_io, "step_300", .{});
    try tmp.dir.access(std.Options.debug_io, "step_400", .{});
    try std.testing.expectEqual(@as(u32, 0), try syncCheckpoints(alloc, "retention-job", "/ckpt", tmp.dir, 2));
}

test "training checkpoint retention keeps newer steps when older directories arrive late" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();
    try seedRetentionJob();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmp.dir.realPathFileAlloc(std.Options.debug_io, ".", alloc);
    defer alloc.free(path);
    for ([_][]const u8{ "step_300", "step_400" }, [_]i64{ 300, 400 }) |name, step| {
        try tmp.dir.createDir(std.Options.debug_io, name, .default_dir);
        const full_path = try std.fs.path.join(alloc, &.{ path, name });
        defer alloc.free(full_path);
        try store.saveCheckpoint("retention-job", step, full_path, 0, 1);
    }
    try tmp.dir.createDir(std.Options.debug_io, "step_100", .default_dir);
    try tmp.dir.createDir(std.Options.debug_io, "step_200", .default_dir);
    try std.testing.expectEqual(@as(u32, 2), try syncCheckpoints(alloc, "retention-job", "/ckpt", tmp.dir, 0));
    const latest = (try store.getLatestCheckpoint(alloc, "retention-job")).?;
    defer latest.deinit(alloc);
    try std.testing.expectEqual(@as(i64, 400), latest.step);
    try std.testing.expectEqual(@as(u32, 0), try syncCheckpoints(alloc, "retention-job", "/ckpt", tmp.dir, 2));
    try expectRetainedSteps(&.{ 400, 300 });
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.Options.debug_io, "step_100", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.Options.debug_io, "step_200", .{}));
    try tmp.dir.access(std.Options.debug_io, "step_300", .{});
    try tmp.dir.access(std.Options.debug_io, "step_400", .{});
}

test "training checkpoint retention preserves failed deletions and retries them" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();
    try seedRetentionJob();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmp.dir.realPathFileAlloc(std.Options.debug_io, ".", alloc);
    defer alloc.free(path);
    for ([_][]const u8{ "step_10", "step_20", "step_30" }) |name|
        try tmp.dir.createDir(std.Options.debug_io, name, .default_dir);
    const Failure = struct {
        fn delete(_: std.Io.Dir, _: []const u8) !void {
            return error.AccessDenied;
        }
    };
    try std.testing.expectError(error.AccessDenied, syncCheckpointsWithDelete(alloc, "retention-job", "/ckpt", tmp.dir, 1, Failure.delete));
    try expectRetainedSteps(&.{ 30, 20, 10 });
    try tmp.dir.access(std.Options.debug_io, "step_20", .{});
    try tmp.dir.access(std.Options.debug_io, "step_10", .{});
    try std.testing.expectEqual(@as(u32, 0), try syncCheckpoints(alloc, "retention-job", "/ckpt", tmp.dir, 1));
    try expectRetainedSteps(&.{30});
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.Options.debug_io, "step_20", .{}));
    try tmp.dir.access(std.Options.debug_io, "step_30", .{});
}

test "training checkpoint retention accepts an empty checkpoint directory" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmp.dir.realPathFileAlloc(std.Options.debug_io, ".", alloc);
    defer alloc.free(path);
    const entries = try scanCheckpointDir(alloc, tmp.dir);
    defer freeEntries(alloc, entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
    try std.testing.expectEqual(@as(u32, 0), try syncCheckpoints(alloc, "not-yet-recorded", "/ckpt", tmp.dir, 2));
}

test "scanCheckpointDir finds step directories in step order" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    for ([_][]const u8{ "step_100", "checkpoint-200", "ckpt_50", "not_a_step" }) |name|
        try tmp.dir.createDir(std.Options.debug_io, name, .default_dir);
    try tmp.dir.symLink(std.Options.debug_io, "step_100", "step_999", .{});

    const entries = try scanCheckpointDir(alloc, tmp.dir);
    defer freeEntries(alloc, entries);
    // the symlinked step_999 is not a checkpoint
    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("ckpt_50", entries[0].name);
    try std.testing.expectEqualStrings("step_100", entries[1].name);
    try std.testing.expectEqualStrings("checkpoint-200", entries[2].name);
}

test "checkpoint scans see every directory, not the first 64" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();
    try seedRetentionJob();
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var name_buf: [32]u8 = undefined;
    // created out of order so readdir order says nothing about steps
    for (0..100) |i| {
        const step = (i * 37) % 100 + 1;
        try tmp.dir.createDir(std.Options.debug_io, try std.fmt.bufPrint(&name_buf, "step_{d}", .{step}), .default_dir);
    }
    const host = try tmp.dir.realPathFileAlloc(std.Options.debug_io, ".", alloc);
    defer alloc.free(host);
    const mounts = [_]@import("../runtime/container.zig").BindMount{.{ .source = host, .target = "/ckpt" }};

    const latest = (try latestMountedCheckpoint(alloc, "/ckpt", &mounts)).?;
    defer alloc.free(latest);
    try std.testing.expectEqualStrings("/ckpt/step_100", latest);

    try std.testing.expectEqual(@as(u32, 100), try syncCheckpoints(alloc, "retention-job", "/ckpt", tmp.dir, 5));
    try expectRetainedSteps(&.{ 100, 99, 98, 97, 96 });
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.Options.debug_io, "step_95", .{}));
}

test "checkpoint paths that cross a symlink below the mount are refused" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    // outside/ holds directories the container must not be able to reach
    try tmp.dir.createDirPath(std.Options.debug_io, "outside");
    var name_buf: [32]u8 = undefined;
    for (1..8) |step| try tmp.dir.createDir(std.Options.debug_io, try std.fmt.bufPrint(&name_buf, "outside/checkpoint-{d}", .{step}), .default_dir);
    try tmp.dir.createDirPath(std.Options.debug_io, "volume/real");
    try tmp.dir.symLink(std.Options.debug_io, "../outside", "volume/model", .{});
    try tmp.dir.symLink(std.Options.debug_io, "../outside", "volume/a", .{});

    const volume = try tmp.dir.realPathFileAlloc(std.Options.debug_io, "volume", alloc);
    defer alloc.free(volume);
    const mounts = [_]@import("../runtime/container.zig").BindMount{.{ .source = volume, .target = "/mnt/checkpoints" }};

    // the link is the checkpoint directory itself, or a component above it
    for ([_][]const u8{ "/mnt/checkpoints/model", "/mnt/checkpoints/a/model" }) |path| {
        try std.testing.expectError(error.CheckpointPathRejected, openMountedDirectory(path, &mounts));
        try std.testing.expectError(error.CheckpointPathRejected, latestMountedCheckpoint(alloc, path, &mounts));
    }
    for (1..8) |step| try tmp.dir.access(std.Options.debug_io, try std.fmt.bufPrint(&name_buf, "outside/checkpoint-{d}", .{step}), .{});

    // the mount root itself and an ordinary subdirectory still open
    var root = (try openMountedDirectory("/mnt/checkpoints", &mounts)).?;
    root.close(std.Options.debug_io);
    var real = (try openMountedDirectory("/mnt/checkpoints/real", &mounts)).?;
    real.close(std.Options.debug_io);
    try std.testing.expect((try openMountedDirectory("/mnt/checkpoints/missing", &mounts)) == null);
}
