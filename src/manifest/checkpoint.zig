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

/// checkpoint directory entry found during scan
pub const CheckpointEntry = struct {
    step: i64,
    path: [512]u8,
    path_len: usize,

    pub fn pathSlice(self: *const CheckpointEntry) []const u8 {
        return self.path[0..self.path_len];
    }
};

/// scan a checkpoint directory for step directories.
/// looks for subdirs matching step_N or checkpoint-N patterns.
/// returns entries sorted by step ascending.
pub fn scanCheckpointDir(buf: []CheckpointEntry, checkpoint_path: []const u8) usize {
    var dir = @import("compat").cwd().openDir(checkpoint_path, .{ .iterate = true }) catch return 0;
    defer dir.close();

    var count: usize = 0;
    var iter = dir.iterate();

    while (iter.next() catch null) |entry| {
        if (count >= buf.len) break;
        if (entry.kind != .directory) continue;

        const step = parseStepFromName(entry.name) orelse continue;

        // build full path
        var path_buf: [512]u8 = undefined;
        const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ checkpoint_path, entry.name }) catch continue;

        buf[count] = .{
            .step = step,
            .path = undefined,
            .path_len = full_path.len,
        };
        @memcpy(buf[count].path[0..full_path.len], full_path);
        count += 1;
    }

    // sort by step ascending
    sortEntries(buf[0..count]);

    return count;
}

fn sortEntries(entries: []CheckpointEntry) void {
    for (1..entries.len) |i| {
        var j = i;
        while (j > 0 and entries[j].step < entries[j - 1].step) {
            const tmp = entries[j];
            entries[j] = entries[j - 1];
            entries[j - 1] = tmp;
            j -= 1;
        }
    }
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
/// keep-N retention. returns the number of new checkpoints recorded.
pub fn syncCheckpoints(alloc: std.mem.Allocator, job_id: []const u8, checkpoint_path: []const u8, keep: u32) !u32 {
    // scan filesystem
    var entries: [64]CheckpointEntry = undefined;
    const count = scanCheckpointDir(&entries, checkpoint_path);
    if (count == 0) return 0;

    // load existing checkpoints from db (newest-first)
    var existing = store.listCheckpoints(alloc, job_id) catch return error.StoreFailed;
    defer {
        for (existing.items) |rec| rec.deinit(alloc);
        existing.deinit(alloc);
    }

    // find which steps are already recorded and save new ones
    var new_count: u32 = 0;
    const now = @import("compat").timestamp();

    for (entries[0..count]) |entry| {
        var found = false;
        for (existing.items) |rec| {
            if (rec.step == entry.step) {
                found = true;
                break;
            }
        }
        if (!found) {
            store.saveCheckpoint(job_id, entry.step, entry.pathSlice(), 0, now) catch continue;
            new_count += 1;
        }
    }

    // enforce keep-N using total count (existing + newly added)
    if (keep > 0) {
        const total = existing.items.len + new_count;
        if (total > keep) {
            // existing list is newest-first; old checkpoints are at the tail.
            // we need to delete (total - keep) oldest entries. the oldest are
            // in the existing list starting from index (keep - new_count) if
            // new_count < keep, otherwise all existing entries are old.
            const delete_from = if (new_count >= keep) 0 else keep - new_count;
            if (delete_from < existing.items.len) {
                for (existing.items[delete_from..]) |old| {
                    @import("compat").cwd().deleteTree(old.path) catch {};
                    store.deleteCheckpoint(old.id) catch {};
                }
            }
        }
    }

    return new_count;
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
    // YOQ_CHECKPOINT_DIR=/path/to/checkpoints
    var dir_buf: [600]u8 = undefined;
    const dir_env = std.fmt.bufPrint(&dir_buf, "YOQ_CHECKPOINT_DIR={s}", .{ckpt.path}) catch return;
    const dir_duped = try alloc.dupe(u8, dir_env);
    env.append(alloc, dir_duped) catch {
        alloc.free(dir_duped);
        return;
    };

    // YOQ_CHECKPOINT_INTERVAL=1800
    var interval_buf: [64]u8 = undefined;
    const interval_env = std.fmt.bufPrint(&interval_buf, "YOQ_CHECKPOINT_INTERVAL={d}", .{ckpt.interval_secs}) catch return;
    const interval_duped = try alloc.dupe(u8, interval_env);
    env.append(alloc, interval_duped) catch {
        alloc.free(interval_duped);
        return;
    };

    // YOQ_CHECKPOINT_KEEP=5
    var keep_buf: [64]u8 = undefined;
    const keep_env = std.fmt.bufPrint(&keep_buf, "YOQ_CHECKPOINT_KEEP={d}", .{ckpt.keep}) catch return;
    const keep_duped = try alloc.dupe(u8, keep_env);
    env.append(alloc, keep_duped) catch {
        alloc.free(keep_duped);
        return;
    };

    // YOQ_RESUME_FROM=/path/to/checkpoint/step_1000 (only if resuming)
    if (resume_path) |rp| {
        var resume_buf: [600]u8 = undefined;
        const resume_env = std.fmt.bufPrint(&resume_buf, "YOQ_RESUME_FROM={s}", .{rp}) catch return;
        const resume_duped = try alloc.dupe(u8, resume_env);
        env.append(alloc, resume_duped) catch {
            alloc.free(resume_duped);
            return;
        };
    }
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

test "sortEntries sorts by step ascending" {
    var entries = [_]CheckpointEntry{
        .{ .step = 300, .path = undefined, .path_len = 0 },
        .{ .step = 100, .path = undefined, .path_len = 0 },
        .{ .step = 200, .path = undefined, .path_len = 0 },
    };

    sortEntries(&entries);

    try std.testing.expectEqual(@as(i64, 100), entries[0].step);
    try std.testing.expectEqual(@as(i64, 200), entries[1].step);
    try std.testing.expectEqual(@as(i64, 300), entries[2].step);
}

test "scanCheckpointDir returns 0 for missing dir" {
    var buf: [16]CheckpointEntry = undefined;
    const count = scanCheckpointDir(&buf, "/tmp/nonexistent_yoq_test_dir_xyz");
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "scanCheckpointDir finds step directories" {
    // create temp dir with step subdirs
    const alloc = std.testing.allocator;
    var tmp_path_buf: [256]u8 = undefined;
    const tmp_path = std.fmt.bufPrint(&tmp_path_buf, "/tmp/yoq_ckpt_test_{d}", .{@import("compat").milliTimestamp()}) catch unreachable;

    @import("compat").cwd().makeDir(tmp_path) catch return;
    defer @import("compat").cwd().deleteTree(tmp_path) catch {};

    // create step subdirs
    var step_buf: [256]u8 = undefined;
    for ([_][]const u8{ "step_100", "step_200", "step_50", "not_a_step" }) |name| {
        const sub = std.fmt.bufPrint(&step_buf, "{s}/{s}", .{ tmp_path, name }) catch continue;
        @import("compat").cwd().makeDir(sub) catch continue;
    }
    _ = alloc;

    var entries: [16]CheckpointEntry = undefined;
    const count = scanCheckpointDir(&entries, tmp_path);

    try std.testing.expectEqual(@as(usize, 3), count);
    // sorted by step ascending
    try std.testing.expectEqual(@as(i64, 50), entries[0].step);
    try std.testing.expectEqual(@as(i64, 100), entries[1].step);
    try std.testing.expectEqual(@as(i64, 200), entries[2].step);
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
