const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const TrainingJobRecord = struct {
    id: []const u8,
    name: []const u8,
    app_name: []const u8,
    state: []const u8,
    image: []const u8,
    gpus: i64,
    checkpoint_path: ?[]const u8,
    checkpoint_interval: ?i64,
    checkpoint_keep: ?i64,
    restart_count: i64,
    created_at: i64,
    updated_at: i64,

    pub fn deinit(self: TrainingJobRecord, alloc: Allocator) void {
        alloc.free(self.id);
        alloc.free(self.name);
        alloc.free(self.app_name);
        alloc.free(self.state);
        alloc.free(self.image);
        if (self.checkpoint_path) |path| alloc.free(path);
    }
};

pub const CheckpointRecord = struct {
    id: i64,
    job_id: []const u8,
    step: i64,
    path: []const u8,
    size_bytes: i64,
    created_at: i64,

    pub fn deinit(self: CheckpointRecord, alloc: Allocator) void {
        alloc.free(self.job_id);
        alloc.free(self.path);
    }
};

pub const TrainingJobSummary = struct {
    active: usize = 0,
    paused: usize = 0,
    failed: usize = 0,
};

const training_job_columns =
    "id, name, app_name, state, image, gpus, checkpoint_path, checkpoint_interval, checkpoint_keep, restart_count, created_at, updated_at";

const TrainingJobRow = struct {
    id: sqlite.Text,
    name: sqlite.Text,
    app_name: sqlite.Text,
    state: sqlite.Text,
    image: sqlite.Text,
    gpus: i64,
    checkpoint_path: ?sqlite.Text,
    checkpoint_interval: ?i64,
    checkpoint_keep: ?i64,
    restart_count: i64,
    created_at: i64,
    updated_at: i64,
};

const CheckpointRow = struct {
    id: i64,
    job_id: sqlite.Text,
    step: i64,
    path: sqlite.Text,
    size_bytes: i64,
    created_at: i64,
};

fn trainingJobRowToRecord(row: TrainingJobRow) TrainingJobRecord {
    return .{
        .id = row.id.data,
        .name = row.name.data,
        .app_name = row.app_name.data,
        .state = row.state.data,
        .image = row.image.data,
        .gpus = row.gpus,
        .checkpoint_path = if (row.checkpoint_path) |path| path.data else null,
        .checkpoint_interval = row.checkpoint_interval,
        .checkpoint_keep = row.checkpoint_keep,
        .restart_count = row.restart_count,
        .created_at = row.created_at,
        .updated_at = row.updated_at,
    };
}

fn checkpointRowToRecord(row: CheckpointRow) CheckpointRecord {
    return .{
        .id = row.id,
        .job_id = row.job_id.data,
        .step = row.step,
        .path = row.path.data,
        .size_bytes = row.size_bytes,
        .created_at = row.created_at,
    };
}

pub fn saveTrainingJob(record: TrainingJobRecord) StoreError!void {
    const Context = struct {
        record: TrainingJobRecord,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!void {
            return saveTrainingJobInDb(db, ctx.record);
        }
    };

    var ctx = Context{ .record = record };
    return common.withDb(void, &ctx, Context.run);
}

pub fn saveTrainingJobInDb(db: *sqlite.Db, record: TrainingJobRecord) StoreError!void {
    db.exec(
        "INSERT OR REPLACE INTO training_jobs (" ++ training_job_columns ++ ")" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            record.id,
            record.name,
            record.app_name,
            record.state,
            record.image,
            record.gpus,
            record.checkpoint_path,
            record.checkpoint_interval,
            record.checkpoint_keep,
            record.restart_count,
            record.created_at,
            record.updated_at,
        },
    ) catch return StoreError.WriteFailed;
}

pub fn updateTrainingJobState(id: []const u8, state: []const u8, now: i64) StoreError!void {
    const Context = struct {
        id: []const u8,
        state: []const u8,
        now: i64,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!void {
            return updateTrainingJobStateInDb(db, ctx.id, ctx.state, ctx.now);
        }
    };

    var ctx = Context{ .id = id, .state = state, .now = now };
    return common.withDb(void, &ctx, Context.run);
}

pub fn updateTrainingJobStateInDb(db: *sqlite.Db, id: []const u8, state: []const u8, now: i64) StoreError!void {
    db.exec(
        "UPDATE training_jobs SET state = ?, updated_at = ? WHERE id = ?;",
        .{},
        .{ state, now, id },
    ) catch return StoreError.WriteFailed;
}

pub fn incrementTrainingJobRestarts(id: []const u8, now: i64) StoreError!void {
    const Context = struct {
        id: []const u8,
        now: i64,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!void {
            return incrementTrainingJobRestartsInDb(db, ctx.id, ctx.now);
        }
    };

    var ctx = Context{ .id = id, .now = now };
    return common.withDb(void, &ctx, Context.run);
}

pub fn incrementTrainingJobRestartsInDb(db: *sqlite.Db, id: []const u8, now: i64) StoreError!void {
    db.exec(
        "UPDATE training_jobs SET restart_count = restart_count + 1, updated_at = ? WHERE id = ?;",
        .{},
        .{ now, id },
    ) catch return StoreError.WriteFailed;
}

pub fn updateTrainingJobGpus(id: []const u8, gpus: u32, now: i64) StoreError!void {
    const Context = struct {
        id: []const u8,
        gpus: u32,
        now: i64,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!void {
            return updateTrainingJobGpusInDb(db, ctx.id, ctx.gpus, ctx.now);
        }
    };

    var ctx = Context{ .id = id, .gpus = gpus, .now = now };
    return common.withDb(void, &ctx, Context.run);
}

pub fn updateTrainingJobGpusInDb(db: *sqlite.Db, id: []const u8, gpus: u32, now: i64) StoreError!void {
    db.exec(
        "UPDATE training_jobs SET gpus = ?, updated_at = ? WHERE id = ?;",
        .{},
        .{ @as(i64, @intCast(gpus)), now, id },
    ) catch return StoreError.WriteFailed;
}

pub fn findTrainingJob(alloc: Allocator, app_name: []const u8, name: []const u8) StoreError!?TrainingJobRecord {
    const Context = struct {
        alloc: Allocator,
        app_name: []const u8,
        name: []const u8,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!?TrainingJobRecord {
            return findTrainingJobInDb(db, ctx.alloc, ctx.app_name, ctx.name);
        }
    };

    var ctx = Context{ .alloc = alloc, .app_name = app_name, .name = name };
    return common.withDb(?TrainingJobRecord, &ctx, Context.run);
}

pub fn findTrainingJobInDb(db: *sqlite.Db, alloc: Allocator, app_name: []const u8, name: []const u8) StoreError!?TrainingJobRecord {
    const row = (db.oneAlloc(
        TrainingJobRow,
        alloc,
        "SELECT " ++ training_job_columns ++ " FROM training_jobs WHERE app_name = ? AND name = ? ORDER BY created_at DESC LIMIT 1;",
        .{},
        .{ app_name, name },
    ) catch return StoreError.ReadFailed) orelse return null;
    return trainingJobRowToRecord(row);
}

pub fn getTrainingJob(alloc: Allocator, id: []const u8) StoreError!TrainingJobRecord {
    const Context = struct {
        alloc: Allocator,
        id: []const u8,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!TrainingJobRecord {
            return getTrainingJobInDb(db, ctx.alloc, ctx.id);
        }
    };

    var ctx = Context{ .alloc = alloc, .id = id };
    return common.withDb(TrainingJobRecord, &ctx, Context.run);
}

pub fn getTrainingJobInDb(db: *sqlite.Db, alloc: Allocator, id: []const u8) StoreError!TrainingJobRecord {
    const row = (db.oneAlloc(
        TrainingJobRow,
        alloc,
        "SELECT " ++ training_job_columns ++ " FROM training_jobs WHERE id = ?;",
        .{},
        .{id},
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;
    return trainingJobRowToRecord(row);
}

pub fn listTrainingJobsByApp(alloc: Allocator, app_name: []const u8) StoreError!std.ArrayList(TrainingJobRecord) {
    const Context = struct {
        alloc: Allocator,
        app_name: []const u8,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!std.ArrayList(TrainingJobRecord) {
            return listTrainingJobsByAppInDb(db, ctx.alloc, ctx.app_name);
        }
    };

    var ctx = Context{ .alloc = alloc, .app_name = app_name };
    return common.withDb(std.ArrayList(TrainingJobRecord), &ctx, Context.run);
}

pub fn listTrainingJobsByAppInDb(
    db: *sqlite.Db,
    alloc: Allocator,
    app_name: []const u8,
) StoreError!std.ArrayList(TrainingJobRecord) {
    var records: std.ArrayList(TrainingJobRecord) = .empty;
    var stmt = db.prepare(
        "SELECT " ++ training_job_columns ++ " FROM training_jobs WHERE app_name = ? ORDER BY updated_at DESC, created_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(TrainingJobRow, .{app_name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        records.append(alloc, trainingJobRowToRecord(row)) catch return StoreError.ReadFailed;
    }
    return records;
}

pub fn summarizeTrainingJobsByApp(alloc: Allocator, app_name: []const u8) StoreError!TrainingJobSummary {
    const Context = struct {
        alloc: Allocator,
        app_name: []const u8,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!TrainingJobSummary {
            return summarizeTrainingJobsByAppInDb(db, ctx.alloc, ctx.app_name);
        }
    };

    var ctx = Context{ .alloc = alloc, .app_name = app_name };
    return common.withDb(TrainingJobSummary, &ctx, Context.run);
}

pub fn summarizeTrainingJobsByAppInDb(
    db: *sqlite.Db,
    alloc: Allocator,
    app_name: []const u8,
) StoreError!TrainingJobSummary {
    var records = try listTrainingJobsByAppInDb(db, alloc, app_name);
    defer {
        for (records.items) |record| record.deinit(alloc);
        records.deinit(alloc);
    }

    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(alloc);

    var summary: TrainingJobSummary = .{};
    for (records.items) |record| {
        const gop = seen.getOrPut(alloc, record.name) catch return StoreError.ReadFailed;
        if (gop.found_existing) continue;
        gop.value_ptr.* = {};

        if (std.mem.eql(u8, record.state, "running") or std.mem.eql(u8, record.state, "scheduling")) {
            summary.active += 1;
        } else if (std.mem.eql(u8, record.state, "paused")) {
            summary.paused += 1;
        } else if (std.mem.eql(u8, record.state, "failed")) {
            summary.failed += 1;
        }
    }
    return summary;
}

pub fn saveCheckpoint(job_id: []const u8, step: i64, path: []const u8, size_bytes: i64, now: i64) StoreError!void {
    const Context = struct {
        job_id: []const u8,
        step: i64,
        path: []const u8,
        size_bytes: i64,
        now: i64,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!void {
            db.exec(
                "INSERT INTO training_checkpoints (job_id, step, path, size_bytes, created_at) VALUES (?, ?, ?, ?, ?);",
                .{},
                .{ ctx.job_id, ctx.step, ctx.path, ctx.size_bytes, ctx.now },
            ) catch return StoreError.WriteFailed;
        }
    };

    var ctx = Context{ .job_id = job_id, .step = step, .path = path, .size_bytes = size_bytes, .now = now };
    return common.withDb(void, &ctx, Context.run);
}

pub fn getLatestCheckpoint(alloc: Allocator, job_id: []const u8) StoreError!?CheckpointRecord {
    const Context = struct {
        alloc: Allocator,
        job_id: []const u8,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!?CheckpointRecord {
            const row = (db.oneAlloc(
                CheckpointRow,
                ctx.alloc,
                "SELECT id, job_id, step, path, size_bytes, created_at FROM training_checkpoints WHERE job_id = ? ORDER BY created_at DESC LIMIT 1;",
                .{},
                .{ctx.job_id},
            ) catch return StoreError.ReadFailed) orelse return null;
            return checkpointRowToRecord(row);
        }
    };

    var ctx = Context{ .alloc = alloc, .job_id = job_id };
    return common.withDb(?CheckpointRecord, &ctx, Context.run);
}

pub fn listCheckpoints(alloc: Allocator, job_id: []const u8) StoreError!std.ArrayList(CheckpointRecord) {
    const Context = struct {
        alloc: Allocator,
        job_id: []const u8,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!std.ArrayList(CheckpointRecord) {
            var records: std.ArrayList(CheckpointRecord) = .empty;
            var stmt = db.prepare(
                "SELECT id, job_id, step, path, size_bytes, created_at FROM training_checkpoints WHERE job_id = ? ORDER BY created_at DESC;",
            ) catch return StoreError.ReadFailed;
            defer stmt.deinit();
            var iter = stmt.iterator(CheckpointRow, .{ctx.job_id}) catch return StoreError.ReadFailed;
            while (iter.nextAlloc(ctx.alloc, .{}) catch return StoreError.ReadFailed) |row| {
                records.append(ctx.alloc, checkpointRowToRecord(row)) catch return StoreError.ReadFailed;
            }
            return records;
        }
    };

    var ctx = Context{ .alloc = alloc, .job_id = job_id };
    return common.withDb(std.ArrayList(CheckpointRecord), &ctx, Context.run);
}

pub fn deleteCheckpoint(id: i64) StoreError!void {
    const Context = struct {
        id: i64,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!void {
            db.exec(
                "DELETE FROM training_checkpoints WHERE id = ?;",
                .{},
                .{ctx.id},
            ) catch return StoreError.WriteFailed;
        }
    };

    var ctx = Context{ .id = id };
    return common.withDb(void, &ctx, Context.run);
}

test "summarizeTrainingJobsByAppInDb groups active paused and failed states" {
    const alloc = std.testing.allocator;
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../schema.zig").init(&db);

    try saveTrainingJobInDb(&db, .{
        .id = "job-1",
        .name = "a",
        .app_name = "demo-app",
        .state = "running",
        .image = "trainer:v1",
        .gpus = 1,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 0,
        .created_at = 100,
        .updated_at = 100,
    });
    try saveTrainingJobInDb(&db, .{
        .id = "job-2",
        .name = "b",
        .app_name = "demo-app",
        .state = "paused",
        .image = "trainer:v1",
        .gpus = 1,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 0,
        .created_at = 110,
        .updated_at = 110,
    });
    try saveTrainingJobInDb(&db, .{
        .id = "job-3",
        .name = "c",
        .app_name = "demo-app",
        .state = "failed",
        .image = "trainer:v1",
        .gpus = 1,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 0,
        .created_at = 120,
        .updated_at = 120,
    });
    try saveTrainingJobInDb(&db, .{
        .id = "job-4",
        .name = "d",
        .app_name = "demo-app",
        .state = "scheduling",
        .image = "trainer:v1",
        .gpus = 1,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 0,
        .created_at = 130,
        .updated_at = 130,
    });

    const summary = try summarizeTrainingJobsByAppInDb(&db, alloc, "demo-app");
    try std.testing.expectEqual(@as(usize, 2), summary.active);
    try std.testing.expectEqual(@as(usize, 1), summary.paused);
    try std.testing.expectEqual(@as(usize, 1), summary.failed);
}

test "summarizeTrainingJobsByAppInDb keeps only the latest row per job name" {
    const alloc = std.testing.allocator;
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../schema.zig").init(&db);

    try saveTrainingJobInDb(&db, .{
        .id = "job-old",
        .name = "finetune",
        .app_name = "demo-app",
        .state = "failed",
        .image = "trainer:v1",
        .gpus = 1,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 0,
        .created_at = 100,
        .updated_at = 100,
    });
    try saveTrainingJobInDb(&db, .{
        .id = "job-new",
        .name = "finetune",
        .app_name = "demo-app",
        .state = "running",
        .image = "trainer:v2",
        .gpus = 2,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 1,
        .created_at = 200,
        .updated_at = 200,
    });

    const summary = try summarizeTrainingJobsByAppInDb(&db, alloc, "demo-app");
    try std.testing.expectEqual(@as(usize, 1), summary.active);
    try std.testing.expectEqual(@as(usize, 0), summary.paused);
    try std.testing.expectEqual(@as(usize, 0), summary.failed);
}
