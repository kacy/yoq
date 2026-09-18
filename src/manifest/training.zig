// training job lifecycle for local rank groups and cluster assignments.
// local control persists cancellation before stopping ranks. cluster control
// uses the app training endpoints so placement and job state change together.

const std = @import("std");
const spec = @import("spec.zig");
const cli = @import("../lib/cli.zig");
const checkpoint_mgr = @import("checkpoint.zig");
const store = @import("../state/store.zig");
const cluster_runner = @import("training/cluster_runner.zig");
const local_runner = @import("training/local_runner.zig");
const state_support = @import("training/state_support.zig");

const write = cli.write;
pub const TrainingJobState = enum {
    pending,
    scheduling,
    running,
    paused,
    completed,
    failed,
    stopped,

    pub fn label(self: TrainingJobState) []const u8 {
        return switch (self) {
            .pending => "pending",
            .scheduling => "scheduling",
            .running => "running",
            .paused => "paused",
            .completed => "completed",
            .failed => "failed",
            .stopped => "stopped",
        };
    }

    pub fn fromLabel(s: []const u8) ?TrainingJobState {
        return std.meta.stringToEnum(TrainingJobState, s);
    }
};

pub const RankStatus = enum {
    pending,
    running,
    stopped,
    failed,
};

pub const TrainingController = struct {
    alloc: std.mem.Allocator,
    job: *const spec.TrainingJob,
    state: TrainingJobState,
    app_name: []const u8,
    gpu_count: u32,
    manifest_volumes: []const spec.Volume = &.{},
    rank_status: []RankStatus,
    job_id: ?[]const u8 = null,
    resume_path: ?[]const u8 = null,
    restart_count: u32 = 0,

    pub fn init(alloc: std.mem.Allocator, job: *const spec.TrainingJob, app_name: []const u8) !TrainingController {
        const rank_status = try alloc.alloc(RankStatus, job.gpus);
        errdefer alloc.free(rank_status);
        @memset(rank_status, .pending);
        const owned_app_name = try alloc.dupe(u8, app_name);

        return .{
            .alloc = alloc,
            .job = job,
            .state = .pending,
            .app_name = owned_app_name,
            .gpu_count = job.gpus,
            .rank_status = rank_status,
        };
    }

    pub fn deinit(self: *TrainingController) void {
        self.alloc.free(self.rank_status);
        self.alloc.free(self.app_name);
        if (self.resume_path) |rp| self.alloc.free(rp);
        if (self.job_id) |jid| self.alloc.free(jid);
    }

    /// generate a job ID from app name and job name.
    fn generateJobId(self: *TrainingController) !void {
        return state_support.generateJobId(self);
    }

    /// persist job state to database.
    fn persistState(self: *TrainingController) !void {
        try state_support.persistState(self);
    }

    /// create initial persistent record for this training job.
    fn createPersistentRecord(self: *TrainingController) !void {
        try state_support.createPersistentRecord(self);
    }

    /// load resume path from the latest checkpoint if one exists.
    fn loadResumeCheckpoint(self: *TrainingController) void {
        state_support.loadResumeCheckpoint(self);
    }

    pub fn isClusterManaged(self: *const TrainingController) bool {
        return state_support.isClusterManaged(self);
    }

    pub fn resizeRanks(self: *TrainingController, gpus: u32) !void {
        if (gpus == 0 or gpus > @import("../cluster/placement_transaction.zig").max_gang_ranks) return error.InvalidGpuCount;
        const statuses = try self.alloc.alloc(RankStatus, gpus);
        @memset(statuses, .pending);
        self.alloc.free(self.rank_status);
        self.rank_status = statuses;
        self.gpu_count = gpus;
    }

    /// launch every rank before waiting for completion. rank containers share
    /// a reachable rendezvous and each receives its own gpu selection.
    pub fn startLocal(self: *TrainingController) !void {
        return local_runner.startLocal(self);
    }

    /// schedule the committed job through its app training endpoint.
    pub fn startCluster(self: *TrainingController, server_ip: [4]u8, server_port: u16) !void {
        return cluster_runner.startCluster(self, server_ip, server_port);
    }

    pub fn stop(self: *TrainingController) !void {
        if (self.isClusterManaged()) return error.RemoteControlRequired;
        self.state = .stopped;
        try self.persistState();
        try state_support.stopRunningRanks(self);
        state_support.syncCheckpoints(self);
    }

    pub fn pause(self: *TrainingController) !void {
        if (self.state != .running and self.state != .scheduling) return;
        if (self.isClusterManaged()) return error.RemoteControlRequired;
        self.state = .paused;
        try self.persistState();
        try state_support.stopRunningRanks(self);
        state_support.syncCheckpoints(self);
    }

    pub fn resume_(self: *TrainingController) !void {
        if (self.state != .paused) return;
        // the previous runner must observe pause and release its owner lease
        // before a resume request can clear the persisted cancellation.
        var owner: ?@import("apply_lock.zig").ApplyLock = if (self.job_id != null) try state_support.waitForOwner(self) else null;
        defer if (owner) |*lock| lock.release();
        if (self.job_id) |id| {
            const record = try store.getTrainingJob(self.alloc, id);
            defer record.deinit(self.alloc);
            if (!std.mem.eql(u8, record.state, "paused")) return error.InvalidTrainingState;
        }
        self.loadResumeCheckpoint();
        self.state = .pending;
        try self.persistState();
    }

    pub fn printStatus(self: *const TrainingController) void {
        write("training job: {s}\n", .{self.job.name});
        write("state:        {s}\n", .{self.state.label()});
        write("image:        {s}\n", .{self.job.image});
        write("gpus:         {d}\n", .{self.gpu_count});
        write("restarts:     {d}/{d}\n", .{ self.restart_count, self.job.fault_tolerance.max_restarts });

        if (self.job.gpu_type) |gt| {
            write("gpu_type:     {s}\n", .{gt});
        }
        if (self.job.checkpoint) |ckpt| {
            write("checkpoint:   {s} (every {d}s, keep {d})\n", .{ ckpt.path, ckpt.interval_secs, ckpt.keep });
        }
        if (self.resume_path) |rp| {
            write("resume_from:  {s}\n", .{rp});
        }

        // show latest checkpoint from database
        if (self.job_id) |jid| {
            if (store.getLatestCheckpoint(self.alloc, jid) catch null) |ckpt_rec| {
                defer ckpt_rec.deinit(self.alloc);
                write("last_ckpt:    step {d} ({s})\n", .{ ckpt_rec.step, ckpt_rec.path });
            }
        }
    }

    /// load persistent state from a previously saved training job record.
    /// used by pause/resume/stop commands to operate on existing jobs.
    pub fn loadFromStore(self: *TrainingController) bool {
        return state_support.loadFromStore(self, TrainingJobState);
    }
};

// -- tests --

test "training controller state transitions" {
    const alloc = std.testing.allocator;

    const tj = spec.TrainingJob{
        .name = "test",
        .image = "scratch",
        .command = &.{},
        .env = &.{},
        .working_dir = null,
        .volumes = &.{},
        .gpus = 4,
    };

    var ctrl = try TrainingController.init(alloc, &tj, "test-app");
    defer ctrl.deinit();

    try std.testing.expectEqual(TrainingJobState.pending, ctrl.state);
    try std.testing.expectEqual(@as(u32, 4), ctrl.job.gpus);

    // all ranks start pending
    for (ctrl.rank_status) |rs| {
        try std.testing.expectEqual(RankStatus.pending, rs);
    }

    // stop from pending
    try ctrl.stop();
    try std.testing.expectEqual(TrainingJobState.stopped, ctrl.state);
}

test "training controller pause/resume" {
    const alloc = std.testing.allocator;

    const tj = spec.TrainingJob{
        .name = "test",
        .image = "scratch",
        .command = &.{},
        .env = &.{},
        .working_dir = null,
        .volumes = &.{},
        .gpus = 2,
    };

    var ctrl = try TrainingController.init(alloc, &tj, "test-app");
    defer ctrl.deinit();

    // simulate running state
    ctrl.state = .running;
    ctrl.rank_status[0] = .running;
    ctrl.rank_status[1] = .running;

    try ctrl.pause();
    try std.testing.expectEqual(TrainingJobState.paused, ctrl.state);
    try std.testing.expectEqual(RankStatus.stopped, ctrl.rank_status[0]);
    try std.testing.expectEqual(RankStatus.stopped, ctrl.rank_status[1]);

    try ctrl.resume_();
    try std.testing.expectEqual(TrainingJobState.pending, ctrl.state);
}

test "training controller pause ignored when not running" {
    const alloc = std.testing.allocator;

    const tj = spec.TrainingJob{
        .name = "test",
        .image = "scratch",
        .command = &.{},
        .env = &.{},
        .working_dir = null,
        .volumes = &.{},
        .gpus = 1,
    };

    var ctrl = try TrainingController.init(alloc, &tj, "test-app");
    defer ctrl.deinit();

    try ctrl.pause();
    try std.testing.expectEqual(TrainingJobState.pending, ctrl.state);
}

test "training controller resume ignored when not paused" {
    const alloc = std.testing.allocator;

    const tj = spec.TrainingJob{
        .name = "test",
        .image = "scratch",
        .command = &.{},
        .env = &.{},
        .working_dir = null,
        .volumes = &.{},
        .gpus = 1,
    };

    var ctrl = try TrainingController.init(alloc, &tj, "test-app");
    defer ctrl.deinit();

    try ctrl.resume_();
    try std.testing.expectEqual(TrainingJobState.pending, ctrl.state);
}

test "training job state fromLabel round-trips with label" {
    const states = [_]TrainingJobState{ .pending, .scheduling, .running, .paused, .completed, .failed, .stopped };
    for (states) |s| {
        try std.testing.expectEqual(s, TrainingJobState.fromLabel(s.label()).?);
    }
    try std.testing.expect(TrainingJobState.fromLabel("unknown") == null);
    try std.testing.expect(TrainingJobState.fromLabel("") == null);
}

test "training controller rank_status matches gpus" {
    const alloc = std.testing.allocator;

    const tj = spec.TrainingJob{
        .name = "test",
        .image = "scratch",
        .command = &.{},
        .env = &.{},
        .working_dir = null,
        .volumes = &.{},
        .gpus = 100,
    };

    var ctrl = try TrainingController.init(alloc, &tj, "test-app");
    defer ctrl.deinit();

    try std.testing.expectEqual(@as(usize, 100), ctrl.rank_status.len);
    try std.testing.expectEqual(@as(u32, 100), ctrl.job.gpus);
}

test "cluster-managed job detection follows job id prefix" {
    const alloc = std.testing.allocator;

    const tj = spec.TrainingJob{
        .name = "test",
        .image = "scratch",
        .command = &.{},
        .env = &.{},
        .working_dir = null,
        .volumes = &.{},
        .gpus = 1,
    };

    var ctrl = try TrainingController.init(alloc, &tj, "test-app");
    defer ctrl.deinit();

    try std.testing.expect(!ctrl.isClusterManaged());

    try state_support.generateClusterJobId(&ctrl);
    try std.testing.expect(ctrl.isClusterManaged());
}

test "training controller owns the app name and restores the persisted rank count" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();
    const job = spec.TrainingJob{ .name = "train", .image = "scratch", .command = &.{}, .env = &.{}, .working_dir = null, .volumes = &.{}, .gpus = 1 };
    var app_name = [_]u8{ 'd', 'e', 'm', 'o' };
    var ctrl = try TrainingController.init(alloc, &job, &app_name);
    defer ctrl.deinit();
    @memset(&app_name, 'x');
    try std.testing.expectEqualStrings("demo", ctrl.app_name);
    try ctrl.generateJobId();
    try ctrl.createPersistentRecord();
    try store.updateTrainingJobGpus(ctrl.job_id.?, 3, 2);
    try store.updateTrainingJobState(ctrl.job_id.?, "paused", 2);
    try std.testing.expect(ctrl.loadFromStore());
    try std.testing.expectEqual(@as(u32, 3), ctrl.gpu_count);
    try std.testing.expectEqual(@as(usize, 3), ctrl.rank_status.len);
    try std.testing.expectEqual(TrainingJobState.paused, ctrl.state);
}

test "training pause survives late runner updates until the previous owner exits" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();
    const job = spec.TrainingJob{ .name = "train", .image = "scratch", .command = &.{}, .env = &.{}, .working_dir = null, .volumes = &.{}, .gpus = 1 };
    var ctrl = try TrainingController.init(alloc, &job, "training-owner-handoff");
    defer ctrl.deinit();
    try ctrl.generateJobId();
    try ctrl.createPersistentRecord();
    try store.updateTrainingJobState(ctrl.job_id.?, "paused", 2);
    ctrl.state = .completed;
    try std.testing.expectError(error.TrainingCanceled, state_support.persistRunnerState(&ctrl));
    try std.testing.expectEqual(TrainingJobState.paused, ctrl.state);
    var owner = try state_support.acquireOwner(&ctrl);
    defer owner.release();
    const PreviousRunner = struct {
        fn finish(lock: *@import("apply_lock.zig").ApplyLock) void {
            _ = @import("../lib/runtime_wait.zig").sleep(.fromMilliseconds(50), "training owner test");
            lock.release();
        }
    };
    const thread = try std.Thread.spawn(.{}, PreviousRunner.finish, .{&owner});
    defer thread.join();
    try ctrl.resume_();
    try std.testing.expectEqual(TrainingJobState.pending, ctrl.state);
    const record = try store.getTrainingJob(alloc, ctrl.job_id.?);
    defer record.deinit(alloc);
    try std.testing.expectEqualStrings("pending", record.state);
    // a second caller that loaded the old paused state cannot resume it again.
    ctrl.state = .paused;
    try std.testing.expectError(error.InvalidTrainingState, ctrl.resume_());
}
