// training — training job lifecycle controller
//
// manages multi-rank GPU training jobs: start (gang-schedule all ranks),
// pause (stop containers), resume (restart from checkpoint), stop.
//
// for local mode: launches rank containers via orchestrator.runOneShot().
// for cluster mode: POSTs to /deploy with gang scheduling parameters.

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
    rank_status: []RankStatus,
    job_id: ?[]const u8 = null,
    resume_path: ?[]const u8 = null,
    restart_count: u32 = 0,

    pub fn init(alloc: std.mem.Allocator, job: *const spec.TrainingJob, app_name: []const u8) !TrainingController {
        const rank_status = try alloc.alloc(RankStatus, job.gpus);
        @memset(rank_status, .pending);

        return .{
            .alloc = alloc,
            .job = job,
            .state = .pending,
            .app_name = app_name,
            .rank_status = rank_status,
        };
    }

    pub fn deinit(self: *TrainingController) void {
        self.alloc.free(self.rank_status);
        if (self.resume_path) |rp| self.alloc.free(rp);
        if (self.job_id) |jid| self.alloc.free(jid);
    }

    /// generate a job ID from app name and job name.
    fn generateJobId(self: *TrainingController) !void {
        return state_support.generateJobId(self);
    }

    /// persist job state to database.
    fn persistState(self: *TrainingController) void {
        state_support.persistState(self);
    }

    /// create initial persistent record for this training job.
    fn createPersistentRecord(self: *TrainingController) void {
        state_support.createPersistentRecord(self);
    }

    /// load resume path from the latest checkpoint if one exists.
    fn loadResumeCheckpoint(self: *TrainingController) void {
        state_support.loadResumeCheckpoint(self);
    }

    /// start training job locally by launching one container per rank.
    /// each rank gets RANK, WORLD_SIZE, MASTER_ADDR, MASTER_PORT, LOCAL_RANK
    /// injected into its environment along with NCCL mesh config.
    ///
    /// NOTE: ranks are launched sequentially via runOneShot which blocks until
    /// exit. this means local multi-rank training will not work for distributed
    /// workloads that require simultaneous rank communication (NCCL all-reduce).
    /// for multi-rank training, use cluster mode (--server) which gang-schedules
    /// ranks across agents. local mode is useful for single-rank testing.
    pub fn startLocal(self: *TrainingController) !void {
        return local_runner.startLocal(self);
    }

    /// start training job in cluster mode by POSTing to /deploy with gang scheduling.
    pub fn startCluster(self: *TrainingController, server_ip: [4]u8, server_port: u16) !void {
        return cluster_runner.startCluster(self, server_ip, server_port);
    }

    pub fn stop(self: *TrainingController) void {
        // sync any final checkpoints
        if (self.job.checkpoint) |ckpt| {
            if (self.job_id) |jid| {
                _ = checkpoint_mgr.syncCheckpoints(self.alloc, jid, ckpt.path, ckpt.keep) catch 0;
            }
        }

        state_support.stopRunningRanks(self);
        self.state = .stopped;
        self.persistState();
    }

    pub fn pause(self: *TrainingController) void {
        if (self.state != .running) return;

        // sync checkpoints before pausing so we capture the latest
        if (self.job.checkpoint) |ckpt| {
            if (self.job_id) |jid| {
                _ = checkpoint_mgr.syncCheckpoints(self.alloc, jid, ckpt.path, ckpt.keep) catch 0;
            }
        }

        state_support.stopRunningRanks(self);
        self.state = .paused;
        self.persistState();
    }

    pub fn resume_(self: *TrainingController) void {
        if (self.state != .paused) return;

        // load latest checkpoint for resume
        self.loadResumeCheckpoint();

        self.state = .pending;
        self.persistState();
    }

    pub fn printStatus(self: *const TrainingController) void {
        write("training job: {s}\n", .{self.job.name});
        write("state:        {s}\n", .{self.state.label()});
        write("image:        {s}\n", .{self.job.image});
        write("gpus:         {d}\n", .{self.job.gpus});
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
    ctrl.stop();
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

    ctrl.pause();
    try std.testing.expectEqual(TrainingJobState.paused, ctrl.state);
    try std.testing.expectEqual(RankStatus.stopped, ctrl.rank_status[0]);
    try std.testing.expectEqual(RankStatus.stopped, ctrl.rank_status[1]);

    ctrl.resume_();
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

    ctrl.pause();
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

    ctrl.resume_();
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
