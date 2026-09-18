const std = @import("std");
const orchestrator = @import("../orchestrator.zig");
const store = @import("../../state/store.zig");
const state_support = @import("state_support.zig");
const rank_group = @import("rank_group.zig");
const runtime_wait = @import("../../lib/runtime_wait.zig");

pub fn startLocal(self: anytype) !void {
    startOwned(self) catch |err| {
        if (err != error.TrainingCanceled) return err;
    };
}

fn startOwned(self: anytype) !void {
    var lock = try state_support.acquireOwner(self);
    defer lock.release();
    if (self.job_id == null) {
        try state_support.generateJobId(self);
        try state_support.createPersistentRecord(self);
    }
    // clear ranks left behind by a prior owner before reusing their names.
    try state_support.stopRunningRanks(self);
    orchestrator.shutdown_requested.store(false, .release);
    orchestrator.installSignalHandlers();
    errdefer {
        if (!(state_support.refreshControl(self) catch false)) {
            self.state = .failed;
            state_support.persistRunnerState(self) catch {};
        }
    }
    while (true) {
        self.state = .scheduling;
        try state_support.persistRunnerState(self);
        if (!orchestrator.ensureImageAvailable(self.alloc, self.job.image)) return error.ImagePullFailed;
        var group = try rank_group.Group.init(self);
        defer group.deinit();
        const succeeded = try runRanks(self, &group);
        state_support.syncCheckpoints(self);
        if (self.state == .paused or self.state == .stopped) return;
        if (succeeded) {
            self.state = .completed;
            try state_support.persistRunnerState(self);
            return;
        }
        if (!self.job.fault_tolerance.auto_restart or self.restart_count >= self.job.fault_tolerance.max_restarts) {
            self.state = .failed;
            try state_support.persistRunnerState(self);
            return error.RankFailed;
        }
        self.restart_count += 1;
        try store.incrementTrainingJobRestarts(self.job_id.?, std.Io.Clock.real.now(std.Options.debug_io).toSeconds());
        state_support.loadResumeCheckpoint(self);
        @memset(self.rank_status, .pending);
    }
}

// starting a rank never waits for it. a failed rank or a control request stops
// the whole group before resources are released or another attempt begins.
pub fn runRanks(self: anytype, group: anytype) !bool {
    defer {
        group.stopAll();
        for (self.rank_status) |*status| if (status.* == .running) {
            status.* = .stopped;
        };
    }
    for (self.rank_status, 0..) |*status, rank| {
        if (try cancelled(self)) return false;
        try group.start(rank);
        status.* = .running;
    }
    self.state = .running;
    try state_support.persistRunnerState(self);
    while (true) {
        if (try cancelled(self)) return false;
        var running: usize = 0;
        for (self.rank_status, 0..) |*status, rank| {
            if (status.* != .running) continue;
            if (try group.poll(rank)) |code| {
                status.* = if (code == 0) .stopped else .failed;
                if (code != 0) return false;
            } else running += 1;
        }
        if (running == 0) return true;
        if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(50), "training rank wait")) {
            if (try cancelled(self)) return false;
            return error.SleepInterrupted;
        }
    }
}

fn cancelled(self: anytype) !bool {
    if (orchestrator.shutdown_requested.load(.acquire)) {
        self.state = .stopped;
        try state_support.persistState(self);
        return true;
    }
    return state_support.refreshControl(self);
}

test "training ranks all start before polling and a failed rank stops its peers" {
    orchestrator.shutdown_requested.store(false, .release);
    const training = @import("../training.zig");
    const spec = @import("../spec.zig");
    const job = spec.TrainingJob{ .name = "train", .image = "scratch", .command = &.{}, .env = &.{}, .working_dir = null, .volumes = &.{}, .gpus = 3 };
    var ctrl = try training.TrainingController.init(std.testing.allocator, &job, "demo");
    defer ctrl.deinit();
    const FakeGroup = struct {
        started: usize = 0,
        stopped: bool = false,
        pub fn start(self: *@This(), rank: usize) !void {
            try std.testing.expectEqual(self.started, rank);
            self.started += 1;
        }
        pub fn poll(self: *@This(), rank: usize) !?u8 {
            try std.testing.expectEqual(@as(usize, 3), self.started);
            return if (rank == 1) 1 else null;
        }
        pub fn stopAll(self: *@This()) void {
            self.stopped = true;
        }
    };
    var group: FakeGroup = .{};
    try std.testing.expect(!try runRanks(&ctrl, &group));
    try std.testing.expect(group.stopped);
    try std.testing.expectEqual(training.RankStatus.failed, ctrl.rank_status[1]);
}

test "training startup failure and cancellation stop every started rank" {
    const training = @import("../training.zig");
    const spec = @import("../spec.zig");
    const job = spec.TrainingJob{ .name = "train", .image = "scratch", .command = &.{}, .env = &.{}, .working_dir = null, .volumes = &.{}, .gpus = 3 };
    var ctrl = try training.TrainingController.init(std.testing.allocator, &job, "demo");
    defer ctrl.deinit();
    const FakeGroup = struct {
        started: usize = 0,
        stopped: bool = false,
        cancel: bool = false,
        pub fn start(self: *@This(), rank: usize) !void {
            if (rank == 1) return error.StartFailed;
            self.started += 1;
            if (self.cancel) orchestrator.shutdown_requested.store(true, .release);
        }
        pub fn poll(_: *@This(), _: usize) !?u8 {
            return error.UnexpectedPoll;
        }
        pub fn stopAll(self: *@This()) void {
            self.stopped = true;
        }
    };
    orchestrator.shutdown_requested.store(false, .release);
    defer orchestrator.shutdown_requested.store(false, .release);
    var failed: FakeGroup = .{};
    try std.testing.expectError(error.StartFailed, runRanks(&ctrl, &failed));
    try std.testing.expectEqual(@as(usize, 1), failed.started);
    try std.testing.expect(failed.stopped);
    @memset(ctrl.rank_status, .pending);
    var canceled: FakeGroup = .{ .cancel = true };
    try std.testing.expect(!try runRanks(&ctrl, &canceled));
    try std.testing.expectEqual(@as(usize, 1), canceled.started);
    try std.testing.expect(canceled.stopped);
    try std.testing.expectEqual(training.TrainingJobState.stopped, ctrl.state);
}
