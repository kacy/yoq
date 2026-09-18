const std = @import("std");
const store = @import("../../state/store.zig");
const training = @import("../training.zig");
const spec = @import("../spec.zig");
const alloc = std.testing.allocator;
const job = spec.TrainingJob{ .name = "train", .image = "scratch", .command = &.{}, .env = &.{}, .working_dir = null, .volumes = &.{}, .gpus = 1 };

fn saveJob(state: []const u8) !void {
    try store.saveTrainingJob(.{ .id = "control-run", .name = "train", .app_name = "control-regression", .state = state, .image = "scratch", .gpus = 1, .checkpoint_path = null, .checkpoint_interval = null, .checkpoint_keep = null, .restart_count = 0, .created_at = 0, .updated_at = 0 });
}

fn controller() !training.TrainingController {
    var ctrl = try training.TrainingController.init(alloc, &job, "control-regression");
    errdefer ctrl.deinit();
    if (!ctrl.loadFromStore()) return error.MissingJob;
    return ctrl;
}

fn expectRecord(state: []const u8, gpus: i64) !void {
    const record = try store.getTrainingJob(alloc, "control-run");
    defer record.deinit(alloc);
    try std.testing.expectEqualStrings(state, record.state);
    try std.testing.expectEqual(gpus, record.gpus);
}

test "training invalid scale leaves the live allocation and control state unchanged" {
    try store.initTestDb();
    defer store.deinitTestDb();
    try saveJob("running");
    var ctrl = try controller();
    defer ctrl.deinit();
    for ([_]u32{ 0, 4097, std.math.maxInt(u32) }) |gpus| {
        try std.testing.expectError(error.InvalidGpuCount, ctrl.scale(gpus));
        try expectRecord("running", 1);
        try std.testing.expectEqual(training.TrainingJobState.running, ctrl.state);
        try std.testing.expectEqual(@as(u32, 1), ctrl.gpu_count);
    }
    var args = std.process.Args.Iterator.init(.{ .vector = &.{ "scale", "train", "--gpus", "4097" } });
    try std.testing.expectError(error.InvalidArgument, @import("../cli/train.zig").train(&args, std.testing.io, alloc));
    try expectRecord("running", 1);
    try ctrl.stop();
    try expectRecord("stopped", 1);
}

test "training scale allocation failure does not pause the job" {
    try store.initTestDb();
    defer store.deinitTestDb();
    try saveJob("running");
    var ctrl = try controller();
    defer ctrl.deinit();
    ctrl.alloc = std.testing.failing_allocator;
    const result = ctrl.scale(2);
    ctrl.alloc = alloc;
    try std.testing.expectError(error.OutOfMemory, result);
    try expectRecord("running", 1);
    try std.testing.expectEqual(training.TrainingJobState.running, ctrl.state);
}

test "training stale pause resume and scale cannot revive an explicitly stopped job" {
    try store.initTestDb();
    defer store.deinitTestDb();
    try saveJob("running");
    var stop = try controller();
    defer stop.deinit();
    var stale = try controller();
    defer stale.deinit();
    try stop.stop();
    try std.testing.expectError(error.InvalidTrainingState, stale.pause());
    try std.testing.expectError(error.InvalidTrainingState, stale.scale(2));
    stale.state = .paused;
    try std.testing.expectError(error.InvalidTrainingState, stale.resume_());
    try expectRecord("stopped", 1);
}

test "training competing scale snapshots cannot replace the committed count" {
    try store.initTestDb();
    defer store.deinitTestDb();
    try saveJob("paused");
    var first = try controller();
    defer first.deinit();
    var stale = try controller();
    defer stale.deinit();
    try first.scale(2);
    try expectRecord("pending", 2);
    try std.testing.expectError(error.InvalidTrainingState, stale.scale(3));
    try expectRecord("pending", 2);
    try std.testing.expectEqual(@as(u32, 1), stale.gpu_count);
}

test "training operator lock excludes competing controls without blocking cancellation" {
    try store.initTestDb();
    defer store.deinitTestDb();
    try saveJob("running");
    var ctrl = try controller();
    defer ctrl.deinit();
    var owner = try @import("state_support.zig").acquireOwner(&ctrl);
    defer owner.release();
    var control = (try @import("state_support.zig").acquireControl(&ctrl)).?;
    try std.testing.expectError(error.AlreadyLocked, ctrl.pause());
    try expectRecord("running", 1);
    control.release();
    try ctrl.pause();
    try expectRecord("paused", 1);
}
