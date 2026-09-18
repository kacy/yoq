const std = @import("std");

const checkpoint_mgr = @import("../checkpoint.zig");
const store = @import("../../state/store.zig");

pub const cluster_job_prefix = "cluster-";

pub fn generateJobId(self: anytype) !void {
    return generateJobIdWithPrefix(self, "");
}

pub fn generateClusterJobId(self: anytype) !void {
    return generateJobIdWithPrefix(self, cluster_job_prefix);
}

fn generateJobIdWithPrefix(self: anytype, prefix: []const u8) !void {
    var id_buf: [256]u8 = undefined;
    var suffix: [12]u8 = undefined;
    try @import("../../runtime/container.zig").generateId(&suffix);
    const id_str = std.fmt.bufPrint(&id_buf, "{s}{s}-{s}-{s}", .{ prefix, self.app_name, self.job.name, suffix }) catch return error.OutOfMemory;
    const owned_id = try self.alloc.dupe(u8, id_str);
    if (self.job_id) |existing| self.alloc.free(existing);
    self.job_id = owned_id;
}

pub fn isClusterManaged(self: anytype) bool {
    const jid = self.job_id orelse return false;
    return std.mem.startsWith(u8, jid, cluster_job_prefix);
}

pub fn persistState(self: anytype) !void {
    const jid = self.job_id orelse return;
    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    try store.updateTrainingJobState(jid, self.state.label(), now);
}

pub fn persistRunnerState(self: anytype) !void {
    const id = self.job_id orelse return;
    if (!try store.updateTrainingRunnerState(id, self.state.label(), std.Io.Clock.real.now(std.Options.debug_io).toSeconds())) {
        if (try refreshControl(self)) return error.TrainingCanceled;
        return error.JobMissing;
    }
}

pub fn acquireOwner(self: anytype) !@import("../apply_lock.zig").ApplyLock {
    const key = try std.fmt.allocPrint(self.alloc, "training:{s}:{s}", .{ self.app_name, self.job.name });
    defer self.alloc.free(key);
    return @import("../apply_lock.zig").acquire(self.alloc, key);
}

pub fn waitForOwner(self: anytype) !@import("../apply_lock.zig").ApplyLock {
    const deadline = std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds() + 10 * std.time.ns_per_s;
    while (true) {
        return acquireOwner(self) catch |err| {
            if (err != error.AlreadyLocked) return err;
            if (std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds() >= deadline) return error.ControllerStillRunning;
            if (!@import("../../lib/runtime_wait.zig").sleep(.fromMilliseconds(50), "training controller shutdown")) return error.ControllerStillRunning;
            continue;
        };
    }
}

pub fn createPersistentRecord(self: anytype) !void {
    const jid = self.job_id orelse return;
    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    const ckpt = self.job.checkpoint;

    try store.saveTrainingJob(.{
        .id = jid,
        .name = self.job.name,
        .app_name = self.app_name,
        .state = self.state.label(),
        .image = self.job.image,
        .gpus = @intCast(self.gpu_count),
        .checkpoint_path = if (ckpt) |c| c.path else null,
        .checkpoint_interval = if (ckpt) |c| @as(?i64, @intCast(c.interval_secs)) else null,
        .checkpoint_keep = if (ckpt) |c| @as(?i64, @intCast(c.keep)) else null,
        .restart_count = 0,
        .created_at = now,
        .updated_at = now,
    });
}

pub fn loadResumeCheckpoint(self: anytype) void {
    const ckpt = self.job.checkpoint orelse return;
    var arena = std.heap.ArenaAllocator.init(self.alloc);
    defer arena.deinit();
    const mounts = @import("../orchestrator/service_runtime.zig").resolveServiceVolumes(arena.allocator(), self.job.volumes, self.manifest_volumes, self.app_name) catch return;
    const path = (checkpoint_mgr.latestMountedCheckpoint(self.alloc, ckpt.path, mounts.bind_mounts.items) catch return) orelse return;
    if (self.resume_path) |existing| self.alloc.free(existing);
    self.resume_path = path;
}

pub fn syncCheckpoints(self: anytype) void {
    const ckpt = self.job.checkpoint orelse return;
    const jid = self.job_id orelse return;
    var arena = std.heap.ArenaAllocator.init(self.alloc);
    defer arena.deinit();
    const mounts = @import("../orchestrator/service_runtime.zig").resolveServiceVolumes(arena.allocator(), self.job.volumes, self.manifest_volumes, self.app_name) catch return;
    const host_path = (checkpoint_mgr.mountedDirectory(arena.allocator(), ckpt.path, mounts.bind_mounts.items) catch return) orelse return;
    const new_ckpts = checkpoint_mgr.syncCheckpoints(self.alloc, jid, host_path, ckpt.keep) catch |err| {
        @import("../../lib/log.zig").warn("checkpoint sync failed for {s}: {}", .{ jid, err });
        return;
    };
    if (new_ckpts > 0) @import("../../lib/cli.zig").writeErr("recorded {d} checkpoint(s)\n", .{new_ckpts});
}

pub fn stopRunningRanks(self: anytype) !void {
    const runtime_state = @import("../../runtime/cli/container/state_support.zig");
    const supervisor = @import("../../runtime/cli/container/supervisor_runtime.zig");
    if (isClusterManaged(self)) return error.RemoteControlRequired;
    if (self.job_id != null) {
        const prefix = try std.fmt.allocPrint(self.alloc, "{s}-rank-", .{self.job.name});
        defer self.alloc.free(prefix);
        var ids = try store.listAppContainerIds(self.alloc, self.app_name);
        defer {
            for (ids.items) |id| self.alloc.free(id);
            ids.deinit(self.alloc);
        }
        // inspect every stored rank, including ranks beyond a newly reduced
        // manifest count and duplicate records left by an interrupted attempt.
        for (ids.items) |id| {
            const record = store.load(self.alloc, id) catch |err| switch (err) {
                error.NotFound => continue,
                else => return err,
            };
            defer record.deinit(self.alloc);
            if (!std.mem.startsWith(u8, record.hostname, prefix)) continue;
            _ = std.fmt.parseInt(u32, record.hostname[prefix.len..], 10) catch continue;
            if (runtime_state.currentOwnedRunningPid(&record)) |pid| {
                try supervisor.stopProcess(pid);
                if (!runtime_state.waitForStoppedState(self.alloc, record.id)) return error.RanksStillRunning;
            }
        }
    }
    for (self.rank_status) |*status| if (status.* == .running) {
        status.* = .stopped;
    };
}

pub fn refreshControl(self: anytype) !bool {
    const id = self.job_id orelse return false;
    const record = try store.getTrainingJob(self.alloc, id);
    defer record.deinit(self.alloc);
    if (std.mem.eql(u8, record.state, "paused")) self.state = .paused else if (std.mem.eql(u8, record.state, "stopped")) self.state = .stopped else return false;
    return true;
}

pub fn loadFromStore(self: anytype, state_enum: type) bool {
    const r = (store.findTrainingJob(self.alloc, self.app_name, self.job.name) catch return false) orelse return false;
    defer r.deinit(self.alloc);
    const gpus = std.math.cast(u32, r.gpus) orelse return false;
    const restarts = std.math.cast(u32, r.restart_count) orelse return false;
    const state = state_enum.fromLabel(r.state) orelse return false;
    const id = self.alloc.dupe(u8, r.id) catch return false;
    self.resizeRanks(gpus) catch {
        self.alloc.free(id);
        return false;
    };
    if (self.job_id) |previous| self.alloc.free(previous);
    self.job_id = id;
    self.restart_count = restarts;
    self.state = state;
    return true;
}
