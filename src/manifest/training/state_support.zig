const std = @import("std");

const checkpoint_mgr = @import("../checkpoint.zig");
const store = @import("../../state/store.zig");

pub fn generateJobId(self: anytype) !void {
    var id_buf: [256]u8 = undefined;
    const ts = std.time.timestamp();
    const id_str = std.fmt.bufPrint(&id_buf, "{s}-{s}-{d}", .{ self.app_name, self.job.name, ts }) catch return error.OutOfMemory;
    self.job_id = try self.alloc.dupe(u8, id_str);
}

pub fn persistState(self: anytype) void {
    const jid = self.job_id orelse return;
    const now = std.time.timestamp();
    store.updateTrainingJobState(jid, self.state.label(), now) catch {};
}

pub fn createPersistentRecord(self: anytype) void {
    const jid = self.job_id orelse return;
    const now = std.time.timestamp();
    const ckpt = self.job.checkpoint;

    store.saveTrainingJob(.{
        .id = jid,
        .name = self.job.name,
        .app_name = self.app_name,
        .state = self.state.label(),
        .image = self.job.image,
        .gpus = @intCast(self.job.gpus),
        .checkpoint_path = if (ckpt) |c| c.path else null,
        .checkpoint_interval = if (ckpt) |c| @as(?i64, @intCast(c.interval_secs)) else null,
        .checkpoint_keep = if (ckpt) |c| @as(?i64, @intCast(c.keep)) else null,
        .restart_count = 0,
        .created_at = now,
        .updated_at = now,
    }) catch {};
}

pub fn loadResumeCheckpoint(self: anytype) void {
    const jid = self.job_id orelse return;
    const path = checkpoint_mgr.getLatestCheckpointPath(self.alloc, jid) orelse return;
    if (self.resume_path) |existing| self.alloc.free(existing);
    self.resume_path = path;
}

pub fn syncCheckpoints(self: anytype) void {
    const ckpt = self.job.checkpoint orelse return;
    const jid = self.job_id orelse return;
    const new_ckpts = checkpoint_mgr.syncCheckpoints(self.alloc, jid, ckpt.path, ckpt.keep) catch 0;
    if (new_ckpts > 0) {
        const cli = @import("../../lib/cli.zig");
        cli.writeErr("recorded {d} checkpoint(s)\n", .{new_ckpts});
    }
}

pub fn stopRunningRanks(self: anytype) void {
    for (self.rank_status) |*rs| {
        if (rs.* == .running) rs.* = .stopped;
    }
}

pub fn loadFromStore(self: anytype, state_enum: type) bool {
    const rec = store.findTrainingJob(self.alloc, self.app_name, self.job.name) catch return false;
    const r = rec orelse return false;

    if (self.job_id) |jid| self.alloc.free(jid);
    self.job_id = r.id;
    self.restart_count = @intCast(r.restart_count);
    self.state = state_enum.fromLabel(r.state) orelse .pending;

    self.alloc.free(r.name);
    self.alloc.free(r.app_name);
    self.alloc.free(r.state);
    self.alloc.free(r.image);
    if (r.checkpoint_path) |p| self.alloc.free(p);

    return true;
}
