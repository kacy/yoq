const std = @import("std");

const orchestrator = @import("../orchestrator.zig");
const gpu_runtime = @import("../gpu_runtime.zig");
const checkpoint_mgr = @import("../checkpoint.zig");
const store = @import("../../state/store.zig");
const cli = @import("../../lib/cli.zig");
const state_support = @import("state_support.zig");

const writeErr = cli.writeErr;

pub fn startLocal(self: anytype) !void {
    const new_job = self.job_id == null;
    if (new_job) state_support.generateJobId(self) catch {};
    if (new_job) state_support.createPersistentRecord(self);

    while (true) {
        self.state = .scheduling;
        state_support.persistState(self);

        writeErr("pulling {s}...\n", .{self.job.image});
        if (!orchestrator.ensureImageAvailable(self.alloc, self.job.image)) {
            self.state = .failed;
            state_support.persistState(self);
            return error.ImagePullFailed;
        }

        self.state = .running;
        state_support.persistState(self);

        var mesh_support = gpu_runtime.MeshSupport.init(self.alloc);
        defer mesh_support.deinit();

        var failed_ranks: u32 = 0;

        for (0..self.job.gpus) |rank| {
            const success = runRank(self, &mesh_support, rank);
            if (success) {
                self.rank_status[rank] = .stopped;
            } else {
                self.rank_status[rank] = .failed;
                failed_ranks += 1;
            }
        }

        state_support.syncCheckpoints(self);

        if (failed_ranks > 0) {
            if (shouldAutoRestart(self, failed_ranks)) continue;

            self.state = .failed;
            state_support.persistState(self);
            writeErr("{d}/{d} ranks failed\n", .{ failed_ranks, self.job.gpus });
            return;
        }

        self.state = .completed;
        state_support.persistState(self);
        return;
    }
}

fn runRank(self: anytype, mesh_support: *gpu_runtime.MeshSupport, rank: usize) bool {
    self.rank_status[rank] = .running;

    var rank_env: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (rank_env.items) |e| self.alloc.free(e);
        rank_env.deinit(self.alloc);
    }

    for (self.job.env) |e| {
        const duped = self.alloc.dupe(u8, e) catch continue;
        rank_env.append(self.alloc, duped) catch {
            self.alloc.free(duped);
            continue;
        };
    }

    mesh_support.appendEnv(
        self.alloc,
        &rank_env,
        "127.0.0.1",
        29500,
        self.job.gpus,
        @intCast(rank),
        @intCast(rank),
    );

    if (self.job.checkpoint) |ckpt| {
        checkpoint_mgr.buildCheckpointEnv(self.alloc, &rank_env, ckpt, self.resume_path) catch {};
    }

    var hostname_buf: [128]u8 = undefined;
    const hostname = std.fmt.bufPrint(&hostname_buf, "{s}-rank-{d}", .{ self.job.name, rank }) catch self.job.name;

    writeErr("  starting rank {d}/{d}...\n", .{ rank, self.job.gpus });

    return orchestrator.runOneShot(
        self.alloc,
        self.job.image,
        self.job.command,
        rank_env.items,
        self.job.volumes,
        self.job.working_dir,
        hostname,
        &.{},
        self.app_name,
    );
}

fn shouldAutoRestart(self: anytype, failed_ranks: u32) bool {
    if (!self.job.fault_tolerance.auto_restart) return false;
    if (self.restart_count >= self.job.fault_tolerance.max_restarts) return false;

    self.restart_count += 1;
    if (self.job_id) |jid| {
        store.incrementTrainingJobRestarts(jid, std.time.timestamp()) catch {};
    }
    writeErr("{d}/{d} ranks failed, restarting (attempt {d}/{d})...\n", .{
        failed_ranks,
        self.job.gpus,
        self.restart_count,
        self.job.fault_tolerance.max_restarts,
    });
    state_support.loadResumeCheckpoint(self);
    for (self.rank_status) |*status| status.* = .pending;
    self.state = .pending;
    state_support.persistState(self);
    return true;
}
