// training — training job lifecycle controller
//
// manages multi-rank GPU training jobs: start (gang-schedule all ranks),
// pause (stop containers), resume (restart from checkpoint), stop.
//
// for local mode: launches rank containers via orchestrator.runOneShot().
// for cluster mode: POSTs to /deploy with gang scheduling parameters.

const std = @import("std");
const spec = @import("spec.zig");
const orchestrator = @import("orchestrator.zig");
const cli = @import("../lib/cli.zig");
const checkpoint_mgr = @import("checkpoint.zig");
const store = @import("../state/store.zig");

const write = cli.write;
const writeErr = cli.writeErr;

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
        var id_buf: [256]u8 = undefined;
        const ts = std.time.timestamp();
        const id_str = std.fmt.bufPrint(&id_buf, "{s}-{s}-{d}", .{ self.app_name, self.job.name, ts }) catch return error.OutOfMemory;
        self.job_id = try self.alloc.dupe(u8, id_str);
    }

    /// persist job state to database.
    fn persistState(self: *TrainingController) void {
        const jid = self.job_id orelse return;
        const now = std.time.timestamp();
        store.updateTrainingJobState(jid, self.state.label(), now) catch {};
    }

    /// create initial persistent record for this training job.
    fn createPersistentRecord(self: *TrainingController) void {
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

    /// load resume path from the latest checkpoint if one exists.
    fn loadResumeCheckpoint(self: *TrainingController) void {
        const jid = self.job_id orelse return;
        if (checkpoint_mgr.getLatestCheckpointPath(self.alloc, jid)) |path| {
            self.resume_path = path;
        }
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
        self.state = .scheduling;

        // create persistent record
        if (self.job_id == null) self.generateJobId() catch {};
        self.createPersistentRecord();

        // pull image
        writeErr("pulling {s}...\n", .{self.job.image});
        if (!orchestrator.ensureImageAvailable(self.alloc, self.job.image)) {
            self.state = .failed;
            self.persistState();
            return error.ImagePullFailed;
        }

        self.state = .running;
        self.persistState();

        // detect IB and GPUs for NCCL mesh env
        const gpu_mesh = @import("../gpu/mesh.zig");
        const gpu_detect = @import("../gpu/detect.zig");
        const ib_result = gpu_mesh.detectInfiniband();

        // generate NCCL topology XML
        var topo_file_path: ?[]const u8 = null;
        const gpu_result = gpu_detect.detect();
        if (gpu_result.count > 0) {
            if (gpu_mesh.generateNcclTopology(
                self.alloc,
                gpu_result.gpus[0..gpu_result.count],
                &ib_result.devices,
                ib_result.count,
            )) |topo_xml| {
                defer self.alloc.free(topo_xml);
                var topo_path_buf: [256]u8 = undefined;
                const topo_path = std.fmt.bufPrint(&topo_path_buf, "/tmp/nccl_topo_{s}.xml", .{self.job.name}) catch null;
                if (topo_path) |tp| {
                    if (std.fs.cwd().createFile(tp, .{})) |file| {
                        file.writeAll(topo_xml) catch {};
                        file.close();
                        topo_file_path = self.alloc.dupe(u8, tp) catch null;
                    } else |_| {}
                }
            } else |_| {}
        }
        defer if (topo_file_path) |p| self.alloc.free(p);

        var failed_ranks: u32 = 0;
        var succeeded_ranks: u32 = 0;

        for (0..self.job.gpus) |rank| {
            self.rank_status[rank] = .running;

            // build per-rank env: base env + mesh env
            var rank_env: std.ArrayListUnmanaged([]const u8) = .empty;
            defer {
                for (rank_env.items) |e| self.alloc.free(e);
                rank_env.deinit(self.alloc);
            }

            // copy job env
            for (self.job.env) |e| {
                const duped = self.alloc.dupe(u8, e) catch continue;
                rank_env.append(self.alloc, duped) catch {
                    self.alloc.free(duped);
                    continue;
                };
            }

            // add mesh env vars
            var mesh_env_buf: [1024]u8 = undefined;
            if (gpu_mesh.generateMeshEnv(
                &mesh_env_buf,
                ib_result,
                "127.0.0.1",
                29500,
                self.job.gpus,
                @intCast(rank),
                @intCast(rank),
                topo_file_path,
            )) |env_data| {
                var env_pos: usize = 0;
                while (env_pos < env_data.len) {
                    const end = std.mem.indexOfScalarPos(u8, env_data, env_pos, 0) orelse env_data.len;
                    if (end > env_pos) {
                        if (self.alloc.dupe(u8, env_data[env_pos..end])) |duped| {
                            rank_env.append(self.alloc, duped) catch {
                                self.alloc.free(duped);
                            };
                        } else |_| {}
                    }
                    env_pos = end + 1;
                }
            } else |_| {}

            // add checkpoint env vars if configured
            if (self.job.checkpoint) |ckpt| {
                checkpoint_mgr.buildCheckpointEnv(self.alloc, &rank_env, ckpt, self.resume_path) catch {};
            }

            // generate hostname for this rank
            var hostname_buf: [128]u8 = undefined;
            const hostname = std.fmt.bufPrint(&hostname_buf, "{s}-rank-{d}", .{ self.job.name, rank }) catch self.job.name;

            writeErr("  starting rank {d}/{d}...\n", .{ rank, self.job.gpus });

            const success = orchestrator.runOneShot(
                self.alloc,
                self.job.image,
                self.job.command,
                rank_env.items,
                self.job.volumes,
                self.job.working_dir,
                hostname,
                &.{}, // manifest volumes (training jobs don't use named volumes from manifest)
                self.app_name,
            );

            if (success) {
                self.rank_status[rank] = .stopped;
                succeeded_ranks += 1;
            } else {
                self.rank_status[rank] = .failed;
                failed_ranks += 1;
            }
        }

        // sync checkpoints from filesystem after training completes
        if (self.job.checkpoint) |ckpt| {
            if (self.job_id) |jid| {
                const new_ckpts = checkpoint_mgr.syncCheckpoints(self.alloc, jid, ckpt.path, ckpt.keep) catch 0;
                if (new_ckpts > 0) {
                    writeErr("recorded {d} checkpoint(s)\n", .{new_ckpts});
                }
            }
        }

        if (failed_ranks > 0) {
            // fault tolerance: auto-restart failed ranks if configured
            if (self.job.fault_tolerance.auto_restart and self.restart_count < self.job.fault_tolerance.max_restarts) {
                self.restart_count += 1;
                if (self.job_id) |jid| {
                    store.incrementTrainingJobRestarts(jid, std.time.timestamp()) catch {};
                }
                writeErr("{d}/{d} ranks failed, restarting (attempt {d}/{d})...\n", .{
                    failed_ranks, self.job.gpus, self.restart_count, self.job.fault_tolerance.max_restarts,
                });
                // reload latest checkpoint for resume
                self.loadResumeCheckpoint();
                self.state = .running;
                self.persistState();
                return;
            }

            self.state = .failed;
            self.persistState();
            writeErr("{d}/{d} ranks failed\n", .{ failed_ranks, self.job.gpus });
        } else {
            self.state = .completed;
            self.persistState();
        }
    }

    /// start training job in cluster mode by POSTing to /deploy with gang scheduling.
    pub fn startCluster(self: *TrainingController, server_ip: [4]u8, server_port: u16) !void {
        self.state = .scheduling;

        const http_client = @import("../cluster/http_client.zig");
        const json_helpers = @import("../lib/json_helpers.zig");

        // build deploy JSON with gang scheduling parameters
        var json_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer json_buf.deinit(self.alloc);
        const writer = json_buf.writer(self.alloc);

        writer.writeAll("{\"services\":[{\"image\":\"") catch return error.OutOfMemory;
        json_helpers.writeJsonEscaped(writer, self.job.image) catch return error.OutOfMemory;
        writer.writeAll("\",\"command\":\"") catch return error.OutOfMemory;

        // join command args
        for (self.job.command, 0..) |arg, j| {
            if (j > 0) writer.writeByte(' ') catch {};
            json_helpers.writeJsonEscaped(writer, arg) catch {};
        }

        var resource_buf: [512]u8 = undefined;
        const resource_str = std.fmt.bufPrint(&resource_buf, "\",\"cpu_limit\":{d},\"memory_limit_mb\":{d},\"gpu_limit\":{d},\"gang_world_size\":{d},\"gpus_per_rank\":1", .{
            self.job.resources.cpu,
            self.job.resources.memory_mb,
            self.job.gpus,
            self.job.gpus,
        }) catch return error.OutOfMemory;
        writer.writeAll(resource_str) catch return error.OutOfMemory;

        if (self.job.gpu_type) |gt| {
            writer.writeAll(",\"gpu_model\":\"") catch return error.OutOfMemory;
            json_helpers.writeJsonEscaped(writer, gt) catch return error.OutOfMemory;
            writer.writeByte('"') catch return error.OutOfMemory;
        }

        writer.writeAll("}]}") catch return error.OutOfMemory;

        var token_buf: [64]u8 = undefined;
        const token = cli.readApiToken(&token_buf);

        var resp = http_client.postWithAuth(self.alloc, server_ip, server_port, "/deploy", json_buf.items, token) catch {
            self.state = .failed;
            return error.ConnectionFailed;
        };
        defer resp.deinit(self.alloc);

        if (resp.status_code == 200) {
            self.state = .running;
            write("{s}\n", .{resp.body});
        } else {
            self.state = .failed;
            writeErr("deploy failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
            return error.DeployFailed;
        }
    }

    pub fn stop(self: *TrainingController) void {
        // sync any final checkpoints
        if (self.job.checkpoint) |ckpt| {
            if (self.job_id) |jid| {
                _ = checkpoint_mgr.syncCheckpoints(self.alloc, jid, ckpt.path, ckpt.keep) catch 0;
            }
        }

        for (self.rank_status) |*rs| {
            if (rs.* == .running) rs.* = .stopped;
        }
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

        for (self.rank_status) |*rs| {
            if (rs.* == .running) rs.* = .stopped;
        }
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
        const rec = store.findTrainingJob(self.alloc, self.app_name, self.job.name) catch return false;
        const r = rec orelse return false;

        // take ownership of the id, free everything else
        self.job_id = r.id;
        self.restart_count = @intCast(r.restart_count);
        self.state = TrainingJobState.fromLabel(r.state) orelse .pending;

        self.alloc.free(r.name);
        self.alloc.free(r.app_name);
        self.alloc.free(r.state);
        self.alloc.free(r.image);
        if (r.checkpoint_path) |p| self.alloc.free(p);

        return true;
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
