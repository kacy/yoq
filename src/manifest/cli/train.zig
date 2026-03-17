const std = @import("std");
const cli = @import("../../lib/cli.zig");
const manifest_loader = @import("../loader.zig");
const manifest_spec = @import("../spec.zig");
const store = @import("../../state/store.zig");
const training = @import("../training.zig");
const logs = @import("../../runtime/logs.zig");

const write = cli.write;
const writeErr = cli.writeErr;

const TrainError = error{
    InvalidArgument,
    ManifestLoadFailed,
    DeploymentFailed,
    StoreError,
    UnknownService,
};

pub fn train(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const action = args.next() orelse {
        writeErr("usage: yoq train <start|status|stop|pause|resume|scale|logs> <name>\n", .{});
        return TrainError.InvalidArgument;
    };

    if (std.mem.eql(u8, action, "start")) return trainStart(args, alloc);
    if (std.mem.eql(u8, action, "status")) return trainStatus(args, alloc);
    if (std.mem.eql(u8, action, "stop")) return trainStop(args, alloc);
    if (std.mem.eql(u8, action, "pause")) return trainPause(args, alloc);
    if (std.mem.eql(u8, action, "resume")) return trainResume(args, alloc);
    if (std.mem.eql(u8, action, "logs")) return trainLogs(args, alloc);
    if (std.mem.eql(u8, action, "scale")) return trainScale(args, alloc);

    writeErr("unknown train action: {s}\n", .{action});
    writeErr("usage: yoq train <start|status|stop|pause|resume|scale|logs> <name>\n", .{});
    return TrainError.InvalidArgument;
}

fn trainStart(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var manifest_path: []const u8 = manifest_loader.default_filename;
    var job_name: ?[]const u8 = null;
    var server_addr: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                return TrainError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return TrainError.InvalidArgument;
            };
        } else {
            job_name = arg;
        }
    }

    const name = job_name orelse {
        writeErr("usage: yoq train start [-f manifest.toml] [--server host:port] <name>\n", .{});
        return TrainError.InvalidArgument;
    };

    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
        return TrainError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    const job = manifest.trainingJobByName(name) orelse {
        writeErr("unknown training job: {s}\n", .{name});
        return TrainError.UnknownService;
    };

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.process.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    var ctrl = training.TrainingController.init(alloc, job, app_name) catch |err| {
        writeErr("failed to initialize training controller: {}\n", .{err});
        return TrainError.DeploymentFailed;
    };
    defer ctrl.deinit();

    writeErr("starting training job {s} ({d} gpus)...\n", .{ name, job.gpus });

    if (server_addr) |addr| {
        const server = cli.parseServerAddr(addr);
        ctrl.startCluster(server.ip, server.port) catch return TrainError.DeploymentFailed;
    } else {
        ctrl.startLocal() catch return TrainError.DeploymentFailed;
    }

    if (ctrl.state == .completed) {
        writeErr("training job {s} completed successfully\n", .{name});
    } else if (ctrl.state == .running) {
        writeErr("training job {s} scheduled on cluster\n", .{name});
    } else {
        writeErr("training job {s} finished with state: {s}\n", .{ name, ctrl.state.label() });
    }
}

fn trainStatus(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var manifest_path: []const u8 = manifest_loader.default_filename;
    var job_name: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                return TrainError.InvalidArgument;
            };
        } else {
            job_name = arg;
        }
    }

    const name = job_name orelse {
        writeErr("usage: yoq train status [-f manifest.toml] <name>\n", .{});
        return TrainError.InvalidArgument;
    };

    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
        return TrainError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    const job = manifest.trainingJobByName(name) orelse {
        writeErr("unknown training job: {s}\n", .{name});
        return TrainError.UnknownService;
    };

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.process.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    var ctrl = training.TrainingController.init(alloc, job, app_name) catch {
        write("training job: {s}\n", .{name});
        write("image:        {s}\n", .{job.image});
        write("gpus:         {d}\n", .{job.gpus});
        return;
    };
    defer ctrl.deinit();
    const has_persistent = ctrl.loadFromStore();

    write("training job: {s}\n", .{name});
    if (has_persistent) {
        write("state:        {s}\n", .{ctrl.state.label()});
        write("restarts:     {d}/{d}\n", .{ ctrl.restart_count, job.fault_tolerance.max_restarts });
    } else {
        write("state:        not started\n", .{});
    }
    write("image:        {s}\n", .{job.image});
    write("gpus:         {d}\n", .{job.gpus});
    if (job.gpu_type) |gt| write("gpu_type:     {s}\n", .{gt});
    if (job.checkpoint) |ckpt| {
        write("checkpoint:   {s} (every {d}s, keep {d})\n", .{ ckpt.path, ckpt.interval_secs, ckpt.keep });

        if (ctrl.job_id) |jid| {
            if (store.listCheckpoints(alloc, jid)) |ckpts_result| {
                var ckpts = ckpts_result;
                defer {
                    for (ckpts.items) |rec| rec.deinit(alloc);
                    ckpts.deinit(alloc);
                }
                if (ckpts.items.len > 0) {
                    write("last_ckpt:    {s}\n", .{ckpts.items[0].path});
                    write("checkpoints:  {d} saved\n", .{ckpts.items.len});
                }
            } else |_| {}
        }
    }
    if (job.data) |d| {
        write("dataset:      {s}\n", .{d.dataset});
        write("sharding:     {s}\n", .{d.sharding});
    }
    if (job.fault_tolerance.spare_ranks > 0) write("spare_ranks:  {d}\n", .{job.fault_tolerance.spare_ranks});
    write("cpu/rank:     {d}m\n", .{job.resources.cpu});
    write("memory/rank:  {d}MB\n", .{job.resources.memory_mb});
}

const TrainJobContext = struct {
    name: []const u8,
    job: *const manifest_spec.TrainingJob,
    ctrl: training.TrainingController,
    manifest: manifest_spec.Manifest,
    server_addr: ?[]const u8 = null,

    fn deinit(self: *TrainJobContext) void {
        self.ctrl.deinit();
        self.manifest.deinit();
    }
};

const TrainArgs = struct {
    manifest_path: []const u8,
    job_name: ?[]const u8,
    server_addr: ?[]const u8,
};

fn parseTrainArgs(args: *std.process.ArgIterator) TrainArgs {
    var result = TrainArgs{
        .manifest_path = manifest_loader.default_filename,
        .job_name = null,
        .server_addr = null,
    };

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            result.manifest_path = args.next() orelse result.manifest_path;
        } else if (std.mem.eql(u8, arg, "--server")) {
            result.server_addr = args.next();
        } else {
            result.job_name = arg;
        }
    }

    return result;
}

fn loadTrainJobContext(args: *std.process.ArgIterator, alloc: std.mem.Allocator, comptime usage: []const u8) !TrainJobContext {
    const parsed = parseTrainArgs(args);

    const name = parsed.job_name orelse {
        writeErr("usage: {s}\n", .{usage});
        return TrainError.InvalidArgument;
    };

    var manifest = manifest_loader.load(alloc, parsed.manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ parsed.manifest_path, err });
        return TrainError.ManifestLoadFailed;
    };
    errdefer manifest.deinit();

    const job = manifest.trainingJobByName(name) orelse {
        writeErr("unknown training job: {s}\n", .{name});
        manifest.deinit();
        return TrainError.UnknownService;
    };

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.process.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    const ctrl = training.TrainingController.init(alloc, job, app_name) catch |err| {
        writeErr("failed to initialize training controller: {}\n", .{err});
        manifest.deinit();
        return TrainError.DeploymentFailed;
    };

    return .{ .name = name, .job = job, .ctrl = ctrl, .manifest = manifest, .server_addr = parsed.server_addr };
}

fn trainStop(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var ctx = try loadTrainJobContext(args, alloc, "yoq train stop [-f manifest.toml] <name>");
    defer ctx.deinit();

    if (!ctx.ctrl.loadFromStore()) {
        writeErr("no active training job found for {s}\n", .{ctx.name});
        return TrainError.DeploymentFailed;
    }

    ctx.ctrl.stop();
    writeErr("training job {s} stopped\n", .{ctx.name});
}

fn trainPause(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var ctx = try loadTrainJobContext(args, alloc, "yoq train pause [-f manifest.toml] <name>");
    defer ctx.deinit();

    if (!ctx.ctrl.loadFromStore()) {
        writeErr("no active training job found for {s}\n", .{ctx.name});
        return TrainError.DeploymentFailed;
    }

    if (ctx.ctrl.state != .running) {
        writeErr("training job {s} is not running (state: {s})\n", .{ ctx.name, ctx.ctrl.state.label() });
        return TrainError.DeploymentFailed;
    }

    ctx.ctrl.pause();
    writeErr("training job {s} paused\n", .{ctx.name});
}

fn trainResume(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var ctx = try loadTrainJobContext(args, alloc, "yoq train resume [-f manifest.toml] [--server host:port] <name>");
    defer ctx.deinit();

    if (!ctx.ctrl.loadFromStore()) {
        writeErr("no training job found for {s} (start it first with 'yoq train start')\n", .{ctx.name});
        return TrainError.DeploymentFailed;
    }

    if (ctx.ctrl.state != .paused) {
        writeErr("training job {s} is not paused (state: {s})\n", .{ ctx.name, ctx.ctrl.state.label() });
        return TrainError.DeploymentFailed;
    }

    ctx.ctrl.resume_();

    if (ctx.ctrl.resume_path) |rp| {
        writeErr("resuming training job {s} from checkpoint {s}\n", .{ ctx.name, rp });
    } else {
        writeErr("resuming training job {s} from scratch (no checkpoint found)\n", .{ctx.name});
    }

    if (ctx.server_addr) |addr| {
        const server = cli.parseServerAddr(addr);
        ctx.ctrl.startCluster(server.ip, server.port) catch return TrainError.DeploymentFailed;
    } else {
        ctx.ctrl.startLocal() catch return TrainError.DeploymentFailed;
    }

    if (ctx.ctrl.state == .completed) {
        writeErr("training job {s} completed successfully\n", .{ctx.name});
    } else if (ctx.ctrl.state == .running) {
        writeErr("training job {s} scheduled on cluster\n", .{ctx.name});
    } else {
        writeErr("training job {s} finished with state: {s}\n", .{ ctx.name, ctx.ctrl.state.label() });
    }
}

fn trainScale(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var job_name: ?[]const u8 = null;
    var new_gpus: ?u32 = null;
    var server_addr: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--gpus")) {
            const gpu_str = args.next() orelse {
                writeErr("--gpus requires a number\n", .{});
                return TrainError.InvalidArgument;
            };
            new_gpus = std.fmt.parseInt(u32, gpu_str, 10) catch {
                writeErr("invalid GPU count: {s}\n", .{gpu_str});
                return TrainError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return TrainError.InvalidArgument;
            };
        } else {
            job_name = arg;
        }
    }

    const name = job_name orelse {
        writeErr("usage: yoq train scale <name> --gpus <count> [--server host:port]\n", .{});
        return TrainError.InvalidArgument;
    };

    const gpus = new_gpus orelse {
        writeErr("--gpus is required for scale\n", .{});
        writeErr("usage: yoq train scale {s} --gpus <count>\n", .{name});
        return TrainError.InvalidArgument;
    };

    if (gpus == 0) {
        writeErr("GPU count must be > 0\n", .{});
        return TrainError.InvalidArgument;
    }

    var manifest = manifest_loader.load(alloc, manifest_loader.default_filename) catch |err| {
        writeErr("failed to load manifest ({})\n", .{err});
        return TrainError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    const job = manifest.trainingJobByName(name) orelse {
        writeErr("unknown training job: {s}\n", .{name});
        return TrainError.UnknownService;
    };

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.process.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    var ctrl = training.TrainingController.init(alloc, job, app_name) catch |err| {
        writeErr("failed to initialize training controller: {}\n", .{err});
        return TrainError.DeploymentFailed;
    };
    defer ctrl.deinit();

    if (!ctrl.loadFromStore()) {
        writeErr("no active training job found for {s} (start it first)\n", .{name});
        return TrainError.DeploymentFailed;
    }

    if (ctrl.state != .running and ctrl.state != .paused) {
        writeErr("training job {s} is {s}, cannot scale (must be running or paused)\n", .{ name, ctrl.state.label() });
        return TrainError.DeploymentFailed;
    }

    if (ctrl.state == .running) {
        writeErr("pausing {s} for rescaling...\n", .{name});
        ctrl.pause();
    }

    if (ctrl.job_id) |jid| {
        store.updateTrainingJobGpus(jid, gpus, std.time.timestamp()) catch {
            writeErr("failed to update GPU count in store\n", .{});
            return TrainError.StoreError;
        };
    }

    writeErr("scaled {s} from {d} to {d} GPUs\n", .{ name, job.gpus, gpus });

    ctrl.resume_();
    writeErr("resuming {s} with {d} GPUs...\n", .{ name, gpus });

    if (server_addr) |addr| {
        const server = cli.parseServerAddr(addr);
        ctrl.startCluster(server.ip, server.port) catch return TrainError.DeploymentFailed;
    } else {
        ctrl.startLocal() catch return TrainError.DeploymentFailed;
    }

    if (ctrl.state == .completed) {
        writeErr("training job {s} completed successfully\n", .{name});
    } else if (ctrl.state == .running) {
        writeErr("training job {s} rescheduled on cluster\n", .{name});
    } else {
        writeErr("training job {s} finished with state: {s}\n", .{ name, ctrl.state.label() });
    }
}

fn trainLogs(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var job_name: ?[]const u8 = null;
    var rank: u32 = 0;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--rank")) {
            const rank_str = args.next() orelse {
                writeErr("--rank requires a number\n", .{});
                return TrainError.InvalidArgument;
            };
            rank = std.fmt.parseInt(u32, rank_str, 10) catch {
                writeErr("invalid rank number: {s}\n", .{rank_str});
                return TrainError.InvalidArgument;
            };
        } else {
            job_name = arg;
        }
    }

    const name = job_name orelse {
        writeErr("usage: yoq train logs [--rank N] <name>\n", .{});
        return TrainError.InvalidArgument;
    };

    var hostname_buf: [128]u8 = undefined;
    const hostname = std.fmt.bufPrint(&hostname_buf, "{s}-rank-{d}", .{ name, rank }) catch {
        writeErr("failed to build hostname\n", .{});
        return TrainError.InvalidArgument;
    };

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.process.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    const record = store.findAppContainer(alloc, app_name, hostname) catch |err| {
        writeErr("failed to query container: {}\n", .{err});
        return TrainError.StoreError;
    };
    const rec = record orelse {
        writeErr("no container found for {s} rank {d}\n", .{ name, rank });
        return TrainError.UnknownService;
    };
    defer rec.deinit(alloc);

    const data = logs.readLogs(alloc, rec.id) catch |err| {
        writeErr("no logs found for rank {d}: {}\n", .{ rank, err });
        return TrainError.StoreError;
    };
    defer alloc.free(data);

    if (data.len == 0) {
        write("(no output)\n", .{});
        return;
    }
    write("{s}", .{data});
}
