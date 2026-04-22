const std = @import("std");
const platform = @import("platform");
const cli = @import("../../lib/cli.zig");
const manifest_loader = @import("../loader.zig");
const manifest_spec = @import("../spec.zig");
const store = @import("../../state/store.zig");
const training = @import("../training.zig");
const http_client = @import("../../cluster/http_client.zig");
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

pub fn train(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
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

fn trainStart(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
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

    if (server_addr) |addr| {
        const body = try remoteTrainingPost(alloc, addr, name, "start", "{}");
        defer alloc.free(body);
        write("{s}\n", .{body});
        return;
    }

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
    const cwd = platform.getCwd(&cwd_buf) catch "app";
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

fn trainStatus(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
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
        writeErr("usage: yoq train status [-f manifest.toml] [--server host:port] <name>\n", .{});
        return TrainError.InvalidArgument;
    };

    if (server_addr) |addr| {
        try remoteTrainingGetStatus(alloc, addr, name);
        return;
    }

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
    const cwd = platform.getCwd(&cwd_buf) catch "app";
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

fn parseTrainArgs(args: *std.process.Args.Iterator) TrainArgs {
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

fn currentAppNameAlloc(alloc: std.mem.Allocator) ![]u8 {
    var cwd_buf: [4096]u8 = undefined;
    const cwd = platform.cwd().realpath(".", &cwd_buf) catch return TrainError.StoreError;
    return alloc.dupe(u8, std.fs.path.basename(cwd)) catch return TrainError.DeploymentFailed;
}

fn remoteTrainingPath(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    job_name: []const u8,
    action: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(alloc, "/apps/{s}/training/{s}/{s}", .{ app_name, job_name, action });
}

fn remoteTrainingPost(
    alloc: std.mem.Allocator,
    server_addr: []const u8,
    job_name: []const u8,
    action: []const u8,
    body: []const u8,
) ![]u8 {
    const app_name = try currentAppNameAlloc(alloc);
    defer alloc.free(app_name);
    const path = try remoteTrainingPath(alloc, app_name, job_name, action);
    defer alloc.free(path);

    const server = cli.parseServerAddr(server_addr);
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);
    var resp = http_client.postWithAuth(alloc, server.ip, server.port, path, body, token) catch return TrainError.DeploymentFailed;
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("training {s} failed (status {d}): {s}\n", .{ action, resp.status_code, resp.body });
        return TrainError.DeploymentFailed;
    }
    return alloc.dupe(u8, resp.body) catch return TrainError.DeploymentFailed;
}

fn remoteTrainingGetStatus(alloc: std.mem.Allocator, server_addr: []const u8, job_name: []const u8) !void {
    const app_name = try currentAppNameAlloc(alloc);
    defer alloc.free(app_name);
    const path = try remoteTrainingPath(alloc, app_name, job_name, "status");
    defer alloc.free(path);

    const server = cli.parseServerAddr(server_addr);
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);
    var resp = http_client.getWithAuth(alloc, server.ip, server.port, path, token) catch return TrainError.DeploymentFailed;
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("training status failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return TrainError.DeploymentFailed;
    }
    write("{s}\n", .{resp.body});
}

fn loadTrainJobContext(args: *std.process.Args.Iterator, alloc: std.mem.Allocator, comptime usage: []const u8) !TrainJobContext {
    const parsed = parseTrainArgs(args);
    return loadTrainJobContextFromParsed(parsed, alloc, usage);
}

fn loadTrainJobContextFromParsed(parsed: TrainArgs, alloc: std.mem.Allocator, comptime usage: []const u8) !TrainJobContext {
    const manifest_path = parsed.manifest_path;

    const name = parsed.job_name orelse {
        writeErr("usage: {s}\n", .{usage});
        return TrainError.InvalidArgument;
    };

    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
        return TrainError.ManifestLoadFailed;
    };
    errdefer manifest.deinit();

    const job = manifest.trainingJobByName(name) orelse {
        writeErr("unknown training job: {s}\n", .{name});
        manifest.deinit();
        return TrainError.UnknownService;
    };

    var cwd_buf: [4096]u8 = undefined;
    const cwd = platform.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    const ctrl = training.TrainingController.init(alloc, job, app_name) catch |err| {
        writeErr("failed to initialize training controller: {}\n", .{err});
        manifest.deinit();
        return TrainError.DeploymentFailed;
    };

    return .{ .name = name, .job = job, .ctrl = ctrl, .manifest = manifest, .server_addr = parsed.server_addr };
}

fn trainStop(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    const parsed = parseTrainArgs(args);
    const name = parsed.job_name orelse {
        writeErr("usage: yoq train stop [-f manifest.toml] [--server host:port] <name>\n", .{});
        return TrainError.InvalidArgument;
    };

    if (parsed.server_addr) |addr| {
        const body = try remoteTrainingPost(alloc, addr, name, "stop", "{}");
        defer alloc.free(body);
        write("{s}\n", .{body});
        return;
    }

    var ctx = try loadTrainJobContextFromParsed(parsed, alloc, "yoq train stop [-f manifest.toml] <name>");
    defer ctx.deinit();

    if (!ctx.ctrl.loadFromStore()) {
        writeErr("no active training job found for {s}\n", .{ctx.name});
        return TrainError.DeploymentFailed;
    }

    if (ctx.ctrl.isClusterManaged()) {
        writeErr("training job {s} is cluster-managed; stop is not supported until remote lifecycle control is implemented\n", .{ctx.name});
        return TrainError.DeploymentFailed;
    }

    ctx.ctrl.stop();
    writeErr("training job {s} stopped\n", .{ctx.name});
}

fn trainPause(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    const parsed = parseTrainArgs(args);
    const name = parsed.job_name orelse {
        writeErr("usage: yoq train pause [-f manifest.toml] [--server host:port] <name>\n", .{});
        return TrainError.InvalidArgument;
    };

    if (parsed.server_addr) |addr| {
        const body = try remoteTrainingPost(alloc, addr, name, "pause", "{}");
        defer alloc.free(body);
        write("{s}\n", .{body});
        return;
    }

    var ctx = try loadTrainJobContextFromParsed(parsed, alloc, "yoq train pause [-f manifest.toml] <name>");
    defer ctx.deinit();

    if (!ctx.ctrl.loadFromStore()) {
        writeErr("no active training job found for {s}\n", .{ctx.name});
        return TrainError.DeploymentFailed;
    }

    if (ctx.ctrl.isClusterManaged()) {
        writeErr("training job {s} is cluster-managed; pause is not supported until remote lifecycle control is implemented\n", .{ctx.name});
        return TrainError.DeploymentFailed;
    }

    if (ctx.ctrl.state != .running) {
        writeErr("training job {s} is not running (state: {s})\n", .{ ctx.name, ctx.ctrl.state.label() });
        return TrainError.DeploymentFailed;
    }

    ctx.ctrl.pause();
    writeErr("training job {s} paused\n", .{ctx.name});
}

fn trainResume(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    const parsed = parseTrainArgs(args);
    const name = parsed.job_name orelse {
        writeErr("usage: yoq train resume [-f manifest.toml] [--server host:port] <name>\n", .{});
        return TrainError.InvalidArgument;
    };

    if (parsed.server_addr) |addr| {
        const body = try remoteTrainingPost(alloc, addr, name, "resume", "{}");
        defer alloc.free(body);
        write("{s}\n", .{body});
        return;
    }

    var ctx = try loadTrainJobContextFromParsed(parsed, alloc, "yoq train resume [-f manifest.toml] [--server host:port] <name>");
    defer ctx.deinit();

    if (!ctx.ctrl.loadFromStore()) {
        writeErr("no training job found for {s} (start it first with 'yoq train start')\n", .{ctx.name});
        return TrainError.DeploymentFailed;
    }

    if (ctx.ctrl.isClusterManaged()) {
        writeErr("training job {s} is cluster-managed; resume is not supported until remote lifecycle control is implemented\n", .{ctx.name});
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

fn trainScale(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
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

    if (server_addr) |addr| {
        const body_json = std.fmt.allocPrint(alloc, "{{\"gpus\":{d}}}", .{gpus}) catch return TrainError.DeploymentFailed;
        defer alloc.free(body_json);
        const body = try remoteTrainingPost(alloc, addr, name, "scale", body_json);
        defer alloc.free(body);
        write("{s}\n", .{body});
        return;
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
    const cwd = platform.getCwd(&cwd_buf) catch "app";
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

    if (ctrl.isClusterManaged()) {
        writeErr("training job {s} is cluster-managed; scaling is not supported until remote lifecycle control is implemented\n", .{name});
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
        store.updateTrainingJobGpus(jid, gpus, platform.timestamp()) catch {
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

fn trainLogs(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var job_name: ?[]const u8 = null;
    var rank: u32 = 0;
    var server_addr: ?[]const u8 = null;

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
        writeErr("usage: yoq train logs [--server host:port] [--rank N] <name>\n", .{});
        return TrainError.InvalidArgument;
    };

    if (server_addr) |addr| {
        const app_name = try currentAppNameAlloc(alloc);
        defer alloc.free(app_name);
        const path = std.fmt.allocPrint(alloc, "/apps/{s}/training/{s}/logs?rank={d}", .{ app_name, name, rank }) catch return TrainError.DeploymentFailed;
        defer alloc.free(path);

        const server = cli.parseServerAddr(addr);
        var token_buf: [64]u8 = undefined;
        const token = cli.readApiToken(&token_buf);
        var resp = http_client.getWithAuth(alloc, server.ip, server.port, path, token) catch return TrainError.DeploymentFailed;
        defer resp.deinit(alloc);

        if (resp.status_code != 200) {
            writeErr("training logs failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
            return TrainError.DeploymentFailed;
        }
        write("{s}", .{resp.body});
        return;
    }

    var hostname_buf: [128]u8 = undefined;
    const hostname = std.fmt.bufPrint(&hostname_buf, "{s}-rank-{d}", .{ name, rank }) catch {
        writeErr("failed to build hostname\n", .{});
        return TrainError.InvalidArgument;
    };

    var cwd_buf: [4096]u8 = undefined;
    const cwd = platform.getCwd(&cwd_buf) catch "app";
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
