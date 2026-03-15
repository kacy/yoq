// manifest commands — CLI handlers for manifest/deployment operations
//
// up, down, rollback, history. extracted from main.zig for
// readability — no logic changes.

const std = @import("std");
const cli = @import("../lib/cli.zig");
const json_out = @import("../lib/json_output.zig");
const init_mod = @import("init.zig");
const manifest_loader = @import("loader.zig");
const validator = @import("validate.zig");
const orchestrator = @import("orchestrator.zig");
const watcher_mod = @import("../dev/watcher.zig");
const manifest_spec = @import("spec.zig");
const update = @import("update.zig");
const store = @import("../state/store.zig");
const process = @import("../runtime/process.zig");
const http_client = @import("../cluster/http_client.zig");
const json_helpers = @import("../lib/json_helpers.zig");
const container_cmds = @import("../runtime/container_commands.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const truncate = cli.truncate;

const ManifestCommandsError = error{
    InvalidArgument,
    ManifestLoadFailed,
    ValidationFailed,
    DeploymentFailed,
    ConnectionFailed,
    StoreError,
    OutOfMemory,
    UnknownService,
};

pub fn init(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var opts: init_mod.Options = .{};

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            opts.output_path = args.next() orelse {
                writeErr("-f requires an output path\n", .{});
                return ManifestCommandsError.InvalidArgument;
            };
        } else {
            writeErr("unknown option: {s}\n", .{arg});
            return ManifestCommandsError.InvalidArgument;
        }
    }

    init_mod.run(alloc, opts) catch |err| switch (err) {
        init_mod.InitError.FileExists => return ManifestCommandsError.InvalidArgument,
        init_mod.InitError.WriteFailed => {
            writeErr("failed to write manifest file\n", .{});
            return ManifestCommandsError.ManifestLoadFailed;
        },
        init_mod.InitError.CwdFailed => {
            writeErr("failed to resolve working directory\n", .{});
            return ManifestCommandsError.ManifestLoadFailed;
        },
    };
}

pub fn validate(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var manifest_path: []const u8 = manifest_loader.default_filename;
    var quiet = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                return ManifestCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "-q") or std.mem.eql(u8, arg, "--quiet")) {
            quiet = true;
        } else {
            writeErr("unknown option: {s}\n", .{arg});
            return ManifestCommandsError.InvalidArgument;
        }
    }

    // load and parse the manifest (catches syntax errors, missing fields, cycles, etc.)
    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        if (!quiet) {
            writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
            writeErr("hint: create one with 'yoq init'\n", .{});
        }
        return ManifestCommandsError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    // run semantic checks on the parsed manifest
    var result = validator.check(alloc, &manifest) catch |err| {
        if (!quiet) writeErr("validation failed: {}\n", .{err});
        return ManifestCommandsError.ValidationFailed;
    };
    defer result.deinit();

    // print diagnostics
    if (!quiet) {
        for (result.diagnostics) |d| {
            switch (d.severity) {
                .@"error" => writeErr("error: {s}\n", .{d.message}),
                .warning => writeErr("warning: {s}\n", .{d.message}),
            }
        }
    }

    if (result.hasErrors()) {
        if (!quiet) writeErr("validation failed\n", .{});
        return ManifestCommandsError.ValidationFailed;
    }

    if (!quiet) {
        // build summary: "path is valid (N services, M workers, K crons)"
        write("{s} is valid", .{manifest_path});

        var has_count = false;
        if (manifest.services.len > 0) {
            write(" ({d} service{s}", .{ manifest.services.len, if (manifest.services.len != 1) "s" else "" });
            has_count = true;
        }
        if (manifest.workers.len > 0) {
            if (has_count) write(",", .{}) else write(" (", .{});
            write(" {d} worker{s}", .{ manifest.workers.len, if (manifest.workers.len != 1) "s" else "" });
            has_count = true;
        }
        if (manifest.crons.len > 0) {
            if (has_count) write(",", .{}) else write(" (", .{});
            write(" {d} cron{s}", .{ manifest.crons.len, if (manifest.crons.len != 1) "s" else "" });
            has_count = true;
        }
        if (manifest.training_jobs.len > 0) {
            if (has_count) write(",", .{}) else write(" (", .{});
            write(" {d} training job{s}", .{ manifest.training_jobs.len, if (manifest.training_jobs.len != 1) "s" else "" });
            has_count = true;
        }
        if (has_count) write(")", .{});
        write("\n", .{});
    }
}

pub fn up(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var manifest_path: []const u8 = manifest_loader.default_filename;
    var dev_mode = false;
    var server_addr: ?[]const u8 = null;
    var service_names: std.ArrayList([]const u8) = .empty;
    defer service_names.deinit(alloc);

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                return ManifestCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--dev")) {
            dev_mode = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return ManifestCommandsError.InvalidArgument;
            };
        } else {
            // positional arg = service name to start
            service_names.append(alloc, arg) catch return ManifestCommandsError.OutOfMemory;
        }
    }

    // load and validate manifest
    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
        writeErr("hint: create one with 'yoq init'\n", .{});
        return ManifestCommandsError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    // validate service filter names
    for (service_names.items) |name| {
        if (manifest.serviceByName(name) == null) {
            writeErr("unknown service: {s}\n", .{name});
            return ManifestCommandsError.UnknownService;
        }
    }

    // if --server is set, deploy to cluster instead of running locally
    if (server_addr) |addr| {
        deployToCluster(alloc, addr, &manifest) catch |e| return e;
        return;
    }

    // derive app name from cwd basename
    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.fs.cwd().realpath(".", &cwd_buf) catch |err| {
        writeErr("failed to resolve working directory: {}\n", .{err});
        return ManifestCommandsError.StoreError;
    };
    const app_name = std.fs.path.basename(cwd);

    // startup message
    if (service_names.items.len > 0) {
        writeErr("starting", .{});
        for (service_names.items, 0..) |name, i| {
            if (i > 0) writeErr(",", .{});
            writeErr(" {s}", .{name});
        }
        writeErr(" ({d} services)...\n", .{service_names.items.len});
    } else if (dev_mode) {
        writeErr("starting {s} in dev mode ({d} services)...\n", .{ app_name, manifest.services.len });
    } else {
        writeErr("starting {s} ({d} services)...\n", .{ app_name, manifest.services.len });
    }

    // install signal handlers for graceful shutdown
    orchestrator.installSignalHandlers();

    // create and run orchestrator
    var orch = orchestrator.Orchestrator.init(alloc, &manifest, app_name) catch |err| {
        writeErr("failed to initialize orchestrator: {}\n", .{err});
        return ManifestCommandsError.DeploymentFailed;
    };
    defer orch.deinit();
    orch.dev_mode = dev_mode;

    // set service filter if specific services were requested
    if (service_names.items.len > 0) {
        orch.service_filter = service_names.items;
    }

    orch.startAll() catch |err| {
        writeErr("failed to start services: {}\n", .{err});
        return ManifestCommandsError.DeploymentFailed;
    };

    // in dev mode, set up file watcher for bind-mounted volumes
    var watcher: ?watcher_mod.Watcher = null;
    var watcher_thread: ?std.Thread = null;

    if (dev_mode) {
        watcher = watcher_mod.Watcher.init(alloc) catch |e| blk: {
            writeErr("warning: file watcher unavailable: {}\n", .{e});
            break :blk null;
        };

        if (watcher != null) {
            // add watches for each service's bind-mounted volumes
            // track if any watches failed
            var any_watch_failed = false;
            for (manifest.services, 0..) |svc, i| {
                for (svc.volumes) |vol| {
                    if (vol.kind != .bind) continue;

                    // resolve relative source path to absolute
                    var resolve_buf: [4096]u8 = undefined;
                    const abs_source = std.fs.cwd().realpath(vol.source, &resolve_buf) catch |e| {
                        writeErr("warning: failed to resolve path {s}: {}\n", .{ vol.source, e });
                        any_watch_failed = true;
                        continue;
                    };

                    watcher.?.addRecursive(abs_source, i) catch |e| {
                        writeErr("warning: failed to watch {s}: {}\n", .{ vol.source, e });
                        any_watch_failed = true;
                    };
                }
            }

            // only spawn watcher thread if we successfully added at least one watch
            if (!any_watch_failed or watcher.?.watch_count > 0) {
                // spawn watcher thread
                watcher_thread = std.Thread.spawn(.{}, orchestrator.watcherThread, .{
                    &orch, &watcher.?,
                }) catch |e| blk: {
                    writeErr("warning: failed to start watcher thread: {}\n", .{e});
                    break :blk null;
                };
            } else {
                writeErr("warning: no directories could be watched, file change detection disabled\n", .{});
            }
        }

        writeErr("all services running. watching for changes...\n", .{});
    } else {
        writeErr("all services running. press ctrl-c to stop.\n", .{});
    }

    // block until shutdown signal or all services exit
    orch.waitForShutdown();

    writeErr("\nshutting down...\n", .{});

    // clean up watcher before stopping services (closes fd, unblocks watcher thread)
    if (watcher) |*w| w.deinit();
    if (watcher_thread) |t| t.join();

    orch.stopAll();
    writeErr("stopped\n", .{});
}

/// deploy manifest services to a cluster server via POST /deploy.
fn deployToCluster(alloc: std.mem.Allocator, addr_str: []const u8, manifest: *const manifest_spec.Manifest) ManifestCommandsError!void {
    const server = cli.parseServerAddr(addr_str);
    const server_ip = server.ip;
    const server_port = server.port;

    // build JSON body: {"services":[{"image":"...","command":"...","cpu_limit":N,"memory_limit_mb":N},...]}
    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeAll("{\"services\":[") catch return ManifestCommandsError.OutOfMemory;

    for (manifest.services, 0..) |svc, i| {
        if (i > 0) writer.writeByte(',') catch break;

        // join command args into a single string
        var cmd_buf: [1024]u8 = undefined;
        var cmd_len: usize = 0;
        for (svc.command, 0..) |arg, j| {
            if (j > 0) {
                if (cmd_len < cmd_buf.len) {
                    cmd_buf[cmd_len] = ' ';
                    cmd_len += 1;
                }
            }
            const copy_len = @min(arg.len, cmd_buf.len - cmd_len);
            @memcpy(cmd_buf[cmd_len..][0..copy_len], arg[0..copy_len]);
            cmd_len += copy_len;
        }

        // use JSON escaping for image and command values — they could contain
        // quotes or special characters that would produce malformed JSON
        writer.writeAll("{\"image\":\"") catch break;
        json_helpers.writeJsonEscaped(writer, svc.image) catch break;
        writer.writeAll("\",\"command\":\"") catch break;
        json_helpers.writeJsonEscaped(writer, cmd_buf[0..cmd_len]) catch break;
        writer.writeAll("\",\"cpu_limit\":1000,\"memory_limit_mb\":256}") catch break;
    }

    writer.writeAll("]}") catch return ManifestCommandsError.OutOfMemory;

    writeErr("deploying {d} services to cluster {s}...\n", .{ manifest.services.len, addr_str });

    // POST to /deploy with auth token if available
    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.postWithAuth(alloc, server_ip, server_port, "/deploy", json_buf.items, token) catch |err| {
        writeErr("failed to connect to cluster server: {}\n", .{err});
        writeErr("hint: is the server running? try 'yoq serve' or 'yoq init-server'\n", .{});
        return ManifestCommandsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code == 200) {
        write("{s}\n", .{resp.body});
    } else {
        writeErr("deploy failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return ManifestCommandsError.DeploymentFailed;
    }
}

pub fn down(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var manifest_path: []const u8 = manifest_loader.default_filename;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                return ManifestCommandsError.InvalidArgument;
            };
        }
    }

    // load manifest to get service names and ordering
    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
        writeErr("hint: create one with 'yoq init'\n", .{});
        return ManifestCommandsError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    // derive app name from cwd basename
    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.fs.cwd().realpath(".", &cwd_buf) catch |err| {
        writeErr("failed to resolve working directory: {}\n", .{err});
        return ManifestCommandsError.StoreError;
    };
    const app_name = std.fs.path.basename(cwd);

    // find all containers belonging to this app
    var ids = store.listAppContainerIds(alloc, app_name) catch |err| {
        writeErr("failed to query app containers: {}\n", .{err});
        return ManifestCommandsError.StoreError;
    };
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    if (ids.items.len == 0) {
        writeErr("no running services found for {s}\n", .{app_name});
        return;
    }

    // stop containers in reverse dependency order.
    // iterate services in reverse (manifest is topo-sorted, so reverse = dependents first)
    var i: usize = manifest.services.len;
    while (i > 0) {
        i -= 1;
        const svc = manifest.services[i];

        // find this service's container by app_name + hostname
        const record = store.findAppContainer(alloc, app_name, svc.name) catch continue;
        const rec = record orelse continue;
        defer rec.deinit(alloc);

        writeErr("stopping {s}...", .{svc.name});

        if (std.mem.eql(u8, rec.status, "running")) {
            if (rec.pid) |pid| {
                process.terminate(pid) catch {
                    process.kill(pid) catch {};
                };

                // wait briefly for process to exit
                var waited: u32 = 0;
                while (waited < 100) : (waited += 1) {
                    const result = process.wait(pid, true) catch break;
                    switch (result.status) {
                        .running => std.Thread.sleep(100 * std.time.ns_per_ms),
                        else => break,
                    }
                }
            }
        }

        // update status and clean up
        store.updateStatus(rec.id, "stopped", null, null) catch |e| {
            writeErr("warning: failed to update status for {s}: {}\n", .{ svc.name, e });
        };
        container_cmds.cleanupStoppedContainer(rec.id, rec.ip_address, rec.veth_host);

        writeErr(" stopped\n", .{});
    }

    writeErr("all services stopped\n", .{});
}

pub fn rollback(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const service_name = args.next() orelse {
        writeErr("usage: yoq rollback <service>\n", .{});
        return ManifestCommandsError.InvalidArgument;
    };

    // look up the previous successful deployment
    const config = update.rollback(alloc, service_name) catch |err| {
        switch (err) {
            update.UpdateError.NoPreviousDeployment => {
                writeErr("no previous deployment found for {s}\n", .{service_name});
            },
            update.UpdateError.StoreFailed => {
                writeErr("failed to read deployment history\n", .{});
            },
            else => {
                writeErr("rollback failed\n", .{});
            },
        }
        return ManifestCommandsError.StoreError;
    };
    defer alloc.free(config);

    write("rollback config for {s}:\n{s}\n", .{ service_name, config });
    write("\nto apply this rollback, redeploy with this config using 'yoq up'\n", .{});
}

pub fn history(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var service_name: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else {
            service_name = arg;
        }
    }

    const svc = service_name orelse {
        writeErr("usage: yoq history <service> [--json]\n", .{});
        return ManifestCommandsError.InvalidArgument;
    };

    var deployments = store.listDeployments(alloc, svc) catch |err| {
        writeErr("failed to read deployment history: {}\n", .{err});
        return ManifestCommandsError.StoreError;
    };
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginArray();
        for (deployments.items) |dep| {
            w.beginObject();
            w.stringField("id", dep.id);
            w.stringField("service", dep.service_name);
            w.stringField("status", dep.status);
            w.stringField("manifest_hash", dep.manifest_hash);
            w.intField("created_at", dep.created_at);
            if (dep.message) |msg| {
                w.stringField("message", msg);
            } else {
                w.nullField("message");
            }
            w.endObject();
        }
        w.endArray();
        w.flush();
        return;
    }

    if (deployments.items.len == 0) {
        write("no deployments found for {s}\n", .{svc});
        return;
    }

    write("{s:<14} {s:<14} {s:<14} {s:<20} {s}\n", .{ "ID", "STATUS", "HASH", "TIMESTAMP", "MESSAGE" });

    for (deployments.items) |dep| {
        var ts_buf: [20]u8 = undefined;
        const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{dep.created_at}) catch "?";
        const msg = dep.message orelse "";

        write("{s:<14} {s:<14} {s:<14} {s:<20} {s}\n", .{
            truncate(dep.id, 12),
            dep.status,
            truncate(dep.manifest_hash, 12),
            ts_str,
            truncate(msg, 40),
        });
    }
}

/// run a worker defined in the manifest by name.
/// loads the manifest, finds the worker, pulls the image, runs it to completion.
pub fn runWorker(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var manifest_path: []const u8 = manifest_loader.default_filename;
    var worker_name: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                return ManifestCommandsError.InvalidArgument;
            };
        } else {
            worker_name = arg;
        }
    }

    const name = worker_name orelse {
        writeErr("usage: yoq run-worker [-f manifest.toml] <name>\n", .{});
        return ManifestCommandsError.InvalidArgument;
    };

    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
        writeErr("hint: create one with 'yoq init'\n", .{});
        return ManifestCommandsError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    const worker = manifest.workerByName(name) orelse {
        writeErr("unknown worker: {s}\n", .{name});
        return ManifestCommandsError.UnknownService;
    };

    // pull image first
    writeErr("pulling {s}...\n", .{worker.image});
    if (!orchestrator.ensureImageAvailable(alloc, worker.image)) {
        writeErr("failed to pull image: {s}\n", .{worker.image});
        return ManifestCommandsError.DeploymentFailed;
    }

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.process.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    writeErr("running worker {s}...\n", .{name});
    if (orchestrator.runOneShot(alloc, worker.image, worker.command, worker.env, worker.volumes, worker.working_dir, name, manifest.volumes, app_name)) {
        writeErr("worker {s} completed successfully\n", .{name});
    } else {
        writeErr("worker {s} failed\n", .{name});
        return ManifestCommandsError.DeploymentFailed;
    }
}

pub fn train(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const action = args.next() orelse {
        writeErr("usage: yoq train <start|status|stop|pause|resume|scale|logs> <name>\n", .{});
        return ManifestCommandsError.InvalidArgument;
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
    return ManifestCommandsError.InvalidArgument;
}

fn trainStart(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var manifest_path: []const u8 = manifest_loader.default_filename;
    var job_name: ?[]const u8 = null;
    var server_addr: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                return ManifestCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return ManifestCommandsError.InvalidArgument;
            };
        } else {
            job_name = arg;
        }
    }

    const name = job_name orelse {
        writeErr("usage: yoq train start [-f manifest.toml] [--server host:port] <name>\n", .{});
        return ManifestCommandsError.InvalidArgument;
    };

    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
        return ManifestCommandsError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    const job = manifest.trainingJobByName(name) orelse {
        writeErr("unknown training job: {s}\n", .{name});
        return ManifestCommandsError.UnknownService;
    };

    const training = @import("training.zig");

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.process.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    var ctrl = training.TrainingController.init(alloc, job, app_name) catch |err| {
        writeErr("failed to initialize training controller: {}\n", .{err});
        return ManifestCommandsError.DeploymentFailed;
    };
    defer ctrl.deinit();

    writeErr("starting training job {s} ({d} gpus)...\n", .{ name, job.gpus });

    if (server_addr) |addr| {
        const server = cli.parseServerAddr(addr);
        ctrl.startCluster(server.ip, server.port) catch {
            return ManifestCommandsError.DeploymentFailed;
        };
    } else {
        ctrl.startLocal() catch {
            return ManifestCommandsError.DeploymentFailed;
        };
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
                return ManifestCommandsError.InvalidArgument;
            };
        } else {
            job_name = arg;
        }
    }

    const name = job_name orelse {
        writeErr("usage: yoq train status [-f manifest.toml] <name>\n", .{});
        return ManifestCommandsError.InvalidArgument;
    };

    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
        return ManifestCommandsError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    const job = manifest.trainingJobByName(name) orelse {
        writeErr("unknown training job: {s}\n", .{name});
        return ManifestCommandsError.UnknownService;
    };

    const training = @import("training.zig");
    const store_mod = @import("../state/store.zig");

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.process.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    // try to load persistent state
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
    if (job.gpu_type) |gt| {
        write("gpu_type:     {s}\n", .{gt});
    }
    if (job.checkpoint) |ckpt| {
        write("checkpoint:   {s} (every {d}s, keep {d})\n", .{ ckpt.path, ckpt.interval_secs, ckpt.keep });

        // show checkpoints from database (single query, newest-first)
        if (ctrl.job_id) |jid| {
            if (store_mod.listCheckpoints(alloc, jid)) |ckpts_result| {
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
    if (job.fault_tolerance.spare_ranks > 0) {
        write("spare_ranks:  {d}\n", .{job.fault_tolerance.spare_ranks});
    }
    write("cpu/rank:     {d}m\n", .{job.resources.cpu});
    write("memory/rank:  {d}MB\n", .{job.resources.memory_mb});
}

const TrainJobContext = struct {
    name: []const u8,
    job: *const manifest_spec.TrainingJob,
    ctrl: @import("training.zig").TrainingController,
    manifest: manifest_spec.Manifest,
    server_addr: ?[]const u8 = null,

    fn deinit(self: *TrainJobContext) void {
        self.ctrl.deinit();
        self.manifest.deinit();
    }
};

/// parsed training subcommand args
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

/// shared setup for train subcommands: parse -f and job name,
/// load manifest, find job, init controller.
fn loadTrainJobContext(args: *std.process.ArgIterator, alloc: std.mem.Allocator, comptime usage: []const u8) !TrainJobContext {
    const parsed = parseTrainArgs(args);

    const name = parsed.job_name orelse {
        writeErr("usage: {s}\n", .{usage});
        return ManifestCommandsError.InvalidArgument;
    };

    var manifest = manifest_loader.load(alloc, parsed.manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ parsed.manifest_path, err });
        return ManifestCommandsError.ManifestLoadFailed;
    };
    errdefer manifest.deinit();

    const job = manifest.trainingJobByName(name) orelse {
        writeErr("unknown training job: {s}\n", .{name});
        manifest.deinit();
        return ManifestCommandsError.UnknownService;
    };

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.process.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    const training = @import("training.zig");
    const ctrl = training.TrainingController.init(alloc, job, app_name) catch |err| {
        writeErr("failed to initialize training controller: {}\n", .{err});
        manifest.deinit();
        return ManifestCommandsError.DeploymentFailed;
    };

    return .{ .name = name, .job = job, .ctrl = ctrl, .manifest = manifest, .server_addr = parsed.server_addr };
}

fn trainStop(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var ctx = try loadTrainJobContext(args, alloc, "yoq train stop [-f manifest.toml] <name>");
    defer ctx.deinit();

    if (!ctx.ctrl.loadFromStore()) {
        writeErr("no active training job found for {s}\n", .{ctx.name});
        return ManifestCommandsError.DeploymentFailed;
    }

    ctx.ctrl.stop();
    writeErr("training job {s} stopped\n", .{ctx.name});
}

fn trainPause(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var ctx = try loadTrainJobContext(args, alloc, "yoq train pause [-f manifest.toml] <name>");
    defer ctx.deinit();

    if (!ctx.ctrl.loadFromStore()) {
        writeErr("no active training job found for {s}\n", .{ctx.name});
        return ManifestCommandsError.DeploymentFailed;
    }

    if (ctx.ctrl.state != .running) {
        writeErr("training job {s} is not running (state: {s})\n", .{ ctx.name, ctx.ctrl.state.label() });
        return ManifestCommandsError.DeploymentFailed;
    }

    ctx.ctrl.pause();
    writeErr("training job {s} paused\n", .{ctx.name});
}

fn trainResume(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var ctx = try loadTrainJobContext(args, alloc, "yoq train resume [-f manifest.toml] [--server host:port] <name>");
    defer ctx.deinit();

    if (!ctx.ctrl.loadFromStore()) {
        writeErr("no training job found for {s} (start it first with 'yoq train start')\n", .{ctx.name});
        return ManifestCommandsError.DeploymentFailed;
    }

    if (ctx.ctrl.state != .paused) {
        writeErr("training job {s} is not paused (state: {s})\n", .{ ctx.name, ctx.ctrl.state.label() });
        return ManifestCommandsError.DeploymentFailed;
    }

    ctx.ctrl.resume_();

    if (ctx.ctrl.resume_path) |rp| {
        writeErr("resuming training job {s} from checkpoint {s}\n", .{ ctx.name, rp });
    } else {
        writeErr("resuming training job {s} from scratch (no checkpoint found)\n", .{ctx.name});
    }

    if (ctx.server_addr) |addr| {
        const server = cli.parseServerAddr(addr);
        ctx.ctrl.startCluster(server.ip, server.port) catch {
            return ManifestCommandsError.DeploymentFailed;
        };
    } else {
        ctx.ctrl.startLocal() catch {
            return ManifestCommandsError.DeploymentFailed;
        };
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
                return ManifestCommandsError.InvalidArgument;
            };
            new_gpus = std.fmt.parseInt(u32, gpu_str, 10) catch {
                writeErr("invalid GPU count: {s}\n", .{gpu_str});
                return ManifestCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return ManifestCommandsError.InvalidArgument;
            };
        } else {
            job_name = arg;
        }
    }

    const name = job_name orelse {
        writeErr("usage: yoq train scale <name> --gpus <count> [--server host:port]\n", .{});
        return ManifestCommandsError.InvalidArgument;
    };

    const gpus = new_gpus orelse {
        writeErr("--gpus is required for scale\n", .{});
        writeErr("usage: yoq train scale {s} --gpus <count>\n", .{name});
        return ManifestCommandsError.InvalidArgument;
    };

    if (gpus == 0) {
        writeErr("GPU count must be > 0\n", .{});
        return ManifestCommandsError.InvalidArgument;
    }

    const training = @import("training.zig");
    const store_mod = @import("../state/store.zig");

    // load manifest to find job
    var manifest = manifest_loader.load(alloc, manifest_loader.default_filename) catch |err| {
        writeErr("failed to load manifest ({})\n", .{err});
        return ManifestCommandsError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    const job = manifest.trainingJobByName(name) orelse {
        writeErr("unknown training job: {s}\n", .{name});
        return ManifestCommandsError.UnknownService;
    };

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.process.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    var ctrl = training.TrainingController.init(alloc, job, app_name) catch |err| {
        writeErr("failed to initialize training controller: {}\n", .{err});
        return ManifestCommandsError.DeploymentFailed;
    };
    defer ctrl.deinit();

    if (!ctrl.loadFromStore()) {
        writeErr("no active training job found for {s} (start it first)\n", .{name});
        return ManifestCommandsError.DeploymentFailed;
    }

    if (ctrl.state != .running and ctrl.state != .paused) {
        writeErr("training job {s} is {s}, cannot scale (must be running or paused)\n", .{ name, ctrl.state.label() });
        return ManifestCommandsError.DeploymentFailed;
    }

    // pause the job (checkpoint + stop ranks)
    if (ctrl.state == .running) {
        writeErr("pausing {s} for rescaling...\n", .{name});
        ctrl.pause();
    }

    // update GPU count in the store
    if (ctrl.job_id) |jid| {
        store_mod.updateTrainingJobGpus(jid, gpus, std.time.timestamp()) catch {
            writeErr("failed to update GPU count in store\n", .{});
            return ManifestCommandsError.StoreError;
        };
    }

    writeErr("scaled {s} from {d} to {d} GPUs\n", .{ name, job.gpus, gpus });

    // resume with new configuration
    ctrl.resume_();
    writeErr("resuming {s} with {d} GPUs...\n", .{ name, gpus });

    if (server_addr) |addr| {
        const server = cli.parseServerAddr(addr);
        ctrl.startCluster(server.ip, server.port) catch {
            return ManifestCommandsError.DeploymentFailed;
        };
    } else {
        ctrl.startLocal() catch {
            return ManifestCommandsError.DeploymentFailed;
        };
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
                return ManifestCommandsError.InvalidArgument;
            };
            rank = std.fmt.parseInt(u32, rank_str, 10) catch {
                writeErr("invalid rank number: {s}\n", .{rank_str});
                return ManifestCommandsError.InvalidArgument;
            };
        } else {
            job_name = arg;
        }
    }

    const name = job_name orelse {
        writeErr("usage: yoq train logs [--rank N] <name>\n", .{});
        return ManifestCommandsError.InvalidArgument;
    };

    // look up the container by hostname pattern: {job_name}-rank-{rank}
    var hostname_buf: [128]u8 = undefined;
    const hostname = std.fmt.bufPrint(&hostname_buf, "{s}-rank-{d}", .{ name, rank }) catch {
        writeErr("failed to build hostname\n", .{});
        return ManifestCommandsError.InvalidArgument;
    };

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.process.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    const record = store.findAppContainer(alloc, app_name, hostname) catch |err| {
        writeErr("failed to query container: {}\n", .{err});
        return ManifestCommandsError.StoreError;
    };
    const rec = record orelse {
        writeErr("no container found for {s} rank {d}\n", .{ name, rank });
        return ManifestCommandsError.UnknownService;
    };
    defer rec.deinit(alloc);

    const logs = @import("../runtime/logs.zig");
    const data = logs.readLogs(alloc, rec.id) catch |err| {
        writeErr("no logs found for rank {d}: {}\n", .{ rank, err });
        return ManifestCommandsError.StoreError;
    };
    defer alloc.free(data);

    if (data.len == 0) {
        write("(no output)\n", .{});
        return;
    }
    write("{s}", .{data});
}
