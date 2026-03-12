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
