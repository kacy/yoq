const std = @import("std");
const cli = @import("../../lib/cli.zig");
const app_spec = @import("../app_spec.zig");
const manifest_loader = @import("../loader.zig");
const orchestrator = @import("../orchestrator.zig");
const startup_runtime = @import("../orchestrator/startup_runtime.zig");
const watcher_mod = @import("../../dev/watcher.zig");
const store = @import("../../state/store.zig");
const process = @import("../../runtime/process.zig");
const http_client = @import("../../cluster/http_client.zig");
const container_cmds = @import("../../runtime/container_commands.zig");
const proxy_control_plane = @import("../../network/proxy/control_plane.zig");
const service_rollout = @import("../../network/service_rollout.zig");
const service_reconciler = @import("../../network/service_reconciler.zig");
const listener_runtime = @import("../../network/proxy/listener_runtime.zig");

const write = cli.write;
const writeErr = cli.writeErr;

const DeployError = error{
    InvalidArgument,
    ManifestLoadFailed,
    DeploymentFailed,
    ConnectionFailed,
    StoreError,
    OutOfMemory,
    UnknownService,
};

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
                return DeployError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--dev")) {
            dev_mode = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return DeployError.InvalidArgument;
            };
        } else {
            service_names.append(alloc, arg) catch return DeployError.OutOfMemory;
        }
    }

    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
        writeErr("hint: create one with 'yoq init'\n", .{});
        return DeployError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.fs.cwd().realpath(".", &cwd_buf) catch |err| {
        writeErr("failed to resolve working directory: {}\n", .{err});
        return DeployError.StoreError;
    };
    const app_name = std.fs.path.basename(cwd);

    var app = app_spec.fromManifest(alloc, app_name, &manifest) catch return DeployError.OutOfMemory;
    defer app.deinit();

    for (service_names.items) |name| {
        if (app.serviceByName(name) == null) {
            writeErr("unknown service: {s}\n", .{name});
            return DeployError.UnknownService;
        }
    }

    if (server_addr) |addr| {
        if (service_names.items.len > 0) {
            var filtered = app.selectServices(alloc, service_names.items) catch return DeployError.OutOfMemory;
            defer filtered.deinit();
            try deployToCluster(alloc, addr, &filtered);
        } else {
            try deployToCluster(alloc, addr, &app);
        }
        return;
    }

    if (service_names.items.len > 0) {
        writeErr("starting", .{});
        for (service_names.items, 0..) |name, i| {
            if (i > 0) writeErr(",", .{});
            writeErr(" {s}", .{name});
        }
        writeErr(" ({d} services)...\n", .{service_names.items.len});
    } else if (dev_mode) {
        writeErr("starting {s} in dev mode ({d} services)...\n", .{ app.app_name, app.services.len });
    } else {
        writeErr("starting {s} ({d} services)...\n", .{ app.app_name, app.services.len });
    }

    var orch = orchestrator.Orchestrator.init(alloc, &manifest, app.app_name) catch |err| {
        writeErr("failed to initialize orchestrator: {}\n", .{err});
        return DeployError.DeploymentFailed;
    };
    defer orch.deinit();
    orch.dev_mode = dev_mode;

    if (service_names.items.len > 0) {
        orch.service_filter = service_names.items;
    }

    orch.computeStartSet() catch |err| {
        writeErr("failed to resolve service start set: {}\n", .{err});
        return DeployError.DeploymentFailed;
    };

    startup_runtime.syncServiceDefinitions(alloc, manifest.services, orch.start_set);

    service_rollout.logStartupSummary();
    service_reconciler.ensureDataPlaneReadyIfEnabled();
    service_reconciler.bootstrapIfEnabled();
    service_reconciler.startAuditLoopIfEnabled();
    listener_runtime.setStateChangeHook(proxy_control_plane.refreshIfEnabled);
    defer listener_runtime.setStateChangeHook(null);
    listener_runtime.startIfEnabled(alloc);
    defer listener_runtime.stop();
    proxy_control_plane.startSyncLoopIfEnabled();
    defer proxy_control_plane.stopSyncLoop();
    orchestrator.installSignalHandlers();

    orch.startAll() catch |err| {
        writeErr("failed to start services: {}\n", .{err});
        return DeployError.DeploymentFailed;
    };

    var watcher: ?watcher_mod.Watcher = null;
    var watcher_thread: ?std.Thread = null;

    if (dev_mode) {
        watcher = watcher_mod.Watcher.init(alloc) catch |e| blk: {
            writeErr("warning: file watcher unavailable: {}\n", .{e});
            break :blk null;
        };

        if (watcher != null) {
            var any_watch_failed = false;
            for (manifest.services, 0..) |svc, i| {
                for (svc.volumes) |vol| {
                    if (vol.kind != .bind) continue;

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

            if (!any_watch_failed or watcher.?.watch_count > 0) {
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

    orch.waitForShutdown();

    writeErr("\nshutting down...\n", .{});

    if (watcher) |*w| w.deinit();
    if (watcher_thread) |t| t.join();

    orch.stopAll();
    writeErr("stopped\n", .{});
}

fn deployToCluster(alloc: std.mem.Allocator, addr_str: []const u8, app: *const app_spec.ApplicationSpec) DeployError!void {
    const server = cli.parseServerAddr(addr_str);
    const body = app.toApplyJson(alloc) catch return DeployError.OutOfMemory;
    defer alloc.free(body);

    writeErr("deploying {d} services to cluster {s}...\n", .{ app.services.len, addr_str });

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.postWithAuth(alloc, server.ip, server.port, "/apps/apply", body, token) catch |err| {
        writeErr("failed to connect to cluster server: {}\n", .{err});
        writeErr("hint: is the server running? try 'yoq serve' or 'yoq init-server'\n", .{});
        return DeployError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code == 200) {
        write("{s}\n", .{resp.body});
    } else {
        writeErr("deploy failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return DeployError.DeploymentFailed;
    }
}

pub fn down(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var manifest_path: []const u8 = manifest_loader.default_filename;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                return DeployError.InvalidArgument;
            };
        }
    }

    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
        writeErr("hint: create one with 'yoq init'\n", .{});
        return DeployError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.fs.cwd().realpath(".", &cwd_buf) catch |err| {
        writeErr("failed to resolve working directory: {}\n", .{err});
        return DeployError.StoreError;
    };
    const app_name = std.fs.path.basename(cwd);

    var ids = store.listAppContainerIds(alloc, app_name) catch |err| {
        writeErr("failed to query app containers: {}\n", .{err});
        return DeployError.StoreError;
    };
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    if (ids.items.len == 0) {
        writeErr("no running services found for {s}\n", .{app_name});
        return;
    }

    var i: usize = manifest.services.len;
    while (i > 0) {
        i -= 1;
        const svc = manifest.services[i];

        const record = store.findAppContainer(alloc, app_name, svc.name) catch continue;
        const rec = record orelse continue;
        defer rec.deinit(alloc);

        writeErr("stopping {s}...", .{svc.name});

        if (std.mem.eql(u8, rec.status, "running")) {
            if (rec.pid) |pid| {
                process.terminate(pid) catch {
                    process.kill(pid) catch {};
                };

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

        store.updateStatus(rec.id, "stopped", null, null) catch |e| {
            writeErr("warning: failed to update status for {s}: {}\n", .{ svc.name, e });
        };
        container_cmds.cleanupStoppedContainer(rec.id, rec.ip_address, rec.veth_host);

        writeErr(" stopped\n", .{});
    }

    writeErr("all services stopped\n", .{});
}
