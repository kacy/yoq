const std = @import("std");
const cli = @import("../../lib/cli.zig");
const app_spec = @import("../app_spec.zig");
const local_apply_backend = @import("../local_apply_backend.zig");
const release_plan = @import("../release_plan.zig");
const manifest_loader = @import("../loader.zig");
const store = @import("../../state/store.zig");
const process = @import("../../runtime/process.zig");
const http_client = @import("../../cluster/http_client.zig");
const container_cmds = @import("../../runtime/container_commands.zig");

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

    var release = release_plan.ReleasePlan.fromAppSpec(alloc, &app, service_names.items) catch return DeployError.OutOfMemory;
    defer release.deinit();

    if (server_addr) |addr| {
        try deployToCluster(alloc, addr, &release);
        return;
    }

    if (service_names.items.len > 0) {
        writeErr("starting", .{});
        for (service_names.items, 0..) |name, i| {
            if (i > 0) writeErr(",", .{});
            writeErr(" {s}", .{name});
        }
        writeErr(" ({d} requested, {d} resolved)...\n", .{ service_names.items.len, release.resolvedServiceCount() });
    } else if (dev_mode) {
        writeErr("starting {s} in dev mode ({d} services)...\n", .{ release.app.app_name, release.resolvedServiceCount() });
    } else {
        writeErr("starting {s} ({d} services)...\n", .{ release.app.app_name, release.resolvedServiceCount() });
    }

    var prepared = local_apply_backend.PreparedLocalApply.init(alloc, &manifest, &release, dev_mode) catch |err| {
        writeErr("failed to initialize orchestrator: {}\n", .{err});
        return DeployError.DeploymentFailed;
    };
    defer prepared.deinit();
    prepared.beginRuntime();

    const apply_report = prepared.startRelease(.{}) catch |err| {
        writeErr("failed to start services: {}\n", .{err});
        return DeployError.DeploymentFailed;
    };
    defer apply_report.deinit(alloc);

    const apply_summary = apply_report.summaryText(alloc) catch return DeployError.OutOfMemory;
    defer alloc.free(apply_summary);
    writeErr("{s}\n", .{apply_summary});

    var watcher = local_apply_backend.DevWatcherRuntime{};

    if (dev_mode) {
        watcher = prepared.startDevWatcher();
        writeErr("all services running. watching for changes...\n", .{});
    } else {
        writeErr("all services running. press ctrl-c to stop.\n", .{});
    }

    prepared.orch.waitForShutdown();

    writeErr("\nshutting down...\n", .{});

    watcher.deinit();

    prepared.orch.stopAll();
    writeErr("stopped\n", .{});
}

fn deployToCluster(alloc: std.mem.Allocator, addr_str: []const u8, release: *const release_plan.ReleasePlan) DeployError!void {
    const server = cli.parseServerAddr(addr_str);
    writeErr("deploying {d} services to cluster {s}...\n", .{ release.resolvedServiceCount(), addr_str });

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.postWithAuth(alloc, server.ip, server.port, "/apps/apply", release.config_snapshot, token) catch |err| {
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
