const std = @import("std");
const cli = @import("../../lib/cli.zig");
const json_out = @import("../../lib/json_output.zig");
const manifest_loader = @import("../loader.zig");
const orchestrator = @import("../orchestrator.zig");
const update = @import("../update.zig");
const store = @import("../../state/store.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const truncate = cli.truncate;

const OpsError = error{
    InvalidArgument,
    ManifestLoadFailed,
    DeploymentFailed,
    StoreError,
    UnknownService,
};

pub fn rollback(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const service_name = args.next() orelse {
        writeErr("usage: yoq rollback <service>\n", .{});
        return OpsError.InvalidArgument;
    };

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
        return OpsError.StoreError;
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
        return OpsError.InvalidArgument;
    };

    var deployments = store.listDeployments(alloc, svc) catch |err| {
        writeErr("failed to read deployment history: {}\n", .{err});
        return OpsError.StoreError;
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
            if (dep.message) |msg| w.stringField("message", msg) else w.nullField("message");
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

pub fn runWorker(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var manifest_path: []const u8 = manifest_loader.default_filename;
    var worker_name: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-f")) {
            manifest_path = args.next() orelse {
                writeErr("-f requires a manifest path\n", .{});
                return OpsError.InvalidArgument;
            };
        } else {
            worker_name = arg;
        }
    }

    const name = worker_name orelse {
        writeErr("usage: yoq run-worker [-f manifest.toml] <name>\n", .{});
        return OpsError.InvalidArgument;
    };

    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ manifest_path, err });
        writeErr("hint: create one with 'yoq init'\n", .{});
        return OpsError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    const worker = manifest.workerByName(name) orelse {
        writeErr("unknown worker: {s}\n", .{name});
        return OpsError.UnknownService;
    };

    writeErr("pulling {s}...\n", .{worker.image});
    if (!orchestrator.ensureImageAvailable(alloc, worker.image)) {
        writeErr("failed to pull image: {s}\n", .{worker.image});
        return OpsError.DeploymentFailed;
    }

    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.process.getCwd(&cwd_buf) catch "app";
    const app_name = std.fs.path.basename(cwd);

    writeErr("running worker {s}...\n", .{name});
    if (orchestrator.runOneShot(alloc, worker.image, worker.command, worker.env, worker.volumes, worker.working_dir, name, manifest.volumes, app_name)) {
        writeErr("worker {s} completed successfully\n", .{name});
    } else {
        writeErr("worker {s} failed\n", .{name});
        return OpsError.DeploymentFailed;
    }
}
