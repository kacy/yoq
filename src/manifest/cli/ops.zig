const std = @import("std");
const cli = @import("../../lib/cli.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const json_out = @import("../../lib/json_output.zig");
const manifest_loader = @import("../loader.zig");
const orchestrator = @import("../orchestrator.zig");
const release_history = @import("../release_history.zig");
const update = @import("../update.zig");
const store = @import("../../state/store.zig");
const http_client = @import("../../cluster/http_client.zig");

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
    var target_name: ?[]const u8 = null;
    var app_mode = false;
    var server_addr: ?[]const u8 = null;
    var release_id: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--app")) {
            app_mode = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return OpsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--release")) {
            release_id = args.next() orelse {
                writeErr("--release requires a release id\n", .{});
                return OpsError.InvalidArgument;
            };
        } else {
            target_name = arg;
        }
    }

    if (server_addr != null) {
        if (!app_mode) {
            writeErr("remote rollback currently requires --app [name]\n", .{});
            return OpsError.InvalidArgument;
        }
        const owned_app_name = if (target_name == null) try currentAppNameAlloc(alloc) else null;
        defer if (owned_app_name) |name| alloc.free(name);
        const app_name = target_name orelse owned_app_name.?;
        const id = release_id orelse {
            writeErr("remote rollback requires --release <id>\n", .{});
            return OpsError.InvalidArgument;
        };
        try rollbackRemoteApp(alloc, server_addr.?, app_name, id);
        return;
    }

    const config = if (app_mode) blk: {
        const owned_app_name = if (target_name == null) try currentAppNameAlloc(alloc) else null;
        defer if (owned_app_name) |name| alloc.free(name);
        const app_name = target_name orelse owned_app_name.?;
        break :blk release_history.rollbackApp(alloc, app_name) catch {
            writeErr("no previous deployment found for app {s}\n", .{app_name});
            return OpsError.StoreError;
        };
    } else blk: {
        const service_name = target_name orelse {
            writeErr("usage: yoq rollback <service>\n", .{});
            writeErr("   or: yoq rollback --app [name]\n", .{});
            writeErr("   or: yoq rollback --app [name] --server host:port --release <id>\n", .{});
            return OpsError.InvalidArgument;
        };

        break :blk update.rollback(alloc, service_name) catch |err| {
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
    };
    defer alloc.free(config);

    if (app_mode) {
        const owned_app_name = if (target_name == null) try currentAppNameAlloc(alloc) else null;
        defer if (owned_app_name) |name| alloc.free(name);
        const app_name = target_name orelse owned_app_name.?;
        write("rollback config for app {s}:\n{s}\n", .{ app_name, config });
    } else {
        write("rollback config for {s}:\n{s}\n", .{ target_name.?, config });
    }
    write("\nto apply this rollback, redeploy with this config using 'yoq up'\n", .{});
}

pub fn history(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var target_name: ?[]const u8 = null;
    var app_mode = false;
    var server_addr: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--app")) {
            app_mode = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            server_addr = args.next() orelse {
                writeErr("--server requires a host:port address\n", .{});
                return OpsError.InvalidArgument;
            };
        } else {
            target_name = arg;
        }
    }

    if (server_addr != null and !app_mode) {
        writeErr("remote history currently requires --app [name]\n", .{});
        return OpsError.InvalidArgument;
    }

    const owned_label = if (app_mode and target_name == null) try currentAppNameAlloc(alloc) else null;
    defer if (owned_label) |label| alloc.free(label);

    const label = if (app_mode)
        target_name orelse owned_label.?
    else
        target_name orelse {
            writeErr("usage: yoq history <service> [--json]\n", .{});
            writeErr("   or: yoq history --app [name] [--server host:port] [--json]\n", .{});
            return OpsError.InvalidArgument;
        };

    if (server_addr) |addr| {
        try printRemoteAppHistory(alloc, addr, label);
        return;
    }

    var deployments = if (app_mode)
        release_history.listAppReleases(alloc, label) catch |err| {
            writeErr("failed to read app release history: {}\n", .{err});
            return OpsError.StoreError;
        }
    else
        store.listDeployments(alloc, label) catch |err| {
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
            if (dep.app_name) |app_name| w.stringField("app", app_name) else w.nullField("app");
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
        if (app_mode) {
            write("no releases found for app {s}\n", .{label});
        } else {
            write("no deployments found for {s}\n", .{label});
        }
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

fn currentAppNameAlloc(alloc: std.mem.Allocator) ![]u8 {
    var cwd_buf: [4096]u8 = undefined;
    const cwd = std.fs.cwd().realpath(".", &cwd_buf) catch return OpsError.StoreError;
    return alloc.dupe(u8, std.fs.path.basename(cwd)) catch return OpsError.StoreError;
}

fn printRemoteAppHistory(alloc: std.mem.Allocator, addr_str: []const u8, app_name: []const u8) !void {
    const server = cli.parseServerAddr(addr_str);
    const path = std.fmt.allocPrint(alloc, "/apps/{s}/history", .{app_name}) catch return OpsError.StoreError;
    defer alloc.free(path);

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.getWithAuth(alloc, server.ip, server.port, path, token) catch |err| {
        writeErr("failed to connect to cluster server: {}\n", .{err});
        writeErr("hint: is the server running? try 'yoq serve' or 'yoq init-server'\n", .{});
        return OpsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("history failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return OpsError.StoreError;
    }

    if (cli.output_mode == .json) {
        write("{s}\n", .{resp.body});
        return;
    }

    var iter = json_helpers.extractJsonObjects(resp.body);
    const first = iter.next() orelse {
        write("no releases found for app {s}\n", .{app_name});
        return;
    };

    write("{s:<14} {s:<14} {s:<14} {s:<20} {s}\n", .{ "ID", "STATUS", "HASH", "TIMESTAMP", "MESSAGE" });
    writeHistoryRow(first);
    while (iter.next()) |obj| {
        writeHistoryRow(obj);
    }
}

fn writeHistoryRow(obj: []const u8) void {
    const id = json_helpers.extractJsonString(obj, "id") orelse "?";
    const status = json_helpers.extractJsonString(obj, "status") orelse "?";
    const manifest_hash = json_helpers.extractJsonString(obj, "manifest_hash") orelse "?";
    const created_at = json_helpers.extractJsonInt(obj, "created_at") orelse 0;
    const message = json_helpers.extractJsonString(obj, "message") orelse "";

    var ts_buf: [20]u8 = undefined;
    const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{created_at}) catch "?";

    write("{s:<14} {s:<14} {s:<14} {s:<20} {s}\n", .{
        truncate(id, 12),
        status,
        truncate(manifest_hash, 12),
        ts_str,
        truncate(message, 40),
    });
}

fn rollbackRemoteApp(alloc: std.mem.Allocator, addr_str: []const u8, app_name: []const u8, release_id: []const u8) !void {
    if (release_id.len == 0) {
        writeErr("remote rollback requires a release id\n", .{});
        return OpsError.InvalidArgument;
    }

    const server = cli.parseServerAddr(addr_str);
    const path = std.fmt.allocPrint(alloc, "/apps/{s}/rollback", .{app_name}) catch return OpsError.StoreError;
    defer alloc.free(path);
    const body = std.fmt.allocPrint(alloc, "{{\"release_id\":\"{s}\"}}", .{release_id}) catch return OpsError.StoreError;
    defer alloc.free(body);

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiToken(&token_buf);

    var resp = http_client.postWithAuth(alloc, server.ip, server.port, path, body, token) catch |err| {
        writeErr("failed to connect to cluster server: {}\n", .{err});
        writeErr("hint: is the server running? try 'yoq serve' or 'yoq init-server'\n", .{});
        return OpsError.ConnectionFailed;
    };
    defer resp.deinit(alloc);

    if (resp.status_code != 200) {
        writeErr("rollback failed (status {d}): {s}\n", .{ resp.status_code, resp.body });
        return OpsError.StoreError;
    }

    write("{s}\n", .{resp.body});
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
