const std = @import("std");
const cli = @import("../../lib/cli.zig");
const app_spec = @import("../app_spec.zig");
const local_apply_backend = @import("../local_apply_backend.zig");
const release_plan = @import("../release_plan.zig");
const manifest_loader = @import("../loader.zig");
const manifest_spec = @import("../spec.zig");
const doctor = @import("../../lib/doctor.zig");
const doctor_manifest = @import("../../lib/doctor_manifest.zig");
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
    PreflightFailed,
};

pub fn up(args: *std.process.Args.Iterator, io: std.Io, alloc: std.mem.Allocator) !void {
    try upWithDeps(args, io, alloc, .{});
}

const UpOptions = struct {
    manifest_path: []const u8 = manifest_loader.default_filename,
    dev_mode: bool = false,
    skip_preflight: bool = false,
    server_addr: ?[]const u8 = null,
    service_names: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *UpOptions, alloc: std.mem.Allocator) void {
        self.service_names.deinit(alloc);
    }
};

const UpDeps = struct {
    ctx: *anyopaque = &noop_context,
    preflight_fn: *const fn (*anyopaque, std.mem.Allocator, *const manifest_spec.Manifest) anyerror!doctor_manifest.ManifestCheckResult = runHostPreflight,
    local_start_fn: *const fn (*anyopaque, std.Io, std.mem.Allocator, *manifest_spec.Manifest, *const release_plan.ReleasePlan, bool) DeployError!void = startLocalRelease,
    cluster_deploy_fn: *const fn (*anyopaque, std.Io, std.mem.Allocator, []const u8, *const release_plan.ReleasePlan) DeployError!void = deployToCluster,
};

var noop_context: u8 = 0;

fn upWithDeps(args: *std.process.Args.Iterator, io: std.Io, alloc: std.mem.Allocator, deps: UpDeps) !void {
    var tokens: std.ArrayList([]const u8) = .empty;
    defer tokens.deinit(alloc);

    while (args.next()) |arg| {
        tokens.append(alloc, arg) catch return DeployError.OutOfMemory;
    }

    var options = try parseUpTokens(alloc, tokens.items);
    defer options.deinit(alloc);

    try runUpOptions(io, alloc, &options, deps);
}

fn parseUpTokens(alloc: std.mem.Allocator, tokens: []const []const u8) DeployError!UpOptions {
    var options = UpOptions{};
    errdefer options.deinit(alloc);

    var i: usize = 0;
    while (i < tokens.len) : (i += 1) {
        const arg = tokens[i];
        if (std.mem.eql(u8, arg, "-f")) {
            i += 1;
            if (i >= tokens.len) {
                writeErr("-f requires a manifest path\n", .{});
                return DeployError.InvalidArgument;
            }
            options.manifest_path = tokens[i];
        } else if (std.mem.eql(u8, arg, "--dev")) {
            options.dev_mode = true;
        } else if (std.mem.eql(u8, arg, "--skip-preflight")) {
            options.skip_preflight = true;
        } else if (std.mem.eql(u8, arg, "--server")) {
            i += 1;
            if (i >= tokens.len) {
                writeErr("--server requires a host:port address\n", .{});
                return DeployError.InvalidArgument;
            }
            options.server_addr = tokens[i];
        } else {
            options.service_names.append(alloc, arg) catch return DeployError.OutOfMemory;
        }
    }

    return options;
}

fn runUpOptions(io: std.Io, alloc: std.mem.Allocator, options: *const UpOptions, deps: UpDeps) !void {
    var manifest = manifest_loader.load(alloc, options.manifest_path) catch |err| {
        writeErr("failed to load manifest: {s} ({})", .{ options.manifest_path, err });
        writeErr("hint: create one with 'yoq init'\n", .{});
        return DeployError.ManifestLoadFailed;
    };
    defer manifest.deinit();

    var cwd_buf: [4096]u8 = undefined;
    const cwd_len = std.Io.Dir.cwd().realPathFile(io, ".", &cwd_buf) catch |err| {
        writeErr("failed to resolve working directory: {}\n", .{err});
        return DeployError.StoreError;
    };
    const cwd = cwd_buf[0..cwd_len];
    const app_name = std.fs.path.basename(cwd);

    var app = app_spec.fromManifest(alloc, app_name, &manifest) catch return DeployError.OutOfMemory;
    defer app.deinit();

    for (options.service_names.items) |name| {
        if (app.serviceByName(name) == null) {
            writeErr("unknown service: {s}\n", .{name});
            return DeployError.UnknownService;
        }
    }

    if (options.server_addr == null and !options.skip_preflight) {
        try runLocalPreflight(deps, alloc, &manifest);
    }

    var release = release_plan.ReleasePlan.fromAppSpec(alloc, &app, options.service_names.items) catch return DeployError.OutOfMemory;
    defer release.deinit();

    if (options.server_addr) |addr| {
        try deps.cluster_deploy_fn(deps.ctx, io, alloc, addr, &release);
        return;
    }

    if (options.service_names.items.len > 0) {
        writeErr("starting", .{});
        for (options.service_names.items, 0..) |name, i| {
            if (i > 0) writeErr(",", .{});
            writeErr(" {s}", .{name});
        }
        writeErr(" ({d} requested, {d} resolved)...\n", .{ options.service_names.items.len, release.resolvedServiceCount() });
    } else if (options.dev_mode) {
        writeErr("starting {s} in dev mode ({d} services)...\n", .{ release.app.app_name, release.resolvedServiceCount() });
    } else {
        writeErr("starting {s} ({d} services)...\n", .{ release.app.app_name, release.resolvedServiceCount() });
    }

    try deps.local_start_fn(deps.ctx, io, alloc, &manifest, &release, options.dev_mode);
}

fn runHostPreflight(
    _: *anyopaque,
    alloc: std.mem.Allocator,
    manifest: *const manifest_spec.Manifest,
) anyerror!doctor_manifest.ManifestCheckResult {
    return doctor_manifest.checkLoadedManifestForHost(alloc, manifest);
}

fn runLocalPreflight(deps: UpDeps, alloc: std.mem.Allocator, manifest: *const manifest_spec.Manifest) DeployError!void {
    var result = deps.preflight_fn(deps.ctx, alloc, manifest) catch |err| {
        writeErr("preflight failed: {}\n", .{err});
        return DeployError.PreflightFailed;
    };
    defer result.deinit();

    var failed = false;
    var warned = false;
    for (result.checks) |check| {
        switch (check.status) {
            .fail => {
                failed = true;
                writeErr("preflight error: {s}: {s}\n", .{ check.getName(), check.getMessage() });
            },
            .warn => {
                warned = true;
                writeErr("preflight warning: {s}: {s}\n", .{ check.getName(), check.getMessage() });
            },
            .pass => {},
        }
    }

    if (failed) {
        writeErr("preflight failed; fix the errors above or rerun with --skip-preflight\n", .{});
        return DeployError.PreflightFailed;
    }
    if (warned) writeErr("preflight completed with warnings\n", .{});
}

fn startLocalRelease(
    _: *anyopaque,
    _: std.Io,
    alloc: std.mem.Allocator,
    manifest: *manifest_spec.Manifest,
    release: *const release_plan.ReleasePlan,
    dev_mode: bool,
) DeployError!void {
    var prepared = local_apply_backend.PreparedLocalApply.init(alloc, manifest, release, dev_mode) catch |err| {
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

fn deployToCluster(
    _: *anyopaque,
    io: std.Io,
    alloc: std.mem.Allocator,
    addr_str: []const u8,
    release: *const release_plan.ReleasePlan,
) DeployError!void {
    const server = cli.parseServerAddr(addr_str);
    writeErr("deploying {d} services to cluster {s}...\n", .{ release.resolvedServiceCount(), addr_str });

    var token_buf: [64]u8 = undefined;
    const token = cli.readApiTokenWithIo(io, &token_buf);

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

pub fn down(args: *std.process.Args.Iterator, io: std.Io, alloc: std.mem.Allocator) !void {
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
    const cwd_len = std.Io.Dir.cwd().realPathFile(io, ".", &cwd_buf) catch |err| {
        writeErr("failed to resolve working directory: {}\n", .{err});
        return DeployError.StoreError;
    };
    const cwd = cwd_buf[0..cwd_len];
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
                        .running => std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(100), .awake) catch unreachable,
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

test "up parser accepts skip preflight" {
    const alloc = std.testing.allocator;
    var options = try parseUpTokens(alloc, &.{ "--skip-preflight", "-f", "demo.toml", "web" });
    defer options.deinit(alloc);

    try std.testing.expect(options.skip_preflight);
    try std.testing.expectEqualStrings("demo.toml", options.manifest_path);
    try std.testing.expectEqual(@as(usize, 1), options.service_names.items.len);
    try std.testing.expectEqualStrings("web", options.service_names.items[0]);
}

test "up preflight failure aborts before local apply" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const manifest_path = try writeTestManifest(alloc, &tmp);
    defer alloc.free(manifest_path);

    var options = try parseUpTokens(alloc, &.{ "-f", manifest_path });
    defer options.deinit(alloc);
    var harness = UpHarness{ .preflight_status = .fail };

    try std.testing.expectError(DeployError.PreflightFailed, runUpOptions(std.testing.io, alloc, &options, harness.deps()));
    try std.testing.expectEqual(@as(u32, 1), harness.preflight_calls);
    try std.testing.expectEqual(@as(u32, 0), harness.local_calls);
    try std.testing.expectEqual(@as(u32, 0), harness.cluster_calls);
}

test "up warning-only preflight continues to local apply" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const manifest_path = try writeTestManifest(alloc, &tmp);
    defer alloc.free(manifest_path);

    var options = try parseUpTokens(alloc, &.{ "-f", manifest_path, "--dev" });
    defer options.deinit(alloc);
    var harness = UpHarness{ .preflight_status = .warn };

    try runUpOptions(std.testing.io, alloc, &options, harness.deps());
    try std.testing.expectEqual(@as(u32, 1), harness.preflight_calls);
    try std.testing.expectEqual(@as(u32, 1), harness.local_calls);
    try std.testing.expectEqual(@as(u32, 0), harness.cluster_calls);
    try std.testing.expect(harness.saw_dev_mode);
}

test "up skip preflight bypasses failing checks" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const manifest_path = try writeTestManifest(alloc, &tmp);
    defer alloc.free(manifest_path);

    var options = try parseUpTokens(alloc, &.{ "-f", manifest_path, "--skip-preflight" });
    defer options.deinit(alloc);
    var harness = UpHarness{ .preflight_status = .fail };

    try runUpOptions(std.testing.io, alloc, &options, harness.deps());
    try std.testing.expectEqual(@as(u32, 0), harness.preflight_calls);
    try std.testing.expectEqual(@as(u32, 1), harness.local_calls);
    try std.testing.expectEqual(@as(u32, 0), harness.cluster_calls);
}

test "up server path skips local preflight" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const manifest_path = try writeTestManifest(alloc, &tmp);
    defer alloc.free(manifest_path);

    var options = try parseUpTokens(alloc, &.{ "-f", manifest_path, "--server", "127.0.0.1:7700" });
    defer options.deinit(alloc);
    var harness = UpHarness{ .preflight_status = .fail };

    try runUpOptions(std.testing.io, alloc, &options, harness.deps());
    try std.testing.expectEqual(@as(u32, 0), harness.preflight_calls);
    try std.testing.expectEqual(@as(u32, 0), harness.local_calls);
    try std.testing.expectEqual(@as(u32, 1), harness.cluster_calls);
    try std.testing.expectEqualStrings("127.0.0.1:7700", harness.cluster_addr.?);
}

const UpHarness = struct {
    preflight_status: doctor.CheckStatus = .pass,
    preflight_calls: u32 = 0,
    local_calls: u32 = 0,
    cluster_calls: u32 = 0,
    saw_dev_mode: bool = false,
    cluster_addr: ?[]const u8 = null,

    fn deps(self: *UpHarness) UpDeps {
        return .{
            .ctx = self,
            .preflight_fn = preflight,
            .local_start_fn = localStart,
            .cluster_deploy_fn = clusterDeploy,
        };
    }

    fn preflight(
        ctx: *anyopaque,
        alloc: std.mem.Allocator,
        _: *const manifest_spec.Manifest,
    ) anyerror!doctor_manifest.ManifestCheckResult {
        const self: *UpHarness = @ptrCast(@alignCast(ctx));
        self.preflight_calls += 1;
        const checks = try alloc.alloc(doctor.Check, 1);
        checks[0] = doctor.makeCheck("mock", self.preflight_status, "mock preflight result");
        return .{ .checks = checks, .alloc = alloc };
    }

    fn localStart(
        ctx: *anyopaque,
        _: std.Io,
        _: std.mem.Allocator,
        _: *manifest_spec.Manifest,
        _: *const release_plan.ReleasePlan,
        dev_mode: bool,
    ) DeployError!void {
        const self: *UpHarness = @ptrCast(@alignCast(ctx));
        self.local_calls += 1;
        self.saw_dev_mode = dev_mode;
    }

    fn clusterDeploy(
        ctx: *anyopaque,
        _: std.Io,
        _: std.mem.Allocator,
        addr: []const u8,
        _: *const release_plan.ReleasePlan,
    ) DeployError!void {
        const self: *UpHarness = @ptrCast(@alignCast(ctx));
        self.cluster_calls += 1;
        self.cluster_addr = addr;
    }
};

fn writeTestManifest(alloc: std.mem.Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "manifest.toml",
        .data =
        \\[service.web]
        \\image = "nginx:latest"
        \\
        ,
    });

    var dir_buf: [4096]u8 = undefined;
    const dir_len = try tmp.dir.realPathFile(std.testing.io, ".", &dir_buf);
    return std.fs.path.join(alloc, &.{ dir_buf[0..dir_len], "manifest.toml" });
}
