const std = @import("std");
const cli = @import("../lib/cli.zig");
const apply_release = @import("apply_release.zig");
const release_history = @import("release_history.zig");
const release_plan = @import("release_plan.zig");
const orchestrator = @import("orchestrator.zig");
const startup_runtime = @import("orchestrator/startup_runtime.zig");
const store = @import("../state/store.zig");
const watcher_mod = @import("../dev/watcher.zig");
const spec = @import("spec.zig");
const proxy_control_plane = @import("../network/proxy/control_plane.zig");
const service_rollout = @import("../network/service_rollout.zig");
const service_reconciler = @import("../network/service_reconciler.zig");
const listener_runtime = @import("../network/proxy/listener_runtime.zig");

const writeErr = cli.writeErr;

pub const LocalApplyMode = enum {
    fresh,
    replacement_candidate,
};

pub const LocalApplyScope = struct {
    mode: LocalApplyMode,
    existing_target_count: usize,
    new_target_count: usize,
};

pub const PreparedLocalApply = struct {
    alloc: std.mem.Allocator,
    manifest: *spec.Manifest,
    release: *const release_plan.ReleasePlan,
    scope: LocalApplyScope,
    orch: orchestrator.Orchestrator,
    runtime_started: bool = false,

    pub fn init(
        alloc: std.mem.Allocator,
        manifest: *spec.Manifest,
        release: *const release_plan.ReleasePlan,
        dev_mode: bool,
    ) !PreparedLocalApply {
        const scope = detectApplyScope(alloc, release);
        var orch = try orchestrator.Orchestrator.init(alloc, manifest, release.app.app_name);
        errdefer orch.deinit();

        orch.dev_mode = dev_mode;
        if (release.service_filter) |filter| {
            orch.service_filter = filter;
        }

        try orch.computeStartSet();
        startup_runtime.syncServiceDefinitions(alloc, manifest.services, orch.start_set);

        return .{
            .alloc = alloc,
            .manifest = manifest,
            .release = release,
            .scope = scope,
            .orch = orch,
        };
    }

    pub fn deinit(self: *PreparedLocalApply) void {
        if (self.runtime_started) {
            listener_runtime.stop();
            proxy_control_plane.stopSyncLoop();
            listener_runtime.setStateChangeHook(null);
        }
        self.orch.deinit();
    }

    pub fn beginRuntime(self: *PreparedLocalApply) void {
        service_rollout.logStartupSummary();
        service_reconciler.ensureDataPlaneReadyIfEnabled();
        service_reconciler.bootstrapIfEnabled();
        service_reconciler.startAuditLoopIfEnabled();
        listener_runtime.setStateChangeHook(proxy_control_plane.refreshIfEnabled);
        listener_runtime.startIfEnabled(self.alloc);
        proxy_control_plane.startSyncLoopIfEnabled();
        orchestrator.installSignalHandlers();
        self.runtime_started = true;
    }

    pub fn startRelease(self: *PreparedLocalApply, context: apply_release.ApplyContext) !apply_release.ApplyReport {
        var release_tracker = LocalReleaseTracker{
            .plan = self.release,
            .context = context,
        };
        var apply_backend = LocalApplyBackend{
            .orch = &self.orch,
            .release = self.release,
        };
        const apply_result = try apply_release.execute(&release_tracker, &apply_backend);
        return apply_result.toReport(self.release.app.app_name, self.release.resolvedServiceCount(), context);
    }

    pub fn startDevWatcher(self: *PreparedLocalApply) DevWatcherRuntime {
        var runtime = DevWatcherRuntime{};
        runtime.watcher = watcher_mod.Watcher.init(self.alloc) catch |e| blk: {
            writeErr("warning: file watcher unavailable: {}\n", .{e});
            break :blk null;
        };

        if (runtime.watcher == null) return runtime;

        var any_watch_failed = false;
        for (self.manifest.services, 0..) |svc, i| {
            if (!self.release.includesService(svc.name)) continue;
            for (svc.volumes) |vol| {
                if (vol.kind != .bind) continue;

                var resolve_buf: [4096]u8 = undefined;
                const abs_source = std.fs.cwd().realpath(vol.source, &resolve_buf) catch |e| {
                    writeErr("warning: failed to resolve path {s}: {}\n", .{ vol.source, e });
                    any_watch_failed = true;
                    continue;
                };

                runtime.watcher.?.addRecursive(abs_source, i) catch |e| {
                    writeErr("warning: failed to watch {s}: {}\n", .{ vol.source, e });
                    any_watch_failed = true;
                };
            }
        }

        if (!any_watch_failed or runtime.watcher.?.watch_count > 0) {
            runtime.thread = std.Thread.spawn(.{}, orchestrator.watcherThread, .{
                &self.orch,
                &runtime.watcher.?,
            }) catch |e| blk: {
                writeErr("warning: failed to start watcher thread: {}\n", .{e});
                break :blk null;
            };
        } else {
            writeErr("warning: no directories could be watched, file change detection disabled\n", .{});
        }

        return runtime;
    }
};

fn detectApplyScope(alloc: std.mem.Allocator, release: *const release_plan.ReleasePlan) LocalApplyScope {
    var existing_target_count: usize = 0;
    var new_target_count: usize = 0;

    for (release.app.services) |svc| {
        const record = store.findAppContainer(alloc, release.app.app_name, svc.name) catch {
            new_target_count += 1;
            continue;
        };

        if (record) |container| {
            defer container.deinit(alloc);
            if (!std.mem.eql(u8, container.status, "stopped")) {
                existing_target_count += 1;
            } else {
                new_target_count += 1;
            }
        } else {
            new_target_count += 1;
        }
    }

    return .{
        .mode = if (existing_target_count > 0) .replacement_candidate else .fresh,
        .existing_target_count = existing_target_count,
        .new_target_count = new_target_count,
    };
}

pub const DevWatcherRuntime = struct {
    watcher: ?watcher_mod.Watcher = null,
    thread: ?std.Thread = null,

    pub fn deinit(self: *DevWatcherRuntime) void {
        if (self.watcher) |*w| w.deinit();
        if (self.thread) |t| t.join();
    }
};

const LocalReleaseTracker = struct {
    plan: *const release_plan.ReleasePlan,
    context: apply_release.ApplyContext = .{},

    pub fn begin(self: *const LocalReleaseTracker) !?[]const u8 {
        return release_history.recordAppReleaseStart(self.plan) catch null;
    }

    pub fn mark(self: *const LocalReleaseTracker, id: []const u8, status: @import("update/common.zig").DeploymentStatus, message: ?[]const u8) !void {
        const resolved_message = try apply_release.materializeMessage(self.plan.alloc, self.context, status, message);
        defer if (resolved_message) |msg| self.plan.alloc.free(msg);

        release_history.markAppReleaseStatus(id, status, resolved_message) catch {};
    }

    pub fn freeReleaseId(self: *const LocalReleaseTracker, id: []const u8) void {
        self.plan.alloc.free(id);
    }
};

const LocalApplyBackend = struct {
    orch: *orchestrator.Orchestrator,
    release: *const release_plan.ReleasePlan,

    pub fn apply(self: *const LocalApplyBackend) !apply_release.ApplyOutcome {
        try self.orch.startAll();
        return .{
            .status = .completed,
            .message = "all requested services started",
            .placed = self.release.resolvedServiceCount(),
        };
    }

    pub fn failureMessage(_: *const LocalApplyBackend, _: anytype) ?[]const u8 {
        return "service startup failed";
    }
};

test "PreparedLocalApply init resolves filtered start set" {
    const alloc = std.testing.allocator;
    const loader = @import("loader.zig");
    const app_spec = @import("app_spec.zig");

    var manifest = try loader.loadFromString(alloc,
        \\[service.db]
        \\image = "postgres:latest"
        \\
        \\[service.web]
        \\image = "nginx:latest"
        \\depends_on = ["db"]
    );
    defer manifest.deinit();

    var app = try app_spec.fromManifest(alloc, "demo-app", &manifest);
    defer app.deinit();

    var release = try release_plan.ReleasePlan.fromAppSpec(alloc, &app, &.{"web"});
    defer release.deinit();

    var prepared = try PreparedLocalApply.init(alloc, &manifest, &release, false);
    defer prepared.deinit();

    const start_set = prepared.orch.start_set.?;
    try std.testing.expectEqual(@as(usize, 2), start_set.count());
    try std.testing.expect(start_set.contains("db"));
    try std.testing.expect(start_set.contains("web"));
}

test "PreparedLocalApply detects replacement candidates from existing app containers" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();

    const loader = @import("loader.zig");
    const app_spec = @import("app_spec.zig");

    var manifest = try loader.loadFromString(alloc,
        \\[service.db]
        \\image = "postgres:latest"
        \\
        \\[service.web]
        \\image = "nginx:latest"
        \\depends_on = ["db"]
    );
    defer manifest.deinit();

    var app = try app_spec.fromManifest(alloc, "demo-app", &manifest);
    defer app.deinit();

    var release = try release_plan.ReleasePlan.fromAppSpec(alloc, &app, &.{"web"});
    defer release.deinit();

    try store.save(.{
        .id = "abcdef123456",
        .rootfs = "/tmp/rootfs",
        .command = "/bin/sh",
        .hostname = "web",
        .status = "running",
        .pid = null,
        .exit_code = null,
        .app_name = "demo-app",
        .created_at = 100,
    });

    var prepared = try PreparedLocalApply.init(alloc, &manifest, &release, false);
    defer prepared.deinit();

    try std.testing.expectEqual(LocalApplyMode.replacement_candidate, prepared.scope.mode);
    try std.testing.expectEqual(@as(usize, 1), prepared.scope.existing_target_count);
    try std.testing.expectEqual(@as(usize, 1), prepared.scope.new_target_count);
}
