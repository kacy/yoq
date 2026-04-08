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
            .scope = self.scope,
        };
        const apply_result = try apply_release.execute(&release_tracker, &apply_backend);
        return apply_result.toReport(self.release.app.app_name, self.release.resolvedServiceCount(), context);
    }

    pub fn replacementServiceIndexes(self: *const PreparedLocalApply, alloc: std.mem.Allocator) !std.ArrayList(usize) {
        return classifyServiceIndexes(alloc, self.manifest, self.release, self.scope, true);
    }

    pub fn newServiceIndexes(self: *const PreparedLocalApply, alloc: std.mem.Allocator) !std.ArrayList(usize) {
        return classifyServiceIndexes(alloc, self.manifest, self.release, self.scope, false);
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

fn classifyServiceIndexes(
    alloc: std.mem.Allocator,
    manifest: *const spec.Manifest,
    release: *const release_plan.ReleasePlan,
    scope: LocalApplyScope,
    want_existing: bool,
) !std.ArrayList(usize) {
    var indexes: std.ArrayList(usize) = .empty;

    for (manifest.services, 0..) |svc, idx| {
        if (!release.includesService(svc.name)) continue;
        if (scope.mode == .fresh) {
            if (!want_existing) try indexes.append(alloc, idx);
            continue;
        }

        const record = store.findAppContainer(alloc, release.app.app_name, svc.name) catch {
            if (!want_existing) try indexes.append(alloc, idx);
            continue;
        };

        if (record) |container| {
            defer container.deinit(alloc);
            const is_existing = !std.mem.eql(u8, container.status, "stopped");
            if (is_existing == want_existing) {
                try indexes.append(alloc, idx);
            }
        } else if (!want_existing) {
            try indexes.append(alloc, idx);
        }
    }

    return indexes;
}

fn syncExistingServiceStates(orch: *orchestrator.Orchestrator, release: *const release_plan.ReleasePlan) void {
    for (orch.manifest.services, 0..) |svc, idx| {
        if (!release.includesService(svc.name)) continue;
        const record = store.findAppContainer(orch.alloc, release.app.app_name, svc.name) catch continue;
        if (record) |container| {
            defer container.deinit(orch.alloc);
            if (std.mem.eql(u8, container.status, "stopped")) continue;
            if (container.id.len != orch.states[idx].container_id.len) continue;
            @memcpy(&orch.states[idx].container_id, container.id);
            orch.states[idx].status = .running;
        }
    }
}

fn runReplacementPlan(
    runner: anytype,
    alloc: std.mem.Allocator,
    new_indexes: []const usize,
    replacement_indexes: []const usize,
) !apply_release.ApplyOutcome {
    var completed_workers: std.StringHashMapUnmanaged(void) = .empty;
    defer completed_workers.deinit(alloc);

    var placed: usize = 0;
    var failed: usize = 0;
    var mutated = false;

    for (new_indexes) |idx| {
        runner.start(idx, &completed_workers) catch {
            failed += 1;
            if (!mutated) return error.StartFailed;
            continue;
        };
        placed += 1;
        mutated = true;
    }

    for (replacement_indexes) |idx| {
        runner.stop(idx);
        mutated = true;
        runner.start(idx, &completed_workers) catch {
            failed += 1;
            continue;
        };
        placed += 1;
    }

    runner.finish();

    if (failed > 0) {
        return .{
            .status = .partially_failed,
            .message = "one or more local service replacements failed",
            .placed = placed,
            .failed = failed,
        };
    }

    return .{
        .status = .completed,
        .message = if (replacement_indexes.len > 0)
            "all requested services replaced"
        else
            "all requested services started",
        .placed = placed,
        .failed = 0,
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
    scope: LocalApplyScope,

    pub fn apply(self: *const LocalApplyBackend) !apply_release.ApplyOutcome {
        if (self.scope.mode == .replacement_candidate) {
            return self.applyReplacementCandidate();
        }

        try self.orch.startAll();
        return .{
            .status = .completed,
            .message = "all requested services started",
            .placed = self.release.resolvedServiceCount(),
        };
    }

    fn applyReplacementCandidate(self: *const LocalApplyBackend) !apply_release.ApplyOutcome {
        syncExistingServiceStates(self.orch, self.release);

        var new_indexes = try classifyServiceIndexes(
            self.orch.alloc,
            self.orch.manifest,
            self.release,
            self.scope,
            false,
        );
        defer new_indexes.deinit(self.orch.alloc);

        var replacement_indexes = try classifyServiceIndexes(
            self.orch.alloc,
            self.orch.manifest,
            self.release,
            self.scope,
            true,
        );
        defer replacement_indexes.deinit(self.orch.alloc);

        var runner = struct {
            orch: *orchestrator.Orchestrator,

            fn start(runner_self: *@This(), idx: usize, completed_workers: *std.StringHashMapUnmanaged(void)) !void {
                try runner_self.orch.startServiceByIndex(idx, completed_workers);
            }

            fn stop(runner_self: *@This(), idx: usize) void {
                runner_self.orch.stopServiceByIndex(idx);
            }

            fn finish(runner_self: *@This()) void {
                runner_self.orch.startTlsProxy();
            }
        }{ .orch = self.orch };

        return runReplacementPlan(
            &runner,
            self.orch.alloc,
            new_indexes.items,
            replacement_indexes.items,
        );
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

test "PreparedLocalApply classifies replacement and new service indexes" {
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

    var replacement_indexes = try prepared.replacementServiceIndexes(alloc);
    defer replacement_indexes.deinit(alloc);
    var new_indexes = try prepared.newServiceIndexes(alloc);
    defer new_indexes.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), replacement_indexes.items.len);
    try std.testing.expectEqual(@as(usize, 1), new_indexes.items.len);
    try std.testing.expectEqual(@as(usize, 1), replacement_indexes.items[0]);
    try std.testing.expectEqual(@as(usize, 0), new_indexes.items[0]);
}

test "syncExistingServiceStates marks selected running services" {
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

    syncExistingServiceStates(&prepared.orch, &release);

    try std.testing.expectEqual(orchestrator.ServiceState.Status.pending, prepared.orch.states[0].status);
    try std.testing.expectEqual(orchestrator.ServiceState.Status.running, prepared.orch.states[1].status);
    try std.testing.expectEqualStrings("abcdef123456", prepared.orch.states[1].container_id[0..]);
}

test "runReplacementPlan counts started and replaced services" {
    const alloc = std.testing.allocator;

    const Runner = struct {
        started: std.ArrayList(usize),
        stopped: std.ArrayList(usize),
        tls_started: bool = false,

        fn start(self: *@This(), idx: usize, _: *std.StringHashMapUnmanaged(void)) !void {
            try self.started.append(alloc, idx);
        }

        fn stop(self: *@This(), idx: usize) void {
            self.stopped.append(alloc, idx) catch unreachable;
        }

        fn finish(self: *@This()) void {
            self.tls_started = true;
        }
    };

    var runner = Runner{
        .started = .empty,
        .stopped = .empty,
    };
    defer runner.started.deinit(alloc);
    defer runner.stopped.deinit(alloc);

    const outcome = try runReplacementPlan(&runner, alloc, &.{0}, &.{1});

    try std.testing.expectEqual(@as(usize, 2), outcome.placed);
    try std.testing.expectEqual(@as(usize, 0), outcome.failed);
    try std.testing.expectEqual(@import("update/common.zig").DeploymentStatus.completed, outcome.status);
    try std.testing.expectEqualStrings("all requested services replaced", outcome.message.?);
    try std.testing.expect(runner.tls_started);
    try std.testing.expectEqual(@as(usize, 2), runner.started.items.len);
    try std.testing.expectEqual(@as(usize, 1), runner.stopped.items.len);
    try std.testing.expectEqual(@as(usize, 0), runner.started.items[0]);
    try std.testing.expectEqual(@as(usize, 1), runner.started.items[1]);
    try std.testing.expectEqual(@as(usize, 1), runner.stopped.items[0]);
}

test "runReplacementPlan reports partial failure after mutation" {
    const alloc = std.testing.allocator;

    const Runner = struct {
        fail_index: usize,
        started: std.ArrayList(usize),
        stopped: std.ArrayList(usize),
        tls_started: bool = false,

        fn start(self: *@This(), idx: usize, _: *std.StringHashMapUnmanaged(void)) !void {
            if (idx == self.fail_index) return error.StartFailed;
            try self.started.append(alloc, idx);
        }

        fn stop(self: *@This(), idx: usize) void {
            self.stopped.append(alloc, idx) catch unreachable;
        }

        fn finish(self: *@This()) void {
            self.tls_started = true;
        }
    };

    var runner = Runner{
        .fail_index = 1,
        .started = .empty,
        .stopped = .empty,
    };
    defer runner.started.deinit(alloc);
    defer runner.stopped.deinit(alloc);

    const outcome = try runReplacementPlan(&runner, alloc, &.{0}, &.{1});

    try std.testing.expectEqual(@as(usize, 1), outcome.placed);
    try std.testing.expectEqual(@as(usize, 1), outcome.failed);
    try std.testing.expectEqual(@import("update/common.zig").DeploymentStatus.partially_failed, outcome.status);
    try std.testing.expectEqualStrings("one or more local service replacements failed", outcome.message.?);
    try std.testing.expect(runner.tls_started);
    try std.testing.expectEqual(@as(usize, 1), runner.started.items.len);
    try std.testing.expectEqual(@as(usize, 1), runner.stopped.items.len);
}
