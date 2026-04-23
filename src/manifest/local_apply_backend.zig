const std = @import("std");
const platform = @import("platform");
const cli = @import("../lib/cli.zig");
const apply_release = @import("apply_release.zig");
const release_history = @import("release_history.zig");
const release_plan = @import("release_plan.zig");
const orchestrator = @import("orchestrator.zig");
const startup_runtime = @import("orchestrator/startup_runtime.zig");
const health = @import("health.zig");
const store = @import("../state/store.zig");
const watcher_mod = @import("../dev/watcher.zig");
const spec = @import("spec.zig");
const update_common = @import("update/common.zig");
const app_spec = @import("app_spec.zig");
const proxy_control_plane = @import("../network/proxy/control_plane.zig");
const service_rollout = @import("../network/service_rollout.zig");
const service_reconciler = @import("../network/service_reconciler.zig");
const listener_runtime = @import("../network/proxy/listener_runtime.zig");
const json_helpers = @import("../lib/json_helpers.zig");

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

const ExistingServiceState = enum {
    active,
    inactive,
};

const ReplacementHealthResult = enum {
    healthy,
    timeout,
    failed,
    canceled,
};

const ReplacementFailureDetail = struct {
    workload_kind: []const u8,
    workload_name: []const u8,
    reason: []const u8,
};

const ReplacementRolloutTarget = struct {
    workload_kind: []const u8,
    workload_name: []const u8,
    state: []const u8,
    reason: ?[]const u8 = null,
};

const ReplacementFailureDetailBuilder = struct {
    alloc: std.mem.Allocator,
    items: std.ArrayListUnmanaged(ReplacementFailureDetail) = .empty,

    fn init(alloc: std.mem.Allocator) ReplacementFailureDetailBuilder {
        return .{ .alloc = alloc };
    }

    fn deinit(self: *ReplacementFailureDetailBuilder) void {
        self.items.deinit(self.alloc);
    }

    fn appendService(self: *ReplacementFailureDetailBuilder, service_name: []const u8, reason: []const u8) !void {
        try self.items.append(self.alloc, .{
            .workload_kind = "service",
            .workload_name = service_name,
            .reason = reason,
        });
    }

    fn appendIndexes(
        self: *ReplacementFailureDetailBuilder,
        services: []const spec.Service,
        indexes: []const usize,
        reason: []const u8,
    ) !void {
        for (indexes) |idx| {
            try self.appendService(services[idx].name, reason);
        }
    }

    fn toOwnedJson(self: *ReplacementFailureDetailBuilder) !?[]u8 {
        if (self.items.items.len == 0) return null;

        var json_buf_writer = std.Io.Writer.Allocating.init(self.alloc);
        defer json_buf_writer.deinit();

        const writer = &json_buf_writer.writer;

        try writer.writeByte('[');
        for (self.items.items, 0..) |detail, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('{');
            try json_helpers.writeJsonStringField(writer, "workload_kind", detail.workload_kind);
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "workload_name", detail.workload_name);
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "reason", detail.reason);
            try writer.writeByte('}');
        }
        try writer.writeByte(']');
        const owned = try json_buf_writer.toOwnedSlice();
        return owned;
    }
};

const ReplacementRolloutTargetBuilder = struct {
    alloc: std.mem.Allocator,
    items: std.ArrayListUnmanaged(ReplacementRolloutTarget) = .empty,

    fn init(alloc: std.mem.Allocator) ReplacementRolloutTargetBuilder {
        return .{ .alloc = alloc };
    }

    fn deinit(self: *ReplacementRolloutTargetBuilder) void {
        self.items.deinit(self.alloc);
    }

    fn appendService(self: *ReplacementRolloutTargetBuilder, service_name: []const u8) !void {
        try self.items.append(self.alloc, .{
            .workload_kind = "service",
            .workload_name = service_name,
            .state = "pending",
            .reason = null,
        });
    }

    fn appendIndexes(
        self: *ReplacementRolloutTargetBuilder,
        services: []const spec.Service,
        indexes: []const usize,
    ) !void {
        for (indexes) |idx| {
            try self.appendService(services[idx].name);
        }
    }

    fn setServiceState(
        self: *ReplacementRolloutTargetBuilder,
        service_name: []const u8,
        state: []const u8,
        reason: ?[]const u8,
    ) void {
        for (self.items.items) |*item| {
            if (std.mem.eql(u8, item.workload_name, service_name)) {
                item.state = state;
                item.reason = reason;
                return;
            }
        }
    }

    fn stateForService(self: *const ReplacementRolloutTargetBuilder, service_name: []const u8) []const u8 {
        for (self.items.items) |item| {
            if (std.mem.eql(u8, item.workload_name, service_name)) return item.state;
        }
        return "pending";
    }

    fn restoreFromJson(self: *ReplacementRolloutTargetBuilder, rollout_targets_json: ?[]const u8) void {
        const json = rollout_targets_json orelse return;
        var iter = json_helpers.extractJsonObjects(json);
        while (iter.next()) |obj| {
            const workload_kind = json_helpers.extractJsonString(obj, "workload_kind") orelse continue;
            if (!std.mem.eql(u8, workload_kind, "service")) continue;
            const workload_name = json_helpers.extractJsonString(obj, "workload_name") orelse continue;
            const state = json_helpers.extractJsonString(obj, "state") orelse continue;
            const reason = json_helpers.extractJsonString(obj, "reason");
            self.setServiceState(workload_name, state, reason);
        }
    }

    fn toOwnedJson(self: *ReplacementRolloutTargetBuilder) !?[]u8 {
        if (self.items.items.len == 0) return null;

        var json_buf_writer = std.Io.Writer.Allocating.init(self.alloc);
        defer json_buf_writer.deinit();

        const writer = &json_buf_writer.writer;

        try writer.writeByte('[');
        for (self.items.items, 0..) |target, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('{');
            try json_helpers.writeJsonStringField(writer, "workload_kind", target.workload_kind);
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "workload_name", target.workload_name);
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "state", target.state);
            try writer.writeByte(',');
            try json_helpers.writeNullableJsonStringField(writer, "reason", target.reason);
            try writer.writeByte('}');
        }
        try writer.writeByte(']');
        return try json_buf_writer.toOwnedSlice();
    }
};

const ReplacementResumeState = struct {
    completed_targets: usize = 0,
    failed_targets: usize = 0,
    rollout_targets_json: ?[]u8 = null,

    fn deinit(self: ReplacementResumeState, alloc: std.mem.Allocator) void {
        if (self.rollout_targets_json) |json| alloc.free(json);
    }
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
        listener_runtime.setStateChangeHook(proxy_control_plane.refreshListenerStateIfEnabled);
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
                const abs_source = platform.cwd().realpath(vol.source, &resolve_buf) catch |e| {
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
        switch (existingServiceState(alloc, release.app.app_name, svc.name)) {
            .active => existing_target_count += 1,
            .inactive => new_target_count += 1,
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

        const is_existing = existingServiceState(alloc, release.app.app_name, svc.name) == .active;
        if (is_existing == want_existing) {
            try indexes.append(alloc, idx);
        }
    }

    return indexes;
}

fn existingServiceState(alloc: std.mem.Allocator, app_name: []const u8, service_name: []const u8) ExistingServiceState {
    const record = store.findAppContainer(alloc, app_name, service_name) catch return .inactive;
    if (record) |container| {
        defer container.deinit(alloc);
        return if (std.mem.eql(u8, container.status, "stopped")) .inactive else .active;
    }
    return .inactive;
}

fn effectiveReplacementStrategy(release: *const release_plan.ReleasePlan) update_common.UpdateStrategy {
    var strategy = update_common.UpdateStrategy{};
    if (release.app.services.len == 0) return strategy;

    strategy = app_spec.rolloutPolicyToUpdateStrategy(release.app.services[0].rollout);
    for (release.app.services[1..]) |svc| {
        const service_strategy = app_spec.rolloutPolicyToUpdateStrategy(svc.rollout);
        strategy.strategy = mergeRolloutStrategy(strategy.strategy, service_strategy.strategy);
        strategy.parallelism = @min(strategy.parallelism, service_strategy.parallelism);
        strategy.delay_between_batches = @max(strategy.delay_between_batches, service_strategy.delay_between_batches);
        strategy.health_check_timeout = @max(strategy.health_check_timeout, service_strategy.health_check_timeout);
        if (service_strategy.failure_action == .pause) strategy.failure_action = .pause;
    }
    return strategy;
}

fn mergeRolloutStrategy(
    left: update_common.RolloutStrategy,
    right: update_common.RolloutStrategy,
) update_common.RolloutStrategy {
    return switch (left) {
        .blue_green => .blue_green,
        .canary => if (right == .blue_green) .blue_green else .canary,
        .rolling => right,
    };
}

fn nextRolloutBatchEnd(
    strategy: update_common.UpdateStrategy,
    start: usize,
    total: usize,
    first_batch: bool,
) usize {
    if (start >= total) return total;
    return switch (strategy.strategy) {
        .blue_green => total,
        .canary => if (first_batch)
            @min(start + 1, total)
        else
            @min(start + @max(@as(usize, 1), @as(usize, strategy.parallelism)), total),
        .rolling => @min(start + @max(@as(usize, 1), @as(usize, strategy.parallelism)), total),
    };
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
    services: []const spec.Service,
    new_indexes: []const usize,
    replacement_indexes: []const usize,
    strategy: update_common.UpdateStrategy,
    initial_completed_targets: usize,
    initial_failed_targets: usize,
    resume_rollout_targets_json: ?[]const u8,
) !apply_release.ApplyOutcome {
    var completed_workers: std.StringHashMapUnmanaged(void) = .empty;
    defer completed_workers.deinit(alloc);
    var failure_details = ReplacementFailureDetailBuilder.init(alloc);
    defer failure_details.deinit();
    var rollout_targets = ReplacementRolloutTargetBuilder.init(alloc);
    defer rollout_targets.deinit();
    try rollout_targets.appendIndexes(services, new_indexes);
    try rollout_targets.appendIndexes(services, replacement_indexes);
    rollout_targets.restoreFromJson(resume_rollout_targets_json);

    var placed: usize = initial_completed_targets;
    var failed: usize = initial_failed_targets;
    var mutated = false;

    var first_rollout_batch = true;
    var new_start: usize = 0;
    while (new_start < new_indexes.len) {
        if (waitForControlIfSupported(runner)) {
            if (mutated) runner.finish();
            return replacementCancelledOutcome(placed, failed, try failure_details.toOwnedJson(), try rollout_targets.toOwnedJson());
        }
        const batch_end = nextRolloutBatchEnd(strategy, new_start, new_indexes.len, first_rollout_batch);
        const batch = new_indexes[new_start..batch_end];
        var started_batch = try alloc.alloc(usize, batch.len);
        defer alloc.free(started_batch);

        var batch_started: usize = 0;
        for (batch) |idx| {
            if (isTerminalRolloutState(rollout_targets.stateForService(services[idx].name))) continue;
            runner.start(idx, &completed_workers) catch {
                failed += 1;
                try failure_details.appendService(services[idx].name, "start_failed");
                rollout_targets.setServiceState(services[idx].name, "failed", "start_failed");
                reportProgressDetailsIfSupported(runner, alloc, "start", new_start, batch_end, new_indexes.len + replacement_indexes.len, placed, failed, &failure_details, &rollout_targets);
                if (!mutated) return error.StartFailed;
                continue;
            };
            started_batch[batch_started] = idx;
            batch_started += 1;
            mutated = true;
            rollout_targets.setServiceState(services[idx].name, "starting", null);
        }

        if (batch_started > 0) {
            const health_results = try waitHealthyIfSupported(alloc, runner, started_batch[0..batch_started], strategy.health_check_timeout);
            defer alloc.free(health_results);

            var batch_completed: usize = 0;
            var batch_failed: usize = 0;
            for (started_batch[0..batch_started], health_results) |idx, health_result| {
                switch (health_result) {
                    .healthy => {
                        batch_completed += 1;
                        rollout_targets.setServiceState(services[idx].name, "ready", null);
                    },
                    .timeout, .failed => {
                        batch_failed += 1;
                        const reason = switch (health_result) {
                            .healthy => unreachable,
                            .timeout => "readiness_timeout",
                            .failed => "readiness_failed",
                            .canceled => unreachable,
                        };
                        try failure_details.appendService(services[idx].name, reason);
                        rollout_targets.setServiceState(services[idx].name, "failed", reason);
                    },
                    .canceled => {
                        rollout_targets.setServiceState(services[idx].name, "blocked", "canceled_by_operator");
                    },
                }
            }

            placed += batch_completed;
            failed += batch_failed;
            reportProgressDetailsIfSupported(runner, alloc, "start", new_start, batch_end, new_indexes.len + replacement_indexes.len, placed, failed, &failure_details, &rollout_targets);

            if (waitForControlIfSupported(runner)) {
                if (mutated) runner.finish();
                return replacementCancelledOutcome(placed, failed, try failure_details.toOwnedJson(), try rollout_targets.toOwnedJson());
            }

            if (batch_failed > 0) {
                if (mutated) runner.finish();
                return replacementFailureOutcome(
                    strategy,
                    placed,
                    failed,
                    try failure_details.toOwnedJson(),
                    try rollout_targets.toOwnedJson(),
                );
            }
        } else if (failed > 0 and !mutated) {
            return error.StartFailed;
        }

        if (batch_started == 0) {
            if (allRemainingServicesTerminal(&rollout_targets, services, batch)) {
                maybeDelayBetweenBatches(strategy.delay_between_batches, batch_end < new_indexes.len);
                new_start = batch_end;
                first_rollout_batch = false;
                continue;
            }
            if (mutated) runner.finish();
            return replacementFailureOutcome(
                strategy,
                placed,
                failed,
                try failure_details.toOwnedJson(),
                try rollout_targets.toOwnedJson(),
            );
        }
        maybeDelayBetweenBatches(strategy.delay_between_batches, batch_end < new_indexes.len);
        new_start = batch_end;
        first_rollout_batch = false;
    }

    var replacement_start: usize = 0;
    while (replacement_start < replacement_indexes.len) {
        if (waitForControlIfSupported(runner)) {
            if (mutated) runner.finish();
            return replacementCancelledOutcome(placed, failed, try failure_details.toOwnedJson(), try rollout_targets.toOwnedJson());
        }
        const batch_end = nextRolloutBatchEnd(strategy, replacement_start, replacement_indexes.len, first_rollout_batch);
        const batch = replacement_indexes[replacement_start..batch_end];
        var started_batch = try alloc.alloc(usize, batch.len);
        defer alloc.free(started_batch);

        var stopped_any = false;
        for (batch) |idx| {
            if (isTerminalRolloutState(rollout_targets.stateForService(services[idx].name))) continue;
            runner.stop(idx);
            stopped_any = true;
        }
        if (stopped_any) mutated = true;

        var batch_started: usize = 0;
        for (batch) |idx| {
            if (isTerminalRolloutState(rollout_targets.stateForService(services[idx].name))) continue;
            runner.start(idx, &completed_workers) catch {
                failed += 1;
                try failure_details.appendService(services[idx].name, "start_failed");
                rollout_targets.setServiceState(services[idx].name, "failed", "start_failed");
                reportProgressDetailsIfSupported(runner, alloc, "replace", replacement_start, batch_end, new_indexes.len + replacement_indexes.len, placed, failed, &failure_details, &rollout_targets);
                continue;
            };
            started_batch[batch_started] = idx;
            batch_started += 1;
            rollout_targets.setServiceState(services[idx].name, "starting", null);
        }

        if (batch_started > 0) {
            const health_results = try waitHealthyIfSupported(alloc, runner, started_batch[0..batch_started], strategy.health_check_timeout);
            defer alloc.free(health_results);

            var batch_completed: usize = 0;
            var batch_failed: usize = 0;
            for (started_batch[0..batch_started], health_results) |idx, health_result| {
                switch (health_result) {
                    .healthy => {
                        batch_completed += 1;
                        rollout_targets.setServiceState(services[idx].name, "ready", null);
                    },
                    .timeout, .failed => {
                        batch_failed += 1;
                        const reason = switch (health_result) {
                            .healthy => unreachable,
                            .timeout => "readiness_timeout",
                            .failed => "readiness_failed",
                            .canceled => unreachable,
                        };
                        try failure_details.appendService(services[idx].name, reason);
                        rollout_targets.setServiceState(services[idx].name, "failed", reason);
                    },
                    .canceled => {
                        rollout_targets.setServiceState(services[idx].name, "blocked", "canceled_by_operator");
                    },
                }
            }

            placed += batch_completed;
            failed += batch_failed;
            reportProgressDetailsIfSupported(runner, alloc, "replace", replacement_start, batch_end, new_indexes.len + replacement_indexes.len, placed, failed, &failure_details, &rollout_targets);

            if (waitForControlIfSupported(runner)) {
                if (mutated) runner.finish();
                return replacementCancelledOutcome(placed, failed, try failure_details.toOwnedJson(), try rollout_targets.toOwnedJson());
            }

            if (batch_failed > 0) {
                if (mutated) runner.finish();
                return replacementFailureOutcome(
                    strategy,
                    placed,
                    failed,
                    try failure_details.toOwnedJson(),
                    try rollout_targets.toOwnedJson(),
                );
            }
        }

        if (batch_started == 0) {
            if (failed > 0) {
                if (mutated) runner.finish();
                return replacementFailureOutcome(
                    strategy,
                    placed,
                    failed,
                    try failure_details.toOwnedJson(),
                    try rollout_targets.toOwnedJson(),
                );
            }
            if (allRemainingServicesTerminal(&rollout_targets, services, batch)) {
                maybeDelayBetweenBatches(strategy.delay_between_batches, batch_end < replacement_indexes.len);
                replacement_start = batch_end;
                first_rollout_batch = false;
                continue;
            }
            if (mutated) runner.finish();
            return replacementFailureOutcome(
                strategy,
                placed,
                failed,
                try failure_details.toOwnedJson(),
                try rollout_targets.toOwnedJson(),
            );
        }

        if (failed > 0) {
            if (mutated) runner.finish();
            return replacementFailureOutcome(
                strategy,
                placed,
                failed,
                try failure_details.toOwnedJson(),
                try rollout_targets.toOwnedJson(),
            );
        }

        maybeDelayBetweenBatches(strategy.delay_between_batches, batch_end < replacement_indexes.len);
        replacement_start = batch_end;
        first_rollout_batch = false;
    }

    if (mutated) runner.finish();

    return .{
        .status = replacementTerminalStatus(placed, failed),
        .message = replacementSuccessMessage(replacement_indexes),
        .placed = placed,
        .failed = failed,
        .completed_targets = placed,
        .failed_targets = failed,
        .failure_details_json = try failure_details.toOwnedJson(),
        .rollout_targets_json = try rollout_targets.toOwnedJson(),
    };
}

fn isTerminalRolloutState(state: []const u8) bool {
    return std.mem.eql(u8, state, "ready") or
        std.mem.eql(u8, state, "failed") or
        std.mem.eql(u8, state, "rolled_back");
}

fn allRemainingServicesTerminal(
    rollout_targets: *const ReplacementRolloutTargetBuilder,
    services: []const spec.Service,
    indexes: []const usize,
) bool {
    for (indexes) |idx| {
        if (!isTerminalRolloutState(rollout_targets.stateForService(services[idx].name))) return false;
    }
    return true;
}

fn replacementTerminalStatus(placed: usize, failed: usize) update_common.DeploymentStatus {
    if (failed == 0) return .completed;
    if (placed > 0) return .partially_failed;
    return .failed;
}

fn replacementSuccessMessage(replacement_indexes: []const usize) []const u8 {
    return if (replacement_indexes.len > 0)
        "all requested services replaced"
    else
        "all requested services started";
}

fn loadReplacementResumeState(
    alloc: std.mem.Allocator,
    progress: ?apply_release.ProgressRecorder,
) ReplacementResumeState {
    const recorder = progress orelse return .{};
    const dep = store.getDeployment(alloc, recorder.release_id) catch return .{};
    defer dep.deinit(alloc);

    return .{
        .completed_targets = dep.completed_targets,
        .failed_targets = dep.failed_targets,
        .rollout_targets_json = if (dep.rollout_targets_json) |json| alloc.dupe(u8, json) catch null else null,
    };
}

fn reportProgressDetailsIfSupported(
    runner: anytype,
    alloc: std.mem.Allocator,
    phase: []const u8,
    batch_start: usize,
    batch_end: usize,
    total_targets: usize,
    completed_targets: usize,
    failed_targets: usize,
    failure_details: *ReplacementFailureDetailBuilder,
    rollout_targets: *ReplacementRolloutTargetBuilder,
) void {
    if (@hasDecl(std.meta.Child(@TypeOf(runner)), "reportProgressDetails")) {
        const failure_details_json = failure_details.toOwnedJson() catch return;
        defer if (failure_details_json) |json| alloc.free(json);
        const rollout_targets_json = rollout_targets.toOwnedJson() catch return;
        defer if (rollout_targets_json) |json| alloc.free(json);
        const control_state = if (@hasField(std.meta.Child(@TypeOf(runner)), "progress"))
            if (runner.progress) |progress| progress.controlState() else apply_release.RolloutControlState.active
        else
            apply_release.RolloutControlState.active;
        const checkpoint_json = apply_release.buildRolloutCheckpointJson(
            alloc,
            "local",
            phase,
            batch_start,
            batch_end,
            total_targets,
            completed_targets,
            failed_targets,
            control_state,
        ) catch return;
        defer alloc.free(checkpoint_json);
        runner.reportProgressDetails(completed_targets, failed_targets, failure_details_json, rollout_targets_json, checkpoint_json);
    } else if (@hasDecl(std.meta.Child(@TypeOf(runner)), "reportProgress")) {
        runner.reportProgress(completed_targets, failed_targets);
    }
}

fn waitForControlIfSupported(runner: anytype) bool {
    if (@hasDecl(std.meta.Child(@TypeOf(runner)), "awaitControl")) {
        return runner.awaitControl();
    }
    return false;
}

fn waitHealthyIfSupported(
    alloc: std.mem.Allocator,
    runner: anytype,
    indexes: []const usize,
    timeout: u32,
) ![]ReplacementHealthResult {
    const results = try alloc.alloc(ReplacementHealthResult, indexes.len);
    errdefer alloc.free(results);

    if (timeout == 0) {
        @memset(results, .healthy);
        return results;
    }
    if (@hasDecl(std.meta.Child(@TypeOf(runner)), "waitHealthyResults")) {
        alloc.free(results);
        return runner.waitHealthyResults(alloc, indexes, timeout);
    }
    if (@hasDecl(std.meta.Child(@TypeOf(runner)), "waitHealthy")) {
        @memset(results, runner.waitHealthy(indexes, timeout));
        return results;
    }
    @memset(results, .healthy);
    return results;
}

fn maybeDelayBetweenBatches(delay_seconds: u32, should_delay: bool) void {
    if (!should_delay or delay_seconds == 0) return;
    platform.sleep(@as(u64, delay_seconds) * std.time.ns_per_s);
}

fn replacementFailureOutcome(
    strategy: update_common.UpdateStrategy,
    placed: usize,
    failed: usize,
    failure_details_json: ?[]const u8,
    rollout_targets_json: ?[]const u8,
) apply_release.ApplyOutcome {
    const status: update_common.DeploymentStatus = switch (strategy.failure_action) {
        .pause => .partially_failed,
        .rollback => if (placed > 0) .partially_failed else .failed,
    };
    return .{
        .status = status,
        .message = switch (strategy.failure_action) {
            .pause => "replacement paused after failed rollout batch",
            .rollback => "replacement failed during rollout batch",
        },
        .placed = placed,
        .failed = failed,
        .completed_targets = placed,
        .failed_targets = failed,
        .failure_details_json = failure_details_json,
        .rollout_targets_json = rollout_targets_json,
    };
}

fn replacementCancelledOutcome(
    placed: usize,
    failed: usize,
    failure_details_json: ?[]const u8,
    rollout_targets_json: ?[]const u8,
) apply_release.ApplyOutcome {
    return .{
        .status = if (placed > 0 or failed > 0) .partially_failed else .failed,
        .message = "rollout canceled by operator",
        .placed = placed,
        .failed = failed,
        .completed_targets = placed,
        .failed_targets = failed,
        .failure_details_json = failure_details_json,
        .rollout_targets_json = rollout_targets_json,
    };
}

fn runScopedApply(scope: LocalApplyScope, runner: anytype) !apply_release.ApplyOutcome {
    return switch (scope.mode) {
        .fresh => runner.runFresh(),
        .replacement_candidate => runner.runReplacement(),
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
        if (self.context.continue_release_id) |existing_id| {
            return @as([]const u8, try self.plan.alloc.dupe(u8, existing_id));
        }
        return release_history.recordAppReleaseStart(self.plan, self.context) catch null;
    }

    pub fn mark(self: *const LocalReleaseTracker, id: []const u8, status: @import("update/common.zig").DeploymentStatus, message: ?[]const u8) !void {
        try self.markProgressDetails(id, status, message, 0, 0, null, null, null);
    }

    pub fn markProgress(
        self: *const LocalReleaseTracker,
        id: []const u8,
        status: @import("update/common.zig").DeploymentStatus,
        message: ?[]const u8,
        completed_targets: usize,
        failed_targets: usize,
    ) !void {
        try self.markProgressDetails(id, status, message, completed_targets, failed_targets, null, null, null);
    }

    pub fn markProgressDetails(
        self: *const LocalReleaseTracker,
        id: []const u8,
        status: @import("update/common.zig").DeploymentStatus,
        message: ?[]const u8,
        completed_targets: usize,
        failed_targets: usize,
        failure_details_json: ?[]const u8,
        rollout_targets_json: ?[]const u8,
        rollout_checkpoint_json: ?[]const u8,
    ) !void {
        const resolved_message = try apply_release.materializeMessage(self.plan.alloc, self.context, status, message);
        defer if (resolved_message) |msg| self.plan.alloc.free(msg);

        @import("update/deployment_store.zig").updateDeploymentProgress(
            id,
            status,
            resolved_message,
            completed_targets,
            failed_targets,
            failure_details_json,
            rollout_targets_json,
            rollout_checkpoint_json,
        ) catch {};
    }

    pub fn freeReleaseId(self: *const LocalReleaseTracker, id: []const u8) void {
        self.plan.alloc.free(id);
    }
};

const LocalApplyBackend = struct {
    orch: *orchestrator.Orchestrator,
    release: *const release_plan.ReleasePlan,
    scope: LocalApplyScope,
    progress: ?apply_release.ProgressRecorder = null,

    pub fn attachProgressRecorder(self: *@This(), recorder: apply_release.ProgressRecorder) void {
        self.progress = recorder;
    }

    pub fn apply(self: *const LocalApplyBackend) !apply_release.ApplyOutcome {
        var runner = ScopedApplyRunner{ .backend = self };
        return runScopedApply(self.scope, &runner);
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

        const resume_state = loadReplacementResumeState(self.orch.alloc, self.progress);
        defer resume_state.deinit(self.orch.alloc);

        var runner = struct {
            orch: *orchestrator.Orchestrator,
            progress: ?apply_release.ProgressRecorder,

            fn start(runner_self: *@This(), idx: usize, completed_workers: *std.StringHashMapUnmanaged(void)) !void {
                try runner_self.orch.startServiceByIndex(idx, completed_workers);
            }

            fn stop(runner_self: *@This(), idx: usize) void {
                runner_self.orch.stopServiceByIndex(idx);
            }

            fn finish(runner_self: *@This()) void {
                runner_self.orch.finishRuntimeSetup();
            }

            fn reportProgress(runner_self: *@This(), completed_targets: usize, failed_targets: usize) void {
                if (runner_self.progress) |progress| {
                    progress.mark(.in_progress, null, completed_targets, failed_targets) catch {};
                }
            }

            fn reportProgressDetails(
                runner_self: *@This(),
                completed_targets: usize,
                failed_targets: usize,
                failure_details_json: ?[]const u8,
                rollout_targets_json: ?[]const u8,
                rollout_checkpoint_json: ?[]const u8,
            ) void {
                if (runner_self.progress) |progress| {
                    progress.markDetails(
                        .in_progress,
                        null,
                        completed_targets,
                        failed_targets,
                        failure_details_json,
                        rollout_targets_json,
                        rollout_checkpoint_json,
                    ) catch {};
                }
            }

            fn awaitControl(runner_self: *@This()) bool {
                if (runner_self.progress) |progress| {
                    return progress.waitWhilePaused() catch false;
                }
                return false;
            }

            fn waitHealthyResults(
                runner_self: *@This(),
                alloc: std.mem.Allocator,
                indexes: []const usize,
                timeout: u32,
            ) ![]ReplacementHealthResult {
                const results = try alloc.alloc(ReplacementHealthResult, indexes.len);
                @memset(results, .timeout);
                const deadline = @as(u64, @intCast(@max(0, platform.timestamp()))) + timeout;
                var remaining = indexes.len;
                while (@as(u64, @intCast(@max(0, platform.timestamp()))) < deadline) {
                    if (runner_self.awaitControl()) {
                        for (results) |*result| {
                            if (result.* == .timeout) {
                                result.* = .canceled;
                            }
                        }
                        return results;
                    }
                    for (indexes, 0..) |idx, i| {
                        if (results[i] != .timeout) continue;
                        const svc = runner_self.orch.manifest.services[idx];
                        if (svc.health_check == null) {
                            results[i] = .healthy;
                            remaining -= 1;
                            continue;
                        }
                        const status = health.getStatus(svc.name) orelse {
                            break;
                        };
                        switch (status) {
                            .healthy => {
                                results[i] = .healthy;
                                remaining -= 1;
                            },
                            .unhealthy => {
                                results[i] = .failed;
                                remaining -= 1;
                            },
                            .starting => {},
                        }
                    }
                    if (remaining == 0) return results;
                    platform.sleep(100 * std.time.ns_per_ms);
                }
                return results;
            }
        }{ .orch = self.orch, .progress = self.progress };

        return runReplacementPlan(
            &runner,
            self.orch.alloc,
            self.orch.manifest.services,
            new_indexes.items,
            replacement_indexes.items,
            effectiveReplacementStrategy(self.release),
            resume_state.completed_targets,
            resume_state.failed_targets,
            resume_state.rollout_targets_json,
        );
    }

    pub fn failureMessage(_: *const LocalApplyBackend, _: anytype) ?[]const u8 {
        return "service startup failed";
    }
};

const ScopedApplyRunner = struct {
    backend: *const LocalApplyBackend,

    fn runFresh(self: *@This()) !apply_release.ApplyOutcome {
        try self.backend.orch.startAll();
        if (self.backend.progress) |progress| {
            progress.mark(.in_progress, null, self.backend.release.resolvedServiceCount(), 0) catch {};
        }
        return .{
            .status = .completed,
            .message = "all requested services started",
            .placed = self.backend.release.resolvedServiceCount(),
            .completed_targets = self.backend.release.resolvedServiceCount(),
            .failed_targets = 0,
        };
    }

    fn runReplacement(self: *@This()) !apply_release.ApplyOutcome {
        return self.backend.applyReplacementCandidate();
    }
};

test "PreparedLocalApply init resolves filtered start set" {
    const alloc = std.testing.allocator;
    const loader = @import("loader.zig");

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
    const services = [_]spec.Service{
        .{ .name = "db", .image = "postgres:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
        .{ .name = "web", .image = "nginx:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
    };

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

    const outcome = try runReplacementPlan(&runner, alloc, &services, &.{0}, &.{1}, .{ .parallelism = 1, .health_check_timeout = 0 }, 0, 0, null);
    defer if (outcome.failure_details_json) |json| alloc.free(json);
    defer if (outcome.rollout_targets_json) |json| alloc.free(json);

    try std.testing.expectEqual(@as(usize, 2), outcome.placed);
    try std.testing.expectEqual(@as(usize, 0), outcome.failed);
    try std.testing.expectEqual(@import("update/common.zig").DeploymentStatus.completed, outcome.status);
    try std.testing.expectEqualStrings("all requested services replaced", outcome.message.?);
    try std.testing.expect(outcome.rollout_targets_json != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rollout_targets_json.?, "\"workload_name\":\"db\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rollout_targets_json.?, "\"state\":\"ready\"") != null);
    try std.testing.expect(runner.tls_started);
    try std.testing.expectEqual(@as(usize, 2), runner.started.items.len);
    try std.testing.expectEqual(@as(usize, 1), runner.stopped.items.len);
    try std.testing.expectEqual(@as(usize, 0), runner.started.items[0]);
    try std.testing.expectEqual(@as(usize, 1), runner.started.items[1]);
    try std.testing.expectEqual(@as(usize, 1), runner.stopped.items[0]);
}

test "runReplacementPlan reports partial failure after mutation" {
    const alloc = std.testing.allocator;
    const services = [_]spec.Service{
        .{ .name = "db", .image = "postgres:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
        .{ .name = "web", .image = "nginx:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
    };

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

    const outcome = try runReplacementPlan(&runner, alloc, &services, &.{0}, &.{1}, .{ .parallelism = 1, .health_check_timeout = 0 }, 0, 0, null);
    defer if (outcome.failure_details_json) |json| alloc.free(json);
    defer if (outcome.rollout_targets_json) |json| alloc.free(json);

    try std.testing.expectEqual(@as(usize, 1), outcome.placed);
    try std.testing.expectEqual(@as(usize, 1), outcome.failed);
    try std.testing.expectEqual(@import("update/common.zig").DeploymentStatus.partially_failed, outcome.status);
    try std.testing.expectEqualStrings("replacement failed during rollout batch", outcome.message.?);
    try std.testing.expect(outcome.failure_details_json != null);
    try std.testing.expect(outcome.rollout_targets_json != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.failure_details_json.?, "\"workload_name\":\"web\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.failure_details_json.?, "\"reason\":\"start_failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rollout_targets_json.?, "\"workload_name\":\"web\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rollout_targets_json.?, "\"state\":\"failed\"") != null);
    try std.testing.expect(runner.tls_started);
    try std.testing.expectEqual(@as(usize, 1), runner.started.items.len);
    try std.testing.expectEqual(@as(usize, 1), runner.stopped.items.len);
}

test "runReplacementPlan emits live target progress after each update" {
    const alloc = std.testing.allocator;
    const services = [_]spec.Service{
        .{ .name = "db", .image = "postgres:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
        .{ .name = "web", .image = "nginx:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
    };

    const Progress = struct {
        completed_targets: usize,
        failed_targets: usize,
    };

    const Runner = struct {
        started: std.ArrayList(usize),
        progress_updates: std.ArrayList(Progress),

        fn start(self: *@This(), idx: usize, _: *std.StringHashMapUnmanaged(void)) !void {
            try self.started.append(alloc, idx);
        }

        fn stop(_: *@This(), _: usize) void {}

        fn finish(_: *@This()) void {}

        fn reportProgress(self: *@This(), completed_targets: usize, failed_targets: usize) void {
            self.progress_updates.append(alloc, .{
                .completed_targets = completed_targets,
                .failed_targets = failed_targets,
            }) catch unreachable;
        }
    };

    var runner = Runner{
        .started = .empty,
        .progress_updates = .empty,
    };
    defer runner.started.deinit(alloc);
    defer runner.progress_updates.deinit(alloc);

    const outcome = try runReplacementPlan(&runner, alloc, &services, &.{0}, &.{1}, .{ .parallelism = 1, .health_check_timeout = 0 }, 0, 0, null);
    defer if (outcome.failure_details_json) |json| alloc.free(json);
    defer if (outcome.rollout_targets_json) |json| alloc.free(json);
    defer if (outcome.rollout_checkpoint_json) |json| alloc.free(json);

    try std.testing.expectEqual(@as(usize, 2), runner.progress_updates.items.len);
    try std.testing.expectEqual(@as(usize, 1), runner.progress_updates.items[0].completed_targets);
    try std.testing.expectEqual(@as(usize, 0), runner.progress_updates.items[0].failed_targets);
    try std.testing.expectEqual(@as(usize, 2), runner.progress_updates.items[1].completed_targets);
    try std.testing.expectEqual(@as(usize, 0), runner.progress_updates.items[1].failed_targets);
}

test "runReplacementPlan reports readiness timeout details" {
    const alloc = std.testing.allocator;
    const services = [_]spec.Service{
        .{ .name = "db", .image = "postgres:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
    };

    const Runner = struct {
        control_checks: usize = 0,

        fn start(_: *@This(), _: usize, _: *std.StringHashMapUnmanaged(void)) !void {}
        fn stop(_: *@This(), _: usize) void {}
        fn finish(_: *@This()) void {}
        fn waitHealthy(_: *@This(), _: []const usize, _: u32) ReplacementHealthResult {
            return .timeout;
        }
    };

    var runner = Runner{};
    const outcome = try runReplacementPlan(&runner, alloc, &services, &.{0}, &.{}, .{
        .parallelism = 1,
        .health_check_timeout = 5,
        .failure_action = .pause,
    }, 0, 0, null);
    defer if (outcome.failure_details_json) |json| alloc.free(json);
    defer if (outcome.rollout_targets_json) |json| alloc.free(json);

    try std.testing.expectEqual(update_common.DeploymentStatus.partially_failed, outcome.status);
    try std.testing.expect(outcome.failure_details_json != null);
    try std.testing.expect(outcome.rollout_targets_json != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.failure_details_json.?, "\"workload_name\":\"db\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.failure_details_json.?, "\"reason\":\"readiness_timeout\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rollout_targets_json.?, "\"reason\":\"readiness_timeout\"") != null);
}

test "runReplacementPlan tracks mixed per-target readiness outcomes" {
    const alloc = std.testing.allocator;
    const services = [_]spec.Service{
        .{ .name = "db", .image = "postgres:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
        .{ .name = "web", .image = "nginx:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
    };

    const Runner = struct {
        fn start(_: *@This(), _: usize, _: *std.StringHashMapUnmanaged(void)) !void {}
        fn stop(_: *@This(), _: usize) void {}
        fn finish(_: *@This()) void {}
        fn waitHealthyResults(_: *@This(), alloc_inner: std.mem.Allocator, _: []const usize, _: u32) ![]ReplacementHealthResult {
            const results = try alloc_inner.alloc(ReplacementHealthResult, 2);
            results[0] = .healthy;
            results[1] = .failed;
            return results;
        }
    };

    var runner = Runner{};
    const outcome = try runReplacementPlan(&runner, alloc, &services, &.{ 0, 1 }, &.{}, .{
        .parallelism = 2,
        .health_check_timeout = 5,
        .failure_action = .pause,
    }, 0, 0, null);
    defer if (outcome.failure_details_json) |json| alloc.free(json);
    defer if (outcome.rollout_targets_json) |json| alloc.free(json);

    try std.testing.expectEqual(@as(usize, 1), outcome.placed);
    try std.testing.expectEqual(@as(usize, 1), outcome.failed);
    try std.testing.expectEqual(update_common.DeploymentStatus.partially_failed, outcome.status);
    try std.testing.expect(outcome.failure_details_json != null);
    try std.testing.expect(outcome.rollout_targets_json != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.failure_details_json.?, "\"workload_name\":\"web\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.failure_details_json.?, "\"reason\":\"readiness_failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rollout_targets_json.?, "\"workload_name\":\"db\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rollout_targets_json.?, "\"state\":\"ready\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rollout_targets_json.?, "\"workload_name\":\"web\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rollout_targets_json.?, "\"reason\":\"readiness_failed\"") != null);
}

test "runReplacementPlan resumes only unfinished targets from stored rollout state" {
    const alloc = std.testing.allocator;
    const services = [_]spec.Service{
        .{ .name = "db", .image = "postgres:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
        .{ .name = "web", .image = "nginx:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
    };

    const Runner = struct {
        started: std.ArrayList(usize),

        fn start(self: *@This(), idx: usize, _: *std.StringHashMapUnmanaged(void)) !void {
            try self.started.append(alloc, idx);
        }

        fn stop(_: *@This(), _: usize) void {}
        fn finish(_: *@This()) void {}
    };

    var runner = Runner{ .started = .empty };
    defer runner.started.deinit(alloc);

    const outcome = try runReplacementPlan(
        &runner,
        alloc,
        &services,
        &.{ 0, 1 },
        &.{},
        .{ .parallelism = 1, .health_check_timeout = 0 },
        1,
        0,
        "[{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"state\":\"ready\",\"reason\":null},{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"pending\",\"reason\":null}]",
    );
    defer if (outcome.failure_details_json) |json| alloc.free(json);
    defer if (outcome.rollout_targets_json) |json| alloc.free(json);

    try std.testing.expectEqual(@as(usize, 1), runner.started.items.len);
    try std.testing.expectEqual(@as(usize, 1), runner.started.items[0]);
    try std.testing.expectEqual(@as(usize, 2), outcome.placed);
    try std.testing.expect(outcome.rollout_targets_json != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rollout_targets_json.?, "\"workload_name\":\"db\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rollout_targets_json.?, "\"workload_name\":\"web\"") != null);
}

test "runReplacementPlan reports canceled rollout before mutation" {
    const alloc = std.testing.allocator;
    const services = [_]spec.Service{
        .{ .name = "web", .image = "nginx:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
    };

    const Runner = struct {
        started: usize = 0,
        control_checks: usize = 0,

        fn start(self: *@This(), _: usize, _: *std.StringHashMapUnmanaged(void)) !void {
            self.started += 1;
        }

        fn stop(_: *@This(), _: usize) void {}
        fn finish(_: *@This()) void {}

        fn awaitControl(self: *@This()) bool {
            self.control_checks += 1;
            return self.control_checks >= 1;
        }
    };

    var runner = Runner{};
    const outcome = try runReplacementPlan(&runner, alloc, &services, &.{0}, &.{}, .{
        .parallelism = 1,
        .health_check_timeout = 0,
    }, 0, 0, null);
    defer if (outcome.failure_details_json) |json| alloc.free(json);
    defer if (outcome.rollout_targets_json) |json| alloc.free(json);

    try std.testing.expectEqual(update_common.DeploymentStatus.failed, outcome.status);
    try std.testing.expectEqualStrings("rollout canceled by operator", outcome.message.?);
    try std.testing.expectEqual(@as(usize, 0), outcome.placed);
    try std.testing.expectEqual(@as(usize, 0), outcome.failed);
    try std.testing.expectEqual(@as(usize, 0), runner.started);
}

test "runReplacementPlan reports canceled rollout after mutation" {
    const alloc = std.testing.allocator;
    const services = [_]spec.Service{
        .{ .name = "db", .image = "postgres:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
        .{ .name = "web", .image = "nginx:latest", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{} },
    };

    const Runner = struct {
        started: std.ArrayList(usize),
        control_checks: usize = 0,

        fn start(self: *@This(), idx: usize, _: *std.StringHashMapUnmanaged(void)) !void {
            try self.started.append(alloc, idx);
        }

        fn stop(_: *@This(), _: usize) void {}
        fn finish(_: *@This()) void {}

        fn awaitControl(self: *@This()) bool {
            self.control_checks += 1;
            return self.control_checks >= 2;
        }
    };

    var runner = Runner{
        .started = .empty,
    };
    defer runner.started.deinit(alloc);

    const outcome = try runReplacementPlan(&runner, alloc, &services, &.{0}, &.{1}, .{
        .parallelism = 1,
        .health_check_timeout = 0,
    }, 0, 0, null);
    defer if (outcome.failure_details_json) |json| alloc.free(json);
    defer if (outcome.rollout_targets_json) |json| alloc.free(json);

    try std.testing.expectEqual(update_common.DeploymentStatus.partially_failed, outcome.status);
    try std.testing.expectEqualStrings("rollout canceled by operator", outcome.message.?);
    try std.testing.expectEqual(@as(usize, 1), outcome.placed);
    try std.testing.expectEqual(@as(usize, 0), outcome.failed);
    try std.testing.expectEqual(@as(usize, 1), runner.started.items.len);
    try std.testing.expectEqual(@as(usize, 0), runner.started.items[0]);
}

test "effectiveReplacementStrategy chooses conservative rollout settings" {
    const alloc = std.testing.allocator;
    const loader = @import("loader.zig");

    var manifest = try loader.loadFromString(alloc,
        \\[service.api]
        \\image = "alpine:latest"
        \\[service.api.rollout]
        \\strategy = "canary"
        \\parallelism = 3
        \\delay_between_batches = "2s"
        \\health_check_timeout = "15s"
        \\
        \\[service.web]
        \\image = "nginx:latest"
        \\[service.web.rollout]
        \\strategy = "blue_green"
        \\parallelism = 2
        \\failure_action = "pause"
        \\health_check_timeout = "5s"
    );
    defer manifest.deinit();

    var app = try app_spec.fromManifest(alloc, "demo-app", &manifest);
    defer app.deinit();

    var release = try release_plan.ReleasePlan.fromAppSpec(alloc, &app, &.{});
    defer release.deinit();

    const strategy = effectiveReplacementStrategy(&release);
    try std.testing.expectEqual(update_common.RolloutStrategy.blue_green, strategy.strategy);
    try std.testing.expectEqual(@as(u32, 2), strategy.parallelism);
    try std.testing.expectEqual(@as(u32, 2), strategy.delay_between_batches);
    try std.testing.expectEqual(@as(u32, 15), strategy.health_check_timeout);
    try std.testing.expectEqual(update_common.FailureAction.pause, strategy.failure_action);
}

test "nextRolloutBatchEnd uses canary first batch then configured parallelism" {
    const strategy: update_common.UpdateStrategy = .{
        .strategy = .canary,
        .parallelism = 3,
    };

    try std.testing.expectEqual(@as(usize, 1), nextRolloutBatchEnd(strategy, 0, 5, true));
    try std.testing.expectEqual(@as(usize, 4), nextRolloutBatchEnd(strategy, 1, 5, false));
}

test "nextRolloutBatchEnd uses full batch for blue green" {
    const strategy: update_common.UpdateStrategy = .{
        .strategy = .blue_green,
        .parallelism = 1,
    };

    try std.testing.expectEqual(@as(usize, 5), nextRolloutBatchEnd(strategy, 0, 5, true));
}

test "runScopedApply chooses replacement branch for replacement candidates" {
    const Runner = struct {
        fresh_calls: usize = 0,
        replacement_calls: usize = 0,

        fn runFresh(self: *@This()) !apply_release.ApplyOutcome {
            self.fresh_calls += 1;
            return .{ .status = .completed, .placed = 1 };
        }

        fn runReplacement(self: *@This()) !apply_release.ApplyOutcome {
            self.replacement_calls += 1;
            return .{ .status = .completed, .placed = 2 };
        }
    };

    var runner = Runner{};
    const outcome = try runScopedApply(.{
        .mode = .replacement_candidate,
        .existing_target_count = 1,
        .new_target_count = 0,
    }, &runner);

    try std.testing.expectEqual(@as(usize, 0), runner.fresh_calls);
    try std.testing.expectEqual(@as(usize, 1), runner.replacement_calls);
    try std.testing.expectEqual(@as(usize, 2), outcome.placed);
}
