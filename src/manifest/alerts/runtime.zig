const std = @import("std");
const spec = @import("../spec.zig");
const evaluator = @import("evaluator.zig");
const sampling = @import("sampling.zig");
const webhook = @import("webhook.zig");
const status_store = @import("../../state/store/alerts.zig");
const local_ownership = @import("../orchestrator/ownership.zig");
const log = @import("../../lib/log.zig");

const alloc = std.heap.page_allocator;
const metrics = std.meta.tags(evaluator.Metric);
const max_services = 256;
const debug_io = std.Options.debug_io;
var ownership: std.Io.Mutex = .init;
var mutex: std.Io.Mutex = .init;
var entries: std.ArrayList(*Service) = .empty;
var sampler_thread: ?std.Thread = null;
var delivery_thread: ?std.Thread = null;
var stopping: std.atomic.Value(bool) = .init(false);

const RuleState = struct {
    rule: evaluator.Rule,
    sample_error: ?[]const u8 = "waiting for first sample",
    sampled_at: i64 = 0,
    delivery: []const u8 = "idle",
    delivery_error: ?[]const u8 = null,
    delivered_at: ?i64 = null,
    http_status: ?u16 = null,
};

const Service = struct {
    app: []const u8,
    name: []const u8,
    config: spec.AlertSpec,
    references: usize = 1,
    local_restarts: bool,
    owner_token: ?[]const u8 = null,
    cluster_generation: ?u64 = null,
    restart_total: u64 = 0,
    activation_revision: u64 = 0,
    sampler: sampling.Sampler = .{},
    rules: [metrics.len]?RuleState = @splat(null),

    fn deinit(self: *Service) void {
        self.sampler.deinit();
        self.config.deinit(alloc);
        if (self.owner_token) |token| alloc.free(token);
        alloc.free(self.app);
        alloc.free(self.name);
        alloc.destroy(self);
    }

    fn isCurrent(self: *const Service) bool {
        if (self.cluster_generation) |generation| return status_store.isClusterGeneration(self.app, self.name, generation) catch false;
        const token = self.owner_token orelse return true;
        return local_ownership.isOwner(self.app, self.name, token) catch false;
    }

    fn persist(self: *Service, index: usize) void {
        const state = self.rules[index] orelse return;
        status_store.saveForOwner(alloc, .{
            .app = self.app,
            .service = self.name,
            .metric = @tagName(metrics[index]),
            .state = if (self.references == 0) "stopped" else state.rule.status(),
            .active = state.rule.active,
            .threshold = state.rule.threshold,
            .value = state.rule.value,
            .sampled_at = state.sampled_at,
            .sample_error = state.sample_error,
            .delivery = state.delivery,
            .delivery_error = state.delivery_error,
            .delivered_at = state.delivered_at,
            .http_status = state.http_status,
        }, self.owner_token, self.cluster_generation) catch |err| log.warn("alerts: cannot persist {s}/{s}/{s}: {s}", .{ self.app, self.name, @tagName(metrics[index]), @errorName(err) });
    }
};

pub const Registration = struct {
    service: *Service,

    pub fn release(self: Registration) void {
        mutex.lockUncancelable(debug_io);
        defer mutex.unlock(debug_io);
        self.service.references -= 1;
        if (self.service.references == 0) for (metrics, 0..) |_, index| {
            if (self.service.rules[index]) |*state| {
                state.rule.observe(null);
                state.sample_error = "service supervisor stopped";
                self.service.persist(index);
            }
        };
        if (self.service.cluster_generation != null) updateClusterOwner(self.service.app, self.service.name) catch |err| {
            log.warn("alerts: cannot update active assignment generation: {s}", .{@errorName(err)});
        };
    }
};

// registrations borrow no manifest memory. entries stay stable until shutdown,
// so a delivery can finish while its service is being stopped or replaced.
pub fn registerCluster(app: []const u8, name: []const u8, config: spec.AlertSpec, generation: u64) !Registration {
    return registerWithOwner(app, name, config, false, null, generation);
}

pub fn registerOwned(app: []const u8, name: []const u8, config: spec.AlertSpec, token: []const u8) !Registration {
    if (!try local_ownership.isOwner(app, name, token)) return error.SupervisorSuperseded;
    return registerWithOwner(app, name, config, true, token, null);
}

fn registerWithOwner(app: []const u8, name: []const u8, config: spec.AlertSpec, local_restarts: bool, token: ?[]const u8, generation: ?u64) !Registration {
    if (generation) |value| if (value > std.math.maxInt(i64)) return error.InvalidAlertConfig;
    for (metrics) |metric| if (metric.threshold(config)) |threshold| {
        const maximum: f64 = switch (metric) {
            .latency_p99_ms => 1e12,
            .restart_count => std.math.maxInt(u32),
            else => 100,
        };
        if (!std.math.isFinite(threshold) or threshold < 0 or threshold > maximum) return error.InvalidAlertConfig;
    };
    ownership.lockUncancelable(debug_io);
    defer ownership.unlock(debug_io);
    mutex.lockUncancelable(debug_io);
    const service = registerLocked(app, name, config, local_restarts, token, generation) catch |err| {
        mutex.unlock(debug_io);
        return err;
    };
    if (generation != null) {
        updateClusterOwner(app, name) catch |err| {
            service.references -= 1;
            mutex.unlock(debug_io);
            return err;
        };
    } else if (service.references == 1) {
        status_store.clearForOwner(app, name, token) catch |err| {
            service.references -= 1;
            mutex.unlock(debug_io);
            return err;
        };
        for (metrics, 0..) |_, index| service.persist(index);
    }
    mutex.unlock(debug_io);
    errdefer (Registration{ .service = service }).release();
    if (sampler_thread == null and hasRules(service)) {
        stopping.store(false, .release);
        sampler_thread = try std.Thread.spawn(.{}, sampleLoop, .{});
        delivery_thread = std.Thread.spawn(.{}, deliveryLoop, .{}) catch |err| {
            stopping.store(true, .release);
            sampler_thread.?.join();
            sampler_thread = null;
            return err;
        };
    }
    return .{ .service = service };
}

fn registerLocked(app: []const u8, name: []const u8, config: spec.AlertSpec, local_restarts: bool, token: ?[]const u8, generation: ?u64) !*Service {
    for (entries.items) |entry| {
        if (!std.mem.eql(u8, entry.app, app) or !std.mem.eql(u8, entry.name, name) or !sameOwner(entry.owner_token, token) or entry.cluster_generation != generation) continue;
        if (!sameConfig(entry.config, config) or entry.local_restarts != local_restarts) {
            if (entry.references != 0) return error.AlertConfigConflict;
            if (hasDelivery(entry)) return error.AlertDeliveryInProgress;
            const owned_config = try config.clone(alloc);
            entry.config.deinit(alloc);
            entry.config = owned_config;
            entry.local_restarts = local_restarts;
            entry.restart_total = 0;
            entry.sampler.deinit();
            entry.sampler = .{};
            entry.rules = @splat(null);
            for (metrics, 0..) |metric, index| if (metric.threshold(config)) |threshold| {
                entry.rules[index] = .{ .rule = .{ .threshold = threshold } };
            };
        }
        entry.references += 1;
        return entry;
    }
    if (entries.items.len == max_services) {
        for (entries.items, 0..) |entry, index| {
            if (entry.references != 0 or hasDelivery(entry)) continue;
            // only inactive entries can move: registrations and deliveries keep
            // active service pointers stable while sampling holds this mutex.
            _ = entries.swapRemove(index);
            entry.deinit();
            break;
        }
        if (entries.items.len == max_services) return error.TooManyAlertServices;
    }
    const entry = try alloc.create(Service);
    errdefer alloc.destroy(entry);
    const owned_app = try alloc.dupe(u8, app);
    errdefer alloc.free(owned_app);
    const owned_name = try alloc.dupe(u8, name);
    errdefer alloc.free(owned_name);
    const owned_config = try config.clone(alloc);
    errdefer owned_config.deinit(alloc);
    const owned_token = if (token) |owner| try alloc.dupe(u8, owner) else null;
    errdefer if (owned_token) |owner| alloc.free(owner);
    entry.* = .{ .app = owned_app, .name = owned_name, .config = owned_config, .local_restarts = local_restarts, .owner_token = owned_token, .cluster_generation = generation };
    for (metrics, 0..) |metric, index| if (metric.threshold(config)) |threshold| {
        entry.rules[index] = .{ .rule = .{ .threshold = threshold } };
    };
    try entries.append(alloc, entry);
    return entry;
}

// callbacks hold the runtime mutex. a generation switch updates the database
// guard before any old worker can persist a late delivery or stopped state.
fn updateClusterOwner(app: []const u8, name: []const u8) !void {
    var selected: ?u64 = null;
    for (entries.items) |entry| {
        if (entry.references == 0 or !std.mem.eql(u8, entry.app, app) or !std.mem.eql(u8, entry.name, name)) continue;
        if (entry.cluster_generation) |generation| selected = if (selected) |previous| @max(previous, generation) else generation;
    }
    if (!try status_store.setClusterGeneration(app, name, selected)) return;
    for (entries.items) |entry| {
        if (entry.cluster_generation == null or !std.mem.eql(u8, entry.app, app) or !std.mem.eql(u8, entry.name, name)) continue;
        entry.activation_revision +|= 1;
        for (metrics, 0..) |_, index| {
            if (entry.rules[index]) |*state| {
                state.* = .{ .rule = .{ .threshold = state.rule.threshold, .revision = state.rule.revision +| 1, .in_flight = state.rule.in_flight } };
                if (entry.references > 0 and entry.cluster_generation == selected) entry.persist(index);
            }
        }
    }
}

fn hasRules(entry: *const Service) bool {
    for (entry.rules) |rule| if (rule != null) return true;
    return false;
}

fn hasDelivery(entry: *const Service) bool {
    for (entry.rules) |state| if (state) |rule| {
        if (rule.rule.in_flight) return true;
    };
    return false;
}

fn sameOwner(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

fn sameConfig(a: spec.AlertSpec, b: spec.AlertSpec) bool {
    for (metrics) |metric| if (metric.threshold(a) != metric.threshold(b)) return false;
    if (a.webhook == null or b.webhook == null) return a.webhook == null and b.webhook == null;
    return std.mem.eql(u8, a.webhook.?, b.webhook.?);
}

pub fn recordRestart(app: []const u8, service: []const u8, token: []const u8) void {
    mutex.lockUncancelable(debug_io);
    defer mutex.unlock(debug_io);
    for (entries.items) |entry| {
        if (entry.local_restarts and sameOwner(entry.owner_token, token) and std.mem.eql(u8, entry.app, app) and std.mem.eql(u8, entry.name, service)) {
            entry.restart_total +|= 1;
            return;
        }
    }
}

// call after releasing registrations and before destroying process-wide state.
// an in-flight webhook is joined within its ten-second delivery deadline.
pub fn shutdownIfUnused() void {
    ownership.lockUncancelable(debug_io);
    defer ownership.unlock(debug_io);
    mutex.lockUncancelable(debug_io);
    for (entries.items) |entry| {
        if (entry.references != 0) {
            mutex.unlock(debug_io);
            return;
        }
    }
    mutex.unlock(debug_io);
    stopRuntime();
}

pub fn shutdown() void {
    ownership.lockUncancelable(debug_io);
    defer ownership.unlock(debug_io);
    stopRuntime();
}

fn stopRuntime() void {
    stopping.store(true, .release);
    if (sampler_thread) |thread| thread.join();
    if (delivery_thread) |thread| thread.join();
    sampler_thread = null;
    delivery_thread = null;
    mutex.lockUncancelable(debug_io);
    defer mutex.unlock(debug_io);
    for (entries.items) |entry| entry.deinit();
    entries.deinit(alloc);
    entries = .empty;
}

fn nowMs() u64 {
    return @intCast(@max(0, std.Io.Clock.awake.now(debug_io).toMilliseconds()));
}

fn wait(milliseconds: u64) void {
    var remaining = milliseconds;
    while (remaining > 0 and !stopping.load(.acquire)) {
        const chunk = @min(remaining, 100);
        std.Io.sleep(debug_io, .fromMilliseconds(@intCast(chunk)), .awake) catch return;
        remaining -= chunk;
    }
}

fn sampleLoop() void {
    while (!stopping.load(.acquire)) {
        @import("../../network/proxy/observations.zig").flush();
        mutex.lockUncancelable(debug_io);
        for (entries.items) |entry| {
            if (entry.references == 0 or !hasRules(entry) or !entry.isCurrent()) continue;
            const values = entry.sampler.collect(entry.app, entry.name, nowMs(), if (entry.local_restarts) entry.restart_total else null);
            inline for (metrics, 0..) |metric, index| {
                if (entry.rules[index]) |*state| {
                    const value = @field(values, @tagName(metric));
                    state.rule.observe(value);
                    state.sampled_at = std.Io.Clock.real.now(debug_io).toSeconds();
                    state.sample_error = if (value != null) null else switch (metric) {
                        .cpu_percent, .memory_percent => values.resource_error orelse "waiting for cpu delta",
                        .restart_count => "cluster restart accounting unavailable",
                        .latency_p99_ms, .error_rate_percent => values.request_error orelse "no recent completed proxy requests on this host",
                    };
                    entry.persist(index);
                }
            }
        }
        mutex.unlock(debug_io);
        wait(evaluator.interval_ms);
    }
}

fn deliveryLoop() void {
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    var cursor: usize = 0;
    while (!stopping.load(.acquire)) {
        mutex.lockUncancelable(debug_io);
        const selected = selectDelivery(&cursor);
        mutex.unlock(debug_io);
        const work = selected orelse {
            wait(100);
            continue;
        };
        const payload = std.json.Stringify.valueAlloc(alloc, .{
            .app = work.service.app,
            .service = work.service.name,
            .metric = @tagName(metrics[work.index]),
            .state = @tagName(work.event.state),
            .value = work.event.value,
            .threshold = work.threshold,
            .timestamp = std.Io.Clock.real.now(debug_io).toSeconds(),
        }, .{}) catch {
            finishDelivery(work, .{ .failure = "OutOfMemory" });
            continue;
        };
        defer alloc.free(payload);
        const outcome = if (workIsCurrent(work)) webhook.send(alloc, threaded.io(), work.service.config.webhook.?, payload) else webhook.Delivery{ .failure = "SupervisorSuperseded" };
        finishDelivery(work, outcome);
    }
}

const Work = struct { service: *Service, index: usize, event: evaluator.Event, threshold: f64, activation_revision: u64 };

fn workIsCurrent(work: Work) bool {
    mutex.lockUncancelable(debug_io);
    defer mutex.unlock(debug_io);
    return work.activation_revision == work.service.activation_revision and work.service.isCurrent();
}

fn selectDelivery(cursor: *usize) ?Work {
    const count = entries.items.len * metrics.len;
    for (0..count) |_| {
        const slot = cursor.* % count;
        cursor.* = (slot + 1) % count;
        const entry = entries.items[slot / metrics.len];
        const index = slot % metrics.len;
        if (entry.references == 0 or !entry.isCurrent()) continue;
        const state = if (entry.rules[index]) |*state| state else continue;
        const event = state.rule.due(nowMs()) orelse continue;
        if (entry.config.webhook == null) {
            state.delivery = "disabled";
            state.delivery_error = "no webhook configured";
            state.rule.next_attempt_ms = nowMs() +| evaluator.cooldown_ms;
            entry.persist(index);
            continue;
        }
        state.rule.queued();
        state.delivery = "sending";
        entry.persist(index);
        return .{ .service = entry, .index = index, .event = event, .threshold = state.rule.threshold, .activation_revision = entry.activation_revision };
    }
    return null;
}

fn finishDelivery(work: Work, outcome: webhook.Delivery) void {
    mutex.lockUncancelable(debug_io);
    defer mutex.unlock(debug_io);
    const state = &work.service.rules[work.index].?;
    // a retired generation can become current again while its old request is
    // still finishing. that response belongs to the previous activation.
    if (work.activation_revision != work.service.activation_revision) {
        state.rule.in_flight = false;
        return;
    }
    state.rule.delivered(work.event.revision, outcome.failure == null, nowMs());
    state.delivery = if (outcome.failure == null) "delivered" else "failed";
    state.delivery_error = outcome.failure;
    state.http_status = outcome.status;
    if (outcome.failure == null) state.delivered_at = std.Io.Clock.real.now(debug_io).toSeconds();
    work.service.persist(work.index);
}

test "alert registrations own configuration and reject conflicting replicas" {
    mutex.lockUncancelable(debug_io);
    defer mutex.unlock(debug_io);
    defer {
        for (entries.items) |entry| entry.deinit();
        entries.deinit(alloc);
        entries = .empty;
    }
    const config: spec.AlertSpec = .{ .cpu_percent = 90, .webhook = "https://example.com/hook" };
    const first = try registerLocked("app", "web", config, true, null, null);
    const second = try registerLocked("app", "web", config, true, null, null);
    try std.testing.expect(first == second);
    try std.testing.expectEqual(@as(usize, 2), first.references);
    try std.testing.expectError(error.AlertConfigConflict, registerLocked("app", "web", .{ .cpu_percent = 80 }, true, null, null));
}

test "alert runtime joins workers and persists stopped status after last registration" {
    const store = @import("../../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    defer shutdown();
    const registration = try registerCluster("alerts-runtime", "api", .{ .restart_count = 1 }, 0);
    var released = false;
    defer if (!released) registration.release();
    var observed = false;
    for (0..100) |_| {
        const json = try status_store.listJson(std.testing.allocator, "alerts-runtime");
        defer std.testing.allocator.free(json);
        if (std.mem.indexOf(u8, json, "cluster restart accounting unavailable") != null) {
            observed = true;
            break;
        }
        std.Io.sleep(debug_io, .fromMilliseconds(20), .awake) catch {};
    }
    try std.testing.expect(observed);
    registration.release();
    released = true;
    shutdownIfUnused();
    try std.testing.expect(sampler_thread == null);
    try std.testing.expect(delivery_thread == null);
    const json = try status_store.listJson(std.testing.allocator, "alerts-runtime");
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"state\":\"stopped\"") != null);
}

test "alert registry reclaims inactive entries but retains active registrations and deliveries" {
    mutex.lockUncancelable(debug_io);
    defer mutex.unlock(debug_io);
    defer {
        for (entries.items) |entry| entry.deinit();
        entries.deinit(alloc);
        entries = .empty;
    }
    const config: spec.AlertSpec = .{ .cpu_percent = 80 };
    for (0..max_services) |index| {
        var name: [32]u8 = undefined;
        _ = try registerLocked("app", try std.fmt.bufPrint(&name, "service-{d}", .{index}), config, false, null, null);
    }
    try std.testing.expectError(error.TooManyAlertServices, registerLocked("app", "new-service", config, false, null, null));
    entries.items[0].references = 0;
    entries.items[0].rules[0].?.rule.in_flight = true;
    try std.testing.expectError(error.TooManyAlertServices, registerLocked("app", "new-service", config, false, null, null));
    entries.items[0].rules[0].?.rule.in_flight = false;
    const added = try registerLocked("app", "new-service", config, false, null, null);
    try std.testing.expectEqualStrings("new-service", added.name);
    try std.testing.expectEqual(@as(usize, max_services), entries.items.len);
}

test "superseded local alerts cannot deliver or overwrite replacement status on release" {
    const store = @import("../../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    defer shutdown();
    try local_ownership.claim("app", "web", "old-owner");
    const old = blk: {
        mutex.lockUncancelable(debug_io);
        defer mutex.unlock(debug_io);
        const entry = try registerLocked("app", "web", .{ .cpu_percent = 80, .webhook = "https://example.com/old" }, true, "old-owner", null);
        for (0..evaluator.consecutive_samples) |_| entry.rules[0].?.rule.observe(90);
        entry.persist(0);
        break :blk entry;
    };
    try local_ownership.claim("app", "web", "new-owner");
    {
        mutex.lockUncancelable(debug_io);
        defer mutex.unlock(debug_io);
        const replacement = try registerLocked("app", "web", .{ .cpu_percent = 50, .webhook = "https://example.com/new" }, true, "new-owner", null);
        for (0..evaluator.consecutive_samples) |_| replacement.rules[0].?.rule.observe(60);
        replacement.persist(0);
        try std.testing.expect(!old.isCurrent());
        var cursor: usize = 0;
        const selected = selectDelivery(&cursor).?;
        try std.testing.expect(selected.service == replacement);
        replacement.rules[0].?.rule.in_flight = false;
        // a response that arrived after replacement must also fail the write guard.
        old.persist(0);
    }
    (Registration{ .service = old }).release();
    try status_store.clearForOwner("app", "web", "old-owner");
    const json = try status_store.listJson(std.testing.allocator, "app");
    defer std.testing.allocator.free(json);
    const parsed = try std.json.parseFromSlice([]status_store.Status, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.len);
    try std.testing.expectEqual(@as(f64, 50), parsed.value[0].threshold);
    try std.testing.expectEqualStrings("firing", parsed.value[0].state);
    try std.testing.expectError(error.SupervisorSuperseded, registerOwned("app", "web", .{ .cpu_percent = 80 }, "old-owner"));
}

test "cluster alert generations tolerate overlap late arrivals and retirement without reviving pending delivery" {
    const store = @import("../../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    defer shutdown();
    const old_config: spec.AlertSpec = .{ .cpu_percent = 80, .webhook = "https://example.com/old" };
    const new_config: spec.AlertSpec = .{ .cpu_percent = 50, .webhook = "https://example.com/new" };
    const old = try registerLocked("app", "web", old_config, false, null, 1);
    try updateClusterOwner("app", "web");
    for (0..evaluator.consecutive_samples) |_| old.rules[0].?.rule.observe(90);
    const newer = try registerLocked("app", "web", new_config, false, null, 2);
    const same_group = try registerLocked("app", "web", new_config, false, null, 2);
    try std.testing.expect(newer == same_group);
    try updateClusterOwner("app", "web");
    const late = try registerLocked("app", "web", old_config, false, null, 0);
    try updateClusterOwner("app", "web");
    try std.testing.expect(!old.isCurrent() and !late.isCurrent() and newer.isCurrent());
    try std.testing.expect(old.rules[0].?.rule.pending == null);
    for (0..evaluator.consecutive_samples) |_| newer.rules[0].?.rule.observe(60);
    newer.persist(0);
    (Registration{ .service = old }).release();
    (Registration{ .service = same_group }).release();
    old.persist(0);
    var cursor: usize = 0;
    const selected = selectDelivery(&cursor).?;
    try std.testing.expect(selected.service == newer);
    newer.rules[0].?.rule.in_flight = false;
    const current = try status_store.listJson(std.testing.allocator, "app");
    defer std.testing.allocator.free(current);
    try std.testing.expect(std.mem.indexOf(u8, current, "\"threshold\":50") != null);

    // if the newer group is retired, the highest remaining group starts a fresh
    // debounce period. its previously queued firing notification stays cleared.
    (Registration{ .service = newer }).release();
    try std.testing.expect(late.isCurrent());
    try std.testing.expect(late.rules[0].?.rule.pending == null);
    try std.testing.expect(selectDelivery(&cursor) == null);
    const empty = try registerLocked("app", "web", .{}, false, null, 3);
    try updateClusterOwner("app", "web");
    try std.testing.expect(empty.isCurrent() and !late.isCurrent());
    const cleared = try status_store.listJson(std.testing.allocator, "app");
    defer std.testing.allocator.free(cleared);
    try std.testing.expectEqualStrings("[]", cleared);
}

test "cluster alert fallback discards delivery selected before retirement" {
    const store = @import("../../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    defer shutdown();
    const config: spec.AlertSpec = .{ .cpu_percent = 80, .webhook = "https://example.com/hook" };
    const old = try registerLocked("app", "web", config, false, null, 1);
    try updateClusterOwner("app", "web");
    for (0..evaluator.consecutive_samples) |_| old.rules[0].?.rule.observe(90);
    var cursor: usize = 0;
    const selected = selectDelivery(&cursor).?;
    const newer = try registerLocked("app", "web", config, false, null, 2);
    try updateClusterOwner("app", "web");
    (Registration{ .service = newer }).release();
    try std.testing.expect(old.isCurrent());
    try std.testing.expect(!workIsCurrent(selected));
    finishDelivery(selected, .{ .status = 204 });
    try std.testing.expect(!old.rules[0].?.rule.in_flight);
    try std.testing.expectEqualStrings("idle", old.rules[0].?.delivery);
    try std.testing.expect(old.rules[0].?.delivered_at == null);
}
