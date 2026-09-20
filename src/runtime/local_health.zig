const std = @import("std");
const spec = @import("../image/spec.zig");
const run_state = @import("run_state.zig");
const process = @import("process.zig");
const cgroups = @import("cgroups.zig");
const exec_runtime = @import("exec.zig");
const runtime_wait = @import("../lib/runtime_wait.zig");
const log = @import("../lib/log.zig");
const AppContext = @import("../lib/app_context.zig").AppContext;
const health_state = @import("local_health/state.zig");
const health_store = @import("local_health/store.zig");
const check = @import("local_health/check.zig");

pub const read = health_store.read;
pub const remove = health_store.remove;
pub const Record = health_store.Record;
pub const cleanupOrphans = check.cleanupOrphans;
pub const Settings = health_state.Settings;

const Availability = enum { ready, paused, stopped };
const ownership_retry_ns = std.time.ns_per_s;

pub const Monitor = struct {
    id: []const u8,
    pid: i32,
    generation: i64,
    cfg: *const run_state.SavedRunConfig,
    parsed: spec.ParseResult(spec.Healthcheck),
    settings: health_state.Settings,
    state: health_state.State,
    cancelled: std.atomic.Value(bool) = .init(false),
    worker: ?std.Thread = null,
    failed_group: ?check.Group = null,
    monitor_failed: bool = false,

    /// the caller retains cfg until stop returns. stop cancels checks and joins
    /// the worker before releasing the monitor.
    pub fn start(id: []const u8, pid: i32, generation: i64, cfg: *const run_state.SavedRunConfig) !?*Monitor {
        const bytes = cfg.healthcheck_json orelse {
            try health_store.clearCurrent(id, pid, generation);
            return null;
        };
        const alloc = std.heap.page_allocator;
        var parsed = try spec.parseJson(spec.Healthcheck, alloc, bytes);
        errdefer parsed.deinit();
        const settings = (try health_state.Settings.fromImage(parsed.value)) orelse {
            try health_store.clearCurrent(id, pid, generation);
            parsed.deinit();
            return null;
        };
        const owned_id = try alloc.dupe(u8, id);
        errdefer alloc.free(owned_id);
        const self = try alloc.create(Monitor);
        errdefer alloc.destroy(self);
        self.* = .{
            .id = owned_id,
            .pid = pid,
            .generation = generation,
            .cfg = cfg,
            .parsed = parsed,
            .settings = settings,
            .state = .{ .started_ns = nowNs() },
        };
        try health_store.write(id, pid, generation, self.state, null);
        self.worker = std.Thread.spawn(.{}, run, .{self}) catch |err| {
            health_store.markUnavailable(id, pid, generation) catch {};
            return err;
        };
        return self;
    }

    pub fn stop(self: *Monitor) !void {
        self.cancelled.store(true, .release);
        if (self.worker) |worker| worker.join();
        defer {
            self.parsed.deinit();
            std.heap.page_allocator.free(self.id);
            std.heap.page_allocator.destroy(self);
        }
        if (self.failed_group) |group| try group.cleanup();
    }

    pub fn availability(self: *const Monitor) !Availability {
        if (!try health_store.current(self.id, self.pid, self.generation)) return .stopped;
        if (process.hasExited(self.pid)) return .stopped;
        try process.sendSignal(self.pid, 0);
        const group = try cgroups.Cgroup.open(self.id);
        const contains = group.containsProcessChecked(self.pid) catch |err| {
            // a deleted group confirms teardown; an unreadable group does not.
            std.Io.Dir.cwd().access(std.Options.debug_io, group.path(), .{}) catch |access_err| switch (access_err) {
                error.FileNotFound => return .stopped,
                else => return access_err,
            };
            return err;
        };
        if (!contains) return .stopped;
        return if (try group.isFrozen()) .paused else .ready;
    }

    fn reportUnavailable(self: *Monitor, err: anyerror) void {
        if (!self.monitor_failed) log.warn("container {s}: health monitoring unavailable: {}", .{ self.id, err });
        self.monitor_failed = true;
        // keep the last completed result and application failure streak. an
        // ownership or monitor failure is not a failed application probe.
        health_store.markUnavailable(self.id, self.pid, self.generation) catch {};
    }

    fn run(self: *Monitor) void {
        while (true) {
            const interval = if (self.monitor_failed) ownership_retry_ns else self.state.interval(self.settings, nowNs());
            if (!waitForCheck(self, interval)) return;
            const result = check.run(self, self.settings.timeout_ns) catch |err| {
                self.reportUnavailable(err);
                // retrying a probe could overlap descendants whose cleanup
                // failed. stop retains the group and retries its teardown.
                if (self.failed_group != null) return;
                continue;
            };
            const code: u8 = switch (result.outcome) {
                .cancelled => continue,
                .timed_out => 124,
                .exited => |code| code,
            };
            self.state.observe(self.settings, nowNs(), code == 0);
            health_store.writeResult(self.id, self.pid, self.generation, self.state, code, &result.output) catch |err| {
                self.reportUnavailable(err);
                continue;
            };
            self.monitor_failed = false;
        }
    }

    fn isCancelled(self: *const Monitor) bool {
        return self.cancelled.load(.acquire);
    }

    fn now(_: *const Monitor) i96 {
        return std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds();
    }

    fn pause(self: *const Monitor, duration: u64) bool {
        const deadline = self.now() + duration;
        while (self.now() < deadline) {
            if (self.isCancelled()) return false;
            const remaining: u64 = @intCast(@max(0, deadline - self.now()));
            const step = @min(remaining, 50 * std.time.ns_per_ms);
            if (!runtime_wait.sleep(std.Io.Duration.fromNanoseconds(@intCast(step)), "container healthcheck interval")) return false;
        }
        return !self.isCancelled();
    }
};

// ownership failures delay the next probe instead of ending its monitor.
// the injected clock keeps cancellation and recovery tests independent of time.
fn waitForCheck(monitor: anytype, duration: u64) bool {
    const deadline = monitor.now() + duration;
    while (!monitor.isCancelled()) {
        const available = monitor.availability() catch |err| {
            monitor.reportUnavailable(err);
            if (!monitor.pause(ownership_retry_ns)) return false;
            continue;
        };
        if (available == .stopped) return false;
        const remaining = @max(0, deadline - monitor.now());
        if (available == .ready and remaining == 0) return true;
        const delay: u64 = if (available == .paused) 50 * std.time.ns_per_ms else @intCast(@min(remaining, 50 * std.time.ns_per_ms));
        if (!monitor.pause(delay)) return false;
    }
    return false;
}

fn nowNs() i64 {
    return @intCast(std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds());
}

/// internal subprocess entrypoint. the supervisor owns its lifetime and cgroup.
pub fn helper(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const id = args.next() orelse return error.InvalidArgument;
    const pid = try std.fmt.parseInt(i32, args.next() orelse return error.InvalidArgument, 10);
    const generation = try std.fmt.parseInt(i64, args.next() orelse return error.InvalidArgument, 10);
    if (args.next() != null or pid <= 0) return error.InvalidArgument;
    var gate: [1]u8 = undefined;
    var stdin_buffer: [16]u8 = undefined;
    var stdin = std.Io.File.stdin().readerStreaming(ctx.io, &stdin_buffer);
    try stdin.interface.readSliceAll(&gate);
    if (gate[0] != '1' or !try health_store.current(id, pid, generation)) return error.CheckCancelled;
    const group = try cgroups.Cgroup.open(id);
    if (!try group.containsProcessChecked(pid) or try group.isFrozen()) return error.CheckCancelled;
    var cfg = try run_state.loadConfig(ctx.alloc, id);
    defer cfg.deinit(ctx.alloc);
    const bytes = cfg.healthcheck_json orelse return error.CheckCancelled;
    var parsed = try spec.parseJson(spec.Healthcheck, ctx.alloc, bytes);
    defer parsed.deinit();
    _ = (try health_state.Settings.fromImage(parsed.value)) orelse return error.CheckCancelled;
    const command = parsed.value.Test.?;
    const shell = std.mem.eql(u8, command[0], "CMD-SHELL");
    const code = try exec_runtime.execInContainer(.{
        .pid = pid,
        .command = if (shell) "/bin/sh" else command[1],
        .args = if (shell) &.{ "-c", command[1] } else command[2..],
        .env = cfg.env,
        .working_dir = cfg.working_dir,
        .user = cfg.user,
    });
    std.process.exit(code);
}

test {
    _ = health_state;
    _ = health_store;
    _ = check;
}

test "health monitoring retries unknown ownership and resumes without spinning" {
    const Observer = struct {
        time: i96 = 0,
        failures_left: usize = 2,
        reports: usize = 0,
        sleeps: usize = 0,
        stop: bool = false,
        cancel_on_sleep: bool = false,
        cancelled: bool = false,

        fn now(self: *@This()) i96 {
            return self.time;
        }
        fn isCancelled(self: *@This()) bool {
            return self.cancelled;
        }
        fn availability(self: *@This()) !Availability {
            if (self.stop) return .stopped;
            if (self.failures_left > 0) {
                self.failures_left -= 1;
                return error.ReadFailed;
            }
            return .ready;
        }
        fn reportUnavailable(self: *@This(), _: anyerror) void {
            self.reports += 1;
        }
        fn pause(self: *@This(), duration: u64) bool {
            self.sleeps += 1;
            self.time += duration;
            self.cancelled = self.cancel_on_sleep;
            return !self.cancelled;
        }
    };
    var observer: Observer = .{};
    try std.testing.expect(waitForCheck(&observer, 0));
    try std.testing.expectEqual(@as(usize, 2), observer.reports);
    try std.testing.expectEqual(@as(usize, 2), observer.sleeps);
    try std.testing.expectEqual(@as(i96, 2 * std.time.ns_per_s), observer.time);

    observer = .{ .cancel_on_sleep = true };
    try std.testing.expect(!waitForCheck(&observer, 0));
    try std.testing.expectEqual(@as(usize, 1), observer.reports);
    observer = .{ .stop = true };
    try std.testing.expect(!waitForCheck(&observer, 0));
    try std.testing.expectEqual(@as(usize, 0), observer.sleeps);
}
