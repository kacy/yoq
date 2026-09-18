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

    /// The caller retains cfg until stop returns. The worker owns its parser,
    /// subprocesses and cgroup, and is always joined before those are released.
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
            self.state.status = .unhealthy;
            health_store.write(id, pid, generation, self.state, 125) catch {};
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

    pub fn isCurrent(self: *const Monitor) bool {
        if (!(health_store.current(self.id, self.pid, self.generation) catch false)) return false;
        process.sendSignal(self.pid, 0) catch return false;
        const cgroup = cgroups.Cgroup.open(self.id) catch return false;
        return cgroup.containsProcessChecked(self.pid) catch false;
    }

    pub fn isPaused(self: *const Monitor) bool {
        const group = cgroups.Cgroup.open(self.id) catch return false;
        return group.isFrozen() catch false;
    }

    fn run(self: *Monitor) void {
        while (!self.cancelled.load(.acquire) and self.isCurrent()) {
            if (!self.waitInterval(self.state.interval(self.settings, nowNs()))) return;
            const group = cgroups.Cgroup.open(self.id) catch return;
            if (group.isFrozen() catch return) continue;
            const outcome = check.run(self, self.settings.timeout_ns) catch |err| {
                log.warn("container {s}: healthcheck failed: {}", .{ self.id, err });
                self.state.observe(self.settings, nowNs(), false);
                if (self.failed_group != null) self.state.status = .unhealthy;
                health_store.write(self.id, self.pid, self.generation, self.state, 125) catch {};
                if (self.failed_group != null) return;
                continue;
            };
            const code: u8 = switch (outcome) {
                .cancelled => {
                    if (self.cancelled.load(.acquire) or !self.isCurrent()) return;
                    continue;
                },
                .timed_out => 124,
                .exited => |code| code,
            };
            self.state.observe(self.settings, nowNs(), code == 0);
            health_store.write(self.id, self.pid, self.generation, self.state, code) catch |err| {
                log.warn("container {s}: cannot save health status: {}", .{ self.id, err });
            };
        }
    }

    fn waitInterval(self: *const Monitor, duration: u64) bool {
        const deadline = @as(i96, nowNs()) + duration;
        while (@as(i96, nowNs()) < deadline) {
            if (self.cancelled.load(.acquire) or !self.isCurrent()) return false;
            const remaining: u64 = @intCast(@max(0, deadline - nowNs()));
            const step = @min(remaining, 50 * std.time.ns_per_ms);
            if (!runtime_wait.sleep(std.Io.Duration.fromNanoseconds(@intCast(step)), "container healthcheck interval")) return false;
        }
        return !self.cancelled.load(.acquire) and self.isCurrent();
    }
};

fn nowNs() i64 {
    return @intCast(std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds());
}

/// Internal subprocess entrypoint. The supervisor owns its lifetime and cgroup.
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
