const std = @import("std");
const AppContext = @import("../../../lib/app_context.zig").AppContext;
const cli = @import("../../../lib/cli.zig");
const store = @import("../../../state/store.zig");
const control = @import("../../local_control.zig");
const cgroups = @import("../../cgroups.zig");
const admin = @import("../../cgroups/admin.zig");
const run_state = @import("../../run_state.zig");
const state = @import("state_support.zig");

const Selection = struct { reference: []const u8, json: bool = false };

fn select(args: anytype) !Selection {
    var reference: ?[]const u8 = null;
    var json = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            json = true;
        } else if (std.mem.startsWith(u8, arg, "-") or reference != null) {
            return error.InvalidArgument;
        } else reference = arg;
    }
    return .{ .reference = reference orelse return error.InvalidArgument, .json = json };
}

pub fn top(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const selected = try select(args);
    const record = try state.resolveContainerRef(ctx.alloc, selected.reference);
    defer record.deinit(ctx.alloc);
    if (record.pid == null) return error.NotRunning;
    const cg = try cgroups.Cgroup.open(record.id);
    const pids = try cg.processes(ctx.alloc);
    defer ctx.alloc.free(pids);
    var output_buffer: [8192]u8 = undefined;
    var output = std.Io.File.stdout().writerStreaming(ctx.io, &output_buffer);
    const writer = &output.interface;
    if (selected.json) try writer.writeByte('[') else try writer.writeAll("PID\tPPID\tSTATE\tCOMMAND\n");
    var first = true;
    for (pids) |pid| {
        const row = readProcess(ctx.io, ctx.alloc, pid) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer ctx.alloc.free(row.command);
        if (selected.json) {
            if (!first) try writer.writeByte(',');
            try std.json.Stringify.value(row, .{}, writer);
        } else {
            try writer.print("{d}\t{d}\t{s}\t{s}\n", .{ row.pid, row.parent_pid, row.state, row.command });
        }
        first = false;
    }
    if (selected.json) try writer.writeAll("]\n");
    try writer.flush();
}

const ProcessRow = struct { pid: i32, parent_pid: i32, state: []const u8, command: []u8 };

fn stateName(value: u8) []const u8 {
    return switch (value) {
        'R' => "running",
        'S' => "sleeping",
        'D' => "waiting",
        'Z' => "zombie",
        'T', 't' => "stopped",
        'I' => "idle",
        'X', 'x' => "dead",
        else => "unknown",
    };
}

fn readProcess(io: std.Io, alloc: std.mem.Allocator, pid: i32) !ProcessRow {
    var path_buffer: [80]u8 = undefined;
    const stat_path = try std.fmt.bufPrint(&path_buffer, "/proc/{d}/stat", .{pid});
    const stat = try readProcFile(io, alloc, stat_path, 4096);
    defer alloc.free(stat);
    const left = std.mem.indexOfScalar(u8, stat, '(') orelse return error.InvalidProcessStat;
    const right = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return error.InvalidProcessStat;
    if (right <= left) return error.InvalidProcessStat;
    var fields = std.mem.tokenizeAny(u8, stat[right + 1 ..], " \t\n");
    const process_state = fields.next() orelse return error.InvalidProcessStat;
    if (process_state.len != 1) return error.InvalidProcessStat;
    const parent = try std.fmt.parseInt(i32, fields.next() orelse return error.InvalidProcessStat, 10);
    const cmd_path = try std.fmt.bufPrint(&path_buffer, "/proc/{d}/cmdline", .{pid});
    var command = try readProcFile(io, alloc, cmd_path, 1024 * 1024);
    if (command.len == 0) {
        alloc.free(command);
        command = try alloc.dupe(u8, stat[left + 1 .. right]);
    }
    for (command) |*ch| if (ch.* == 0 or std.ascii.isControl(ch.*)) {
        ch.* = ' ';
    };
    return .{ .pid = pid, .parent_pid = parent, .state = stateName(process_state[0]), .command = command };
}

pub fn stats(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const selected = try select(args);
    const record = try state.resolveContainerRef(ctx.alloc, selected.reference);
    defer record.deinit(ctx.alloc);
    if (record.pid == null) return error.NotRunning;
    const cg = try cgroups.Cgroup.open(record.id);
    const metrics = cg.readAllMetrics();
    var buffer: [64]u8 = undefined;
    const pids = try std.fmt.parseInt(u64, try cg.readFile("pids.current", &buffer), 10);
    const frozen = try cg.isFrozen();
    if (selected.json) {
        var limits: [5][64]u8 = undefined;
        try writeJson(ctx.alloc, .{ .id = record.id, .paused = frozen, .pids = pids, .metrics = metrics, .limits = .{
            .cpu_weight = cg.readFile("cpu.weight", &limits[0]) catch null,
            .cpu_max = cg.readFile("cpu.max", &limits[1]) catch null,
            .memory_max = cg.readFile("memory.max", &limits[2]) catch null,
            .memory_high = cg.readFile("memory.high", &limits[3]) catch null,
            .pids_max = cg.readFile("pids.max", &limits[4]) catch null,
        } });
    } else {
        cli.write("ID\tMEMORY(bytes)\tLIMIT(bytes)\tCPU(usec)\tPIDS\tPAUSED\n", .{});
        cli.write("{s}\t{?d}\t{?d}\t{?d}\t{d}\t{}\n", .{ record.id, metrics.memory_bytes, metrics.memory_limit, metrics.cpu_usec, pids, frozen });
    }
}

pub fn pause(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return changePause(args, ctx, true);
}

pub fn unpause(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    return changePause(args, ctx, false);
}

fn changePause(args: *std.process.Args.Iterator, ctx: AppContext, frozen: bool) !void {
    const selected = try select(args);
    if (selected.json) return error.InvalidArgument;
    const resolved = try state.resolveContainerRef(ctx.alloc, selected.reference);
    defer resolved.deinit(ctx.alloc);
    const command = try control.lock(resolved.id, .command, true);
    defer command.deinit();
    const transition = try control.lock(resolved.id, .transition, true);
    defer transition.deinit();
    const record = try store.load(ctx.alloc, resolved.id);
    defer record.deinit(ctx.alloc);
    if (record.pid == null) return error.NotRunning;
    const cg = try cgroups.Cgroup.open(record.id);
    if (!try cg.containsProcessChecked(record.pid.?)) return error.NotRunning;
    const previous = try cg.isFrozen();
    cg.setFrozen(frozen) catch |err| {
        cg.setFrozen(previous) catch return error.PartialUpdate;
        return err;
    };
    savePausedStatus(record.id, record.pid.?, frozen) catch |err| {
        cg.setFrozen(previous) catch return error.PartialUpdate;
        return err;
    };
    cli.write("{s}\n", .{record.id});
}

fn savePausedStatus(id: []const u8, pid: i32, frozen: bool) !void {
    var lease = try @import("../../../state/store/common.zig").leaseDb();
    defer lease.deinit();
    // thawing can let the process exit before this write. never restore a PID
    // that the supervisor has already reaped and cleared.
    try lease.db.exec("UPDATE containers SET status = ? WHERE id = ? AND pid = ? AND status IN ('running', 'paused');", .{}, .{ if (frozen) "paused" else "running", id, pid });
    if (lease.db.rowsAffected() != 1) return error.NotRunning;
}

const Patch = struct {
    reference: []const u8 = "",
    memory: ?[]const u8 = null,
    memory_high: ?[]const u8 = null,
    pids: ?[]const u8 = null,
    cpu_weight: ?[]const u8 = null,
    cpus: ?[]const u8 = null,
    restart: ?run_state.RestartPolicy.Parsed = null,

    fn apply(self: Patch, config: *run_state.SavedRunConfig, fields: *[5]admin.Field) ![]const admin.Field {
        var count: usize = 0;
        if (self.cpu_weight) |value| {
            const weight = std.fmt.parseUnsigned(u16, value, 10) catch return error.InvalidArgument;
            if (weight < 1 or weight > 10000) return error.InvalidArgument;
            config.limits.cpu_weight = weight;
            fields[count] = .cpu_weight;
            count += 1;
        }
        if (self.cpus) |value| {
            config.limits.cpu_max_usec = if (std.mem.eql(u8, value, "unlimited")) null else cli.parseCpuQuota(value, config.limits.cpu_max_period) orelse return error.InvalidArgument;
            fields[count] = .cpu_max;
            count += 1;
        }
        if (self.memory) |value| {
            config.limits.memory_max = if (std.mem.eql(u8, value, "unlimited")) null else cli.parseMemorySize(value) orelse return error.InvalidArgument;
            fields[count] = .memory_max;
            count += 1;
        }
        if (self.memory_high) |value| {
            config.limits.memory_high = if (std.mem.eql(u8, value, "unlimited")) null else cli.parseMemorySize(value) orelse return error.InvalidArgument;
            if (config.limits.memory_high) |high| if (high == 0) return error.InvalidArgument;
            fields[count] = .memory_high;
            count += 1;
        }
        if (self.pids) |value| {
            config.limits.pids_max = if (std.mem.eql(u8, value, "unlimited")) null else std.fmt.parseUnsigned(u32, value, 10) catch return error.InvalidArgument;
            fields[count] = .pids_max;
            count += 1;
        }
        if (self.restart) |value| {
            config.restart_policy = value.policy;
            config.restart_max_retries = value.max_retries;
        }
        if (config.auto_remove and config.restart_policy != .no) return error.InvalidArgument;
        try config.limits.validate();
        return fields[0..count];
    }
};

fn parsePatch(args: anytype) !Patch {
    var patch: Patch = .{};
    var changed = false;
    while (args.next()) |arg| {
        if (!std.mem.startsWith(u8, arg, "-")) {
            if (patch.reference.len != 0) return error.InvalidArgument;
            patch.reference = arg;
            continue;
        }
        const eq = std.mem.indexOfScalar(u8, arg, '=');
        const option = if (eq) |index| arg[0..index] else arg;
        const value = if (eq) |index| arg[index + 1 ..] else args.next() orelse return error.InvalidArgument;
        if (std.mem.eql(u8, option, "--memory")) {
            patch.memory = value;
        } else if (std.mem.eql(u8, option, "--memory-high")) {
            patch.memory_high = value;
        } else if (std.mem.eql(u8, option, "--pids")) {
            patch.pids = value;
        } else if (std.mem.eql(u8, option, "--cpu-weight")) {
            patch.cpu_weight = value;
        } else if (std.mem.eql(u8, option, "--cpus")) {
            patch.cpus = value;
        } else if (std.mem.eql(u8, option, "--restart")) {
            patch.restart = run_state.RestartPolicy.parseWithRetries(value) catch return error.InvalidArgument;
        } else return error.InvalidArgument;
        changed = true;
    }
    if (!changed or patch.reference.len == 0) return error.InvalidArgument;
    return patch;
}

pub fn update(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const patch = try parsePatch(args);
    const resolved = try state.resolveContainerRef(ctx.alloc, patch.reference);
    defer resolved.deinit(ctx.alloc);
    const command = try control.lock(resolved.id, .command, true);
    defer command.deinit();
    const transition = try control.lock(resolved.id, .transition, true);
    defer transition.deinit();
    const record = try store.load(ctx.alloc, resolved.id);
    defer record.deinit(ctx.alloc);
    if (std.mem.eql(u8, record.status, "cleanup_failed")) return error.CleanupFailed;
    var config = try run_state.loadConfig(ctx.alloc, record.id);
    defer config.deinit(ctx.alloc);
    var fields: [5]admin.Field = undefined;
    const changed = try patch.apply(&config, &fields);
    var cg: ?cgroups.Cgroup = null;
    var transaction: ?admin.Update = null;
    if (record.pid != null and changed.len > 0) {
        cg = try cgroups.Cgroup.open(record.id);
        transaction = try admin.Update.prepare(&cg.?, config.limits, changed);
        transaction.?.apply(&cg.?) catch |err| {
            cli.writeErr("resource update failed: {}; saved configuration was not changed\n", .{err});
            return err;
        };
    }
    run_state.saveConfig(record.id, config) catch |err| {
        if (transaction) |*pending| {
            pending.rollback(&cg.?) catch {
                cli.writeErr("configuration was not saved and resource rollback failed; inspect current limits with stats --json\n", .{});
                return error.PartialUpdate;
            };
        }
        return err;
    };
    cli.write("{s}\n", .{record.id});
}

fn writeJson(alloc: std.mem.Allocator, value: anytype) !void {
    const output = try std.json.Stringify.valueAlloc(alloc, value, .{});
    defer alloc.free(output);
    cli.write("{s}\n", .{output});
}

test {
    _ = @import("../../cgroups/admin.zig");
}

fn testConfig() run_state.SavedRunConfig {
    return .{
        .rootfs = "/fixture",
        .command = "/bin/sh",
        .hostname = "fixture",
        .working_dir = "/",
        .args = &.{},
        .env = &.{},
        .lower_dirs = &.{},
        .mounts = &.{},
        .network_enabled = false,
        .port_maps = &.{},
        .limits = .{ .memory_max = 128 * 1024 * 1024, .cpu_weight = 42, .pids_max = 128 },
        .restart_policy = .always,
    };
}

const TestArgs = struct {
    values: []const []const u8,
    index: usize = 0,
    fn next(self: *@This()) ?[]const u8 {
        if (self.index == self.values.len) return null;
        defer self.index += 1;
        return self.values[self.index];
    }
};

test "container resource patch preserves unspecified settings and distinguishes unlimited" {
    var args: TestArgs = .{ .values = &.{ "web", "--memory=unlimited", "--restart", "on-failure", "--cpus", "0.5" } };
    const patch = try parsePatch(&args);
    var config = testConfig();
    var fields: [5]admin.Field = undefined;
    const changed = try patch.apply(&config, &fields);
    try std.testing.expectEqualStrings("web", patch.reference);
    try std.testing.expect(config.limits.memory_max == null);
    try std.testing.expectEqual(@as(?u64, 50_000), config.limits.cpu_max_usec);
    try std.testing.expectEqual(@as(?u16, 42), config.limits.cpu_weight);
    try std.testing.expectEqual(@as(?u32, 128), config.limits.pids_max);
    try std.testing.expectEqual(run_state.RestartPolicy.on_failure, config.restart_policy);
    try std.testing.expectEqualSlices(admin.Field, &.{ .cpu_max, .memory_max }, changed);
}

test "container resource patch rejects invalid values before changing the kernel" {
    const invalid = [_][]const []const u8{
        &.{ "web", "--unknown", "1" },
        &.{ "web", "--memory", "0" },
        &.{ "web", "--pids", "0" },
        &.{ "web", "--cpu-weight", "10001" },
        &.{ "web", "--cpus", "nan" },
        &.{ "web", "--cpus", "inf" },
        &.{ "web", "--cpus", "0.0000001" },
        &.{ "web", "--restart", "sometimes" },
        &.{ "web", "extra", "--memory", "256m" },
        &.{"web"},
    };
    for (invalid) |values| {
        var args: TestArgs = .{ .values = values };
        const patch = parsePatch(&args) catch continue;
        var config = testConfig();
        var fields: [5]admin.Field = undefined;
        if (patch.apply(&config, &fields)) |_| return error.ExpectedInvalidArgument else |_| {}
    }
    var config = testConfig();
    config.auto_remove = true;
    config.restart_policy = .no;
    var fields: [5]admin.Field = undefined;
    try std.testing.expectError(error.InvalidArgument, (Patch{ .restart = .{ .policy = .always } }).apply(&config, &fields));
}

test "container pause status never restores an exited process" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const id = "f00dbadcafe0";
    try store.save(.{ .id = id, .rootfs = "/fixture", .command = "test", .hostname = "test", .status = "running", .pid = 12345, .exit_code = null, .created_at = 0 });
    try savePausedStatus(id, 12345, true);
    try store.updateStatus(id, "stopped", null, 0);
    try std.testing.expectError(error.NotRunning, savePausedStatus(id, 12345, false));
    const record = try store.load(std.testing.allocator, id);
    defer record.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("stopped", record.status);
    try std.testing.expect(record.pid == null);
}

// proc files have no useful reported size. streaming also tolerates a process
// disappearing between reading its stat and command line.
fn readProcFile(io: std.Io, alloc: std.mem.Allocator, path: []const u8, limit: usize) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var buffer: [4096]u8 = undefined;
    var reader = file.readerStreaming(io, &buffer);
    return reader.interface.allocRemaining(alloc, .limited(limit));
}

test "container top reads a live process from zero size proc files" {
    const row = try readProcess(std.testing.io, std.testing.allocator, @intCast(std.os.linux.getpid()));
    defer std.testing.allocator.free(row.command);
    try std.testing.expect(row.parent_pid > 0);
    try std.testing.expect(row.command.len > 0);
    try std.testing.expect(!std.mem.eql(u8, row.state, "unknown"));
}
