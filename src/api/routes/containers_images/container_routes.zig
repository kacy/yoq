const std = @import("std");
const store = @import("../../../state/store.zig");
const process = @import("../../../runtime/process.zig");
const logs = @import("../../../runtime/logs.zig");
const container = @import("../../../runtime/container.zig");
const cgroups = @import("../../../runtime/cgroups.zig");
const log = @import("../../../lib/log.zig");
const common = @import("../common.zig");
const writers = @import("writers.zig");
const runtime_wait = @import("../../../lib/runtime_wait.zig");

const Response = common.Response;
const stop_poll_attempts: usize = 10;
const stop_poll_interval_ms: u64 = 50;
const ContainerListContext = struct {
    alloc: std.mem.Allocator,
    ids: []const []const u8,
};
const ContainerContext = struct {
    record: store.ContainerRecord,
};
const ContainerLogsContext = struct {
    log_data: []const u8,
};

pub fn handleListContainers(alloc: std.mem.Allocator) Response {
    var ids = store.listIds(alloc) catch return common.internalError();
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    return common.jsonOkWrite(alloc, ContainerListContext{
        .alloc = alloc,
        .ids = ids.items,
    }, writeContainerListJson);
}

pub fn handleGetContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };
    defer record.deinit(alloc);

    return common.jsonOkWrite(alloc, ContainerContext{
        .record = record,
    }, writeContainerJson);
}

pub fn handleGetLogs(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };
    record.deinit(alloc);

    const log_data = logs.readLogs(alloc, id) catch {
        const empty = alloc.dupe(u8, "{\"logs\":\"\"}") catch return common.internalError();
        return .{ .status = .ok, .body = empty, .allocated = true };
    };
    defer alloc.free(log_data);

    return common.jsonOkWrite(alloc, ContainerLogsContext{
        .log_data = log_data,
    }, writeContainerLogsJson);
}

pub fn handleStopContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => common.internalError(),
    };
    defer record.deinit(alloc);
    if (!(isStandalone(alloc, &record) catch return common.internalError()))
        return stopManagedContainer(&record);
    @import("../../../runtime/local_lifecycle.zig").stop(id, alloc) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => common.internalError(),
    };
    return .{ .status = .ok, .body = "{\"status\":\"stopped\"}", .allocated = false };
}

// Manifest and assignment owners already supervise their Container object and
// finalize its runtime resources. Standalone recovery must not take over that
// cleanup or require a SavedRunConfig that those owners never write.
fn isStandalone(alloc: std.mem.Allocator, record: *const store.ContainerRecord) !bool {
    if (record.app_name != null) return false;
    if (try @import("../../../runtime/local_control.zig").currentGeneration(record.id) != null) return true;
    const config = @import("../../../runtime/run_state.zig").loadConfig(alloc, record.id) catch |err| switch (err) {
        error.NotFound, error.InvalidId => return false,
        else => return err,
    };
    config.deinit(alloc);
    return true;
}

fn stopManagedContainer(record: *const store.ContainerRecord) Response {
    if (!std.mem.eql(u8, record.status, "running")) return common.badRequest("container is not running");
    const pid = record.pid orelse return common.badRequest("container has no pid");
    const cg = cgroups.Cgroup.open(record.id) catch {
        store.updateStatus(record.id, "stopped", null, null) catch {};
        return common.badRequest("container is not running");
    };
    if (!cg.containsProcess(pid)) {
        store.updateStatus(record.id, "stopped", null, null) catch {};
        return common.badRequest("container is not running");
    }
    process.terminate(pid) catch return common.internalError();
    if (waitForProcessExit(record.id, pid)) {
        store.updateStatus(record.id, "stopped", null, null) catch |err| {
            log.warn("failed to update status after stopping {s}: {}", .{ record.id, err });
        };
        return .{ .status = .ok, .body = "{\"status\":\"stopped\"}", .allocated = false };
    }
    return .{ .status = .ok, .body = "{\"status\":\"stopping\"}", .allocated = false };
}

pub fn waitForProcessExit(id: []const u8, pid: i32) bool {
    var attempts: usize = 0;
    while (attempts < stop_poll_attempts) : (attempts += 1) {
        const cg = cgroups.Cgroup.open(id) catch return true;
        if (!cg.containsProcess(pid)) return true;
        process.sendSignal(pid, 0) catch return true;
        if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(@intCast(stop_poll_interval_ms)), "container stop wait")) return false;
    }
    return false;
}

pub fn handleRemoveContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => common.internalError(),
    };
    defer record.deinit(alloc);
    if (!(isStandalone(alloc, &record) catch return common.internalError())) {
        if (record.pid != null or std.mem.eql(u8, record.status, "running")) return common.badRequest("cannot remove running container");
        store.remove(id) catch return common.internalError();
        logs.deleteLogFile(id);
        container.cleanupContainerDirs(id);
        return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
    }
    @import("../../../runtime/local_lifecycle.zig").remove(id, alloc) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        error.ContainerRunning => common.badRequest("cannot remove running container"),
        else => common.internalError(),
    };
    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}

fn writeContainerListJson(writer: *std.Io.Writer, ctx: ContainerListContext) !void {
    try writer.writeByte('[');
    var first = true;
    for (ctx.ids) |id| {
        const record = store.load(ctx.alloc, id) catch continue;
        defer record.deinit(ctx.alloc);

        if (!first) try writer.writeByte(',');
        first = false;
        try writers.writeContainerJson(writer, record);
    }
    try writer.writeByte(']');
}

fn writeContainerJson(writer: *std.Io.Writer, ctx: ContainerContext) !void {
    try writers.writeContainerJson(writer, ctx.record);
}

fn writeContainerLogsJson(writer: *std.Io.Writer, ctx: ContainerLogsContext) !void {
    try writer.writeAll("{\"logs\":\"");
    try @import("../../../lib/json_helpers.zig").writeJsonEscaped(writer, ctx.log_data);
    try writer.writeAll("\"}");
}

test "native container stop does not claim manifest lifecycle ownership" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const id = "edca01234567";
    try store.save(.{ .id = id, .rootfs = "/fixture", .command = "serve", .hostname = "web", .app_name = "managed-app", .status = "running", .pid = 999999, .exit_code = null, .created_at = 0 });
    const response = handleStopContainer(std.testing.allocator, id);
    try std.testing.expectEqual(@import("../../http.zig").StatusCode.bad_request, response.status);
    try std.testing.expect((try @import("../../../runtime/local_control.zig").currentGeneration(id)) == null);
    const record = try store.load(std.testing.allocator, id);
    defer record.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("stopped", record.status);
}

test "native container owner selection recognizes standalone metadata and managed apps" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const id = "edca12345678";
    const control = @import("../../../runtime/local_control.zig");
    var record: store.ContainerRecord = .{ .id = id, .rootfs = "/fixture", .command = "serve", .hostname = "web", .status = "created", .pid = null, .exit_code = null, .created_at = 0 };
    try std.testing.expect(!try isStandalone(std.testing.allocator, &record));
    try control.register(id, null);
    try std.testing.expect(try isStandalone(std.testing.allocator, &record));
    // An app owner remains authoritative even if an older API call previously
    // registered this container in the standalone control table.
    record.app_name = "managed-app";
    try std.testing.expect(!try isStandalone(std.testing.allocator, &record));
}
