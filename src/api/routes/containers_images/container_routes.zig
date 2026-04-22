const std = @import("std");
const platform = @import("platform");
const store = @import("../../../state/store.zig");
const process = @import("../../../runtime/process.zig");
const logs = @import("../../../runtime/logs.zig");
const container = @import("../../../runtime/container.zig");
const cgroups = @import("../../../runtime/cgroups.zig");
const log = @import("../../../lib/log.zig");
const common = @import("../common.zig");
const writers = @import("writers.zig");

const Response = common.Response;
const stop_poll_attempts: usize = 10;
const stop_poll_interval_ms: u64 = 50;

pub fn handleListContainers(alloc: std.mem.Allocator) Response {
    var ids = store.listIds(alloc) catch return common.internalError();
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = platform.arrayListWriter(&json_buf, alloc);

    writer.writeByte('[') catch return common.internalError();

    var first = true;
    for (ids.items) |id| {
        const record = store.load(alloc, id) catch continue;
        defer record.deinit(alloc);

        if (!first) writer.writeByte(',') catch return common.internalError();
        first = false;

        writers.writeContainerJson(writer, record) catch return common.internalError();
    }

    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleGetContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };
    defer record.deinit(alloc);

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = platform.arrayListWriter(&json_buf, alloc);

    writers.writeContainerJson(writer, record) catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
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

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = platform.arrayListWriter(&json_buf, alloc);

    writer.writeAll("{\"logs\":\"") catch return common.internalError();
    @import("../../../lib/json_helpers.zig").writeJsonEscaped(writer, log_data) catch return common.internalError();
    writer.writeAll("\"}") catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleStopContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };
    defer record.deinit(alloc);

    if (!std.mem.eql(u8, record.status, "running")) {
        return common.badRequest("container is not running");
    }

    const pid = record.pid orelse return common.badRequest("container has no pid");

    const cg = cgroups.Cgroup.open(id) catch {
        store.updateStatus(id, "stopped", null, null) catch {};
        return common.badRequest("container is not running");
    };
    if (!cg.containsProcess(pid)) {
        store.updateStatus(id, "stopped", null, null) catch {};
        return common.badRequest("container is not running");
    }

    process.terminate(pid) catch return common.internalError();

    if (waitForProcessExit(id, pid)) {
        store.updateStatus(id, "stopped", null, null) catch |err| {
            log.warn("failed to update status after stopping {s}: {}", .{ id, err });
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
        platform.sleep(stop_poll_interval_ms * std.time.ns_per_ms);
    }
    return false;
}

pub fn handleRemoveContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return common.notFound();
        return common.internalError();
    };

    if (std.mem.eql(u8, record.status, "running")) {
        record.deinit(alloc);
        return common.badRequest("cannot remove running container");
    }
    record.deinit(alloc);

    store.remove(id) catch return common.internalError();
    logs.deleteLogFile(id);
    container.cleanupContainerDirs(id);

    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}
