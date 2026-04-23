const std = @import("std");
const platform = @import("platform");
const http = @import("../../http.zig");
const store = @import("../../../state/store.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const net_policy = @import("../../../network/policy.zig");
const common = @import("../common.zig");

const Response = common.Response;
const extractJsonString = json_helpers.extractJsonString;

pub fn handleListPolicies(alloc: std.mem.Allocator) Response {
    var policies = store.listNetworkPolicies(alloc) catch return common.internalError();
    defer {
        for (policies.items) |p| p.deinit(alloc);
        policies.deinit(alloc);
    }

    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;

    writer.writeByte('[') catch return common.internalError();
    for (policies.items, 0..) |pol, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writer.writeAll("{\"source\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, pol.source_service) catch return common.internalError();
        writer.writeAll("\",\"target\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, pol.target_service) catch return common.internalError();
        writer.writeAll("\",\"action\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, pol.action) catch return common.internalError();
        writer.writeAll("\"}") catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf_writer.toOwnedSlice() catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleAddPolicy(alloc: std.mem.Allocator, request: http.Request) Response {
    if (request.body.len == 0) return common.badRequest("missing request body");

    const source = extractJsonString(request.body, "source") orelse return common.badRequest("missing source field");
    const target = extractJsonString(request.body, "target") orelse return common.badRequest("missing target field");
    const action = extractJsonString(request.body, "action") orelse return common.badRequest("missing action field");

    if (source.len == 0) return common.badRequest("source cannot be empty");
    if (target.len == 0) return common.badRequest("target cannot be empty");

    if (!std.mem.eql(u8, action, "deny") and !std.mem.eql(u8, action, "allow")) {
        return common.badRequest("action must be 'deny' or 'allow'");
    }

    store.addNetworkPolicy(source, target, action) catch return common.internalError();
    net_policy.syncPolicies(alloc);

    return .{ .status = .ok, .body = "{\"status\":\"ok\"}", .allocated = false };
}

pub fn handleDeletePolicy(alloc: std.mem.Allocator, source: []const u8, target: []const u8) Response {
    store.removeNetworkPolicy(source, target) catch return common.internalError();
    net_policy.syncPolicies(alloc);

    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}
