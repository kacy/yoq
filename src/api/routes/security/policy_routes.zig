const std = @import("std");
const http = @import("../../http.zig");
const store = @import("../../../state/store.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const net_policy = @import("../../../network/policy.zig");
const common = @import("../common.zig");

const Response = common.Response;
const extractJsonString = json_helpers.extractJsonString;
const PolicyListContext = struct {
    policies: []const store.NetworkPolicyRecord,
};

pub fn handleListPolicies(alloc: std.mem.Allocator) Response {
    var policies = store.listNetworkPolicies(alloc) catch return common.internalError();
    defer {
        for (policies.items) |p| p.deinit(alloc);
        policies.deinit(alloc);
    }

    return common.jsonOkWrite(alloc, PolicyListContext{
        .policies = policies.items,
    }, writePolicyListJson);
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

fn writePolicyListJson(writer: *std.Io.Writer, ctx: PolicyListContext) !void {
    try writer.writeByte('[');
    for (ctx.policies, 0..) |policy, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll("{\"source\":\"");
        try json_helpers.writeJsonEscaped(writer, policy.source_service);
        try writer.writeAll("\",\"target\":\"");
        try json_helpers.writeJsonEscaped(writer, policy.target_service);
        try writer.writeAll("\",\"action\":\"");
        try json_helpers.writeJsonEscaped(writer, policy.action);
        try writer.writeAll("\"}");
    }
    try writer.writeByte(']');
}
