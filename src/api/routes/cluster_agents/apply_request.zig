const std = @import("std");
const scheduler = @import("../../../cluster/scheduler.zig");
const volumes_mod = @import("../../../state/volumes.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const common = @import("../common.zig");

const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;
const extractJsonArray = json_helpers.extractJsonArray;

pub const ApplyRequest = struct {
    app_name: ?[]const u8,
    requests: std.ArrayListUnmanaged(scheduler.PlacementRequest) = .empty,

    pub fn deinit(self: *ApplyRequest, alloc: std.mem.Allocator) void {
        for (self.requests.items) |req| alloc.free(req.command);
        self.requests.deinit(alloc);
    }

    pub fn setVolumeConstraints(self: *ApplyRequest, constraints: []const volumes_mod.VolumeConstraint) void {
        if (constraints.len == 0) return;
        for (self.requests.items) |*req| {
            req.volume_constraints = constraints;
        }
    }
};

pub const ParseError = error{
    MissingAppName,
    MissingServicesArray,
    NoServices,
    OutOfMemory,
    InvalidRequest,
};

pub fn parse(alloc: std.mem.Allocator, body: []const u8, require_app_name: bool) ParseError!ApplyRequest {
    var parsed: ApplyRequest = .{
        .app_name = extractJsonString(body, "app_name") orelse extractJsonString(body, "volume_app"),
    };
    errdefer parsed.deinit(alloc);

    if (require_app_name and parsed.app_name == null) {
        return ParseError.MissingAppName;
    }

    const services_json = extractJsonArray(body, "services") orelse return ParseError.MissingServicesArray;

    var iter = json_helpers.extractJsonObjects(services_json);
    while (iter.next()) |block| {
        const image = extractJsonString(block, "image") orelse continue;
        const command = extractCommandString(alloc, block) catch return ParseError.OutOfMemory;
        errdefer alloc.free(command);

        if (!common.validateClusterInput(image)) {
            alloc.free(command);
            continue;
        }
        if (command.len > 0 and !common.validateClusterInput(command)) {
            alloc.free(command);
            continue;
        }

        parsed.requests.append(alloc, .{
            .image = image,
            .command = command,
            .cpu_limit = extractJsonInt(block, "cpu_limit") orelse 1000,
            .memory_limit_mb = extractJsonInt(block, "memory_limit_mb") orelse 256,
            .gpu_limit = extractJsonInt(block, "gpu_limit") orelse 0,
            .gpu_model = extractJsonString(block, "gpu_model"),
            .gpu_vram_min_mb = if (extractJsonInt(block, "gpu_vram_min_mb")) |v| @as(u64, @intCast(@max(0, v))) else null,
            .required_labels = extractJsonString(block, "required_labels") orelse "",
            .gang_world_size = if (extractJsonInt(block, "gang_world_size")) |v| @intCast(@max(0, v)) else 0,
            .gpus_per_rank = if (extractJsonInt(block, "gpus_per_rank")) |v| @intCast(@max(1, v)) else 1,
        }) catch {
            alloc.free(command);
            return ParseError.OutOfMemory;
        };
    }

    if (parsed.requests.items.len == 0) return ParseError.NoServices;
    return parsed;
}

fn extractJsonStringArray(alloc: std.mem.Allocator, json: []const u8, key: []const u8) !?[]u8 {
    const array_json = extractJsonArray(json, key) orelse return null;
    if (array_json.len < 2) return null;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    var pos: usize = 1;
    var first = true;
    while (pos < array_json.len - 1) {
        while (pos < array_json.len - 1 and (array_json[pos] == ' ' or array_json[pos] == '\n' or array_json[pos] == '\r' or array_json[pos] == '\t' or array_json[pos] == ',')) : (pos += 1) {}
        if (pos >= array_json.len - 1) break;
        if (array_json[pos] != '"') return ParseError.InvalidRequest;
        pos += 1;
        const start = pos;

        while (pos < array_json.len - 1) : (pos += 1) {
            if (array_json[pos] == '\\') {
                pos += 1;
                if (pos >= array_json.len - 1) return ParseError.InvalidRequest;
                continue;
            }
            if (array_json[pos] == '"') break;
        }
        if (pos >= array_json.len - 1) return ParseError.InvalidRequest;

        if (!first) try out.append(alloc, ' ');
        first = false;
        try out.appendSlice(alloc, array_json[start..pos]);
        pos += 1;
    }

    return try out.toOwnedSlice(alloc);
}

fn extractCommandString(alloc: std.mem.Allocator, block: []const u8) ![]const u8 {
    if (extractJsonString(block, "command")) |command| {
        return alloc.dupe(u8, command);
    }
    if (try extractJsonStringArray(alloc, block, "command")) |joined| {
        defer alloc.free(joined);
        return alloc.dupe(u8, joined);
    }
    return alloc.dupe(u8, "");
}

test "parse finds services array regardless of field order" {
    const alloc = std.testing.allocator;
    const json =
        \\{"services":[{"name":"svc-a","image":"alpine","gpu":{"devices":["../../dev/sda"]}},{"image":"busybox","name":"svc-b"}]}
    ;

    var parsed = try parse(alloc, json, false);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 2), parsed.requests.items.len);
    try std.testing.expectEqualStrings("alpine", parsed.requests.items[0].image);
    try std.testing.expectEqualStrings("busybox", parsed.requests.items[1].image);
}

test "parse joins structured command arrays" {
    const alloc = std.testing.allocator;
    const json =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx","command":["nginx","-g","daemon off"]}]}
    ;

    var parsed = try parse(alloc, json, true);
    defer parsed.deinit(alloc);

    try std.testing.expectEqualStrings("demo-app", parsed.app_name.?);
    try std.testing.expectEqual(@as(usize, 1), parsed.requests.items.len);
    try std.testing.expectEqualStrings("nginx -g daemon off", parsed.requests.items[0].command);
}
