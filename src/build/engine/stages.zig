const std = @import("std");
const dockerfile = @import("../dockerfile.zig");
const types = @import("types.zig");

pub fn splitIntoStages(alloc: std.mem.Allocator, instructions: []const dockerfile.Instruction) ![]types.BuildStage {
    var stages: std.ArrayListUnmanaged(types.BuildStage) = .empty;
    errdefer stages.deinit(alloc);

    var current_start: usize = 0;
    var stage_index: usize = 0;

    for (instructions, 0..) |inst, i| {
        if (inst.kind == .from and i > 0) {
            try stages.append(alloc, .{
                .name = parseStageName(instructions[current_start].args),
                .index = stage_index,
                .instructions = instructions[current_start..i],
            });
            current_start = i;
            stage_index += 1;
        }
    }

    if (current_start < instructions.len) {
        try stages.append(alloc, .{
            .name = parseStageName(instructions[current_start].args),
            .index = stage_index,
            .instructions = instructions[current_start..],
        });
    }

    return try stages.toOwnedSlice(alloc);
}

pub fn parseStageName(from_args: []const u8) ?[]const u8 {
    if (from_args.len < 5) return null;
    for (0..from_args.len - 3) |i| {
        if (from_args[i] == ' ' and
            std.ascii.toLower(from_args[i + 1]) == 'a' and
            std.ascii.toLower(from_args[i + 2]) == 's' and
            from_args[i + 3] == ' ')
        {
            const name = std.mem.trim(u8, from_args[i + 4 ..], " \t");
            if (name.len > 0) return name;
        }
    }
    return null;
}

pub fn findStageByRef(
    stages: []const types.BuildStage,
    completed_states: []const types.BuildState,
    ref: []const u8,
) ?*const types.BuildState {
    for (stages, 0..) |stage, i| {
        if (i >= completed_states.len) break;
        if (stage.name) |name| {
            if (std.mem.eql(u8, name, ref)) return &completed_states[i];
        }
    }

    const idx = std.fmt.parseInt(usize, ref, 10) catch return null;
    if (idx < completed_states.len) return &completed_states[idx];

    return null;
}

test "parseStageName — with AS" {
    const name = parseStageName("golang:1.21 AS builder");
    try std.testing.expectEqualStrings("builder", name.?);
}

test "parseStageName — lowercase as" {
    const name = parseStageName("node:20 as build-stage");
    try std.testing.expectEqualStrings("build-stage", name.?);
}

test "parseStageName — mixed case As" {
    const name = parseStageName("golang:1.21 As builder");
    try std.testing.expectEqualStrings("builder", name.?);
}

test "parseStageName — mixed case aS" {
    const name = parseStageName("golang:1.21 aS builder");
    try std.testing.expectEqualStrings("builder", name.?);
}

test "parseStageName — no AS clause" {
    const name = parseStageName("ubuntu:24.04");
    try std.testing.expect(name == null);
}

test "splitIntoStages — two stages" {
    const alloc = std.testing.allocator;
    const instructions = [_]dockerfile.Instruction{
        .{ .kind = .from, .args = "golang:1.21 AS builder", .line_number = 1 },
        .{ .kind = .run, .args = "go build", .line_number = 2 },
        .{ .kind = .from, .args = "alpine:latest", .line_number = 3 },
        .{ .kind = .copy, .args = "--from=builder /app /app", .line_number = 4 },
    };

    const stages = try splitIntoStages(alloc, &instructions);
    defer alloc.free(stages);

    try std.testing.expectEqual(@as(usize, 2), stages.len);
    try std.testing.expectEqualStrings("builder", stages[0].name.?);
}

test "findStageByRef — by index" {
    const alloc = std.testing.allocator;
    const stages = [_]types.BuildStage{
        .{ .name = "builder", .index = 0, .instructions = &.{} },
        .{ .name = null, .index = 1, .instructions = &.{} },
    };
    var states: [2]types.BuildState = .{ types.BuildState.init(alloc), types.BuildState.init(alloc) };
    defer for (&states) |*s| s.deinit();

    const found0 = findStageByRef(&stages, &states, "0");
    const found1 = findStageByRef(&stages, &states, "1");
    try std.testing.expect(found0 != null);
    try std.testing.expect(found1 != null);
}
