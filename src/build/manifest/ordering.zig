const std = @import("std");

const log = @import("../../lib/log.zig");
const types = @import("types.zig");

pub fn resolveStageOrder(
    alloc: std.mem.Allocator,
    stages: []const types.StageSpec,
) types.LoadError![]types.StageSpec {
    const n = stages.len;
    if (n <= 1) {
        const result = alloc.alloc(types.StageSpec, n) catch return types.LoadError.OutOfMemory;
        if (n == 1) result[0] = stages[0];
        return result;
    }

    var result = alloc.alloc(types.StageSpec, n) catch return types.LoadError.OutOfMemory;
    errdefer alloc.free(result);

    var placed = alloc.alloc(bool, n) catch return types.LoadError.OutOfMemory;
    defer alloc.free(placed);
    @memset(placed, false);

    var result_idx: usize = 0;
    var progress = true;
    while (progress and result_idx < n) {
        progress = false;
        for (stages, 0..) |stage, i| {
            if (placed[i]) continue;

            if (allDepsPlaced(stage, stages, placed)) {
                result[result_idx] = stage;
                result_idx += 1;
                placed[i] = true;
                progress = true;
            }
        }
    }

    if (result_idx != n) {
        alloc.free(result);
        log.err("build manifest: circular dependency between stages", .{});
        return types.LoadError.CyclicDependency;
    }

    return result;
}

pub fn extractFromStage(step: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, step, " \t");
    const first_space = std.mem.indexOfAny(u8, trimmed, &[_]u8{ ' ', '\t' }) orelse return null;
    const keyword = trimmed[0..first_space];

    var lower_buf: [8]u8 = undefined;
    if (keyword.len > lower_buf.len) return null;
    for (keyword, 0..) |c, i| {
        lower_buf[i] = std.ascii.toLower(c);
    }
    const lower = lower_buf[0..keyword.len];

    if (!std.mem.eql(u8, lower, "copy") and !std.mem.eql(u8, lower, "add")) return null;

    const rest = std.mem.trimStart(u8, trimmed[first_space + 1 ..], " \t");
    if (!std.mem.startsWith(u8, rest, "--from=")) return null;

    const after_eq = rest["--from=".len..];
    const end = std.mem.indexOfAny(u8, after_eq, &[_]u8{ ' ', '\t' }) orelse after_eq.len;
    if (end == 0) return null;

    return after_eq[0..end];
}

fn allDepsPlaced(
    stage: types.StageSpec,
    all_stages: []const types.StageSpec,
    placed: []const bool,
) bool {
    const stage_steps = stage.steps orelse return true;
    for (stage_steps) |step| {
        const dep_name = extractFromStage(step) orelse continue;
        for (all_stages, 0..) |candidate, j| {
            if (std.mem.eql(u8, candidate.name, dep_name) and !placed[j]) {
                return false;
            }
        }
    }
    return true;
}
