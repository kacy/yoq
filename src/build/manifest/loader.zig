const std = @import("std");

const toml = @import("../../lib/toml.zig");
const log = @import("../../lib/log.zig");
const instructions = @import("instructions.zig");
const ordering = @import("ordering.zig");
const stage_reader = @import("stage_reader.zig");
const types = @import("types.zig");

pub fn loadFromString(
    alloc: std.mem.Allocator,
    content: []const u8,
) types.LoadError!types.LoadResult {
    var parsed = toml.parse(alloc, content) catch {
        return types.LoadError.ParseFailed;
    };
    defer parsed.deinit();

    if (parsed.root.getTable("stage")) |stages| {
        return parseMultiStage(alloc, stages);
    }

    if (parsed.root.getString("from") != null) {
        return parseSingleStage(alloc, &parsed.root);
    }

    log.err("build manifest: no stages found (need [stage.*] sections or top-level 'from')", .{});
    return types.LoadError.EmptyManifest;
}

fn parseSingleStage(
    alloc: std.mem.Allocator,
    root: *const toml.Table,
) types.LoadError!types.LoadResult {
    const stage = stage_reader.readStage(root, "default") orelse
        return types.LoadError.MissingFrom;
    const stages = [_]types.StageSpec{stage};
    return instructions.toInstructions(alloc, &stages);
}

fn parseMultiStage(
    alloc: std.mem.Allocator,
    stage_table: *const toml.Table,
) types.LoadError!types.LoadResult {
    var stages: std.ArrayListUnmanaged(types.StageSpec) = .empty;
    defer stages.deinit(alloc);

    for (stage_table.entries.keys(), stage_table.entries.values()) |name, val| {
        switch (val) {
            .table => |table| {
                const stage = stage_reader.readStage(table, name) orelse {
                    log.err("build manifest: stage '{s}' missing required 'from' field", .{name});
                    return types.LoadError.MissingFrom;
                };
                stages.append(alloc, stage) catch return types.LoadError.OutOfMemory;
            },
            else => {
                log.err("build manifest: stage '{s}' must be a table", .{name});
                return types.LoadError.ParseFailed;
            },
        }
    }

    if (stages.items.len == 0) return types.LoadError.EmptyManifest;

    const ordered = try ordering.resolveStageOrder(alloc, stages.items);
    defer alloc.free(ordered);

    return instructions.toInstructions(alloc, ordered);
}
