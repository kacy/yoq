const std = @import("std");

const dockerfile = @import("../dockerfile.zig");
const steps = @import("steps.zig");
const types = @import("types.zig");
const log = @import("../../lib/log.zig");

pub fn toInstructions(
    alloc: std.mem.Allocator,
    stages: []const types.StageSpec,
) types.LoadError!types.LoadResult {
    var instructions: std.ArrayListUnmanaged(dockerfile.Instruction) = .empty;
    errdefer {
        for (instructions.items) |inst| alloc.free(inst.args);
        instructions.deinit(alloc);
    }

    for (stages) |stage| {
        const from_args = if (stages.len > 1 and !std.mem.eql(u8, stage.name, "default"))
            std.fmt.allocPrint(alloc, "{s} AS {s}", .{ stage.from, stage.name }) catch
                return types.LoadError.OutOfMemory
        else
            alloc.dupe(u8, stage.from) catch return types.LoadError.OutOfMemory;

        instructions.append(alloc, .{
            .kind = .from,
            .args = from_args,
            .line_number = 0,
        }) catch {
            alloc.free(from_args);
            return types.LoadError.OutOfMemory;
        };

        try appendRepeated(alloc, &instructions, .arg, stage.arg);
        try appendRepeated(alloc, &instructions, .env, stage.env);

        if (stage.workdir) |workdir| try appendInstruction(alloc, &instructions, .workdir, workdir);
        if (stage.user) |user| try appendInstruction(alloc, &instructions, .user, user);

        if (stage.shell) |shell| try appendJsonInstruction(alloc, &instructions, .shell, shell);

        if (stage.steps) |stage_steps| {
            for (stage_steps) |step| {
                const parsed = steps.parseStep(step) orelse {
                    log.err("build manifest: invalid step: '{s}'", .{step});
                    return types.LoadError.InvalidStep;
                };
                try appendInstruction(alloc, &instructions, parsed.kind, parsed.args);
            }
        }

        try appendRepeated(alloc, &instructions, .expose, stage.expose);
        try appendRepeated(alloc, &instructions, .volume, stage.volume);
        try appendRepeated(alloc, &instructions, .label, stage.label);

        if (stage.healthcheck) |healthcheck| try appendInstruction(alloc, &instructions, .healthcheck, healthcheck);
        if (stage.stopsignal) |stop_signal| try appendInstruction(alloc, &instructions, .stopsignal, stop_signal);
        if (stage.entrypoint) |entrypoint| try appendJsonInstruction(alloc, &instructions, .entrypoint, entrypoint);
        if (stage.cmd) |cmd| try appendJsonInstruction(alloc, &instructions, .cmd, cmd);
    }

    return .{
        .instructions = instructions.toOwnedSlice(alloc) catch return types.LoadError.OutOfMemory,
        .alloc = alloc,
    };
}

pub fn formatJsonArray(alloc: std.mem.Allocator, items: []const []const u8) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);

    try buf.append(alloc, '[');
    for (items, 0..) |item, i| {
        if (i > 0) try buf.appendSlice(alloc, ", ");
        try buf.append(alloc, '"');
        try buf.appendSlice(alloc, item);
        try buf.append(alloc, '"');
    }
    try buf.append(alloc, ']');

    return buf.toOwnedSlice(alloc);
}

fn appendRepeated(
    alloc: std.mem.Allocator,
    instructions: *std.ArrayListUnmanaged(dockerfile.Instruction),
    kind: dockerfile.InstructionKind,
    items: ?[]const []const u8,
) types.LoadError!void {
    if (items) |values| {
        for (values) |value| {
            try appendInstruction(alloc, instructions, kind, value);
        }
    }
}

fn appendJsonInstruction(
    alloc: std.mem.Allocator,
    instructions: *std.ArrayListUnmanaged(dockerfile.Instruction),
    kind: dockerfile.InstructionKind,
    items: []const []const u8,
) types.LoadError!void {
    const json = formatJsonArray(alloc, items) catch return types.LoadError.OutOfMemory;
    instructions.append(alloc, .{
        .kind = kind,
        .args = json,
        .line_number = 0,
    }) catch {
        alloc.free(json);
        return types.LoadError.OutOfMemory;
    };
}

fn appendInstruction(
    alloc: std.mem.Allocator,
    instructions: *std.ArrayListUnmanaged(dockerfile.Instruction),
    kind: dockerfile.InstructionKind,
    args: []const u8,
) types.LoadError!void {
    const owned_args = alloc.dupe(u8, args) catch return types.LoadError.OutOfMemory;
    instructions.append(alloc, .{
        .kind = kind,
        .args = owned_args,
        .line_number = 0,
    }) catch {
        alloc.free(owned_args);
        return types.LoadError.OutOfMemory;
    };
}
