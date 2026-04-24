const std = @import("std");

const types = @import("types.zig");
const keywords = @import("keywords.zig");

const LogicalLine = struct {
    text: []const u8,
    line_number: usize,
};

const KeywordSplit = struct {
    keyword: []const u8,
    rest: []const u8,
};

pub fn parse(alloc: std.mem.Allocator, content: []const u8) types.ParseError!types.ParseResult {
    var instructions: std.ArrayListUnmanaged(types.Instruction) = .empty;
    errdefer {
        for (instructions.items) |inst| alloc.free(inst.args);
        instructions.deinit(alloc);
    }

    var lines = try joinLogicalLines(alloc, content);
    defer {
        for (lines.items) |line| alloc.free(line.text);
        lines.deinit(alloc);
    }

    for (lines.items) |logical_line| {
        const trimmed = std.mem.trim(u8, logical_line.text, " \t");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        const split = splitFirst(trimmed);
        const kind = keywords.matchKeyword(split.keyword) orelse
            return types.ParseError.UnknownInstruction;
        if (split.rest.len == 0) return types.ParseError.EmptyInstruction;

        const args = alloc.dupe(u8, split.rest) catch return types.ParseError.OutOfMemory;
        instructions.append(alloc, .{
            .kind = kind,
            .args = args,
            .line_number = logical_line.line_number,
        }) catch {
            alloc.free(args);
            return types.ParseError.OutOfMemory;
        };
    }

    return .{
        .instructions = instructions.toOwnedSlice(alloc) catch return types.ParseError.OutOfMemory,
        .alloc = alloc,
    };
}

pub fn isJsonForm(args: []const u8) bool {
    const trimmed = std.mem.trim(u8, args, " \t");
    return trimmed.len >= 2 and trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']';
}

fn joinLogicalLines(
    alloc: std.mem.Allocator,
    content: []const u8,
) types.ParseError!std.ArrayListUnmanaged(LogicalLine) {
    var lines: std.ArrayListUnmanaged(LogicalLine) = .empty;
    errdefer {
        for (lines.items) |line| alloc.free(line.text);
        lines.deinit(alloc);
    }

    var joined_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer joined_buf.deinit(alloc);

    var line_iter = std.mem.splitScalar(u8, content, '\n');
    var physical_line: usize = 0;
    var logical_start: usize = 1;
    var in_continuation = false;

    while (line_iter.next()) |raw_line| {
        physical_line += 1;
        const line = trimTrailingCarriageReturn(raw_line);

        if (!in_continuation) {
            logical_start = physical_line;
            joined_buf.clearRetainingCapacity();
        }

        if (endsWithContinuation(line)) {
            joined_buf.appendSlice(alloc, line[0 .. line.len - 1]) catch
                return types.ParseError.OutOfMemory;
            joined_buf.append(alloc, ' ') catch return types.ParseError.OutOfMemory;
            in_continuation = true;
            continue;
        }

        joined_buf.appendSlice(alloc, line) catch return types.ParseError.OutOfMemory;
        in_continuation = false;
        try appendLogicalLine(alloc, &lines, joined_buf.items, logical_start);
    }

    if (in_continuation and joined_buf.items.len > 0) {
        try appendLogicalLine(alloc, &lines, joined_buf.items, logical_start);
    }

    return lines;
}

fn appendLogicalLine(
    alloc: std.mem.Allocator,
    lines: *std.ArrayListUnmanaged(LogicalLine),
    text: []const u8,
    line_number: usize,
) types.ParseError!void {
    const joined = alloc.dupe(u8, text) catch return types.ParseError.OutOfMemory;
    lines.append(alloc, .{ .text = joined, .line_number = line_number }) catch {
        alloc.free(joined);
        return types.ParseError.OutOfMemory;
    };
}

fn trimTrailingCarriageReturn(raw_line: []const u8) []const u8 {
    if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r') {
        return raw_line[0 .. raw_line.len - 1];
    }
    return raw_line;
}

fn endsWithContinuation(line: []const u8) bool {
    return line.len > 0 and line[line.len - 1] == '\\';
}

fn splitFirst(line: []const u8) KeywordSplit {
    for (line, 0..) |c, i| {
        if (c == ' ' or c == '\t') {
            return .{
                .keyword = line[0..i],
                .rest = std.mem.trimStart(u8, line[i + 1 ..], " \t"),
            };
        }
    }
    return .{ .keyword = line, .rest = "" };
}
