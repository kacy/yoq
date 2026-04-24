const std = @import("std");

const dockerfile = @import("../dockerfile.zig");
const types = @import("types.zig");

pub fn parseStep(step: []const u8) ?types.ParsedStep {
    const trimmed = std.mem.trim(u8, step, " \t");
    if (trimmed.len == 0) return null;

    var split_pos: ?usize = null;
    for (trimmed, 0..) |c, i| {
        if (c == ' ' or c == '\t') {
            split_pos = i;
            break;
        }
    }

    const keyword = if (split_pos) |pos| trimmed[0..pos] else trimmed;
    const args = if (split_pos) |pos|
        std.mem.trimStart(u8, trimmed[pos + 1 ..], " \t")
    else
        "";

    if (args.len == 0) return null;

    const kind = dockerfile.matchKeyword(keyword) orelse return null;
    if (kind == .from or kind == .onbuild) return null;

    return .{ .kind = kind, .args = args };
}
