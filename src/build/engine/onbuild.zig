const std = @import("std");
const dockerfile = @import("../dockerfile.zig");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");

pub const TriggerDispatchFn = *const fn (
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    kind: dockerfile.InstructionKind,
    args: []const u8,
    context_dir: []const u8,
    stages: []const types.BuildStage,
    completed_states: []const types.BuildState,
) types.BuildError!void;

pub fn executePendingOnbuild(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    context_dir: []const u8,
    stages: []const types.BuildStage,
    completed_states: []const types.BuildState,
    dispatch_fn: TriggerDispatchFn,
) types.BuildError!void {
    if (state.pending_onbuild.items.len == 0) return;

    log.info("executing {d} ONBUILD trigger(s) from base image", .{state.pending_onbuild.items.len});

    for (state.pending_onbuild.items) |trigger| {
        const parsed = parseTrigger(trigger) orelse {
            log.warn("ONBUILD: skipping unparseable trigger: {s}", .{trigger});
            continue;
        };

        log.info("ONBUILD: {s} {s}", .{ @tagName(parsed.kind), parsed.args });

        switch (parsed.kind) {
            .from, .onbuild => {
                log.warn("ONBUILD: {s} is not allowed in triggers, skipping", .{@tagName(parsed.kind)});
            },
            else => try dispatch_fn(alloc, state, parsed.kind, parsed.args, context_dir, stages, completed_states),
        }
    }

    for (state.pending_onbuild.items) |t| alloc.free(t);
    state.pending_onbuild.clearRetainingCapacity();
}

pub fn parseTrigger(trigger: []const u8) ?types.TriggerInstruction {
    const trimmed = std.mem.trim(u8, trigger, " \t");
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
        std.mem.trimLeft(u8, trimmed[pos + 1 ..], " \t")
    else
        "";

    if (args.len == 0) return null;

    var lower_buf: [16]u8 = undefined;
    if (keyword.len > lower_buf.len) return null;
    for (keyword, 0..) |c, i| lower_buf[i] = std.ascii.toLower(c);
    const lower = lower_buf[0..keyword.len];

    const kind: dockerfile.InstructionKind = if (std.mem.eql(u8, lower, "run"))
        .run
    else if (std.mem.eql(u8, lower, "copy"))
        .copy
    else if (std.mem.eql(u8, lower, "add"))
        .add
    else if (std.mem.eql(u8, lower, "env"))
        .env
    else if (std.mem.eql(u8, lower, "expose"))
        .expose
    else if (std.mem.eql(u8, lower, "entrypoint"))
        .entrypoint
    else if (std.mem.eql(u8, lower, "cmd"))
        .cmd
    else if (std.mem.eql(u8, lower, "workdir"))
        .workdir
    else if (std.mem.eql(u8, lower, "arg"))
        .arg
    else if (std.mem.eql(u8, lower, "user"))
        .user
    else if (std.mem.eql(u8, lower, "label"))
        .label
    else if (std.mem.eql(u8, lower, "volume"))
        .volume
    else if (std.mem.eql(u8, lower, "shell"))
        .shell
    else if (std.mem.eql(u8, lower, "healthcheck"))
        .healthcheck
    else if (std.mem.eql(u8, lower, "stopsignal"))
        .stopsignal
    else if (std.mem.eql(u8, lower, "from"))
        .from
    else if (std.mem.eql(u8, lower, "onbuild"))
        .onbuild
    else
        return null;

    return .{ .kind = kind, .args = args };
}

test "parseTrigger valid instructions" {
    const t1 = parseTrigger("RUN echo hello").?;
    try std.testing.expectEqual(dockerfile.InstructionKind.run, t1.kind);
    try std.testing.expectEqualStrings("echo hello", t1.args);
}

test "parseTrigger rejects empty and unknown" {
    try std.testing.expect(parseTrigger("") == null);
    try std.testing.expect(parseTrigger("BADINSTRUCTION args") == null);
    try std.testing.expect(parseTrigger("RUN") == null);
}
