const std = @import("std");
const dockerfile = @import("../dockerfile.zig");
const types = @import("types.zig");
const fs_handlers = @import("handlers_fs.zig");
const meta_handlers = @import("handlers_meta.zig");

pub fn dispatchInstruction(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    kind: dockerfile.InstructionKind,
    args: []const u8,
    context_dir: []const u8,
    stages: []const types.BuildStage,
    completed_states: []const types.BuildState,
) types.BuildError!void {
    switch (kind) {
        .from => try fs_handlers.processFrom(alloc, state, args),
        .run => try fs_handlers.processRun(alloc, state, args),
        .copy => try fs_handlers.processCopyMultiStage(alloc, state, args, context_dir, stages, completed_states),
        .add => try fs_handlers.processAddMultiStage(alloc, state, args, context_dir, stages, completed_states),
        .env => meta_handlers.processEnv(alloc, state, args),
        .workdir => meta_handlers.processWorkdir(alloc, state, args),
        .cmd => meta_handlers.processCmd(alloc, state, args),
        .entrypoint => meta_handlers.processEntrypoint(alloc, state, args),
        .expose => meta_handlers.processExpose(alloc, state, args),
        .user => meta_handlers.processUser(alloc, state, args),
        .label => meta_handlers.processLabel(alloc, state, args),
        .volume => meta_handlers.processVolume(alloc, state, args),
        .shell => meta_handlers.processShell(alloc, state, args),
        .healthcheck => meta_handlers.processHealthcheck(alloc, state, args),
        .stopsignal => meta_handlers.processStopsignal(alloc, state, args),
        .onbuild => meta_handlers.processOnbuild(alloc, state, args),
        .arg => meta_handlers.processArg(alloc, state, args),
    }
}
