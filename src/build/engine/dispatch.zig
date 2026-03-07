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
        .env => try meta_handlers.processEnv(alloc, state, args),
        .workdir => try meta_handlers.processWorkdir(alloc, state, args),
        .cmd => try meta_handlers.processCmd(alloc, state, args),
        .entrypoint => try meta_handlers.processEntrypoint(alloc, state, args),
        .expose => try meta_handlers.processExpose(alloc, state, args),
        .user => try meta_handlers.processUser(alloc, state, args),
        .label => try meta_handlers.processLabel(alloc, state, args),
        .volume => try meta_handlers.processVolume(alloc, state, args),
        .shell => try meta_handlers.processShell(alloc, state, args),
        .healthcheck => try meta_handlers.processHealthcheck(alloc, state, args),
        .stopsignal => try meta_handlers.processStopsignal(alloc, state, args),
        .onbuild => try meta_handlers.processOnbuild(alloc, state, args),
        .arg => try meta_handlers.processArg(alloc, state, args), // processArg is still void return
    }
}
