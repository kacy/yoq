const std = @import("std");
const dockerfile = @import("../dockerfile.zig");
const types = @import("types.zig");
const stages_mod = @import("stages.zig");
const dispatch = @import("dispatch.zig");
const meta_handlers = @import("handlers_meta.zig");
const onbuild = @import("onbuild.zig");
const image_output = @import("image_output.zig");

pub const Engine = struct {
    alloc: std.mem.Allocator,
    instructions: []const dockerfile.Instruction,
    context_dir: []const u8,
    tag: ?[]const u8,
    cli_build_args: ?[]const []const u8,

    pub fn init(
        alloc: std.mem.Allocator,
        instructions: []const dockerfile.Instruction,
        context_dir: []const u8,
        tag: ?[]const u8,
        cli_build_args: ?[]const []const u8,
    ) Engine {
        return .{
            .alloc = alloc,
            .instructions = instructions,
            .context_dir = context_dir,
            .tag = tag,
            .cli_build_args = cli_build_args,
        };
    }

    pub fn run(self: *Engine) types.BuildError!types.BuildResult {
        try self.validateInput();

        const stages = stages_mod.splitIntoStages(self.alloc, self.instructions) catch
            return types.BuildError.ParseFailed;
        defer self.alloc.free(stages);

        var completed_states: std.ArrayListUnmanaged(types.BuildState) = .empty;
        defer {
            for (completed_states.items) |*s| s.deinit();
            completed_states.deinit(self.alloc);
        }

        for (stages) |stage| {
            const state = try self.runStage(stage, stages, completed_states.items);
            completed_states.append(self.alloc, state) catch {
                var s = state;
                s.deinit();
                return types.BuildError.ImageStoreFailed;
            };
        }

        if (completed_states.items.len == 0) return types.BuildError.NoFromInstruction;
        const final_state = &completed_states.items[completed_states.items.len - 1];
        return image_output.produceImage(self.alloc, final_state, self.tag);
    }

    fn validateInput(self: *Engine) types.BuildError!void {
        if (self.instructions.len == 0 or self.instructions[0].kind != .from) {
            return types.BuildError.NoFromInstruction;
        }
    }

    fn seedCliBuildArgs(self: *Engine, state: *types.BuildState) void {
        if (self.cli_build_args) |args| {
            for (args) |arg| {
                if (std.mem.indexOfScalar(u8, arg, '=')) |eq| {
                    const key = self.alloc.dupe(u8, arg[0..eq]) catch continue;
                    const val = self.alloc.dupe(u8, arg[eq + 1 ..]) catch {
                        self.alloc.free(key);
                        continue;
                    };
                    state.build_args.put(self.alloc, key, val) catch {
                        self.alloc.free(key);
                        self.alloc.free(val);
                    };
                }
            }
        }
    }

    fn runStage(
        self: *Engine,
        stage: types.BuildStage,
        all_stages: []const types.BuildStage,
        completed_states: []const types.BuildState,
    ) types.BuildError!types.BuildState {
        var state = types.BuildState.init(self.alloc);
        errdefer state.deinit();

        self.seedCliBuildArgs(&state);

        for (stage.instructions) |inst| {
            const effective_args = if (inst.kind != .arg)
                meta_handlers.expandArgs(self.alloc, inst.args, &state.build_args) catch inst.args
            else
                inst.args;
            defer if (inst.kind != .arg and effective_args.ptr != inst.args.ptr)
                self.alloc.free(effective_args);

            try dispatch.dispatchInstruction(
                self.alloc,
                &state,
                inst.kind,
                effective_args,
                self.context_dir,
                all_stages,
                completed_states,
            );

            if (inst.kind == .from) {
                try onbuild.executePendingOnbuild(
                    self.alloc,
                    &state,
                    self.context_dir,
                    all_stages,
                    completed_states,
                    dispatch.dispatchInstruction,
                );
            }
        }

        return state;
    }
};
