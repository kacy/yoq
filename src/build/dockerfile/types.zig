const std = @import("std");

pub const InstructionKind = enum {
    from,
    run,
    copy,
    add,
    env,
    expose,
    entrypoint,
    cmd,
    workdir,
    arg,
    user,
    label,
    volume,
    shell,
    healthcheck,
    stopsignal,
    onbuild,
};

pub const Instruction = struct {
    kind: InstructionKind,
    /// raw text after the keyword (trimmed of leading/trailing whitespace)
    args: []const u8,
    /// 1-based line number where this instruction starts
    line_number: usize,
};

pub const ParseError = error{
    /// line starts with an unrecognized keyword (not a valid Dockerfile instruction)
    UnknownInstruction,
    /// instruction keyword found but no arguments follow it
    EmptyInstruction,
    /// allocator ran out of memory during parsing
    OutOfMemory,
};

pub const ParseResult = struct {
    instructions: []Instruction,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *ParseResult) void {
        for (self.instructions) |inst| {
            self.alloc.free(inst.args);
        }
        self.alloc.free(self.instructions);
    }
};
