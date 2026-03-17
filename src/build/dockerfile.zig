// dockerfile — Dockerfile parser
//
// parses a Dockerfile into a list of instructions. simple line-by-line
// parser: no tokenizer, no AST. handles continuation lines (trailing \),
// comments, and the standard instruction set.
//
// supported instructions:
//   FROM, RUN, COPY, ADD, ENV, EXPOSE, ENTRYPOINT, CMD, WORKDIR, ARG,
//   USER, LABEL, VOLUME, SHELL, HEALTHCHECK, STOPSIGNAL, ONBUILD

const std = @import("std");
const parser = @import("dockerfile/parser.zig");
const keywords = @import("dockerfile/keywords.zig");
const types = @import("dockerfile/types.zig");

pub const InstructionKind = types.InstructionKind;
pub const Instruction = types.Instruction;
pub const ParseError = types.ParseError;
pub const ParseResult = types.ParseResult;

pub const parse = parser.parse;
pub const isJsonForm = parser.isJsonForm;
pub const matchKeyword = keywords.matchKeyword;

// -- tests --

test "parse minimal dockerfile" {
    const alloc = std.testing.allocator;
    const content =
        \\FROM ubuntu:24.04
        \\RUN echo hello
    ;

    var result = try parse(alloc, content);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.from, result.instructions[0].kind);
    try std.testing.expectEqualStrings("ubuntu:24.04", result.instructions[0].args);
    try std.testing.expectEqual(@as(usize, 1), result.instructions[0].line_number);

    try std.testing.expectEqual(InstructionKind.run, result.instructions[1].kind);
    try std.testing.expectEqualStrings("echo hello", result.instructions[1].args);
    try std.testing.expectEqual(@as(usize, 2), result.instructions[1].line_number);
}

test "parse with comments and empty lines" {
    const alloc = std.testing.allocator;
    const content =
        \\# this is a comment
        \\FROM alpine:latest
        \\
        \\# another comment
        \\RUN apk add curl
    ;

    var result = try parse(alloc, content);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.from, result.instructions[0].kind);
    try std.testing.expectEqualStrings("alpine:latest", result.instructions[0].args);
    try std.testing.expectEqual(InstructionKind.run, result.instructions[1].kind);
    try std.testing.expectEqualStrings("apk add curl", result.instructions[1].args);
}

test "parse line continuation" {
    const alloc = std.testing.allocator;
    const content =
        \\FROM ubuntu:24.04
        \\RUN apt-get update && \
        \\    apt-get install -y curl && \
        \\    rm -rf /var/lib/apt/lists/*
    ;

    var result = try parse(alloc, content);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.run, result.instructions[1].kind);
    // continuation lines are joined with space replacing the backslash
    try std.testing.expect(std.mem.indexOf(u8, result.instructions[1].args, "apt-get update") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.instructions[1].args, "rm -rf") != null);
    // line number should point to the first physical line
    try std.testing.expectEqual(@as(usize, 2), result.instructions[1].line_number);
}

test "parse all instruction types" {
    const alloc = std.testing.allocator;
    const content =
        \\FROM node:20
        \\ARG VERSION=1.0
        \\LABEL maintainer=test
        \\ENV NODE_ENV=production
        \\WORKDIR /app
        \\USER node
        \\COPY package.json .
        \\ADD archive.tar.gz /app/
        \\RUN npm install
        \\EXPOSE 3000
        \\VOLUME /data
        \\SHELL ["/bin/bash", "-c"]
        \\HEALTHCHECK CMD curl -f http://localhost/
        \\STOPSIGNAL SIGTERM
        \\ONBUILD RUN echo trigger
        \\ENTRYPOINT ["node"]
        \\CMD ["server.js"]
    ;

    var result = try parse(alloc, content);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 17), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.from, result.instructions[0].kind);
    try std.testing.expectEqual(InstructionKind.arg, result.instructions[1].kind);
    try std.testing.expectEqual(InstructionKind.label, result.instructions[2].kind);
    try std.testing.expectEqual(InstructionKind.env, result.instructions[3].kind);
    try std.testing.expectEqual(InstructionKind.workdir, result.instructions[4].kind);
    try std.testing.expectEqual(InstructionKind.user, result.instructions[5].kind);
    try std.testing.expectEqual(InstructionKind.copy, result.instructions[6].kind);
    try std.testing.expectEqual(InstructionKind.add, result.instructions[7].kind);
    try std.testing.expectEqual(InstructionKind.run, result.instructions[8].kind);
    try std.testing.expectEqual(InstructionKind.expose, result.instructions[9].kind);
    try std.testing.expectEqual(InstructionKind.volume, result.instructions[10].kind);
    try std.testing.expectEqual(InstructionKind.shell, result.instructions[11].kind);
    try std.testing.expectEqual(InstructionKind.healthcheck, result.instructions[12].kind);
    try std.testing.expectEqual(InstructionKind.stopsignal, result.instructions[13].kind);
    try std.testing.expectEqual(InstructionKind.onbuild, result.instructions[14].kind);
    try std.testing.expectEqual(InstructionKind.entrypoint, result.instructions[15].kind);
    try std.testing.expectEqual(InstructionKind.cmd, result.instructions[16].kind);
}

test "case insensitive keywords" {
    const alloc = std.testing.allocator;
    const content =
        \\from ubuntu:24.04
        \\RUN echo one
        \\Run echo two
        \\rUn echo three
    ;

    var result = try parse(alloc, content);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 4), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.from, result.instructions[0].kind);
    try std.testing.expectEqual(InstructionKind.run, result.instructions[1].kind);
    try std.testing.expectEqual(InstructionKind.run, result.instructions[2].kind);
    try std.testing.expectEqual(InstructionKind.run, result.instructions[3].kind);
}

test "unknown instruction returns error" {
    const alloc = std.testing.allocator;
    const content =
        \\FROM ubuntu:24.04
        \\INVALID something
    ;

    const result = parse(alloc, content);
    try std.testing.expectError(ParseError.UnknownInstruction, result);
}

test "empty instruction returns error" {
    const alloc = std.testing.allocator;
    // FROM with no args
    const content = "FROM";

    const result = parse(alloc, content);
    try std.testing.expectError(ParseError.EmptyInstruction, result);
}

test "json form detection" {
    try std.testing.expect(isJsonForm("[\"node\", \"server.js\"]"));
    try std.testing.expect(isJsonForm("[\"echo\"]"));
    try std.testing.expect(isJsonForm("  [\"cmd\"]  "));
    try std.testing.expect(!isJsonForm("echo hello"));
    try std.testing.expect(!isJsonForm("[incomplete"));
    try std.testing.expect(!isJsonForm(""));
}

test "parse empty content" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "");
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.instructions.len);
}

test "parse comments only" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "# just a comment\n# another one");
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.instructions.len);
}

test "windows line endings" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "FROM alpine:latest\r\nRUN echo hi\r\n");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqualStrings("alpine:latest", result.instructions[0].args);
    try std.testing.expectEqualStrings("echo hi", result.instructions[1].args);
}

test "trailing continuation at eof" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "FROM alpine:latest\nRUN echo hello \\");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.from, result.instructions[0].kind);
    try std.testing.expectEqual(InstructionKind.run, result.instructions[1].kind);
    // the backslash is stripped and a trailing space is appended during continuation join
    try std.testing.expect(std.mem.indexOf(u8, result.instructions[1].args, "echo hello") != null);
}

test "from with as alias" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "FROM node:20 AS builder\nRUN echo build");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.from, result.instructions[0].kind);
    // parser preserves the full string including AS — engine handles stripping
    try std.testing.expectEqualStrings("node:20 AS builder", result.instructions[0].args);
    try std.testing.expectEqual(InstructionKind.run, result.instructions[1].kind);
    try std.testing.expectEqualStrings("echo build", result.instructions[1].args);
}

test "extra whitespace between keyword and args" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "FROM    ubuntu:24.04\nRUN\t\techo hello");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqualStrings("ubuntu:24.04", result.instructions[0].args);
    try std.testing.expectEqualStrings("echo hello", result.instructions[1].args);
}

test "parse ADD instruction" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "FROM alpine:latest\nADD archive.tar.gz /app/");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.add, result.instructions[1].kind);
    try std.testing.expectEqualStrings("archive.tar.gz /app/", result.instructions[1].args);
}

test "parse VOLUME instruction" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "FROM alpine:latest\nVOLUME /data");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.volume, result.instructions[1].kind);
    try std.testing.expectEqualStrings("/data", result.instructions[1].args);
}

test "parse VOLUME json form" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "FROM alpine:latest\nVOLUME [\"/data\", \"/logs\"]");
    defer result.deinit();

    try std.testing.expectEqual(InstructionKind.volume, result.instructions[1].kind);
    try std.testing.expect(isJsonForm(result.instructions[1].args));
}

test "parse SHELL instruction" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "FROM alpine:latest\nSHELL [\"/bin/bash\", \"-c\"]");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.shell, result.instructions[1].kind);
    try std.testing.expectEqualStrings("[\"/bin/bash\", \"-c\"]", result.instructions[1].args);
}

test "parse HEALTHCHECK instruction" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "FROM alpine:latest\nHEALTHCHECK CMD curl -f http://localhost/");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.healthcheck, result.instructions[1].kind);
    try std.testing.expectEqualStrings("CMD curl -f http://localhost/", result.instructions[1].args);
}

test "parse HEALTHCHECK NONE" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "FROM alpine:latest\nHEALTHCHECK NONE");
    defer result.deinit();

    try std.testing.expectEqual(InstructionKind.healthcheck, result.instructions[1].kind);
    try std.testing.expectEqualStrings("NONE", result.instructions[1].args);
}

test "parse STOPSIGNAL instruction" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "FROM alpine:latest\nSTOPSIGNAL SIGTERM");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.stopsignal, result.instructions[1].kind);
    try std.testing.expectEqualStrings("SIGTERM", result.instructions[1].args);
}

test "parse ONBUILD instruction" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "FROM alpine:latest\nONBUILD RUN echo triggered");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.onbuild, result.instructions[1].kind);
    try std.testing.expectEqualStrings("RUN echo triggered", result.instructions[1].args);
}

test "new directives case insensitive" {
    const alloc = std.testing.allocator;
    const content =
        \\FROM alpine:latest
        \\add file.txt /app/
        \\volume /data
        \\Shell ["/bin/bash", "-c"]
        \\healthcheck CMD curl localhost
        \\StopSignal SIGINT
        \\onBuild RUN echo hi
    ;

    var result = try parse(alloc, content);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 7), result.instructions.len);
    try std.testing.expectEqual(InstructionKind.add, result.instructions[1].kind);
    try std.testing.expectEqual(InstructionKind.volume, result.instructions[2].kind);
    try std.testing.expectEqual(InstructionKind.shell, result.instructions[3].kind);
    try std.testing.expectEqual(InstructionKind.healthcheck, result.instructions[4].kind);
    try std.testing.expectEqual(InstructionKind.stopsignal, result.instructions[5].kind);
    try std.testing.expectEqual(InstructionKind.onbuild, result.instructions[6].kind);
}
