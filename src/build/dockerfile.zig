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

/// parse a Dockerfile into a list of instructions.
/// caller must call result.deinit() when done.
pub fn parse(alloc: std.mem.Allocator, content: []const u8) ParseError!ParseResult {
    var instructions: std.ArrayListUnmanaged(Instruction) = .empty;
    errdefer {
        for (instructions.items) |inst| alloc.free(inst.args);
        instructions.deinit(alloc);
    }

    // first pass: join continuation lines (trailing \)
    var lines: std.ArrayListUnmanaged(LogicalLine) = .empty;
    defer lines.deinit(alloc);

    var joined_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer joined_buf.deinit(alloc);

    var line_iter = std.mem.splitScalar(u8, content, '\n');
    var physical_line: usize = 0;
    var logical_start: usize = 1;
    var in_continuation = false;

    while (line_iter.next()) |raw_line| {
        physical_line += 1;

        // strip trailing \r for windows line endings
        const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
            raw_line[0 .. raw_line.len - 1]
        else
            raw_line;

        if (!in_continuation) {
            logical_start = physical_line;
            joined_buf.clearRetainingCapacity();
        }

        // check for continuation (trailing backslash)
        if (line.len > 0 and line[line.len - 1] == '\\') {
            // append without the backslash, add a space instead
            joined_buf.appendSlice(alloc, line[0 .. line.len - 1]) catch return ParseError.OutOfMemory;
            joined_buf.append(alloc, ' ') catch return ParseError.OutOfMemory;
            in_continuation = true;
            continue;
        }

        // final line of this logical line
        joined_buf.appendSlice(alloc, line) catch return ParseError.OutOfMemory;
        in_continuation = false;

        const joined = alloc.dupe(u8, joined_buf.items) catch return ParseError.OutOfMemory;
        lines.append(alloc, .{ .text = joined, .line_number = logical_start }) catch {
            alloc.free(joined);
            return ParseError.OutOfMemory;
        };
    }

    // if we ended mid-continuation, treat the accumulated text as a final line
    if (in_continuation and joined_buf.items.len > 0) {
        const joined = alloc.dupe(u8, joined_buf.items) catch return ParseError.OutOfMemory;
        lines.append(alloc, .{ .text = joined, .line_number = logical_start }) catch {
            alloc.free(joined);
            return ParseError.OutOfMemory;
        };
    }

    // second pass: parse each logical line
    for (lines.items) |logical_line| {
        defer alloc.free(logical_line.text);

        const trimmed = std.mem.trim(u8, logical_line.text, " \t");

        // skip empty lines and comments
        if (trimmed.len == 0) continue;
        if (trimmed[0] == '#') continue;

        // split on first whitespace: keyword + args
        const split = splitFirst(trimmed);
        const keyword = split.keyword;
        const args_raw = split.rest;

        const kind = matchKeyword(keyword) orelse return ParseError.UnknownInstruction;

        // args are required for all instructions
        if (args_raw.len == 0) return ParseError.EmptyInstruction;

        const args = alloc.dupe(u8, args_raw) catch return ParseError.OutOfMemory;
        instructions.append(alloc, .{
            .kind = kind,
            .args = args,
            .line_number = logical_line.line_number,
        }) catch {
            alloc.free(args);
            return ParseError.OutOfMemory;
        };
    }

    return ParseResult{
        .instructions = instructions.toOwnedSlice(alloc) catch return ParseError.OutOfMemory,
        .alloc = alloc,
    };
}

/// detect if args represent JSON form (e.g. ["cmd", "arg"]).
/// used for CMD, ENTRYPOINT, and RUN instructions.
pub fn isJsonForm(args: []const u8) bool {
    const trimmed = std.mem.trim(u8, args, " \t");
    return trimmed.len >= 2 and trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']';
}

// -- internal --

const LogicalLine = struct {
    text: []const u8,
    line_number: usize,
};

const KeywordSplit = struct {
    keyword: []const u8,
    rest: []const u8,
};

/// split a line into keyword and remaining text at first whitespace
fn splitFirst(line: []const u8) KeywordSplit {
    for (line, 0..) |c, i| {
        if (c == ' ' or c == '\t') {
            return .{
                .keyword = line[0..i],
                .rest = std.mem.trimLeft(u8, line[i + 1 ..], " \t"),
            };
        }
    }
    return .{ .keyword = line, .rest = "" };
}

/// match a keyword string (case-insensitive) to an InstructionKind
pub fn matchKeyword(keyword: []const u8) ?InstructionKind {
    // convert to lowercase for comparison
    var lower_buf: [16]u8 = undefined;
    if (keyword.len > lower_buf.len) return null;

    for (keyword, 0..) |c, i| {
        lower_buf[i] = std.ascii.toLower(c);
    }
    const lower = lower_buf[0..keyword.len];

    if (std.mem.eql(u8, lower, "from")) return .from;
    if (std.mem.eql(u8, lower, "run")) return .run;
    if (std.mem.eql(u8, lower, "copy")) return .copy;
    if (std.mem.eql(u8, lower, "add")) return .add;
    if (std.mem.eql(u8, lower, "env")) return .env;
    if (std.mem.eql(u8, lower, "expose")) return .expose;
    if (std.mem.eql(u8, lower, "entrypoint")) return .entrypoint;
    if (std.mem.eql(u8, lower, "cmd")) return .cmd;
    if (std.mem.eql(u8, lower, "workdir")) return .workdir;
    if (std.mem.eql(u8, lower, "arg")) return .arg;
    if (std.mem.eql(u8, lower, "user")) return .user;
    if (std.mem.eql(u8, lower, "label")) return .label;
    if (std.mem.eql(u8, lower, "volume")) return .volume;
    if (std.mem.eql(u8, lower, "shell")) return .shell;
    if (std.mem.eql(u8, lower, "healthcheck")) return .healthcheck;
    if (std.mem.eql(u8, lower, "stopsignal")) return .stopsignal;
    if (std.mem.eql(u8, lower, "onbuild")) return .onbuild;
    return null;
}

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
