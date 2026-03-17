// manifest — TOML build manifest parser
//
// alternative to Dockerfile: a declarative TOML format for defining
// image builds. each [stage.*] section maps to a build stage with
// metadata fields and an ordered steps array.
//
// steps are strings in "instruction args" format, just like Dockerfile
// lines. metadata fields (from, env, workdir, cmd, etc.) are top-level
// keys on the stage table. this keeps the format simple and compatible
// with the existing TOML parser (no inline tables or array-of-tables
// needed).
//
// multi-stage example:
//
//   [stage.build]
//   from = "golang:1.22"
//   workdir = "/app"
//   env = ["CGO_ENABLED=0"]
//   steps = [
//       "copy go.mod go.sum .",
//       "run go mod download",
//       "run go build -o /app/server",
//   ]
//
//   [stage.runtime]
//   from = "alpine:3.19"
//   workdir = "/app"
//   steps = ["copy --from=build /app/server /app/server"]
//   expose = ["8080"]
//   entrypoint = ["/app/server"]
//
// single-stage shorthand (no [stage.*] wrapper):
//
//   from = "node:20"
//   workdir = "/app"
//   steps = ["copy package.json .", "run npm install", "copy src/ src/"]
//   cmd = ["node", "server.js"]

const std = @import("std");
const dockerfile = @import("dockerfile.zig");
const loader = @import("manifest/loader.zig");
const ordering = @import("manifest/ordering.zig");
const instruction_builder = @import("manifest/instructions.zig");
const step_parser = @import("manifest/steps.zig");
const types = @import("manifest/types.zig");

pub const LoadError = types.LoadError;
pub const LoadResult = types.LoadResult;

/// load a build manifest from a file path.
/// caller must call result.deinit() when done.
pub fn load(alloc: std.mem.Allocator, path: []const u8) LoadError!LoadResult {
    const content = std.fs.cwd().readFileAlloc(alloc, path, 1024 * 1024) catch |err| {
        return switch (err) {
            error.FileNotFound => LoadError.FileNotFound,
            else => LoadError.ReadFailed,
        };
    };
    defer alloc.free(content);

    return loader.loadFromString(alloc, content);
}
pub const loadFromString = loader.loadFromString;

fn parseStep(step: []const u8) ?types.ParsedStep {
    return step_parser.parseStep(step);
}

fn formatJsonArray(alloc: std.mem.Allocator, items: []const []const u8) ![]const u8 {
    return instruction_builder.formatJsonArray(alloc, items);
}

fn extractFromStage(step: []const u8) ?[]const u8 {
    return ordering.extractFromStage(step);
}

// -- tests --

test "single stage manifest" {
    const alloc = std.testing.allocator;
    const content =
        \\from = "node:20"
        \\workdir = "/app"
        \\steps = [
        \\    "copy package.json .",
        \\    "run npm install",
        \\    "copy src/ src/"
        \\]
        \\cmd = ["node", "server.js"]
    ;

    var result = try loadFromString(alloc, content);
    defer result.deinit();

    // FROM, WORKDIR, 3 steps, CMD = 6 instructions
    try std.testing.expectEqual(@as(usize, 6), result.instructions.len);

    try std.testing.expectEqual(dockerfile.InstructionKind.from, result.instructions[0].kind);
    try std.testing.expectEqualStrings("node:20", result.instructions[0].args);

    try std.testing.expectEqual(dockerfile.InstructionKind.workdir, result.instructions[1].kind);
    try std.testing.expectEqualStrings("/app", result.instructions[1].args);

    try std.testing.expectEqual(dockerfile.InstructionKind.copy, result.instructions[2].kind);
    try std.testing.expectEqualStrings("package.json .", result.instructions[2].args);

    try std.testing.expectEqual(dockerfile.InstructionKind.run, result.instructions[3].kind);
    try std.testing.expectEqualStrings("npm install", result.instructions[3].args);

    try std.testing.expectEqual(dockerfile.InstructionKind.copy, result.instructions[4].kind);
    try std.testing.expectEqualStrings("src/ src/", result.instructions[4].args);

    try std.testing.expectEqual(dockerfile.InstructionKind.cmd, result.instructions[5].kind);
    try std.testing.expectEqualStrings("[\"node\", \"server.js\"]", result.instructions[5].args);
}

test "multi-stage manifest" {
    const alloc = std.testing.allocator;
    const content =
        \\[stage.build]
        \\from = "golang:1.22"
        \\workdir = "/app"
        \\env = ["CGO_ENABLED=0"]
        \\steps = [
        \\    "copy go.mod go.sum .",
        \\    "run go mod download",
        \\    "run go build -o /app/server"
        \\]
        \\
        \\[stage.runtime]
        \\from = "alpine:3.19"
        \\workdir = "/app"
        \\steps = ["copy --from=build /app/server /app/server"]
        \\expose = ["8080"]
        \\entrypoint = ["/app/server"]
    ;

    var result = try loadFromString(alloc, content);
    defer result.deinit();

    // build stage: FROM + ENV + WORKDIR + 3 steps = 6
    // runtime stage: FROM + WORKDIR + 1 step + EXPOSE + ENTRYPOINT = 5
    // total = 11
    try std.testing.expectEqual(@as(usize, 11), result.instructions.len);

    // build stage comes first (runtime depends on it via --from=build)
    try std.testing.expectEqual(dockerfile.InstructionKind.from, result.instructions[0].kind);
    try std.testing.expectEqualStrings("golang:1.22 AS build", result.instructions[0].args);

    // runtime stage
    try std.testing.expectEqual(dockerfile.InstructionKind.from, result.instructions[6].kind);
    try std.testing.expectEqualStrings("alpine:3.19 AS runtime", result.instructions[6].args);
}

test "stage dependency resolution" {
    const alloc = std.testing.allocator;
    // declare runtime before build — resolver should reorder
    const content =
        \\[stage.runtime]
        \\from = "alpine:3.19"
        \\steps = ["copy --from=build /app/server /app/server"]
        \\
        \\[stage.build]
        \\from = "golang:1.22"
        \\steps = ["run go build -o /app/server"]
    ;

    var result = try loadFromString(alloc, content);
    defer result.deinit();

    // build should come before runtime despite declaration order
    try std.testing.expectEqual(dockerfile.InstructionKind.from, result.instructions[0].kind);
    try std.testing.expectEqualStrings("golang:1.22 AS build", result.instructions[0].args);

    // find the second FROM
    var second_from_idx: ?usize = null;
    for (result.instructions, 0..) |inst, i| {
        if (i > 0 and inst.kind == .from) {
            second_from_idx = i;
            break;
        }
    }
    try std.testing.expect(second_from_idx != null);
    try std.testing.expectEqualStrings("alpine:3.19 AS runtime", result.instructions[second_from_idx.?].args);
}

test "metadata fields produce correct instructions" {
    const alloc = std.testing.allocator;
    const content =
        \\from = "alpine:3.19"
        \\user = "appuser"
        \\env = ["NODE_ENV=production", "PORT=8080"]
        \\arg = ["VERSION=1.0"]
        \\expose = ["8080", "443"]
        \\volume = ["/data"]
        \\label = ["maintainer=test"]
        \\stopsignal = "SIGTERM"
        \\healthcheck = "CMD curl -f http://localhost/"
        \\entrypoint = ["/app/server"]
        \\cmd = ["--port", "8080"]
    ;

    var result = try loadFromString(alloc, content);
    defer result.deinit();

    // verify we find each instruction type
    var found_arg = false;
    var found_env_count: usize = 0;
    var found_user = false;
    var found_expose_count: usize = 0;
    var found_volume = false;
    var found_label = false;
    var found_stopsignal = false;
    var found_healthcheck = false;
    var found_entrypoint = false;
    var found_cmd = false;

    for (result.instructions) |inst| {
        switch (inst.kind) {
            .arg => {
                found_arg = true;
                try std.testing.expectEqualStrings("VERSION=1.0", inst.args);
            },
            .env => {
                found_env_count += 1;
            },
            .user => {
                found_user = true;
                try std.testing.expectEqualStrings("appuser", inst.args);
            },
            .expose => {
                found_expose_count += 1;
            },
            .volume => {
                found_volume = true;
                try std.testing.expectEqualStrings("/data", inst.args);
            },
            .label => {
                found_label = true;
                try std.testing.expectEqualStrings("maintainer=test", inst.args);
            },
            .stopsignal => {
                found_stopsignal = true;
                try std.testing.expectEqualStrings("SIGTERM", inst.args);
            },
            .healthcheck => {
                found_healthcheck = true;
                try std.testing.expectEqualStrings("CMD curl -f http://localhost/", inst.args);
            },
            .entrypoint => {
                found_entrypoint = true;
                try std.testing.expectEqualStrings("[\"/app/server\"]", inst.args);
            },
            .cmd => {
                found_cmd = true;
                try std.testing.expectEqualStrings("[\"--port\", \"8080\"]", inst.args);
            },
            else => {},
        }
    }

    try std.testing.expect(found_arg);
    try std.testing.expectEqual(@as(usize, 2), found_env_count);
    try std.testing.expect(found_user);
    try std.testing.expectEqual(@as(usize, 2), found_expose_count);
    try std.testing.expect(found_volume);
    try std.testing.expect(found_label);
    try std.testing.expect(found_stopsignal);
    try std.testing.expect(found_healthcheck);
    try std.testing.expect(found_entrypoint);
    try std.testing.expect(found_cmd);
}

test "missing from field returns error" {
    const alloc = std.testing.allocator;
    const content =
        \\workdir = "/app"
        \\steps = ["run echo hello"]
    ;

    const result = loadFromString(alloc, content);
    try std.testing.expectError(LoadError.EmptyManifest, result);
}

test "stage missing from returns error" {
    const alloc = std.testing.allocator;
    const content =
        \\[stage.build]
        \\workdir = "/app"
    ;

    const result = loadFromString(alloc, content);
    try std.testing.expectError(LoadError.MissingFrom, result);
}

test "invalid step keyword returns error" {
    const alloc = std.testing.allocator;
    const content =
        \\from = "alpine:3.19"
        \\steps = ["invalid command"]
    ;

    const result = loadFromString(alloc, content);
    try std.testing.expectError(LoadError.InvalidStep, result);
}

test "empty manifest returns error" {
    const alloc = std.testing.allocator;
    const content =
        \\# just a comment
    ;

    const result = loadFromString(alloc, content);
    try std.testing.expectError(LoadError.EmptyManifest, result);
}

test "from and onbuild disallowed in steps" {
    const alloc = std.testing.allocator;
    const content =
        \\from = "alpine:3.19"
        \\steps = ["from ubuntu:24.04"]
    ;

    const result = loadFromString(alloc, content);
    try std.testing.expectError(LoadError.InvalidStep, result);
}

test "shell metadata formatted as json" {
    const alloc = std.testing.allocator;
    const content =
        \\from = "alpine:3.19"
        \\shell = ["/bin/bash", "-c"]
    ;

    var result = try loadFromString(alloc, content);
    defer result.deinit();

    // FROM + SHELL = 2 instructions
    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(dockerfile.InstructionKind.shell, result.instructions[1].kind);
    try std.testing.expectEqualStrings("[\"/bin/bash\", \"-c\"]", result.instructions[1].args);
}

test "invalid toml returns parse error" {
    const alloc = std.testing.allocator;
    const content = "[invalid";
    const result = loadFromString(alloc, content);
    try std.testing.expectError(LoadError.ParseFailed, result);
}

test "manifest with no steps" {
    const alloc = std.testing.allocator;
    const content =
        \\from = "alpine:3.19"
        \\cmd = ["echo", "hello"]
    ;

    var result = try loadFromString(alloc, content);
    defer result.deinit();

    // FROM + CMD = 2
    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(dockerfile.InstructionKind.from, result.instructions[0].kind);
    try std.testing.expectEqual(dockerfile.InstructionKind.cmd, result.instructions[1].kind);
}

test "copy from stage in steps" {
    const alloc = std.testing.allocator;
    const content =
        \\from = "alpine:3.19"
        \\steps = ["copy --from=build /app/server /app/server"]
    ;

    var result = try loadFromString(alloc, content);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.instructions.len);
    try std.testing.expectEqual(dockerfile.InstructionKind.copy, result.instructions[1].kind);
    try std.testing.expectEqualStrings("--from=build /app/server /app/server", result.instructions[1].args);
}

test "extract from stage helper" {
    try std.testing.expectEqualStrings("build", extractFromStage("copy --from=build /src /dest").?);
    try std.testing.expectEqualStrings("stage0", extractFromStage("COPY --from=stage0 /a /b").?);
    try std.testing.expectEqualStrings("base", extractFromStage("add --from=base /file /dest").?);
    try std.testing.expect(extractFromStage("copy src dest") == null);
    try std.testing.expect(extractFromStage("run echo hello") == null);
    try std.testing.expect(extractFromStage("") == null);
}

test "format json array" {
    const alloc = std.testing.allocator;

    const result1 = try formatJsonArray(alloc, &.{"node"});
    defer alloc.free(result1);
    try std.testing.expectEqualStrings("[\"node\"]", result1);

    const result2 = try formatJsonArray(alloc, &.{ "/bin/sh", "-c", "echo hello" });
    defer alloc.free(result2);
    try std.testing.expectEqualStrings("[\"/bin/sh\", \"-c\", \"echo hello\"]", result2);

    const result3 = try formatJsonArray(alloc, &.{});
    defer alloc.free(result3);
    try std.testing.expectEqualStrings("[]", result3);
}

test "parse step helper" {
    const step1 = parseStep("run echo hello");
    try std.testing.expect(step1 != null);
    try std.testing.expectEqual(dockerfile.InstructionKind.run, step1.?.kind);
    try std.testing.expectEqualStrings("echo hello", step1.?.args);

    const step2 = parseStep("COPY src/ dest/");
    try std.testing.expect(step2 != null);
    try std.testing.expectEqual(dockerfile.InstructionKind.copy, step2.?.kind);
    try std.testing.expectEqualStrings("src/ dest/", step2.?.args);

    const step3 = parseStep(""); // empty
    try std.testing.expect(step3 == null);

    const step4 = parseStep("from ubuntu:24.04"); // disallowed
    try std.testing.expect(step4 == null);

    const step5 = parseStep("invalid stuff"); // unknown keyword
    try std.testing.expect(step5 == null);
}
