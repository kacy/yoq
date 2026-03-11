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
const toml = @import("../lib/toml.zig");
const dockerfile = @import("dockerfile.zig");
const log = @import("../lib/log.zig");

pub const LoadError = error{
    /// the manifest file does not exist at the given path
    FileNotFound,
    /// the manifest file exists but could not be read
    ReadFailed,
    /// the file content is not valid TOML
    ParseFailed,
    /// a stage is missing the required 'from' field
    MissingFrom,
    /// a step string has an unrecognized or disallowed instruction keyword
    InvalidStep,
    /// the manifest has no stages defined
    EmptyManifest,
    /// stages have circular copy --from references
    CyclicDependency,
    /// allocator ran out of memory
    OutOfMemory,
};

pub const LoadResult = struct {
    instructions: []dockerfile.Instruction,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *LoadResult) void {
        for (self.instructions) |inst| {
            self.alloc.free(inst.args);
        }
        self.alloc.free(self.instructions);
    }
};

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

    return loadFromString(alloc, content);
}

/// load a build manifest from a TOML string.
/// caller must call result.deinit() when done.
pub fn loadFromString(alloc: std.mem.Allocator, content: []const u8) LoadError!LoadResult {
    var parsed = toml.parse(alloc, content) catch {
        return LoadError.ParseFailed;
    };
    defer parsed.deinit();

    // multi-stage: [stage.*] subtables
    if (parsed.root.getTable("stage")) |stages| {
        return parseMultiStage(alloc, stages);
    }

    // single-stage: from + steps at root level
    if (parsed.root.getString("from") != null) {
        return parseSingleStage(alloc, &parsed.root);
    }

    log.err("build manifest: no stages found (need [stage.*] sections or top-level 'from')", .{});
    return LoadError.EmptyManifest;
}

// -- internal types --

const StageSpec = struct {
    name: []const u8,
    from: []const u8,
    workdir: ?[]const u8,
    env: ?[]const []const u8,
    arg: ?[]const []const u8,
    steps: ?[]const []const u8,
    expose: ?[]const []const u8,
    entrypoint: ?[]const []const u8,
    cmd: ?[]const []const u8,
    user: ?[]const u8,
    volume: ?[]const []const u8,
    shell: ?[]const []const u8,
    stopsignal: ?[]const u8,
    label: ?[]const []const u8,
    healthcheck: ?[]const u8,
};

// -- parsing --

fn parseSingleStage(alloc: std.mem.Allocator, root: *const toml.Table) LoadError!LoadResult {
    const stage = readStage(root, "default") orelse {
        return LoadError.MissingFrom;
    };
    const stages = [_]StageSpec{stage};
    return toInstructions(alloc, &stages);
}

fn parseMultiStage(alloc: std.mem.Allocator, stage_table: *const toml.Table) LoadError!LoadResult {
    var stages: std.ArrayListUnmanaged(StageSpec) = .empty;
    defer stages.deinit(alloc);

    for (stage_table.entries.keys(), stage_table.entries.values()) |name, val| {
        switch (val) {
            .table => |t| {
                const stage = readStage(t, name) orelse {
                    log.err("build manifest: stage '{s}' missing required 'from' field", .{name});
                    return LoadError.MissingFrom;
                };
                stages.append(alloc, stage) catch return LoadError.OutOfMemory;
            },
            else => {
                log.err("build manifest: stage '{s}' must be a table", .{name});
                return LoadError.ParseFailed;
            },
        }
    }

    if (stages.items.len == 0) {
        return LoadError.EmptyManifest;
    }

    // topological sort: stages referenced by --from= must come first
    const ordered = resolveStageOrder(alloc, stages.items) catch |err| {
        return err;
    };
    defer alloc.free(ordered);

    return toInstructions(alloc, ordered);
}

/// extract metadata fields from a TOML table into a StageSpec.
/// returns null if the required 'from' field is missing.
fn readStage(table: *const toml.Table, name: []const u8) ?StageSpec {
    const from = table.getString("from") orelse return null;

    return StageSpec{
        .name = name,
        .from = from,
        .workdir = table.getString("workdir"),
        .env = table.getArray("env"),
        .arg = table.getArray("arg"),
        .steps = table.getArray("steps"),
        .expose = table.getArray("expose"),
        .entrypoint = table.getArray("entrypoint"),
        .cmd = table.getArray("cmd"),
        .user = table.getString("user"),
        .volume = table.getArray("volume"),
        .shell = table.getArray("shell"),
        .stopsignal = table.getString("stopsignal"),
        .label = table.getArray("label"),
        .healthcheck = table.getString("healthcheck"),
    };
}

// -- instruction generation --

/// convert parsed stages into a flat instruction list compatible with
/// the build engine. each stage produces: FROM, then metadata setup
/// (ARG, ENV, WORKDIR, USER, SHELL), then ordered steps, then final
/// metadata (EXPOSE, VOLUME, LABEL, HEALTHCHECK, STOPSIGNAL, ENTRYPOINT,
/// CMD).
fn toInstructions(alloc: std.mem.Allocator, stages: []const StageSpec) LoadError!LoadResult {
    var instructions: std.ArrayListUnmanaged(dockerfile.Instruction) = .empty;
    errdefer {
        for (instructions.items) |inst| alloc.free(inst.args);
        instructions.deinit(alloc);
    }

    for (stages) |stage| {
        // FROM — include AS alias for named stages in multi-stage builds
        const from_args = if (stages.len > 1 and !std.mem.eql(u8, stage.name, "default"))
            std.fmt.allocPrint(alloc, "{s} AS {s}", .{ stage.from, stage.name }) catch
                return LoadError.OutOfMemory
        else
            alloc.dupe(u8, stage.from) catch return LoadError.OutOfMemory;

        instructions.append(alloc, .{
            .kind = .from,
            .args = from_args,
            .line_number = 0,
        }) catch {
            alloc.free(from_args);
            return LoadError.OutOfMemory;
        };

        // setup metadata — these apply before steps execute

        if (stage.arg) |args| {
            for (args) |a| {
                try appendInstruction(alloc, &instructions, .arg, a);
            }
        }

        if (stage.env) |envs| {
            for (envs) |e| {
                try appendInstruction(alloc, &instructions, .env, e);
            }
        }

        if (stage.workdir) |w| {
            try appendInstruction(alloc, &instructions, .workdir, w);
        }

        if (stage.user) |u| {
            try appendInstruction(alloc, &instructions, .user, u);
        }

        if (stage.shell) |s| {
            const json = formatJsonArray(alloc, s) catch return LoadError.OutOfMemory;
            instructions.append(alloc, .{
                .kind = .shell,
                .args = json,
                .line_number = 0,
            }) catch {
                alloc.free(json);
                return LoadError.OutOfMemory;
            };
        }

        // ordered steps — the core build instructions

        if (stage.steps) |steps| {
            for (steps) |step| {
                const parsed = parseStep(step) orelse {
                    log.err("build manifest: invalid step: '{s}'", .{step});
                    return LoadError.InvalidStep;
                };
                try appendInstruction(alloc, &instructions, parsed.kind, parsed.args);
            }
        }

        // final metadata — applied after steps

        if (stage.expose) |ports| {
            for (ports) |p| {
                try appendInstruction(alloc, &instructions, .expose, p);
            }
        }

        if (stage.volume) |vols| {
            for (vols) |v| {
                try appendInstruction(alloc, &instructions, .volume, v);
            }
        }

        if (stage.label) |labels| {
            for (labels) |l| {
                try appendInstruction(alloc, &instructions, .label, l);
            }
        }

        if (stage.healthcheck) |h| {
            try appendInstruction(alloc, &instructions, .healthcheck, h);
        }

        if (stage.stopsignal) |s| {
            try appendInstruction(alloc, &instructions, .stopsignal, s);
        }

        if (stage.entrypoint) |ep| {
            const json = formatJsonArray(alloc, ep) catch return LoadError.OutOfMemory;
            instructions.append(alloc, .{
                .kind = .entrypoint,
                .args = json,
                .line_number = 0,
            }) catch {
                alloc.free(json);
                return LoadError.OutOfMemory;
            };
        }

        if (stage.cmd) |cmd| {
            const json = formatJsonArray(alloc, cmd) catch return LoadError.OutOfMemory;
            instructions.append(alloc, .{
                .kind = .cmd,
                .args = json,
                .line_number = 0,
            }) catch {
                alloc.free(json);
                return LoadError.OutOfMemory;
            };
        }
    }

    return LoadResult{
        .instructions = instructions.toOwnedSlice(alloc) catch return LoadError.OutOfMemory,
        .alloc = alloc,
    };
}

fn appendInstruction(
    alloc: std.mem.Allocator,
    instructions: *std.ArrayListUnmanaged(dockerfile.Instruction),
    kind: dockerfile.InstructionKind,
    args: []const u8,
) LoadError!void {
    const owned_args = alloc.dupe(u8, args) catch return LoadError.OutOfMemory;
    instructions.append(alloc, .{
        .kind = kind,
        .args = owned_args,
        .line_number = 0,
    }) catch {
        alloc.free(owned_args);
        return LoadError.OutOfMemory;
    };
}

// -- step parsing --

const ParsedStep = struct {
    kind: dockerfile.InstructionKind,
    args: []const u8,
};

/// parse a step string like "run echo hello" into kind + args.
/// returns null for empty steps, unrecognized keywords, or
/// stage-level instructions (from, onbuild) that don't belong in steps.
fn parseStep(step: []const u8) ?ParsedStep {
    const trimmed = std.mem.trim(u8, step, " \t");
    if (trimmed.len == 0) return null;

    // split on first whitespace: keyword + args
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

    // all step instructions require arguments
    if (args.len == 0) return null;

    const kind = dockerfile.matchKeyword(keyword) orelse return null;

    // FROM and ONBUILD are stage-level, not allowed in steps
    if (kind == .from or kind == .onbuild) return null;

    return ParsedStep{ .kind = kind, .args = args };
}

// -- helpers --

/// format a string slice as a JSON array: ["a", "b", "c"]
fn formatJsonArray(alloc: std.mem.Allocator, items: []const []const u8) ![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);

    try buf.append(alloc, '[');
    for (items, 0..) |item, i| {
        if (i > 0) {
            try buf.appendSlice(alloc, ", ");
        }
        try buf.append(alloc, '"');
        try buf.appendSlice(alloc, item);
        try buf.append(alloc, '"');
    }
    try buf.append(alloc, ']');

    return buf.toOwnedSlice(alloc);
}

// -- stage ordering --

/// topological sort of stages by copy --from= dependencies.
/// stages referenced by --from= in other stages' steps are placed first.
/// uses a simple iterative approach (fine for the handful of stages
/// typical in a build manifest).
fn resolveStageOrder(alloc: std.mem.Allocator, stages: []const StageSpec) LoadError![]StageSpec {
    const n = stages.len;
    if (n <= 1) {
        const result = alloc.alloc(StageSpec, n) catch return LoadError.OutOfMemory;
        if (n == 1) result[0] = stages[0];
        return result;
    }

    var result = alloc.alloc(StageSpec, n) catch return LoadError.OutOfMemory;
    errdefer alloc.free(result);

    var placed = alloc.alloc(bool, n) catch return LoadError.OutOfMemory;
    defer alloc.free(placed);
    @memset(placed, false);

    var result_idx: usize = 0;

    // repeatedly place stages whose dependencies are all satisfied
    var progress = true;
    while (progress and result_idx < n) {
        progress = false;
        for (stages, 0..) |stage, i| {
            if (placed[i]) continue;

            if (allDepsPlaced(stage, stages, placed)) {
                result[result_idx] = stage;
                result_idx += 1;
                placed[i] = true;
                progress = true;
            }
        }
    }

    if (result_idx != n) {
        alloc.free(result);
        log.err("build manifest: circular dependency between stages", .{});
        return LoadError.CyclicDependency;
    }

    return result;
}

/// check if all stages referenced by --from= in this stage's steps
/// have already been placed in the output.
fn allDepsPlaced(stage: StageSpec, all_stages: []const StageSpec, placed: []const bool) bool {
    const steps = stage.steps orelse return true;
    for (steps) |step| {
        const dep_name = extractFromStage(step) orelse continue;
        for (all_stages, 0..) |s, j| {
            if (std.mem.eql(u8, s.name, dep_name) and !placed[j]) {
                return false;
            }
        }
    }
    return true;
}

/// extract the stage name from a "copy --from=name src dest" step.
/// returns null if the step doesn't reference another stage.
fn extractFromStage(step: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, step, " \t");

    // must start with copy or add
    const first_space = std.mem.indexOfAny(u8, trimmed, &[_]u8{ ' ', '\t' }) orelse return null;
    const keyword = trimmed[0..first_space];

    var lower_buf: [8]u8 = undefined;
    if (keyword.len > lower_buf.len) return null;
    for (keyword, 0..) |c, i| {
        lower_buf[i] = std.ascii.toLower(c);
    }
    const lower = lower_buf[0..keyword.len];

    if (!std.mem.eql(u8, lower, "copy") and !std.mem.eql(u8, lower, "add")) return null;

    // look for --from= in the remaining args
    const rest = std.mem.trimLeft(u8, trimmed[first_space + 1 ..], " \t");
    if (!std.mem.startsWith(u8, rest, "--from=")) return null;

    const after_eq = rest["--from=".len..];
    const end = std.mem.indexOfAny(u8, after_eq, &[_]u8{ ' ', '\t' }) orelse after_eq.len;
    if (end == 0) return null;

    return after_eq[0..end];
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
