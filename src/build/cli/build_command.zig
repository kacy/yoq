const std = @import("std");

const cli = @import("../../lib/cli.zig");
const dockerfile = @import("../dockerfile.zig");
const build_engine = @import("../engine.zig");
const build_manifest = @import("../manifest.zig");
const spec = @import("../../image/spec.zig");

const write = cli.write;
const writeErr = cli.writeErr;

pub const BuildCommandsError = error{
    InvalidArgument,
    BuildFailed,
    ParseFailed,
    OutOfMemory,
};

const BuildFormat = enum {
    dockerfile,
    toml,
};

const BuildOptions = struct {
    tag: ?[]const u8 = null,
    dockerfile_path: []const u8 = "Dockerfile",
    context_path: ?[]const u8 = null,
    format: BuildFormat = .dockerfile,
    build_args_list: std.ArrayListUnmanaged([]const u8) = .empty,

    fn deinit(self: *BuildOptions, alloc: std.mem.Allocator) void {
        self.build_args_list.deinit(alloc);
    }
};

const LoadedInstructions = union(enum) {
    dockerfile: dockerfile.ParseResult,
    manifest: build_manifest.LoadResult,

    fn instructions(self: *const LoadedInstructions) []const dockerfile.Instruction {
        return switch (self.*) {
            .dockerfile => |result| result.instructions,
            .manifest => |result| result.instructions,
        };
    }

    fn deinit(self: *LoadedInstructions) void {
        switch (self.*) {
            .dockerfile => |*result| result.deinit(),
            .manifest => |*result| result.deinit(),
        }
    }
};

pub fn build_cmd(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var options = try parseBuildOptions(args, alloc);
    defer options.deinit(alloc);

    const ctx_dir = options.context_path orelse ".";
    try validateTag(options.tag);

    var path_buf: [4096]u8 = undefined;
    const build_file_path = try resolveBuildFilePath(&options, ctx_dir, &path_buf);

    var loaded = try loadInstructions(alloc, options.format, build_file_path);
    defer loaded.deinit();

    writeErr("building from {s} ({d} instructions)...\n", .{
        build_file_path,
        loaded.instructions().len,
    });

    var abs_ctx_buf: [4096]u8 = undefined;
    const abs_ctx = @import("compat").cwd().realpath(ctx_dir, &abs_ctx_buf) catch {
        writeErr("cannot resolve context directory: {s}\n", .{ctx_dir});
        return BuildCommandsError.InvalidArgument;
    };

    const cli_args: ?[]const []const u8 = if (options.build_args_list.items.len > 0)
        options.build_args_list.items
    else
        null;
    var result = build_engine.build(alloc, loaded.instructions(), abs_ctx, options.tag, cli_args) catch |err| {
        renderBuildError(err);
        return BuildCommandsError.BuildFailed;
    };
    defer result.deinit();

    renderBuildResult(options.tag, result);
}

fn parseBuildOptions(
    args: *std.process.Args.Iterator,
    alloc: std.mem.Allocator,
) BuildCommandsError!BuildOptions {
    var options = BuildOptions{};
    errdefer options.deinit(alloc);

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-t")) {
            options.tag = args.next() orelse {
                writeErr("-t requires an image tag\n", .{});
                return BuildCommandsError.InvalidArgument;
            };
            continue;
        }

        if (std.mem.eql(u8, arg, "-f")) {
            options.dockerfile_path = args.next() orelse {
                writeErr("-f requires a Dockerfile path\n", .{});
                return BuildCommandsError.InvalidArgument;
            };
            continue;
        }

        if (std.mem.eql(u8, arg, "--format")) {
            options.format = try parseFormat(args.next() orelse {
                writeErr("--format requires 'dockerfile' or 'toml'\n", .{});
                return BuildCommandsError.InvalidArgument;
            });
            continue;
        }

        if (std.mem.eql(u8, arg, "--build-arg")) {
            const build_arg = args.next() orelse {
                writeErr("--build-arg requires KEY=VALUE\n", .{});
                return BuildCommandsError.InvalidArgument;
            };
            options.build_args_list.append(alloc, build_arg) catch return BuildCommandsError.OutOfMemory;
            continue;
        }

        options.context_path = arg;
    }

    return options;
}

fn parseFormat(fmt: []const u8) BuildCommandsError!BuildFormat {
    if (std.mem.eql(u8, fmt, "toml")) return .toml;
    if (std.mem.eql(u8, fmt, "dockerfile")) return .dockerfile;
    writeErr("unknown format '{s}', expected 'dockerfile' or 'toml'\n", .{fmt});
    return BuildCommandsError.InvalidArgument;
}

fn validateTag(tag: ?[]const u8) BuildCommandsError!void {
    const value = tag orelse return;
    const ref = spec.parseImageRef(value);
    if (!isValidTag(ref.reference)) {
        writeErr("invalid tag: must be alphanumeric with '.', '-', '_' (max 128 chars)\n", .{});
        return BuildCommandsError.InvalidArgument;
    }
}

fn resolveBuildFilePath(
    options: *const BuildOptions,
    ctx_dir: []const u8,
    path_buf: []u8,
) BuildCommandsError![]const u8 {
    const default_filename: []const u8 = switch (options.format) {
        .dockerfile => "Dockerfile",
        .toml => "build.toml",
    };
    const using_default = std.mem.eql(u8, options.dockerfile_path, "Dockerfile");

    if (!using_default) return options.dockerfile_path;

    return std.fmt.bufPrint(path_buf, "{s}/{s}", .{ ctx_dir, default_filename }) catch {
        writeErr("path too long\n", .{});
        return BuildCommandsError.InvalidArgument;
    };
}

fn loadInstructions(
    alloc: std.mem.Allocator,
    format: BuildFormat,
    path: []const u8,
) BuildCommandsError!LoadedInstructions {
    return switch (format) {
        .dockerfile => .{ .dockerfile = try loadDockerfile(alloc, path) },
        .toml => .{ .manifest = try loadManifest(alloc, path) },
    };
}

fn loadDockerfile(
    alloc: std.mem.Allocator,
    path: []const u8,
) BuildCommandsError!dockerfile.ParseResult {
    const content = @import("compat").cwd().readFileAlloc(alloc, path, 1024 * 1024) catch {
        writeErr("cannot read {s}\n", .{path});
        return BuildCommandsError.ParseFailed;
    };
    defer alloc.free(content);

    return dockerfile.parse(alloc, content) catch |err| {
        switch (err) {
            dockerfile.ParseError.UnknownInstruction => writeErr("unknown instruction in Dockerfile\n", .{}),
            dockerfile.ParseError.EmptyInstruction => writeErr("empty instruction in Dockerfile\n", .{}),
            dockerfile.ParseError.OutOfMemory => return BuildCommandsError.OutOfMemory,
        }
        return BuildCommandsError.ParseFailed;
    };
}

fn loadManifest(
    alloc: std.mem.Allocator,
    path: []const u8,
) BuildCommandsError!build_manifest.LoadResult {
    return build_manifest.load(alloc, path) catch |err| {
        switch (err) {
            build_manifest.LoadError.FileNotFound => writeErr("cannot find {s}\n", .{path}),
            build_manifest.LoadError.ReadFailed => writeErr("cannot read {s}\n", .{path}),
            build_manifest.LoadError.ParseFailed => writeErr("invalid TOML in {s}\n", .{path}),
            build_manifest.LoadError.MissingFrom => writeErr("stage missing required 'from' field\n", .{}),
            build_manifest.LoadError.InvalidStep => writeErr("invalid step in build manifest\n", .{}),
            build_manifest.LoadError.EmptyManifest => writeErr("no stages found in build manifest\n", .{}),
            build_manifest.LoadError.CyclicDependency => writeErr("circular dependency between stages\n", .{}),
            build_manifest.LoadError.OutOfMemory => return BuildCommandsError.OutOfMemory,
        }
        return BuildCommandsError.ParseFailed;
    };
}

fn renderBuildError(err: anyerror) void {
    switch (err) {
        build_engine.BuildError.NoFromInstruction => writeErr("build must start with FROM\n", .{}),
        build_engine.BuildError.PullFailed => writeErr("failed to pull base image\n", .{}),
        build_engine.BuildError.RunStepFailed => writeErr("RUN step failed\n", .{}),
        build_engine.BuildError.CopyStepFailed => writeErr("COPY step failed\n", .{}),
        build_engine.BuildError.LayerFailed => writeErr("failed to create layer\n", .{}),
        build_engine.BuildError.ImageStoreFailed => writeErr("failed to store image\n", .{}),
        build_engine.BuildError.ParseFailed => writeErr("failed to parse build instructions\n", .{}),
        build_engine.BuildError.CacheFailed => writeErr("cache error\n", .{}),
        error.OutOfMemory => writeErr("out of memory\n", .{}),
        error.MetadataFailed => writeErr("metadata error\n", .{}),
        else => writeErr("build failed\n", .{}),
    }
}

fn renderBuildResult(tag: ?[]const u8, result: build_engine.BuildResult) void {
    const size_mb = result.total_size / (1024 * 1024);

    if (tag) |value| {
        write("built {s} ({d} layers, {d} MB)\n", .{ value, result.layer_count, size_mb });
        return;
    }

    const digest_prefix_len = "sha256:".len;
    const short_id_len = 12;
    const short_id = if (result.manifest_digest.len > digest_prefix_len + short_id_len)
        result.manifest_digest[digest_prefix_len..][0..short_id_len]
    else
        result.manifest_digest;
    write("built {s} ({d} layers, {d} MB)\n", .{ short_id, result.layer_count, size_mb });
}

fn isValidTag(tag: []const u8) bool {
    if (tag.len == 0 or tag.len > 128) return false;
    for (tag) |c| {
        if (std.ascii.isAlphanumeric(c)) continue;
        if (c == '.' or c == '-' or c == '_') continue;
        return false;
    }
    return true;
}
