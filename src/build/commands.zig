// build commands — CLI handler for `yoq build`
//
// extracted from main.zig for readability — no logic changes.

const std = @import("std");
const cli = @import("../lib/cli.zig");
const dockerfile = @import("dockerfile.zig");
const build_engine = @import("engine.zig");
const build_manifest = @import("manifest.zig");
const spec = @import("../image/spec.zig");

const write = cli.write;
const writeErr = cli.writeErr;

const BuildCommandsError = error{
    InvalidArgument,
    BuildFailed,
    ParseFailed,
    OutOfMemory,
};

/// validate an image tag per OCI distribution spec constraints.
/// tags must be alphanumeric with '.', '-', '_' separators, max 128 chars.
fn isValidTag(tag: []const u8) bool {
    if (tag.len == 0 or tag.len > 128) return false;
    for (tag) |c| {
        if (std.ascii.isAlphanumeric(c)) continue;
        if (c == '.' or c == '-' or c == '_') continue;
        return false;
    }
    return true;
}

pub fn build_cmd(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    var tag: ?[]const u8 = null;
    var dockerfile_path: []const u8 = "Dockerfile";
    var context_path: ?[]const u8 = null;
    var format: enum { dockerfile, toml } = .dockerfile;
    var build_args_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer build_args_list.deinit(alloc);

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-t")) {
            tag = args.next() orelse {
                writeErr("-t requires an image tag\n", .{});
                return BuildCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "-f")) {
            dockerfile_path = args.next() orelse {
                writeErr("-f requires a Dockerfile path\n", .{});
                return BuildCommandsError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--format")) {
            const fmt = args.next() orelse {
                writeErr("--format requires 'dockerfile' or 'toml'\n", .{});
                return BuildCommandsError.InvalidArgument;
            };
            if (std.mem.eql(u8, fmt, "toml")) {
                format = .toml;
            } else if (std.mem.eql(u8, fmt, "dockerfile")) {
                format = .dockerfile;
            } else {
                writeErr("unknown format '{s}', expected 'dockerfile' or 'toml'\n", .{fmt});
                return BuildCommandsError.InvalidArgument;
            }
        } else if (std.mem.eql(u8, arg, "--build-arg")) {
            const ba = args.next() orelse {
                writeErr("--build-arg requires KEY=VALUE\n", .{});
                return BuildCommandsError.InvalidArgument;
            };
            build_args_list.append(alloc, ba) catch return BuildCommandsError.OutOfMemory;
        } else {
            context_path = arg;
        }
    }

    const ctx_dir = context_path orelse ".";

    // validate tag format
    if (tag) |t| {
        const ref = spec.parseImageRef(t);
        if (!isValidTag(ref.reference)) {
            writeErr("invalid tag: must be alphanumeric with '.', '-', '_' (max 128 chars)\n", .{});
            return BuildCommandsError.InvalidArgument;
        }
    }

    // determine the build file path and default filename based on format
    const default_filename: []const u8 = switch (format) {
        .dockerfile => "Dockerfile",
        .toml => "build.toml",
    };
    const using_default = std.mem.eql(u8, dockerfile_path, "Dockerfile");

    var df_path_buf: [4096]u8 = undefined;
    const effective_path = if (using_default)
        std.fmt.bufPrint(&df_path_buf, "{s}/{s}", .{ ctx_dir, default_filename }) catch {
            writeErr("path too long\n", .{});
            return BuildCommandsError.InvalidArgument;
        }
    else
        dockerfile_path;

    // parse instructions — both formats produce []Instruction
    var instructions: []const dockerfile.Instruction = undefined;

    // we need to track which deinit to call
    var df_parsed: ?dockerfile.ParseResult = null;
    var toml_parsed: ?build_manifest.LoadResult = null;

    switch (format) {
        .dockerfile => {
            const content = std.fs.cwd().readFileAlloc(alloc, effective_path, 1024 * 1024) catch {
                writeErr("cannot read {s}\n", .{effective_path});
                return BuildCommandsError.ParseFailed;
            };
            defer alloc.free(content);

            const parsed = dockerfile.parse(alloc, content) catch |err| {
                switch (err) {
                    dockerfile.ParseError.UnknownInstruction => writeErr("unknown instruction in Dockerfile\n", .{}),
                    dockerfile.ParseError.EmptyInstruction => writeErr("empty instruction in Dockerfile\n", .{}),
                    dockerfile.ParseError.OutOfMemory => return BuildCommandsError.OutOfMemory,
                }
                return BuildCommandsError.ParseFailed;
            };
            df_parsed = parsed;
            instructions = parsed.instructions;
        },
        .toml => {
            const parsed = build_manifest.load(alloc, effective_path) catch |err| {
                switch (err) {
                    build_manifest.LoadError.FileNotFound => writeErr("cannot find {s}\n", .{effective_path}),
                    build_manifest.LoadError.ReadFailed => writeErr("cannot read {s}\n", .{effective_path}),
                    build_manifest.LoadError.ParseFailed => writeErr("invalid TOML in {s}\n", .{effective_path}),
                    build_manifest.LoadError.MissingFrom => writeErr("stage missing required 'from' field\n", .{}),
                    build_manifest.LoadError.InvalidStep => writeErr("invalid step in build manifest\n", .{}),
                    build_manifest.LoadError.EmptyManifest => writeErr("no stages found in build manifest\n", .{}),
                    build_manifest.LoadError.CyclicDependency => writeErr("circular dependency between stages\n", .{}),
                    build_manifest.LoadError.OutOfMemory => return BuildCommandsError.OutOfMemory,
                }
                return BuildCommandsError.ParseFailed;
            };
            toml_parsed = parsed;
            instructions = parsed.instructions;
        },
    }
    defer {
        if (df_parsed) |*p| p.deinit();
        if (toml_parsed) |*p| p.deinit();
    }

    writeErr("building from {s} ({d} instructions)...\n", .{
        effective_path, instructions.len,
    });

    // resolve context directory to absolute path
    var abs_ctx_buf: [4096]u8 = undefined;
    const abs_ctx = std.fs.cwd().realpath(ctx_dir, &abs_ctx_buf) catch {
        writeErr("cannot resolve context directory: {s}\n", .{ctx_dir});
        return BuildCommandsError.InvalidArgument;
    };

    // build
    const cli_args: ?[]const []const u8 = if (build_args_list.items.len > 0)
        build_args_list.items
    else
        null;
    var result = build_engine.build(alloc, instructions, abs_ctx, tag, cli_args) catch |err| {
        switch (err) {
            build_engine.BuildError.NoFromInstruction => writeErr("build must start with FROM\n", .{}),
            build_engine.BuildError.PullFailed => writeErr("failed to pull base image\n", .{}),
            build_engine.BuildError.RunStepFailed => writeErr("RUN step failed\n", .{}),
            build_engine.BuildError.CopyStepFailed => writeErr("COPY step failed\n", .{}),
            build_engine.BuildError.LayerFailed => writeErr("failed to create layer\n", .{}),
            build_engine.BuildError.ImageStoreFailed => writeErr("failed to store image\n", .{}),
            build_engine.BuildError.ParseFailed => writeErr("failed to parse build instructions\n", .{}),
            build_engine.BuildError.CacheFailed => writeErr("cache error\n", .{}),
        }
        return BuildCommandsError.BuildFailed;
    };
    defer result.deinit();

    const size_mb = result.total_size / (1024 * 1024);

    if (tag) |t| {
        write("built {s} ({d} layers, {d} MB)\n", .{ t, result.layer_count, size_mb });
    } else {
        // show short digest
        const short_id = if (result.manifest_digest.len > 19)
            result.manifest_digest[7..19]
        else
            result.manifest_digest;
        write("built {s} ({d} layers, {d} MB)\n", .{ short_id, result.layer_count, size_mb });
    }
}
