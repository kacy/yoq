// engine — build execution engine
//
// takes a parsed Dockerfile ([]Instruction) and executes each step
// to produce an OCI image. the core build loop:
//
//   FROM:  pull base image, init layer list
//   RUN:   mount overlay, spawn container, capture upper dir → new layer
//   COPY:  copy from build context → new layer
//   ENV/WORKDIR/CMD/etc: accumulate config metadata
//
// content-hash caching makes rebuilds instant when inputs haven't
// changed. cache keys include the instruction, args, parent digest,
// and (for COPY) source file hashes.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const dockerfile = @import("dockerfile.zig");
const context = @import("context.zig");
const blob_store = @import("../image/store.zig");
const layer = @import("../image/layer.zig");
const spec = @import("../image/spec.zig");
const registry = @import("../image/registry.zig");
const state_store = @import("../state/store.zig");
const container = @import("../runtime/container.zig");
const filesystem = @import("../runtime/filesystem.zig");
const namespaces = @import("../runtime/namespaces.zig");
const paths = @import("../lib/paths.zig");
const log = @import("../lib/log.zig");
const exec_helpers = @import("../lib/exec_helpers.zig");
const json_helpers = @import("../lib/json_helpers.zig");

pub const BuildError = error{
    ParseFailed,
    PullFailed,
    RunStepFailed,
    CopyStepFailed,
    LayerFailed,
    ImageStoreFailed,
    NoFromInstruction,
    CacheFailed,
};

/// result of a successful build
pub const BuildResult = struct {
    /// manifest digest (image ID)
    manifest_digest: []const u8,
    /// total compressed size of all layers
    total_size: u64,
    /// number of layers in the image
    layer_count: usize,
    /// allocator that owns manifest_digest
    alloc: std.mem.Allocator,

    pub fn deinit(self: *BuildResult) void {
        self.alloc.free(self.manifest_digest);
    }
};

/// accumulated image configuration built up during instruction processing
const BuildState = struct {
    /// compressed layer digests for the manifest (as "sha256:..." strings)
    layer_digests: std.ArrayListUnmanaged([]const u8) = .empty,
    /// layer sizes for the manifest
    layer_sizes: std.ArrayListUnmanaged(u64) = .empty,
    /// uncompressed layer digests for config diff_ids
    diff_ids: std.ArrayListUnmanaged([]const u8) = .empty,
    /// total compressed size
    total_size: u64 = 0,

    // config metadata
    env: std.ArrayListUnmanaged([]const u8) = .empty,
    cmd: ?[]const u8 = null,
    entrypoint: ?[]const u8 = null,
    workdir: []const u8 = "/",
    user: ?[]const u8 = null,
    exposed_ports: std.ArrayListUnmanaged([]const u8) = .empty,
    labels: std.ArrayListUnmanaged([]const u8) = .empty,
    volumes: std.ArrayListUnmanaged([]const u8) = .empty,
    shell: ?[]const u8 = null,
    stop_signal: ?[]const u8 = null,
    healthcheck: ?[]const u8 = null,

    /// build args — set by ARG instructions and --build-arg CLI flags.
    /// keys and values are owned by the allocator.
    build_args: std.StringHashMapUnmanaged([]const u8) = .empty,

    /// digest of the "current" image state — starts as base image digest,
    /// updates after each layer-producing step. used for cache key computation.
    parent_digest: []const u8 = "",

    alloc: std.mem.Allocator,

    fn init(alloc: std.mem.Allocator) BuildState {
        return .{ .alloc = alloc };
    }

    fn deinit(self: *BuildState) void {
        for (self.layer_digests.items) |d| self.alloc.free(d);
        self.layer_digests.deinit(self.alloc);
        for (self.diff_ids.items) |d| self.alloc.free(d);
        self.diff_ids.deinit(self.alloc);
        self.layer_sizes.deinit(self.alloc);
        for (self.env.items) |e| self.alloc.free(e);
        self.env.deinit(self.alloc);
        self.exposed_ports.deinit(self.alloc);
        self.labels.deinit(self.alloc);
        for (self.volumes.items) |v| self.alloc.free(v);
        self.volumes.deinit(self.alloc);
        if (self.cmd) |c| self.alloc.free(c);
        if (self.entrypoint) |e| self.alloc.free(e);
        if (!std.mem.eql(u8, self.workdir, "/")) self.alloc.free(self.workdir);
        if (self.user) |u| self.alloc.free(u);
        if (self.shell) |s| self.alloc.free(s);
        if (self.stop_signal) |s| self.alloc.free(s);
        if (self.healthcheck) |h| self.alloc.free(h);
        var arg_it = self.build_args.iterator();
        while (arg_it.next()) |entry| {
            self.alloc.free(entry.key_ptr.*);
            self.alloc.free(entry.value_ptr.*);
        }
        self.build_args.deinit(self.alloc);
        if (self.parent_digest.len > 0) self.alloc.free(self.parent_digest);
    }

    fn addLayer(self: *BuildState, compressed_digest: []const u8, diff_id: []const u8, size: u64) !void {
        const cd = try self.alloc.dupe(u8, compressed_digest);
        errdefer self.alloc.free(cd);
        const di = try self.alloc.dupe(u8, diff_id);
        errdefer self.alloc.free(di);

        try self.layer_digests.append(self.alloc, cd);
        try self.diff_ids.append(self.alloc, di);
        try self.layer_sizes.append(self.alloc, size);
        self.total_size += size;

        // update parent digest to the new compressed layer digest
        if (self.parent_digest.len > 0) self.alloc.free(self.parent_digest);
        self.parent_digest = try self.alloc.dupe(u8, compressed_digest);
    }
};

/// a build stage — one per FROM instruction in a multi-stage build.
/// each stage has its own name (optional), index, and instruction range.
const BuildStage = struct {
    /// stage name from "FROM ... AS name", null if unnamed
    name: ?[]const u8,
    /// 0-based stage index
    index: usize,
    /// slice of instructions belonging to this stage (starts with FROM)
    instructions: []const dockerfile.Instruction,
};

/// split instructions into stages at FROM boundaries.
/// each stage starts with a FROM instruction.
fn splitIntoStages(alloc: std.mem.Allocator, instructions: []const dockerfile.Instruction) ![]BuildStage {
    var stages: std.ArrayListUnmanaged(BuildStage) = .empty;
    errdefer stages.deinit(alloc);

    var current_start: usize = 0;
    var stage_index: usize = 0;

    for (instructions, 0..) |inst, i| {
        if (inst.kind == .from and i > 0) {
            // close out the previous stage
            try stages.append(alloc, .{
                .name = parseStageName(instructions[current_start].args),
                .index = stage_index,
                .instructions = instructions[current_start..i],
            });
            current_start = i;
            stage_index += 1;
        }
    }

    // append the final stage
    if (current_start < instructions.len) {
        try stages.append(alloc, .{
            .name = parseStageName(instructions[current_start].args),
            .index = stage_index,
            .instructions = instructions[current_start..],
        });
    }

    return try stages.toOwnedSlice(alloc);
}

/// extract stage name from FROM args: "image:tag AS name" -> "name"
fn parseStageName(from_args: []const u8) ?[]const u8 {
    // look for " AS " or " as " (case-insensitive)
    if (std.mem.indexOf(u8, from_args, " AS ") orelse std.mem.indexOf(u8, from_args, " as ")) |idx| {
        const name = std.mem.trim(u8, from_args[idx + 4 ..], " \t");
        if (name.len > 0) return name;
    }
    return null;
}

/// find a completed stage by name or index string.
/// returns the stage's layer digests if found.
fn findStageByRef(
    stages: []const BuildStage,
    completed_states: []const BuildState,
    ref: []const u8,
) ?*const BuildState {
    // try to match by name first
    for (stages, 0..) |stage, i| {
        if (i >= completed_states.len) break;
        if (stage.name) |name| {
            if (std.mem.eql(u8, name, ref)) return &completed_states[i];
        }
    }

    // try to parse as stage index
    const idx = std.fmt.parseInt(usize, ref, 10) catch return null;
    if (idx < completed_states.len) return &completed_states[idx];

    return null;
}

/// build an image from a Dockerfile.
///
/// instructions: parsed Dockerfile instructions
/// context_dir: path to the build context (for COPY)
/// tag: optional image tag (e.g. "myapp:latest")
/// cli_build_args: optional key=value pairs from --build-arg flags
pub fn build(
    alloc: std.mem.Allocator,
    instructions: []const dockerfile.Instruction,
    context_dir: []const u8,
    tag: ?[]const u8,
    cli_build_args: ?[]const []const u8,
) BuildError!BuildResult {
    if (instructions.len == 0 or instructions[0].kind != .from) {
        return BuildError.NoFromInstruction;
    }

    // split into stages for multi-stage builds
    const stages = splitIntoStages(alloc, instructions) catch
        return BuildError.ParseFailed;
    defer alloc.free(stages);

    // process each stage, keeping completed states around for COPY --from
    var completed_states: std.ArrayListUnmanaged(BuildState) = .empty;
    defer {
        for (completed_states.items) |*s| s.deinit();
        completed_states.deinit(alloc);
    }

    for (stages) |stage| {
        const state = try buildStage(alloc, stage, context_dir, cli_build_args, stages, completed_states.items);
        completed_states.append(alloc, state) catch {
            var s = state;
            s.deinit();
            return BuildError.ImageStoreFailed;
        };
    }

    // produce image from the final stage only
    if (completed_states.items.len == 0) return BuildError.NoFromInstruction;
    const final_state = &completed_states.items[completed_states.items.len - 1];
    return produceImage(alloc, final_state, tag);
}

/// process a single build stage — returns the completed BuildState.
/// caller takes ownership and must call deinit() when done.
fn buildStage(
    alloc: std.mem.Allocator,
    stage: BuildStage,
    context_dir: []const u8,
    cli_build_args: ?[]const []const u8,
    stages: []const BuildStage,
    completed_states: []const BuildState,
) BuildError!BuildState {
    var state = BuildState.init(alloc);
    errdefer state.deinit();

    // seed build args from CLI --build-arg flags
    if (cli_build_args) |args| {
        for (args) |arg| {
            if (std.mem.indexOfScalar(u8, arg, '=')) |eq| {
                const key = alloc.dupe(u8, arg[0..eq]) catch continue;
                const val = alloc.dupe(u8, arg[eq + 1 ..]) catch {
                    alloc.free(key);
                    continue;
                };
                state.build_args.put(alloc, key, val) catch {
                    alloc.free(key);
                    alloc.free(val);
                };
            }
        }
    }

    // process instructions for this stage
    for (stage.instructions) |inst| {
        // expand build args (except for ARG itself)
        const effective_args = if (inst.kind != .arg)
            expandArgs(alloc, inst.args, &state.build_args) catch inst.args
        else
            inst.args;
        defer if (inst.kind != .arg and effective_args.ptr != inst.args.ptr)
            alloc.free(effective_args);

        switch (inst.kind) {
            .from => try processFrom(alloc, &state, effective_args),
            .run => try processRun(alloc, &state, effective_args),
            .copy => try processCopyMultiStage(alloc, &state, effective_args, context_dir, stages, completed_states),
            .add => try processAddMultiStage(alloc, &state, effective_args, context_dir, stages, completed_states),
            .env => processEnv(alloc, &state, effective_args),
            .workdir => processWorkdir(alloc, &state, effective_args),
            .cmd => processCmd(alloc, &state, effective_args),
            .entrypoint => processEntrypoint(alloc, &state, effective_args),
            .expose => processExpose(alloc, &state, effective_args),
            .user => processUser(alloc, &state, effective_args),
            .label => processLabel(alloc, &state, effective_args),
            .volume => processVolume(alloc, &state, effective_args),
            .shell => processShell(alloc, &state, effective_args),
            .healthcheck => processHealthcheck(alloc, &state, effective_args),
            .stopsignal => processStopsignal(alloc, &state, effective_args),
            .onbuild => processOnbuild(effective_args),
            .arg => processArg(alloc, &state, inst.args),
        }
    }

    return state;
}

// -- instruction handlers --

fn processFrom(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) BuildError!void {
    // parse "image:tag" or "image:tag AS name" (ignore AS for now)
    const image_str = if (std.mem.indexOf(u8, args, " AS ") orelse std.mem.indexOf(u8, args, " as ")) |idx|
        args[0..idx]
    else
        args;

    const ref = spec.parseImageRef(image_str);

    log.info("FROM {s}", .{image_str});

    // try to find the image locally first
    const local = state_store.findImage(alloc, ref.repository, ref.reference) catch null;

    if (local) |img| {
        defer img.deinit(alloc);
        // load the manifest to get layer digests
        const manifest_digest = blob_store.Digest.parse(img.manifest_digest) orelse
            return BuildError.PullFailed;
        const manifest_bytes = blob_store.getBlob(alloc, manifest_digest) catch
            return BuildError.PullFailed;
        defer alloc.free(manifest_bytes);

        var parsed_manifest = spec.parseManifest(alloc, manifest_bytes) catch
            return BuildError.PullFailed;
        defer parsed_manifest.deinit();

        // add base image layers
        for (parsed_manifest.value.layers) |l| {
            state.addLayer(l.digest, l.digest, l.size) catch
                return BuildError.PullFailed;
        }

        // load and inherit config from the base image
        const config_digest = blob_store.Digest.parse(parsed_manifest.value.config.digest) orelse
            return BuildError.PullFailed;
        const config_bytes = blob_store.getBlob(alloc, config_digest) catch
            return BuildError.PullFailed;
        defer alloc.free(config_bytes);

        inheritConfig(alloc, state, config_bytes);

        // set parent digest to manifest digest
        if (state.parent_digest.len > 0) alloc.free(state.parent_digest);
        state.parent_digest = alloc.dupe(u8, img.manifest_digest) catch
            return BuildError.PullFailed;
    } else {
        // pull from registry
        var result = registry.pull(alloc, ref) catch return BuildError.PullFailed;
        defer result.deinit();

        // compute the actual config digest from the pulled config bytes
        const pulled_config_digest = blob_store.computeDigest(result.config_bytes);
        var pulled_config_buf: [71]u8 = undefined;
        const pulled_config_str = pulled_config_digest.string(&pulled_config_buf);

        // save the pulled image record
        state_store.saveImage(.{
            .id = result.manifest_digest,
            .repository = ref.repository,
            .tag = ref.reference,
            .manifest_digest = result.manifest_digest,
            .config_digest = pulled_config_str,
            .total_size = @intCast(result.total_size),
            .created_at = std.time.timestamp(),
        }) catch |err| {
            log.warn("failed to save base image record: {}", .{err});
        };

        // extract layers so they're available for overlayfs
        const layer_paths = layer.assembleRootfs(alloc, result.layer_digests) catch
            return BuildError.PullFailed;
        defer {
            for (layer_paths) |p| alloc.free(p);
            alloc.free(layer_paths);
        }

        // parse the manifest to get layer details
        var parsed_manifest = spec.parseManifest(alloc, result.manifest_bytes) catch
            return BuildError.PullFailed;
        defer parsed_manifest.deinit();

        // add base image layers from manifest (has proper sizes)
        for (parsed_manifest.value.layers) |l| {
            state.addLayer(l.digest, l.digest, l.size) catch
                return BuildError.PullFailed;
        }

        // inherit config from the base image
        inheritConfig(alloc, state, result.config_bytes);

        // set parent digest
        if (state.parent_digest.len > 0) alloc.free(state.parent_digest);
        state.parent_digest = alloc.dupe(u8, result.manifest_digest) catch
            return BuildError.PullFailed;
    }
}

fn processRun(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) BuildError!void {
    log.info("RUN {s}", .{args});

    // compute cache key
    const cache_key = computeCacheKey(alloc, "RUN", args, state) catch
        return BuildError.CacheFailed;
    defer alloc.free(cache_key);

    // check cache
    if (checkCache(alloc, cache_key, state)) return;

    // cache miss — execute the RUN step

    // extract all current layers for overlayfs
    var layer_paths_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (layer_paths_list.items) |p| alloc.free(p);
        layer_paths_list.deinit(alloc);
    }

    for (state.layer_digests.items) |digest| {
        const path = layer.extractLayer(alloc, digest) catch
            return BuildError.RunStepFailed;
        layer_paths_list.append(alloc, path) catch {
            alloc.free(path);
            return BuildError.RunStepFailed;
        };
    }

    // create overlay directories for the build step
    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf);
    const build_id = id_buf[0..];

    var dirs = container.createContainerDirs(build_id) catch
        return BuildError.RunStepFailed;

    defer container.cleanupContainerDirs(build_id);

    // set up the build container context
    var child_ctx = BuildChildContext{
        .layer_dirs = layer_paths_list.items,
        .upper_dir = dirs.upperPath(),
        .work_dir = dirs.workPath(),
        .merged_dir = dirs.mergedPath(),
        .command = args,
        .env = state.env.items,
        .workdir = state.workdir,
        .shell = state.shell,
    };

    // spawn the build container in namespaces
    var spawn_result = namespaces.spawn(
        .{ .net = false, .cgroup = false }, // no networking or cgroup for builds
        null,
        buildChildMain,
        @ptrCast(&child_ctx),
    ) catch return BuildError.RunStepFailed;

    // signal child immediately (no parent-side setup needed for builds)
    spawn_result.signalReady();

    // close pipe fds we don't need
    posix.close(spawn_result.stdout_fd);
    posix.close(spawn_result.stderr_fd);

    // wait for the build step to finish
    const wait_result = @import("../runtime/process.zig").wait(spawn_result.pid, false) catch
        return BuildError.RunStepFailed;

    const exit_code: u8 = switch (wait_result.status) {
        .exited => |code| code,
        .signaled => 128,
        .running => 0,
    };

    if (exit_code != 0) {
        log.err("RUN step failed with exit code {d}", .{exit_code});
        return BuildError.RunStepFailed;
    }

    // capture the upper dir as a new layer
    const layer_result = layer.createLayerFromDir(alloc, dirs.upperPath()) catch
        return BuildError.LayerFailed;

    if (layer_result) |lr| {
        var digest_buf: [71]u8 = undefined;
        const compressed_str = lr.compressed_digest.string(&digest_buf);
        var diff_buf: [71]u8 = undefined;
        const diff_str = lr.uncompressed_digest.string(&diff_buf);

        state.addLayer(compressed_str, diff_str, lr.compressed_size) catch
            return BuildError.LayerFailed;

        // store in cache
        storeCache(cache_key, compressed_str, diff_str, lr.compressed_size);
    }
}

fn processCopy(alloc: std.mem.Allocator, state: *BuildState, args: []const u8, context_dir: []const u8) BuildError!void {
    log.info("COPY {s}", .{args});

    // parse "src dest" from args
    const split = parseCopyArgs(args);
    const src = split.src;
    const dest = split.dest;

    // compute content hash of source files for cache key
    const file_hash = context.hashFiles(alloc, context_dir, src) catch
        return BuildError.CopyStepFailed;
    var file_hash_buf: [71]u8 = undefined;
    const file_hash_str = file_hash.string(&file_hash_buf);

    // build a cache key that includes the file content hash
    var cache_input_buf: [2048]u8 = undefined;
    const cache_input = std.fmt.bufPrint(&cache_input_buf, "COPY\n{s}\n{s}\n{s}", .{
        args, state.parent_digest, file_hash_str,
    }) catch return BuildError.CacheFailed;

    const cache_digest = blob_store.computeDigest(cache_input);
    var cache_key_buf: [71]u8 = undefined;
    const cache_key = cache_digest.string(&cache_key_buf);

    // check cache
    if (checkCache(alloc, cache_key, state)) return;

    // cache miss — create a layer from the copied files

    // create a temp directory for the layer contents
    paths.ensureDataDir("tmp") catch return BuildError.CopyStepFailed;
    var layer_dir_buf: [paths.max_path]u8 = undefined;
    const layer_dir = paths.dataPathFmt(&layer_dir_buf, "tmp/build-copy-layer", .{}) catch
        return BuildError.CopyStepFailed;

    // clean up and recreate
    std.fs.cwd().deleteTree(layer_dir) catch {};
    std.fs.cwd().makePath(layer_dir) catch return BuildError.CopyStepFailed;
    defer std.fs.cwd().deleteTree(layer_dir) catch {};

    // determine the actual destination path within the layer
    // if workdir is set and dest is relative, prepend workdir
    var actual_dest_buf: [1024]u8 = undefined;
    const actual_dest = if (dest.len > 0 and dest[0] != '/') blk: {
        break :blk std.fmt.bufPrint(&actual_dest_buf, "{s}/{s}", .{
            state.workdir, dest,
        }) catch return BuildError.CopyStepFailed;
    } else dest;

    // ensure destination directory exists in the layer
    if (actual_dest.len > 0) {
        const dest_in_layer = if (actual_dest[0] == '/') actual_dest[1..] else actual_dest;
        if (std.fs.path.dirname(dest_in_layer)) |parent| {
            var full_dir = std.fs.cwd().openDir(layer_dir, .{}) catch
                return BuildError.CopyStepFailed;
            defer full_dir.close();
            full_dir.makePath(parent) catch return BuildError.CopyStepFailed;
        }
    }

    // copy files into the layer directory
    context.copyFiles(context_dir, src, layer_dir, actual_dest) catch
        return BuildError.CopyStepFailed;

    // create layer from the directory
    const layer_result = layer.createLayerFromDir(alloc, layer_dir) catch
        return BuildError.LayerFailed;

    if (layer_result) |lr| {
        var digest_buf: [71]u8 = undefined;
        const compressed_str = lr.compressed_digest.string(&digest_buf);
        var diff_buf: [71]u8 = undefined;
        const diff_str = lr.uncompressed_digest.string(&diff_buf);

        state.addLayer(compressed_str, diff_str, lr.compressed_size) catch
            return BuildError.LayerFailed;

        storeCache(cache_key, compressed_str, diff_str, lr.compressed_size);
    }
}

fn processEnv(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) void {
    // ENV KEY=VALUE or ENV KEY VALUE
    const owned = alloc.dupe(u8, args) catch return;
    state.env.append(alloc, owned) catch {
        alloc.free(owned);
    };
}

fn processWorkdir(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) void {
    const owned = alloc.dupe(u8, args) catch return;
    if (!std.mem.eql(u8, state.workdir, "/")) alloc.free(state.workdir);
    state.workdir = owned;
}

fn processCmd(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) void {
    const owned = alloc.dupe(u8, args) catch return;
    if (state.cmd) |old| alloc.free(old);
    state.cmd = owned;
}

fn processEntrypoint(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) void {
    const owned = alloc.dupe(u8, args) catch return;
    if (state.entrypoint) |old| alloc.free(old);
    state.entrypoint = owned;
}

fn processExpose(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) void {
    const owned = alloc.dupe(u8, args) catch return;
    state.exposed_ports.append(alloc, owned) catch {
        alloc.free(owned);
    };
}

fn processUser(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) void {
    const owned = alloc.dupe(u8, args) catch return;
    if (state.user) |old| alloc.free(old);
    state.user = owned;
}

fn processLabel(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) void {
    const owned = alloc.dupe(u8, args) catch return;
    state.labels.append(alloc, owned) catch {
        alloc.free(owned);
    };
}

fn processArg(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) void {
    // ARG KEY=VALUE or ARG KEY (declares without default)
    // if the key was already set by --build-arg, the CLI value takes precedence.
    const trimmed = std.mem.trim(u8, args, " \t");
    if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq| {
        const key = trimmed[0..eq];
        const val = trimmed[eq + 1 ..];

        // only set if not already provided by CLI --build-arg
        if (state.build_args.get(key) != null) return;

        const owned_key = alloc.dupe(u8, key) catch return;
        const owned_val = alloc.dupe(u8, val) catch {
            alloc.free(owned_key);
            return;
        };
        state.build_args.put(alloc, owned_key, owned_val) catch {
            alloc.free(owned_key);
            alloc.free(owned_val);
        };
    } else {
        // ARG with no default — declare the key with empty value if not
        // already set by CLI
        if (state.build_args.get(trimmed) != null) return;

        const owned_key = alloc.dupe(u8, trimmed) catch return;
        const owned_val = alloc.dupe(u8, "") catch {
            alloc.free(owned_key);
            return;
        };
        state.build_args.put(alloc, owned_key, owned_val) catch {
            alloc.free(owned_key);
            alloc.free(owned_val);
        };
    }
}

/// expand build arg references in a string.
/// supports three forms:
///   $VAR        — simple variable reference
///   ${VAR}      — braced variable reference
///   ${VAR:-default} — variable with default value
///
/// returns a new string if any expansion occurred, or the original
/// string (same pointer) if nothing was expanded.
pub fn expandArgs(
    alloc: std.mem.Allocator,
    input: []const u8,
    args_map: *const std.StringHashMapUnmanaged([]const u8),
) ![]const u8 {
    // quick scan: if there's no $ in the string, nothing to expand
    if (std.mem.indexOfScalar(u8, input, '$') == null) return input;

    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(alloc);

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] != '$') {
            try result.append(alloc, input[i]);
            i += 1;
            continue;
        }

        // found a '$' — try to parse a variable reference
        i += 1; // skip the '$'
        if (i >= input.len) {
            // trailing '$' — keep it literal
            try result.append(alloc, '$');
            break;
        }

        if (input[i] == '{') {
            // braced form: ${VAR} or ${VAR:-default}
            i += 1; // skip '{'
            const var_start = i;

            // find the closing '}'
            var default_start: ?usize = null;
            while (i < input.len and input[i] != '}') {
                if (i + 1 < input.len and input[i] == ':' and input[i + 1] == '-') {
                    default_start = i + 2;
                    i += 2;
                    continue;
                }
                i += 1;
            }

            if (i >= input.len) {
                // unclosed brace — emit everything as literal
                try result.append(alloc, '$');
                try result.append(alloc, '{');
                try result.appendSlice(alloc, input[var_start..]);
                break;
            }

            // extract variable name and optional default
            const var_end = if (default_start) |ds| ds - 2 else i;
            const var_name = input[var_start..var_end];
            const default_val = if (default_start) |ds| input[ds..i] else null;

            i += 1; // skip '}'

            // look up the value
            if (args_map.get(var_name)) |val| {
                if (val.len > 0) {
                    try result.appendSlice(alloc, val);
                } else if (default_val) |dv| {
                    try result.appendSlice(alloc, dv);
                }
            } else if (default_val) |dv| {
                try result.appendSlice(alloc, dv);
            }
        } else {
            // simple form: $VAR — variable name must start with a letter or
            // underscore, then can contain letters, digits, and underscores.
            // this matches Docker's ARG variable naming rules.
            if (!std.ascii.isAlphabetic(input[i]) and input[i] != '_') {
                // '$' followed by non-variable char (e.g. $5) — keep literal
                try result.append(alloc, '$');
                continue;
            }

            const var_start = i;
            while (i < input.len and (std.ascii.isAlphanumeric(input[i]) or input[i] == '_')) {
                i += 1;
            }

            const var_name = input[var_start..i];
            if (args_map.get(var_name)) |val| {
                try result.appendSlice(alloc, val);
            }
            // if not found, variable is silently dropped (matches Docker behavior)
        }
    }

    // if nothing changed, return original string to avoid allocation
    if (result.items.len == input.len and std.mem.eql(u8, result.items, input)) {
        result.deinit(alloc);
        return input;
    }

    return try result.toOwnedSlice(alloc);
}

fn processCopyMultiStage(
    alloc: std.mem.Allocator,
    state: *BuildState,
    args: []const u8,
    context_dir: []const u8,
    stages: []const BuildStage,
    completed_states: []const BuildState,
) BuildError!void {
    const split = parseCopyArgs(args);

    if (split.from_stage) |stage_ref| {
        // COPY --from=stage — copy from a previous build stage
        return processCopyFromStage(alloc, state, split.src, split.dest, stage_ref, stages, completed_states);
    }

    // regular COPY from build context
    return processCopy(alloc, state, args, context_dir);
}

fn processAddMultiStage(
    alloc: std.mem.Allocator,
    state: *BuildState,
    args: []const u8,
    context_dir: []const u8,
    stages: []const BuildStage,
    completed_states: []const BuildState,
) BuildError!void {
    // ADD with --from= is unusual but technically valid
    const split = parseCopyArgs(args);

    if (split.from_stage) |stage_ref| {
        log.info("ADD --from={s} {s} (treated as COPY --from)", .{ stage_ref, args });
        return processCopyFromStage(alloc, state, split.src, split.dest, stage_ref, stages, completed_states);
    }

    // regular ADD from build context
    log.info("ADD {s} (treated as COPY)", .{args});
    return processCopy(alloc, state, args, context_dir);
}

/// copy files from a previous build stage's filesystem.
/// extracts the source stage's layers into a temporary overlay,
/// then copies the requested files into a new layer.
fn processCopyFromStage(
    alloc: std.mem.Allocator,
    state: *BuildState,
    src: []const u8,
    dest: []const u8,
    stage_ref: []const u8,
    stages: []const BuildStage,
    completed_states: []const BuildState,
) BuildError!void {
    log.info("COPY --from={s} {s} {s}", .{ stage_ref, src, dest });

    // find the source stage
    const source_state = findStageByRef(stages, completed_states, stage_ref) orelse {
        log.err("COPY --from={s}: stage not found", .{stage_ref});
        return BuildError.CopyStepFailed;
    };

    // extract source stage layers into a temporary merged directory
    var layer_paths_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (layer_paths_list.items) |p| alloc.free(p);
        layer_paths_list.deinit(alloc);
    }

    for (source_state.layer_digests.items) |digest| {
        const path = layer.extractLayer(alloc, digest) catch
            return BuildError.CopyStepFailed;
        layer_paths_list.append(alloc, path) catch {
            alloc.free(path);
            return BuildError.CopyStepFailed;
        };
    }

    if (layer_paths_list.items.len == 0) {
        log.warn("COPY --from={s}: source stage has no layers", .{stage_ref});
        return;
    }

    // create temp directories for the overlay mount
    paths.ensureDataDir("tmp") catch return BuildError.CopyStepFailed;

    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf);

    var upper_buf: [paths.max_path]u8 = undefined;
    const upper_dir = paths.dataPathFmt(&upper_buf, "tmp/stage-copy-upper-{s}", .{id_buf}) catch
        return BuildError.CopyStepFailed;
    var work_buf: [paths.max_path]u8 = undefined;
    const work_dir = paths.dataPathFmt(&work_buf, "tmp/stage-copy-work-{s}", .{id_buf}) catch
        return BuildError.CopyStepFailed;
    var merged_buf: [paths.max_path]u8 = undefined;
    const merged_dir = paths.dataPathFmt(&merged_buf, "tmp/stage-copy-merged-{s}", .{id_buf}) catch
        return BuildError.CopyStepFailed;

    std.fs.cwd().makePath(upper_dir) catch return BuildError.CopyStepFailed;
    std.fs.cwd().makePath(work_dir) catch return BuildError.CopyStepFailed;
    std.fs.cwd().makePath(merged_dir) catch return BuildError.CopyStepFailed;

    defer {
        std.fs.cwd().deleteTree(upper_dir) catch {};
        std.fs.cwd().deleteTree(work_dir) catch {};
        // unmount before deleting
        const merged_z = std.posix.toPosixPath(merged_dir) catch unreachable;
        _ = linux.syscall2(.umount2, @intFromPtr(&merged_z), 0);
        std.fs.cwd().deleteTree(merged_dir) catch {};
    }

    // mount overlay from source stage's layers (read-only)
    filesystem.mountOverlay(.{
        .lower_dirs = layer_paths_list.items,
        .upper_dir = upper_dir,
        .work_dir = work_dir,
        .merged_dir = merged_dir,
    }) catch return BuildError.CopyStepFailed;

    // now copy the requested files from the merged dir to a new layer
    paths.ensureDataDir("tmp") catch return BuildError.CopyStepFailed;
    var layer_dir_buf: [paths.max_path]u8 = undefined;
    const layer_dir = paths.dataPathFmt(&layer_dir_buf, "tmp/build-stage-copy-layer-{s}", .{id_buf}) catch
        return BuildError.CopyStepFailed;

    std.fs.cwd().deleteTree(layer_dir) catch {};
    std.fs.cwd().makePath(layer_dir) catch return BuildError.CopyStepFailed;
    defer std.fs.cwd().deleteTree(layer_dir) catch {};

    // determine destination path (respect workdir)
    var actual_dest_buf: [1024]u8 = undefined;
    const actual_dest = if (dest.len > 0 and dest[0] != '/') blk: {
        break :blk std.fmt.bufPrint(&actual_dest_buf, "{s}/{s}", .{
            state.workdir, dest,
        }) catch return BuildError.CopyStepFailed;
    } else dest;

    // ensure destination directory exists
    if (actual_dest.len > 0) {
        const dest_in_layer = if (actual_dest[0] == '/') actual_dest[1..] else actual_dest;
        if (std.fs.path.dirname(dest_in_layer)) |parent| {
            var full_dir = std.fs.cwd().openDir(layer_dir, .{}) catch
                return BuildError.CopyStepFailed;
            defer full_dir.close();
            full_dir.makePath(parent) catch return BuildError.CopyStepFailed;
        }
    }

    // copy from merged (source stage filesystem) to layer dir
    context.copyFiles(merged_dir, src, layer_dir, actual_dest) catch
        return BuildError.CopyStepFailed;

    // create layer from the directory
    const layer_result = layer.createLayerFromDir(alloc, layer_dir) catch
        return BuildError.LayerFailed;

    if (layer_result) |lr| {
        var digest_buf: [71]u8 = undefined;
        const compressed_str = lr.compressed_digest.string(&digest_buf);
        var diff_buf: [71]u8 = undefined;
        const diff_str = lr.uncompressed_digest.string(&diff_buf);

        state.addLayer(compressed_str, diff_str, lr.compressed_size) catch
            return BuildError.LayerFailed;
    }
}

fn processAdd(alloc: std.mem.Allocator, state: *BuildState, args: []const u8, context_dir: []const u8) BuildError!void {
    // ADD is treated as an alias for COPY. tar auto-extraction and URL
    // fetch are not yet implemented — those are niche features we can
    // add later without changing the interface.
    log.info("ADD {s} (treated as COPY)", .{args});
    return processCopy(alloc, state, args, context_dir);
}

fn processVolume(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) void {
    // VOLUME is metadata only — stored in the image config so the runtime
    // knows which paths should be mounted as volumes.
    log.info("VOLUME {s}", .{args});

    if (dockerfile.isJsonForm(args)) {
        // JSON form: VOLUME ["/data", "/logs"]
        // parse individual paths out of the array
        const trimmed = std.mem.trim(u8, args, " \t[]");
        var iter = std.mem.splitScalar(u8, trimmed, ',');
        while (iter.next()) |entry| {
            const path = std.mem.trim(u8, entry, " \t\"");
            if (path.len == 0) continue;
            const owned = alloc.dupe(u8, path) catch continue;
            state.volumes.append(alloc, owned) catch {
                alloc.free(owned);
            };
        }
    } else {
        // space-separated form: VOLUME /data /logs
        var iter = std.mem.tokenizeAny(u8, args, " \t");
        while (iter.next()) |path| {
            const owned = alloc.dupe(u8, path) catch continue;
            state.volumes.append(alloc, owned) catch {
                alloc.free(owned);
            };
        }
    }
}

fn processShell(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) void {
    // SHELL sets the default shell for subsequent RUN instructions.
    // the args should be in JSON form: ["/bin/bash", "-c"]
    log.info("SHELL {s}", .{args});
    const owned = alloc.dupe(u8, args) catch return;
    if (state.shell) |old| alloc.free(old);
    state.shell = owned;
}

fn processHealthcheck(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) void {
    // HEALTHCHECK is metadata only — stored in the image config for the
    // runtime to use. we store the raw args string and let the runtime
    // parse the details (interval, timeout, retries, command).
    log.info("HEALTHCHECK {s}", .{args});
    const owned = alloc.dupe(u8, args) catch return;
    if (state.healthcheck) |old| alloc.free(old);
    state.healthcheck = owned;
}

fn processStopsignal(alloc: std.mem.Allocator, state: *BuildState, args: []const u8) void {
    // STOPSIGNAL sets the signal sent to the container on stop.
    // metadata only — stored in the image config.
    log.info("STOPSIGNAL {s}", .{args});
    const owned = alloc.dupe(u8, args) catch return;
    if (state.stop_signal) |old| alloc.free(old);
    state.stop_signal = owned;
}

fn processOnbuild(args: []const u8) void {
    // ONBUILD triggers are rarely used and complex to implement properly
    // (they require storing instructions that run when this image is used
    // as a base). log a warning and skip for now.
    log.warn("ONBUILD is not yet supported, skipping: {s}", .{args});
}

// -- cache helpers --

fn computeCacheKey(alloc: std.mem.Allocator, instruction: []const u8, args: []const u8, state: *const BuildState) ![]const u8 {
    // cache key = sha256(instruction + "\n" + args + "\n" + parent_digest + "\n" + env + shell)
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(instruction);
    hasher.update("\n");
    hasher.update(args);
    hasher.update("\n");
    hasher.update(state.parent_digest);
    hasher.update("\n");

    // include environment in cache key (already ordered by insertion)
    for (state.env.items) |env| {
        hasher.update(env);
        hasher.update("\n");
    }

    // include shell in cache key — a different shell produces different
    // RUN results even with the same command
    if (state.shell) |sh| {
        hasher.update("shell:");
        hasher.update(sh);
        hasher.update("\n");
    }

    const digest = blob_store.Digest{ .hash = hasher.finalResult() };
    var buf: [71]u8 = undefined;
    return try alloc.dupe(u8, digest.string(&buf));
}

fn checkCache(alloc: std.mem.Allocator, cache_key: []const u8, state: *BuildState) bool {
    const entry = state_store.lookupBuildCache(alloc, cache_key) catch return false;
    if (entry) |e| {
        defer e.deinit(alloc);

        // verify the cached blob still exists
        const cached_digest = blob_store.Digest.parse(e.layer_digest) orelse return false;
        if (!blob_store.hasBlob(cached_digest)) return false;

        log.info("  -> cached", .{});

        state.addLayer(e.layer_digest, e.diff_id, @intCast(e.layer_size)) catch return false;
        return true;
    }
    return false;
}

fn storeCache(cache_key: []const u8, layer_digest: []const u8, diff_id: []const u8, size: u64) void {
    state_store.storeBuildCache(.{
        .cache_key = cache_key,
        .layer_digest = layer_digest,
        .diff_id = diff_id,
        .layer_size = @intCast(size),
        .created_at = std.time.timestamp(),
    }) catch |err| {
        log.warn("failed to store build cache: {}", .{err});
    };
}

// -- config inheritance --

fn inheritConfig(alloc: std.mem.Allocator, state: *BuildState, config_bytes: []const u8) void {
    var parsed = spec.parseImageConfig(alloc, config_bytes) catch return;
    defer parsed.deinit();

    if (parsed.value.config) |cc| {
        // inherit environment variables
        if (cc.Env) |envs| {
            for (envs) |env| {
                const owned = alloc.dupe(u8, env) catch continue;
                state.env.append(alloc, owned) catch {
                    alloc.free(owned);
                };
            }
        }

        // inherit working directory
        if (cc.WorkingDir) |wd| {
            if (wd.len > 0) {
                const owned = alloc.dupe(u8, wd) catch return;
                if (!std.mem.eql(u8, state.workdir, "/")) alloc.free(state.workdir);
                state.workdir = owned;
            }
        }

        // inherit CMD
        if (cc.Cmd) |cmds| {
            if (cmds.len > 0) {
                const owned = alloc.dupe(u8, cmds[0]) catch return;
                if (state.cmd) |old| alloc.free(old);
                state.cmd = owned;
            }
        }

        // inherit ENTRYPOINT
        if (cc.Entrypoint) |ep| {
            if (ep.len > 0) {
                const owned = alloc.dupe(u8, ep[0]) catch return;
                if (state.entrypoint) |old| alloc.free(old);
                state.entrypoint = owned;
            }
        }

        // inherit USER
        if (cc.User) |u| {
            if (u.len > 0) {
                const owned = alloc.dupe(u8, u) catch return;
                if (state.user) |old| alloc.free(old);
                state.user = owned;
            }
        }
    }
}

// -- COPY argument parsing --

const CopyArgs = struct {
    src: []const u8,
    dest: []const u8,
    /// stage name or index from --from=..., null if copying from build context
    from_stage: ?[]const u8,
};

fn parseCopyArgs(args: []const u8) CopyArgs {
    var trimmed = std.mem.trim(u8, args, " \t");
    var from_stage: ?[]const u8 = null;

    // check for --from=stage flag at the beginning
    if (std.mem.startsWith(u8, trimmed, "--from=")) {
        const rest = trimmed["--from=".len..];
        // find the end of the --from value (next whitespace)
        var end: usize = 0;
        while (end < rest.len and rest[end] != ' ' and rest[end] != '\t') {
            end += 1;
        }
        from_stage = rest[0..end];
        if (end < rest.len) {
            trimmed = std.mem.trimLeft(u8, rest[end..], " \t");
        } else {
            trimmed = "";
        }
    }

    // find the last space that separates src from dest
    var i: usize = trimmed.len;
    while (i > 0) {
        i -= 1;
        if (trimmed[i] == ' ' or trimmed[i] == '\t') {
            return .{
                .src = std.mem.trim(u8, trimmed[0..i], " \t"),
                .dest = std.mem.trim(u8, trimmed[i + 1 ..], " \t"),
                .from_stage = from_stage,
            };
        }
    }

    // no space found — treat as "src src" (copy to same name)
    return .{ .src = trimmed, .dest = trimmed, .from_stage = from_stage };
}

// -- build child process --
//
// simpler than the runtime childMain — no security.apply, no networking,
// no cgroup limits. just filesystem isolation and exec.

const BuildChildContext = struct {
    layer_dirs: []const []const u8,
    upper_dir: []const u8,
    work_dir: []const u8,
    merged_dir: []const u8,
    command: []const u8,
    env: []const []const u8,
    workdir: []const u8,
    /// custom shell from SHELL instruction, null means use default /bin/sh -c
    shell: ?[]const u8,
};

fn buildChildMain(arg: ?*anyopaque) callconv(.c) u8 {
    const ctx: *const BuildChildContext = @ptrCast(@alignCast(arg));

    // mount overlay from all layers
    if (ctx.layer_dirs.len > 0) {
        filesystem.mountOverlay(.{
            .lower_dirs = ctx.layer_dirs,
            .upper_dir = ctx.upper_dir,
            .work_dir = ctx.work_dir,
            .merged_dir = ctx.merged_dir,
        }) catch return 1;

        filesystem.pivotRoot(ctx.merged_dir) catch return 1;
    }

    // mount essential filesystems
    filesystem.mountEssential() catch return 1;

    // chdir to workdir
    posix.chdir(ctx.workdir) catch {
        posix.chdir("/") catch {};
    };

    // exec command using the configured shell (or /bin/sh -c by default)
    return execShellCommand(ctx.command, ctx.env, ctx.shell);
}

/// execute a command using the specified shell (or /bin/sh -c by default).
/// the shell parameter is in JSON array form: ["/bin/bash", "-c"]
fn execShellCommand(command: []const u8, env: []const []const u8, shell: ?[]const u8) u8 {
    var str_buf: [65536]u8 = undefined;
    var str_pos: usize = 0;

    // parse shell from JSON form if provided, otherwise use default
    var argv: [16]?[*:0]const u8 = .{null} ** 16;
    var argv_len: usize = 0;

    if (shell) |sh| {
        // parse JSON array form: ["/bin/bash", "-c"]
        // simple parser: strip brackets, split on commas, strip quotes
        const trimmed = std.mem.trim(u8, sh, " \t[]");
        var iter = std.mem.splitScalar(u8, trimmed, ',');
        while (iter.next()) |entry| {
            if (argv_len >= argv.len - 2) break; // leave room for command + null
            const part = std.mem.trim(u8, entry, " \t\"");
            if (part.len == 0) continue;
            argv[argv_len] = exec_helpers.packString(&str_buf, &str_pos, part) orelse return 127;
            argv_len += 1;
        }
    }

    // fall back to /bin/sh -c if shell wasn't set or parsing produced nothing
    if (argv_len == 0) {
        argv[0] = exec_helpers.packString(&str_buf, &str_pos, "/bin/sh") orelse return 127;
        argv[1] = exec_helpers.packString(&str_buf, &str_pos, "-c") orelse return 127;
        argv_len = 2;
    }

    // append the command as the final argument
    argv[argv_len] = exec_helpers.packString(&str_buf, &str_pos, command) orelse return 127;

    // envp
    var envp: [257]?[*:0]const u8 = .{null} ** 257;
    for (env, 0..) |e, i| {
        if (i >= envp.len - 1) break;
        envp[i] = exec_helpers.packString(&str_buf, &str_pos, e) orelse return 127;
    }

    _ = linux.syscall3(
        .execve,
        @intFromPtr(argv[0].?),
        @intFromPtr(&argv),
        @intFromPtr(&envp),
    );

    return 127;
}

// -- OCI image production --

fn produceImage(alloc: std.mem.Allocator, state: *BuildState, tag: ?[]const u8) BuildError!BuildResult {
    // build the OCI image config JSON
    const config_json = buildConfigJson(alloc, state) catch return BuildError.ImageStoreFailed;
    defer alloc.free(config_json);

    // store config as a blob
    const config_digest = blob_store.putBlob(config_json) catch return BuildError.ImageStoreFailed;

    // build the manifest JSON
    const manifest_json = buildManifestJson(alloc, state, config_digest, config_json.len) catch
        return BuildError.ImageStoreFailed;
    defer alloc.free(manifest_json);

    // store manifest as a blob
    const manifest_digest = blob_store.putBlob(manifest_json) catch
        return BuildError.ImageStoreFailed;

    var digest_str_buf: [71]u8 = undefined;
    const manifest_digest_str = manifest_digest.string(&digest_str_buf);
    const owned_digest = alloc.dupe(u8, manifest_digest_str) catch
        return BuildError.ImageStoreFailed;

    // save image record
    const repo = if (tag) |t| blk: {
        // split tag into repo:tag
        if (std.mem.lastIndexOfScalar(u8, t, ':')) |colon| {
            break :blk t[0..colon];
        }
        break :blk t;
    } else "build";

    const img_tag = if (tag) |t| blk: {
        if (std.mem.lastIndexOfScalar(u8, t, ':')) |colon| {
            break :blk t[colon + 1 ..];
        }
        break :blk @as([]const u8, "latest");
    } else "latest";

    var config_digest_str_buf: [71]u8 = undefined;
    const config_digest_str = config_digest.string(&config_digest_str_buf);

    state_store.saveImage(.{
        .id = owned_digest,
        .repository = repo,
        .tag = img_tag,
        .manifest_digest = owned_digest,
        .config_digest = config_digest_str,
        .total_size = @intCast(state.total_size),
        .created_at = std.time.timestamp(),
    }) catch |err| {
        log.warn("failed to save built image record: {}", .{err});
    };

    return BuildResult{
        .manifest_digest = owned_digest,
        .total_size = state.total_size,
        .layer_count = state.layer_digests.items.len,
        .alloc = alloc,
    };
}

fn buildConfigJson(alloc: std.mem.Allocator, state: *const BuildState) ![]const u8 {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(alloc);
    const writer = buf.writer(alloc);

    try writer.writeAll("{");

    // architecture and os
    try writer.writeAll("\"architecture\":\"amd64\",\"os\":\"linux\"");

    // config section
    try writer.writeAll(",\"config\":{");

    var first = true;

    // Env
    if (state.env.items.len > 0) {
        try writer.writeAll("\"Env\":[");
        for (state.env.items, 0..) |env, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeByte('"');
            try json_helpers.writeJsonEscaped(writer, env);
            try writer.writeByte('"');
        }
        try writer.writeAll("]");
        first = false;
    }

    // Cmd
    if (state.cmd) |cmd| {
        if (!first) try writer.writeAll(",");
        if (dockerfile.isJsonForm(cmd)) {
            try writer.writeAll("\"Cmd\":");
            try writer.writeAll(cmd);
        } else {
            try writer.writeAll("\"Cmd\":[\"/bin/sh\",\"-c\",\"");
            try json_helpers.writeJsonEscaped(writer, cmd);
            try writer.writeAll("\"]");
        }
        first = false;
    }

    // Entrypoint
    if (state.entrypoint) |ep| {
        if (!first) try writer.writeAll(",");
        if (dockerfile.isJsonForm(ep)) {
            try writer.writeAll("\"Entrypoint\":");
            try writer.writeAll(ep);
        } else {
            try writer.writeAll("\"Entrypoint\":[\"");
            try json_helpers.writeJsonEscaped(writer, ep);
            try writer.writeAll("\"]");
        }
        first = false;
    }

    // WorkingDir
    if (!std.mem.eql(u8, state.workdir, "/")) {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"WorkingDir\":\"");
        try json_helpers.writeJsonEscaped(writer, state.workdir);
        try writer.writeByte('"');
        first = false;
    }

    // User
    if (state.user) |u| {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"User\":\"");
        try json_helpers.writeJsonEscaped(writer, u);
        try writer.writeByte('"');
        first = false;
    }

    // Volumes — OCI format is {"path":{}} for each volume
    if (state.volumes.items.len > 0) {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"Volumes\":{");
        for (state.volumes.items, 0..) |vol, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeByte('"');
            try json_helpers.writeJsonEscaped(writer, vol);
            try writer.writeAll("\":{}");
        }
        try writer.writeAll("}");
        first = false;
    }

    // Shell
    if (state.shell) |sh| {
        if (!first) try writer.writeAll(",");
        if (dockerfile.isJsonForm(sh)) {
            try writer.writeAll("\"Shell\":");
            try writer.writeAll(sh);
        } else {
            // shouldn't happen (SHELL requires JSON form), but handle gracefully
            try writer.writeAll("\"Shell\":[\"");
            try json_helpers.writeJsonEscaped(writer, sh);
            try writer.writeAll("\"]");
        }
        first = false;
    }

    // StopSignal
    if (state.stop_signal) |sig| {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"StopSignal\":\"");
        try json_helpers.writeJsonEscaped(writer, sig);
        try writer.writeByte('"');
        first = false;
    }

    // Healthcheck
    if (state.healthcheck) |hc| {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"Healthcheck\":{\"Test\":[\"CMD-SHELL\",\"");
        // strip the leading "CMD " prefix if present
        const cmd_str = if (std.mem.startsWith(u8, hc, "CMD "))
            hc[4..]
        else
            hc;
        try json_helpers.writeJsonEscaped(writer, cmd_str);
        try writer.writeAll("\"]}");
        first = false;
    }

    try writer.writeAll("}");

    // rootfs section
    try writer.writeAll(",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[");
    for (state.diff_ids.items, 0..) |diff_id, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeByte('"');
        try writer.writeAll(diff_id);
        try writer.writeByte('"');
    }
    try writer.writeAll("]}");

    try writer.writeAll("}");

    return try buf.toOwnedSlice(alloc);
}

fn buildManifestJson(
    alloc: std.mem.Allocator,
    state: *const BuildState,
    config_digest: blob_store.Digest,
    config_size: usize,
) ![]const u8 {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(alloc);
    const writer = buf.writer(alloc);

    try writer.writeAll("{\"schemaVersion\":2");
    try writer.writeAll(",\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\"");

    // config descriptor
    var digest_buf: [71]u8 = undefined;
    try writer.writeAll(",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\"");
    try writer.writeAll(",\"digest\":\"");
    try writer.writeAll(config_digest.string(&digest_buf));
    try writer.writeAll("\"");
    try std.fmt.format(writer, ",\"size\":{d}", .{config_size});
    try writer.writeAll("}");

    // layers
    try writer.writeAll(",\"layers\":[");
    for (state.layer_digests.items, 0..) |digest, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\"");
        try writer.writeAll(",\"digest\":\"");
        try writer.writeAll(digest);
        try writer.writeAll("\"");
        try std.fmt.format(writer, ",\"size\":{d}", .{state.layer_sizes.items[i]});
        try writer.writeAll("}");
    }
    try writer.writeAll("]}");

    return try buf.toOwnedSlice(alloc);
}

// -- tests --

test "compute cache key determinism" {
    const alloc = std.testing.allocator;
    var state1 = BuildState.init(alloc);
    defer state1.deinit();

    var state2 = BuildState.init(alloc);
    defer state2.deinit();

    const key1 = try computeCacheKey(alloc, "RUN", "echo hello", &state1);
    defer alloc.free(key1);
    const key2 = try computeCacheKey(alloc, "RUN", "echo hello", &state2);
    defer alloc.free(key2);

    try std.testing.expectEqualStrings(key1, key2);
}

test "cache key differs with different args" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    const key1 = try computeCacheKey(alloc, "RUN", "echo hello", &state);
    defer alloc.free(key1);
    const key2 = try computeCacheKey(alloc, "RUN", "echo world", &state);
    defer alloc.free(key2);

    try std.testing.expect(!std.mem.eql(u8, key1, key2));
}

test "cache key differs with different env" {
    const alloc = std.testing.allocator;
    var state1 = BuildState.init(alloc);
    defer state1.deinit();

    var state2 = BuildState.init(alloc);
    defer state2.deinit();

    const env_val = try alloc.dupe(u8, "FOO=bar");
    try state2.env.append(alloc, env_val);

    const key1 = try computeCacheKey(alloc, "RUN", "echo hello", &state1);
    defer alloc.free(key1);
    const key2 = try computeCacheKey(alloc, "RUN", "echo hello", &state2);
    defer alloc.free(key2);

    try std.testing.expect(!std.mem.eql(u8, key1, key2));
}

test "parse copy args" {
    const result = parseCopyArgs("package.json /app/");
    try std.testing.expectEqualStrings("package.json", result.src);
    try std.testing.expectEqualStrings("/app/", result.dest);
    try std.testing.expect(result.from_stage == null);
}

test "parse copy args — current dir" {
    const result = parseCopyArgs(". .");
    try std.testing.expectEqualStrings(".", result.src);
    try std.testing.expectEqualStrings(".", result.dest);
    try std.testing.expect(result.from_stage == null);
}

test "config json format" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    const env = try alloc.dupe(u8, "PATH=/usr/bin");
    try state.env.append(alloc, env);

    const cmd = try alloc.dupe(u8, "node server.js");
    state.cmd = cmd;

    const wd = try alloc.dupe(u8, "/app");
    state.workdir = wd;

    const json = try buildConfigJson(alloc, &state);
    defer alloc.free(json);

    // verify it's valid JSON-ish (contains expected fields)
    try std.testing.expect(std.mem.indexOf(u8, json, "\"architecture\":\"amd64\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"os\":\"linux\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "PATH=/usr/bin") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"WorkingDir\":\"/app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rootfs\"") != null);
}

test "manifest json format" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    const layer_d = try alloc.dupe(u8, "sha256:abc123");
    try state.layer_digests.append(alloc, layer_d);
    try state.layer_sizes.append(alloc, 4096);
    const diff_d = try alloc.dupe(u8, "sha256:def456");
    try state.diff_ids.append(alloc, diff_d);

    const config_digest = blob_store.computeDigest("test config");
    const json = try buildManifestJson(alloc, &state, config_digest, 100);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"schemaVersion\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "sha256:abc123") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"size\":4096") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "application/vnd.oci.image.manifest.v1+json") != null);
}

test "no from instruction returns error" {
    const alloc = std.testing.allocator;
    const result = build(alloc, &.{}, ".", null, null);
    try std.testing.expectError(BuildError.NoFromInstruction, result);
}

test "json escaping" {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(std.testing.allocator);

    try json_helpers.writeJsonEscaped(buf.writer(std.testing.allocator), "hello \"world\"\nfoo\\bar");
    try std.testing.expectEqualStrings("hello \\\"world\\\"\\nfoo\\\\bar", buf.items);
}

test "cache key differs with different parent digest" {
    const alloc = std.testing.allocator;

    var state1 = BuildState.init(alloc);
    defer state1.deinit();
    state1.parent_digest = try alloc.dupe(u8, "sha256:aaaa");

    var state2 = BuildState.init(alloc);
    defer state2.deinit();
    state2.parent_digest = try alloc.dupe(u8, "sha256:bbbb");

    const key1 = try computeCacheKey(alloc, "RUN", "echo hello", &state1);
    defer alloc.free(key1);
    const key2 = try computeCacheKey(alloc, "RUN", "echo hello", &state2);
    defer alloc.free(key2);

    try std.testing.expect(!std.mem.eql(u8, key1, key2));
}

test "cache key differs between instruction types" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    const key1 = try computeCacheKey(alloc, "RUN", "echo hello", &state);
    defer alloc.free(key1);
    const key2 = try computeCacheKey(alloc, "COPY", "echo hello", &state);
    defer alloc.free(key2);

    try std.testing.expect(!std.mem.eql(u8, key1, key2));
}

test "config json with entrypoint and user" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    state.entrypoint = try alloc.dupe(u8, "node");
    state.user = try alloc.dupe(u8, "nobody");

    const json = try buildConfigJson(alloc, &state);
    defer alloc.free(json);

    // shell form entrypoint gets wrapped in a JSON array (single element)
    try std.testing.expect(std.mem.indexOf(u8, json, "\"Entrypoint\":[\"node\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"User\":\"nobody\"") != null);
}

test "config json with json form cmd and entrypoint" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    state.cmd = try alloc.dupe(u8, "[\"node\", \"server.js\"]");
    state.entrypoint = try alloc.dupe(u8, "[\"docker-entrypoint.sh\"]");

    const json = try buildConfigJson(alloc, &state);
    defer alloc.free(json);

    // JSON form should be passed through verbatim (not wrapped in /bin/sh -c)
    try std.testing.expect(std.mem.indexOf(u8, json, "\"Cmd\":[\"node\", \"server.js\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"Entrypoint\":[\"docker-entrypoint.sh\"]") != null);
    // should NOT contain /bin/sh
    try std.testing.expect(std.mem.indexOf(u8, json, "/bin/sh") == null);
}

test "manifest json with multiple layers" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    // add 3 layers with different digests and sizes
    const digests = [_][]const u8{ "sha256:aaa111", "sha256:bbb222", "sha256:ccc333" };
    const sizes = [_]u64{ 1024, 2048, 4096 };
    const diff_ids = [_][]const u8{ "sha256:ddd111", "sha256:ddd222", "sha256:ddd333" };

    for (digests, sizes, diff_ids) |d, s, di| {
        const ld = try alloc.dupe(u8, d);
        try state.layer_digests.append(alloc, ld);
        try state.layer_sizes.append(alloc, s);
        const did = try alloc.dupe(u8, di);
        try state.diff_ids.append(alloc, did);
    }

    const config_digest = blob_store.computeDigest("test config");
    const json = try buildManifestJson(alloc, &state, config_digest, 200);
    defer alloc.free(json);

    // all 3 layer digests should appear
    for (digests) |d| {
        try std.testing.expect(std.mem.indexOf(u8, json, d) != null);
    }

    // all 3 sizes should appear
    try std.testing.expect(std.mem.indexOf(u8, json, "\"size\":1024") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"size\":2048") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"size\":4096") != null);
}

test "parse copy args — single word" {
    const result = parseCopyArgs("myfile.txt");
    try std.testing.expectEqualStrings("myfile.txt", result.src);
    try std.testing.expectEqualStrings("myfile.txt", result.dest);
    try std.testing.expect(result.from_stage == null);
}

test "first instruction not from returns error" {
    const alloc = std.testing.allocator;
    const instructions = [_]dockerfile.Instruction{
        .{ .kind = .run, .args = "echo hello", .line_number = 1 },
    };
    const result = build(alloc, &instructions, ".", null, null);
    try std.testing.expectError(BuildError.NoFromInstruction, result);
}

test "parseCopyArgs with empty string" {
    const result = parseCopyArgs("");
    try std.testing.expectEqualStrings("", result.src);
    try std.testing.expectEqualStrings("", result.dest);
    try std.testing.expect(result.from_stage == null);
}

test "cache key determinism with empty command" {
    const alloc = std.testing.allocator;
    var state1 = BuildState.init(alloc);
    defer state1.deinit();

    var state2 = BuildState.init(alloc);
    defer state2.deinit();

    const key1 = try computeCacheKey(alloc, "RUN", "", &state1);
    defer alloc.free(key1);
    const key2 = try computeCacheKey(alloc, "RUN", "", &state2);
    defer alloc.free(key2);

    try std.testing.expectEqualStrings(key1, key2);
}

test "processVolume — space-separated paths" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    processVolume(alloc, &state, "/data /logs /cache");

    try std.testing.expectEqual(@as(usize, 3), state.volumes.items.len);
    try std.testing.expectEqualStrings("/data", state.volumes.items[0]);
    try std.testing.expectEqualStrings("/logs", state.volumes.items[1]);
    try std.testing.expectEqualStrings("/cache", state.volumes.items[2]);
}

test "processVolume — json form" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    processVolume(alloc, &state, "[\"/data\", \"/logs\"]");

    try std.testing.expectEqual(@as(usize, 2), state.volumes.items.len);
    try std.testing.expectEqualStrings("/data", state.volumes.items[0]);
    try std.testing.expectEqualStrings("/logs", state.volumes.items[1]);
}

test "processVolume — single path" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    processVolume(alloc, &state, "/data");

    try std.testing.expectEqual(@as(usize, 1), state.volumes.items.len);
    try std.testing.expectEqualStrings("/data", state.volumes.items[0]);
}

test "processShell sets shell" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    processShell(alloc, &state, "[\"/bin/bash\", \"-c\"]");
    try std.testing.expectEqualStrings("[\"/bin/bash\", \"-c\"]", state.shell.?);
}

test "processShell replaces previous shell" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    processShell(alloc, &state, "[\"/bin/bash\", \"-c\"]");
    processShell(alloc, &state, "[\"/bin/zsh\", \"-c\"]");
    try std.testing.expectEqualStrings("[\"/bin/zsh\", \"-c\"]", state.shell.?);
}

test "processStopsignal sets signal" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    processStopsignal(alloc, &state, "SIGTERM");
    try std.testing.expectEqualStrings("SIGTERM", state.stop_signal.?);
}

test "processStopsignal replaces previous signal" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    processStopsignal(alloc, &state, "SIGTERM");
    processStopsignal(alloc, &state, "SIGKILL");
    try std.testing.expectEqualStrings("SIGKILL", state.stop_signal.?);
}

test "processHealthcheck stores command" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    processHealthcheck(alloc, &state, "CMD curl -f http://localhost/");
    try std.testing.expectEqualStrings("CMD curl -f http://localhost/", state.healthcheck.?);
}

test "processHealthcheck replaces previous" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    processHealthcheck(alloc, &state, "CMD curl -f http://localhost/");
    processHealthcheck(alloc, &state, "NONE");
    try std.testing.expectEqualStrings("NONE", state.healthcheck.?);
}

test "config json with volumes" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    const v1 = try alloc.dupe(u8, "/data");
    try state.volumes.append(alloc, v1);
    const v2 = try alloc.dupe(u8, "/logs");
    try state.volumes.append(alloc, v2);

    const json = try buildConfigJson(alloc, &state);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"Volumes\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"/data\":{}") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"/logs\":{}") != null);
}

test "config json with shell" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    state.shell = try alloc.dupe(u8, "[\"/bin/bash\", \"-c\"]");

    const json = try buildConfigJson(alloc, &state);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"Shell\":[\"/bin/bash\", \"-c\"]") != null);
}

test "config json with stop signal" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    state.stop_signal = try alloc.dupe(u8, "SIGTERM");

    const json = try buildConfigJson(alloc, &state);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"StopSignal\":\"SIGTERM\"") != null);
}

test "config json with healthcheck" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    state.healthcheck = try alloc.dupe(u8, "CMD curl -f http://localhost/");

    const json = try buildConfigJson(alloc, &state);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"Healthcheck\":{") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"Test\":[\"CMD-SHELL\",\"curl -f http://localhost/\"]") != null);
}

test "processOnbuild does not crash" {
    // just verify it doesn't panic — ONBUILD logs a warning and skips
    processOnbuild("RUN echo triggered");
}

test "processArg — key=value" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    processArg(alloc, &state, "VERSION=1.0");
    try std.testing.expectEqualStrings("1.0", state.build_args.get("VERSION").?);
}

test "processArg — key only (no default)" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    processArg(alloc, &state, "MY_VAR");
    try std.testing.expectEqualStrings("", state.build_args.get("MY_VAR").?);
}

test "processArg — cli build-arg takes precedence" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    // simulate CLI --build-arg
    const key = try alloc.dupe(u8, "VERSION");
    const val = try alloc.dupe(u8, "2.0");
    try state.build_args.put(alloc, key, val);

    // ARG VERSION=1.0 should not override the CLI value
    processArg(alloc, &state, "VERSION=1.0");
    try std.testing.expectEqualStrings("2.0", state.build_args.get("VERSION").?);
}

test "expandArgs — simple $VAR" {
    const alloc = std.testing.allocator;
    var args_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer args_map.deinit(alloc);

    const key = try alloc.dupe(u8, "NAME");
    const val = try alloc.dupe(u8, "world");
    defer alloc.free(key);
    defer alloc.free(val);
    try args_map.put(alloc, key, val);

    const result = try expandArgs(alloc, "hello $NAME", &args_map);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("hello world", result);
}

test "expandArgs — braced ${VAR}" {
    const alloc = std.testing.allocator;
    var args_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer args_map.deinit(alloc);

    const key = try alloc.dupe(u8, "VER");
    const val = try alloc.dupe(u8, "1.0");
    defer alloc.free(key);
    defer alloc.free(val);
    try args_map.put(alloc, key, val);

    const result = try expandArgs(alloc, "app-${VER}-release", &args_map);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("app-1.0-release", result);
}

test "expandArgs — default value ${VAR:-default}" {
    const alloc = std.testing.allocator;
    var args_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer args_map.deinit(alloc);

    // VAR is not set — should use default
    const result = try expandArgs(alloc, "value is ${MISSING:-fallback}", &args_map);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("value is fallback", result);
}

test "expandArgs — default not used when var is set" {
    const alloc = std.testing.allocator;
    var args_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer args_map.deinit(alloc);

    const key = try alloc.dupe(u8, "MODE");
    const val = try alloc.dupe(u8, "production");
    defer alloc.free(key);
    defer alloc.free(val);
    try args_map.put(alloc, key, val);

    const result = try expandArgs(alloc, "mode=${MODE:-development}", &args_map);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("mode=production", result);
}

test "expandArgs — no vars returns same pointer" {
    const alloc = std.testing.allocator;
    var args_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer args_map.deinit(alloc);

    const input = "no variables here";
    const result = try expandArgs(alloc, input, &args_map);
    // should return the same pointer — no allocation
    try std.testing.expect(result.ptr == input.ptr);
}

test "expandArgs — undefined var is silently dropped" {
    const alloc = std.testing.allocator;
    var args_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer args_map.deinit(alloc);

    const result = try expandArgs(alloc, "hello $MISSING world", &args_map);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("hello  world", result);
}

test "expandArgs — multiple vars in one string" {
    const alloc = std.testing.allocator;
    var args_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer args_map.deinit(alloc);

    const k1 = try alloc.dupe(u8, "A");
    const v1 = try alloc.dupe(u8, "one");
    defer alloc.free(k1);
    defer alloc.free(v1);
    try args_map.put(alloc, k1, v1);

    const k2 = try alloc.dupe(u8, "B");
    const v2 = try alloc.dupe(u8, "two");
    defer alloc.free(k2);
    defer alloc.free(v2);
    try args_map.put(alloc, k2, v2);

    const result = try expandArgs(alloc, "$A and ${B}", &args_map);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("one and two", result);
}

test "expandArgs — empty default value" {
    const alloc = std.testing.allocator;
    var args_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer args_map.deinit(alloc);

    const result = try expandArgs(alloc, "${MISSING:-}", &args_map);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "expandArgs — trailing dollar sign" {
    const alloc = std.testing.allocator;
    var args_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer args_map.deinit(alloc);

    const result = try expandArgs(alloc, "cost is $", &args_map);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("cost is $", result);
}

test "expandArgs — dollar followed by non-var char" {
    const alloc = std.testing.allocator;
    var args_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer args_map.deinit(alloc);

    const result = try expandArgs(alloc, "price is $5", &args_map);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("price is $5", result);
}

test "expandArgs — var with empty value uses default" {
    const alloc = std.testing.allocator;
    var args_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer args_map.deinit(alloc);

    const key = try alloc.dupe(u8, "EMPTY");
    const val = try alloc.dupe(u8, "");
    defer alloc.free(key);
    defer alloc.free(val);
    try args_map.put(alloc, key, val);

    const result = try expandArgs(alloc, "${EMPTY:-fallback}", &args_map);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("fallback", result);
}

// -- multi-stage build tests --

test "parseCopyArgs — with --from flag" {
    const result = parseCopyArgs("--from=builder /app/dist /usr/share/nginx/html");
    try std.testing.expectEqualStrings("/app/dist", result.src);
    try std.testing.expectEqualStrings("/usr/share/nginx/html", result.dest);
    try std.testing.expectEqualStrings("builder", result.from_stage.?);
}

test "parseCopyArgs — --from with numeric index" {
    const result = parseCopyArgs("--from=0 /go/bin/app /usr/local/bin/");
    try std.testing.expectEqualStrings("/go/bin/app", result.src);
    try std.testing.expectEqualStrings("/usr/local/bin/", result.dest);
    try std.testing.expectEqualStrings("0", result.from_stage.?);
}

test "parseCopyArgs — no --from flag" {
    const result = parseCopyArgs("src/app.js /app/");
    try std.testing.expect(result.from_stage == null);
    try std.testing.expectEqualStrings("src/app.js", result.src);
    try std.testing.expectEqualStrings("/app/", result.dest);
}

test "parseStageName — with AS" {
    const name = parseStageName("golang:1.21 AS builder");
    try std.testing.expectEqualStrings("builder", name.?);
}

test "parseStageName — lowercase as" {
    const name = parseStageName("node:20 as build-stage");
    try std.testing.expectEqualStrings("build-stage", name.?);
}

test "parseStageName — no AS clause" {
    const name = parseStageName("ubuntu:24.04");
    try std.testing.expect(name == null);
}

test "splitIntoStages — single stage" {
    const alloc = std.testing.allocator;
    const instructions = [_]dockerfile.Instruction{
        .{ .kind = .from, .args = "alpine:latest", .line_number = 1 },
        .{ .kind = .run, .args = "echo hello", .line_number = 2 },
    };

    const stages = try splitIntoStages(alloc, &instructions);
    defer alloc.free(stages);

    try std.testing.expectEqual(@as(usize, 1), stages.len);
    try std.testing.expectEqual(@as(usize, 0), stages[0].index);
    try std.testing.expect(stages[0].name == null);
    try std.testing.expectEqual(@as(usize, 2), stages[0].instructions.len);
}

test "splitIntoStages — two stages" {
    const alloc = std.testing.allocator;
    const instructions = [_]dockerfile.Instruction{
        .{ .kind = .from, .args = "golang:1.21 AS builder", .line_number = 1 },
        .{ .kind = .run, .args = "go build", .line_number = 2 },
        .{ .kind = .from, .args = "alpine:latest", .line_number = 3 },
        .{ .kind = .copy, .args = "--from=builder /app /app", .line_number = 4 },
    };

    const stages = try splitIntoStages(alloc, &instructions);
    defer alloc.free(stages);

    try std.testing.expectEqual(@as(usize, 2), stages.len);

    // first stage
    try std.testing.expectEqual(@as(usize, 0), stages[0].index);
    try std.testing.expectEqualStrings("builder", stages[0].name.?);
    try std.testing.expectEqual(@as(usize, 2), stages[0].instructions.len);

    // second stage
    try std.testing.expectEqual(@as(usize, 1), stages[1].index);
    try std.testing.expect(stages[1].name == null);
    try std.testing.expectEqual(@as(usize, 2), stages[1].instructions.len);
}

test "splitIntoStages — three stages" {
    const alloc = std.testing.allocator;
    const instructions = [_]dockerfile.Instruction{
        .{ .kind = .from, .args = "node:20 AS deps", .line_number = 1 },
        .{ .kind = .run, .args = "npm install", .line_number = 2 },
        .{ .kind = .from, .args = "node:20 AS build", .line_number = 3 },
        .{ .kind = .run, .args = "npm run build", .line_number = 4 },
        .{ .kind = .from, .args = "nginx:alpine", .line_number = 5 },
        .{ .kind = .copy, .args = "--from=build /app/dist /usr/share/nginx/html", .line_number = 6 },
    };

    const stages = try splitIntoStages(alloc, &instructions);
    defer alloc.free(stages);

    try std.testing.expectEqual(@as(usize, 3), stages.len);
    try std.testing.expectEqualStrings("deps", stages[0].name.?);
    try std.testing.expectEqualStrings("build", stages[1].name.?);
    try std.testing.expect(stages[2].name == null);
}

test "findStageByRef — by name" {
    const alloc = std.testing.allocator;
    const stages = [_]BuildStage{
        .{ .name = "builder", .index = 0, .instructions = &.{} },
        .{ .name = null, .index = 1, .instructions = &.{} },
    };
    var states: [2]BuildState = .{ BuildState.init(alloc), BuildState.init(alloc) };
    defer for (&states) |*s| s.deinit();

    const found = findStageByRef(&stages, &states, "builder");
    try std.testing.expect(found != null);
}

test "findStageByRef — by index" {
    const alloc = std.testing.allocator;
    const stages = [_]BuildStage{
        .{ .name = "builder", .index = 0, .instructions = &.{} },
        .{ .name = null, .index = 1, .instructions = &.{} },
    };
    var states: [2]BuildState = .{ BuildState.init(alloc), BuildState.init(alloc) };
    defer for (&states) |*s| s.deinit();

    const found = findStageByRef(&stages, &states, "0");
    try std.testing.expect(found != null);

    const found1 = findStageByRef(&stages, &states, "1");
    try std.testing.expect(found1 != null);
}

test "findStageByRef — not found" {
    const alloc = std.testing.allocator;
    const stages = [_]BuildStage{
        .{ .name = "builder", .index = 0, .instructions = &.{} },
    };
    var states: [1]BuildState = .{BuildState.init(alloc)};
    defer for (&states) |*s| s.deinit();

    const found = findStageByRef(&stages, &states, "nonexistent");
    try std.testing.expect(found == null);

    const found2 = findStageByRef(&stages, &states, "5");
    try std.testing.expect(found2 == null);
}

// -- SHELL affecting RUN tests --

test "processShell sets shell that would be used by RUN" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    // default: no shell set
    try std.testing.expect(state.shell == null);

    // after SHELL instruction
    processShell(alloc, &state, "[\"/bin/bash\", \"-c\"]");
    try std.testing.expectEqualStrings("[\"/bin/bash\", \"-c\"]", state.shell.?);

    // BuildChildContext would receive this shell
    const child_ctx = BuildChildContext{
        .layer_dirs = &.{},
        .upper_dir = "/tmp",
        .work_dir = "/tmp",
        .merged_dir = "/tmp",
        .command = "echo hello",
        .env = &.{},
        .workdir = "/",
        .shell = state.shell,
    };
    try std.testing.expectEqualStrings("[\"/bin/bash\", \"-c\"]", child_ctx.shell.?);
}

test "shell does not leak across stages" {
    const alloc = std.testing.allocator;

    // stage 1: sets SHELL
    var state1 = BuildState.init(alloc);
    defer state1.deinit();
    processShell(alloc, &state1, "[\"/bin/bash\", \"-c\"]");

    // stage 2: fresh state, shell should be null
    var state2 = BuildState.init(alloc);
    defer state2.deinit();

    try std.testing.expectEqualStrings("[\"/bin/bash\", \"-c\"]", state1.shell.?);
    try std.testing.expect(state2.shell == null);
}

test "shell resets to default when null" {
    // verify that a BuildChildContext with null shell means default /bin/sh -c
    const child_ctx = BuildChildContext{
        .layer_dirs = &.{},
        .upper_dir = "/tmp",
        .work_dir = "/tmp",
        .merged_dir = "/tmp",
        .command = "echo hello",
        .env = &.{},
        .workdir = "/",
        .shell = null,
    };
    try std.testing.expect(child_ctx.shell == null);
}

test "shell with powershell-style args" {
    const alloc = std.testing.allocator;
    var state = BuildState.init(alloc);
    defer state.deinit();

    // some Dockerfiles use SHELL for Windows-style shells
    processShell(alloc, &state, "[\"/usr/bin/env\", \"bash\", \"-c\"]");
    try std.testing.expectEqualStrings("[\"/usr/bin/env\", \"bash\", \"-c\"]", state.shell.?);
}

test "cache key changes when shell changes" {
    const alloc = std.testing.allocator;

    var state1 = BuildState.init(alloc);
    defer state1.deinit();

    var state2 = BuildState.init(alloc);
    defer state2.deinit();
    state2.shell = try alloc.dupe(u8, "[\"/bin/bash\", \"-c\"]");

    // same RUN command, different shell — should produce different cache keys
    const key1 = try computeCacheKey(alloc, "RUN", "echo hello", &state1);
    defer alloc.free(key1);
    const key2 = try computeCacheKey(alloc, "RUN", "echo hello", &state2);
    defer alloc.free(key2);

    try std.testing.expect(!std.mem.eql(u8, key1, key2));
}

test "cache key same when shell is same" {
    const alloc = std.testing.allocator;

    var state1 = BuildState.init(alloc);
    defer state1.deinit();
    state1.shell = try alloc.dupe(u8, "[\"/bin/bash\", \"-c\"]");

    var state2 = BuildState.init(alloc);
    defer state2.deinit();
    state2.shell = try alloc.dupe(u8, "[\"/bin/bash\", \"-c\"]");

    const key1 = try computeCacheKey(alloc, "RUN", "echo hello", &state1);
    defer alloc.free(key1);
    const key2 = try computeCacheKey(alloc, "RUN", "echo hello", &state2);
    defer alloc.free(key2);

    try std.testing.expectEqualStrings(key1, key2);
}
