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
        if (self.cmd) |c| self.alloc.free(c);
        if (self.entrypoint) |e| self.alloc.free(e);
        if (!std.mem.eql(u8, self.workdir, "/")) self.alloc.free(self.workdir);
        if (self.user) |u| self.alloc.free(u);
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

/// build an image from a Dockerfile.
///
/// instructions: parsed Dockerfile instructions
/// context_dir: path to the build context (for COPY)
/// tag: optional image tag (e.g. "myapp:latest")
pub fn build(
    alloc: std.mem.Allocator,
    instructions: []const dockerfile.Instruction,
    context_dir: []const u8,
    tag: ?[]const u8,
) BuildError!BuildResult {
    if (instructions.len == 0 or instructions[0].kind != .from) {
        return BuildError.NoFromInstruction;
    }

    var state = BuildState.init(alloc);
    defer state.deinit();

    // process each instruction
    for (instructions) |inst| {
        switch (inst.kind) {
            .from => try processFrom(alloc, &state, inst.args),
            .run => try processRun(alloc, &state, inst.args),
            .copy => try processCopy(alloc, &state, inst.args, context_dir),
            .env => processEnv(alloc, &state, inst.args),
            .workdir => processWorkdir(alloc, &state, inst.args),
            .cmd => processCmd(alloc, &state, inst.args),
            .entrypoint => processEntrypoint(alloc, &state, inst.args),
            .expose => processExpose(alloc, &state, inst.args),
            .user => processUser(alloc, &state, inst.args),
            .label => processLabel(alloc, &state, inst.args),
            .arg => {}, // ARG is handled at parse time in a full implementation
        }
    }

    // produce the OCI image (config + manifest) and store it
    return produceImage(alloc, &state, tag);
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

        // save the pulled image record
        state_store.saveImage(.{
            .id = result.manifest_digest,
            .repository = ref.repository,
            .tag = ref.reference,
            .manifest_digest = result.manifest_digest,
            .config_digest = "sha256:config",
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

// -- cache helpers --

fn computeCacheKey(alloc: std.mem.Allocator, instruction: []const u8, args: []const u8, state: *const BuildState) ![]const u8 {
    // cache key = sha256(instruction + "\n" + args + "\n" + parent_digest + "\n" + sorted_env)
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

        state.addLayer(e.layer_digest, e.diff_id, e.layer_size) catch return false;
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
};

fn parseCopyArgs(args: []const u8) CopyArgs {
    // simple split on last space: "src dest"
    // TODO: handle --from=stage and --chown in the future
    const trimmed = std.mem.trim(u8, args, " \t");

    // find the last space that separates src from dest
    var i: usize = trimmed.len;
    while (i > 0) {
        i -= 1;
        if (trimmed[i] == ' ' or trimmed[i] == '\t') {
            return .{
                .src = std.mem.trim(u8, trimmed[0..i], " \t"),
                .dest = std.mem.trim(u8, trimmed[i + 1 ..], " \t"),
            };
        }
    }

    // no space found — treat as "src src" (copy to same name)
    return .{ .src = trimmed, .dest = trimmed };
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

    // exec: /bin/sh -c "<command>"
    return execShellCommand(ctx.command, ctx.env);
}

/// execute a shell command via /bin/sh -c
fn execShellCommand(command: []const u8, env: []const []const u8) u8 {
    var str_buf: [65536]u8 = undefined;
    var str_pos: usize = 0;

    // argv: /bin/sh -c "command"
    var argv: [4]?[*:0]const u8 = .{null} ** 4;
    argv[0] = packString(&str_buf, &str_pos, "/bin/sh") orelse return 127;
    argv[1] = packString(&str_buf, &str_pos, "-c") orelse return 127;
    argv[2] = packString(&str_buf, &str_pos, command) orelse return 127;

    // envp
    var envp: [257]?[*:0]const u8 = .{null} ** 257;
    for (env, 0..) |e, i| {
        if (i >= envp.len - 1) break;
        envp[i] = packString(&str_buf, &str_pos, e) orelse return 127;
    }

    _ = linux.syscall3(
        .execve,
        @intFromPtr(argv[0].?),
        @intFromPtr(&argv),
        @intFromPtr(&envp),
    );

    return 127;
}

/// copy a string into a buffer and null-terminate it (same as container.zig)
fn packString(buf: *[65536]u8, pos: *usize, src: []const u8) ?[*:0]const u8 {
    if (pos.* + src.len + 1 > buf.len) return null;
    @memcpy(buf[pos.*..][0..src.len], src);
    buf[pos.* + src.len] = 0;
    const result: [*:0]const u8 = @ptrCast(&buf[pos.*]);
    pos.* += src.len + 1;
    return result;
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

    state_store.saveImage(.{
        .id = owned_digest,
        .repository = repo,
        .tag = img_tag,
        .manifest_digest = owned_digest,
        .config_digest = manifest_digest_str,
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
    var buf = std.ArrayList(u8).init(alloc);
    defer buf.deinit();
    const writer = buf.writer();

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
            try writeJsonEscaped(writer, env);
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
            try writeJsonEscaped(writer, cmd);
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
            try writeJsonEscaped(writer, ep);
            try writer.writeAll("\"]");
        }
        first = false;
    }

    // WorkingDir
    if (!std.mem.eql(u8, state.workdir, "/")) {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"WorkingDir\":\"");
        try writeJsonEscaped(writer, state.workdir);
        try writer.writeByte('"');
        first = false;
    }

    // User
    if (state.user) |u| {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"User\":\"");
        try writeJsonEscaped(writer, u);
        try writer.writeByte('"');
        first = false;
    }

    _ = first;
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

    return try buf.toOwnedSlice();
}

fn buildManifestJson(
    alloc: std.mem.Allocator,
    state: *const BuildState,
    config_digest: blob_store.Digest,
    config_size: usize,
) ![]const u8 {
    var buf = std.ArrayList(u8).init(alloc);
    defer buf.deinit();
    const writer = buf.writer();

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

    return try buf.toOwnedSlice();
}

fn writeJsonEscaped(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => try writer.writeByte(c),
        }
    }
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
}

test "parse copy args — current dir" {
    const result = parseCopyArgs(". .");
    try std.testing.expectEqualStrings(".", result.src);
    try std.testing.expectEqualStrings(".", result.dest);
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
    const result = build(alloc, &.{}, ".", null);
    try std.testing.expectError(BuildError.NoFromInstruction, result);
}

test "json escaping" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeJsonEscaped(buf.writer(), "hello \"world\"\nfoo\\bar");
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
}

test "first instruction not from returns error" {
    const alloc = std.testing.allocator;
    const instructions = [_]dockerfile.Instruction{
        .{ .kind = .run, .args = "echo hello", .line_number = 1 },
    };
    const result = build(alloc, &instructions, ".", null);
    try std.testing.expectError(BuildError.NoFromInstruction, result);
}
