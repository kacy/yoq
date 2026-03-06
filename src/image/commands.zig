const std = @import("std");
const cli = @import("../lib/cli.zig");
const json_out = @import("../lib/json_output.zig");
const spec = @import("spec.zig");
const registry = @import("registry.zig");
const layer = @import("layer.zig");
const oci = @import("oci.zig");
const blob_store = @import("store.zig");
const store = @import("../state/store.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const requireArg = cli.requireArg;

pub const ImageResolution = struct {
    rootfs: []const u8,
    entrypoint: []const []const u8 = &.{},
    default_cmd: []const []const u8 = &.{},
    image_env: []const []const u8 = &.{},
    working_dir: []const u8 = "/",
    layer_paths: []const []const u8 = &.{},
    pull_result: ?registry.PullResult = null,
    config_parsed: ?spec.ParseResult(spec.ImageConfig) = null,
    /// set when layer_paths was allocated and needs freeing.
    /// null for local rootfs paths (not heap-allocated).
    alloc: ?std.mem.Allocator = null,

    pub fn deinit(self: *ImageResolution) void {
        if (self.alloc) |a| {
            for (self.layer_paths) |p| a.free(p);
            a.free(self.layer_paths);
        }
        if (self.pull_result) |*r| r.deinit();
        if (self.config_parsed) |*c| c.deinit();
    }
};

/// pull an image and extract its config. returns the rootfs path,
/// image defaults, and layer paths for overlayfs.
pub fn pullAndResolveImage(alloc: std.mem.Allocator, target: []const u8) ImageResolution {
    const ref = spec.parseImageRef(target);

    writeErr("pulling {s}...\n", .{target});

    var result = ImageResolution{ .rootfs = target };

    result.pull_result = registry.pull(alloc, ref) catch |err| {
        writeErr("failed to pull image: {s} ({})\n", .{ target, err });
        std.process.exit(1);
    };

    result.config_parsed = spec.parseImageConfig(alloc, result.pull_result.?.config_bytes) catch |err| {
        writeErr("failed to parse image config: {}\n", .{err});
        std.process.exit(1);
    };

    // extract defaults from image config
    if (result.config_parsed.?.value.config) |cc| {
        if (cc.Entrypoint) |ep| result.entrypoint = ep;
        if (cc.Cmd) |cmd| result.default_cmd = cmd;
        if (cc.Env) |env| result.image_env = env;
        if (cc.WorkingDir) |wd| {
            if (wd.len > 0) result.working_dir = wd;
        }
    }

    // extract layers for overlayfs
    result.layer_paths = layer.assembleRootfs(alloc, result.pull_result.?.layer_digests) catch |err| {
        writeErr("failed to extract image layers: {}\n", .{err});
        std.process.exit(1);
    };
    result.alloc = alloc;

    if (result.layer_paths.len > 0) {
        result.rootfs = result.layer_paths[result.layer_paths.len - 1];
    }

    // compute config digest from config bytes
    const pr = result.pull_result.?;
    const cfg_computed = blob_store.computeDigest(pr.config_bytes);
    var cfg_digest_buf: [71]u8 = undefined;
    const cfg_digest_str = cfg_computed.string(&cfg_digest_buf);

    // save image record (stores manifest/config blobs and metadata)
    oci.saveImageFromPull(
        ref,
        pr.manifest_digest,
        pr.manifest_bytes,
        pr.config_bytes,
        cfg_digest_str,
        pr.total_size,
    ) catch |e| {
        writeErr("warning: failed to save image record: {}\n", .{e});
    };

    writeErr("image pulled and extracted\n", .{});
    return result;
}

pub fn pull(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const image_str = requireArg(args, "usage: yoq pull <image>\n");

    const ref = spec.parseImageRef(image_str);

    writeErr("pulling {s}...\n", .{image_str});

    var result = registry.pull(alloc, ref) catch |err| {
        writeErr("failed to pull image: {s} ({})\n", .{ image_str, err });
        std.process.exit(1);
    };
    defer result.deinit();

    // extract layers so they're cached for future runs
    const layer_paths = layer.assembleRootfs(alloc, result.layer_digests) catch |err| {
        writeErr("failed to extract image layers: {}\n", .{err});
        std.process.exit(1);
    };
    defer {
        for (layer_paths) |p| alloc.free(p);
        alloc.free(layer_paths);
    }

    // compute config digest from config bytes
    const config_computed = blob_store.computeDigest(result.config_bytes);
    var config_digest_buf: [71]u8 = undefined;
    const config_digest_str = config_computed.string(&config_digest_buf);

    // save image record (stores manifest/config blobs and metadata)
    oci.saveImageFromPull(
        ref,
        result.manifest_digest,
        result.manifest_bytes,
        result.config_bytes,
        config_digest_str,
        result.total_size,
    ) catch |err| {
        writeErr("failed to save image record: {}\n", .{err});
        std.process.exit(1);
    };

    // format size for display
    const size_mb = result.total_size / (1024 * 1024);
    write("{s}: pulled ({d} layers, {d} MB)\n", .{
        image_str,
        result.layer_digests.len,
        size_mb,
    });
}

pub fn push(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const source_str = requireArg(args, "usage: yoq push <source> [target]\n");

    // optional target — if not given, push to the same ref
    const target_str = args.next() orelse source_str;

    // look up the source image in the local store
    const source_ref = spec.parseImageRef(source_str);
    const image_record = store.findImage(alloc, source_ref.repository, source_ref.reference) catch |err| {
        writeErr("image not found: {s} ({})\n", .{ source_str, err });
        writeErr("hint: pull or build the image first, then push\n", .{});
        std.process.exit(1);
    };
    defer image_record.deinit(alloc);

    // read manifest bytes from the blob store
    const manifest_parsed_digest = blob_store.Digest.parse(image_record.manifest_digest) orelse {
        writeErr("invalid manifest digest in image record\n", .{});
        std.process.exit(1);
    };
    const manifest_bytes = blob_store.getBlob(alloc, manifest_parsed_digest) catch |err| {
        writeErr("failed to read manifest from blob store: {}\n", .{err});
        writeErr("hint: the image may be corrupted — try pulling again\n", .{});
        std.process.exit(1);
    };
    defer alloc.free(manifest_bytes);

    // read config bytes from the blob store
    const config_parsed_digest = blob_store.Digest.parse(image_record.config_digest) orelse {
        writeErr("invalid config digest in image record\n", .{});
        std.process.exit(1);
    };
    const config_bytes = blob_store.getBlob(alloc, config_parsed_digest) catch |err| {
        writeErr("failed to read config from blob store: {}\n", .{err});
        writeErr("hint: the image may be corrupted — try pulling again\n", .{});
        std.process.exit(1);
    };
    defer alloc.free(config_bytes);

    // parse manifest to get layer digests
    var parsed_manifest = spec.parseManifest(alloc, manifest_bytes) catch |err| {
        writeErr("failed to parse image manifest: {}\n", .{err});
        std.process.exit(1);
    };
    defer parsed_manifest.deinit();

    // collect layer digests
    var layer_digest_strs: std.ArrayListUnmanaged([]const u8) = .empty;
    defer layer_digest_strs.deinit(alloc);
    for (parsed_manifest.value.layers) |l| {
        layer_digest_strs.append(alloc, l.digest) catch {
            writeErr("out of memory\n", .{});
            std.process.exit(1);
        };
    }

    // parse the target reference for pushing
    const target_ref = spec.parseImageRef(target_str);

    writeErr("pushing {s}...\n", .{target_str});

    var result = registry.push(alloc, target_ref, manifest_bytes, config_bytes, layer_digest_strs.items) catch |e| {
        writeErr("failed to push image: {}\n", .{e});
        std.process.exit(1);
    };
    defer result.deinit();

    write("{s}: pushed ({d} layers uploaded, {d} skipped)\n", .{
        target_str,
        result.layers_uploaded,
        result.layers_skipped,
    });
}

pub fn images(alloc: std.mem.Allocator) void {
    var imgs = store.listImages(alloc) catch |err| {
        writeErr("failed to list images: {}\n", .{err});
        std.process.exit(1);
    };
    defer {
        for (imgs.items) |img| img.deinit(alloc);
        imgs.deinit(alloc);
    }

    if (cli.output_mode == .json) {
        imagesJson(imgs.items);
        return;
    }

    if (imgs.items.len == 0) {
        write("no images\n", .{});
        return;
    }

    write("{s:<30} {s:<15} {s:<14} {s:<10}\n", .{ "REPOSITORY", "TAG", "IMAGE ID", "SIZE" });
    for (imgs.items) |img| {
        // truncate the digest for display (first 12 chars after "sha256:")
        const short_id = if (img.id.len > 19) img.id[7..19] else img.id;
        const size_mb = @divTrunc(img.total_size, 1024 * 1024);

        write("{s:<30} {s:<15} {s:<14} {d} MB\n", .{
            img.repository,
            img.tag,
            short_id,
            size_mb,
        });
    }
}

fn imagesJson(imgs: []const store.ImageRecord) void {
    var w = json_out.JsonWriter{};
    w.beginArray();
    for (imgs) |img| {
        w.beginObject();
        w.stringField("repository", img.repository);
        w.stringField("tag", img.tag);
        w.stringField("id", img.id);
        w.stringField("manifest_digest", img.manifest_digest);
        w.stringField("config_digest", img.config_digest);
        w.uintField("size_bytes", img.total_size);
        w.intField("created_at", img.created_at);
        w.endObject();
    }
    w.endArray();
    w.flush();
}

fn inspectJson(image: *const store.ImageRecord, config: *const spec.ImageConfig, manifest: *const spec.Manifest) void {
    var w = json_out.JsonWriter{};
    w.beginObject();
    w.stringField("repository", image.repository);
    w.stringField("tag", image.tag);
    w.stringField("manifest_digest", image.manifest_digest);
    w.uintField("size_bytes", image.total_size);
    w.intField("created_at", image.created_at);

    if (config.architecture) |arch| w.stringField("architecture", arch);
    if (config.os) |os_name| w.stringField("os", os_name);
    if (config.created) |created| w.stringField("created", created);

    w.uintField("layer_count", manifest.layers.len);

    if (config.config) |cc| {
        w.beginObjectField("config");
        if (cc.WorkingDir) |wd| w.stringField("working_dir", wd);
        if (cc.User) |user| w.stringField("user", user);
        if (cc.StopSignal) |sig| w.stringField("stop_signal", sig);
        w.endObject(); // config
    }

    w.endObject();
    w.flush();
}

pub fn rmi(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const image_str = requireArg(args, "usage: yoq rmi <image>\n");

    // try to find the image by repository:tag
    const ref = spec.parseImageRef(image_str);
    const image = store.findImage(alloc, ref.repository, ref.reference) catch |err| {
        writeErr("image not found: {s} ({})\n", .{ image_str, err });
        std.process.exit(1);
    };
    defer image.deinit(alloc);

    // remove the image record from the database
    store.removeImage(image.id) catch |err| {
        writeErr("failed to remove image record: {}\n", .{err});
        std.process.exit(1);
    };

    // note: we don't delete the blobs or extracted layers here.
    // a future `yoq prune` command can handle garbage collection
    // of unreferenced blobs. this matches docker's behavior —
    // rmi removes the tag, prune cleans up storage.

    write("untagged: {s}:{s}\n", .{ image.repository, image.tag });
}

pub fn inspect(args: *std.process.ArgIterator, alloc: std.mem.Allocator) void {
    const image_str = requireArg(args, "usage: yoq inspect <image>\n");

    // check for --json flag in remaining args
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) cli.output_mode = .json;
    }

    // find the image (same pattern as rmi)
    const ref = spec.parseImageRef(image_str);
    const image = store.findImage(alloc, ref.repository, ref.reference) catch |err| {
        writeErr("image not found: {s} ({})\n", .{ image_str, err });
        std.process.exit(1);
    };
    defer image.deinit(alloc);

    // read manifest blob
    const manifest_digest = blob_store.Digest.parse(image.manifest_digest) orelse {
        writeErr("invalid manifest digest\n", .{});
        std.process.exit(1);
    };
    const manifest_bytes = blob_store.getBlob(alloc, manifest_digest) catch |err| {
        writeErr("failed to read manifest blob: {}\n", .{err});
        std.process.exit(1);
    };
    defer alloc.free(manifest_bytes);

    var parsed_manifest = spec.parseManifest(alloc, manifest_bytes) catch |err| {
        writeErr("failed to parse manifest: {}\n", .{err});
        std.process.exit(1);
    };
    defer parsed_manifest.deinit();

    // read config blob
    const config_digest = blob_store.Digest.parse(image.config_digest) orelse {
        writeErr("invalid config digest\n", .{});
        std.process.exit(1);
    };
    const config_bytes = blob_store.getBlob(alloc, config_digest) catch |err| {
        writeErr("failed to read config blob: {}\n", .{err});
        std.process.exit(1);
    };
    defer alloc.free(config_bytes);

    var parsed_config = spec.parseImageConfig(alloc, config_bytes) catch |err| {
        writeErr("failed to parse config: {}\n", .{err});
        std.process.exit(1);
    };
    defer parsed_config.deinit();

    const config = parsed_config.value;
    const manifest = parsed_manifest.value;

    if (cli.output_mode == .json) {
        inspectJson(&image, &config, &manifest);
        return;
    }

    // -- display --
    write("{s}:{s}\n\n", .{ image.repository, image.tag });

    // digest (truncated for readability)
    const short_digest = if (image.manifest_digest.len > 19) image.manifest_digest[0..19] else image.manifest_digest;
    write("  digest:       {s}...\n", .{short_digest});

    // platform
    if (config.architecture) |arch| {
        if (config.os) |os_name| {
            write("  platform:     {s}/{s}\n", .{ os_name, arch });
        }
    }

    // created
    if (config.created) |created| {
        write("  created:      {s}\n", .{created});
    }

    // size
    const size_mb = @divTrunc(image.total_size, 1024 * 1024);
    write("  size:         {d} MB\n", .{size_mb});

    // layers
    write("  layers:       {d}\n", .{manifest.layers.len});
    for (manifest.layers, 0..) |l, i| {
        const layer_mb = l.size / (1024 * 1024);
        const layer_short = if (l.digest.len > 19) l.digest[7..19] else l.digest;
        write("    [{d}] {s}  {d} MB\n", .{ i, layer_short, layer_mb });
    }

    // container config
    if (config.config) |cc| {
        write("\n", .{});

        if (cc.Entrypoint) |ep| {
            write("  entrypoint:   ", .{});
            for (ep, 0..) |arg, i| {
                if (i > 0) write(" ", .{});
                write("{s}", .{arg});
            }
            write("\n", .{});
        }

        if (cc.Cmd) |cmd| {
            write("  cmd:          ", .{});
            for (cmd, 0..) |arg, i| {
                if (i > 0) write(" ", .{});
                write("{s}", .{arg});
            }
            write("\n", .{});
        }

        if (cc.Env) |env| {
            write("  env:\n", .{});
            for (env) |e| {
                write("    {s}\n", .{e});
            }
        }

        if (cc.ExposedPorts) |ports| {
            if (ports == .object) {
                write("  ports:        ", .{});
                var first = true;
                var port_iter = ports.object.iterator();
                while (port_iter.next()) |entry| {
                    if (!first) write(", ", .{});
                    write("{s}", .{entry.key_ptr.*});
                    first = false;
                }
                write("\n", .{});
            }
        }

        if (cc.Volumes) |volumes| {
            if (volumes == .object) {
                write("  volumes:      ", .{});
                var first = true;
                var vol_iter = volumes.object.iterator();
                while (vol_iter.next()) |entry| {
                    if (!first) write(", ", .{});
                    write("{s}", .{entry.key_ptr.*});
                    first = false;
                }
                write("\n", .{});
            }
        }

        if (cc.WorkingDir) |wd| {
            write("  workdir:      {s}\n", .{wd});
        }

        if (cc.User) |user| {
            write("  user:         {s}\n", .{user});
        }

        if (cc.Shell) |shell| {
            write("  shell:        ", .{});
            for (shell, 0..) |arg, i| {
                if (i > 0) write(" ", .{});
                write("{s}", .{arg});
            }
            write("\n", .{});
        }

        if (cc.StopSignal) |sig| {
            write("  stopsignal:   {s}\n", .{sig});
        }

        if (cc.Healthcheck) |hc| {
            write("  healthcheck:\n", .{});
            if (hc.Test) |test_cmd| {
                write("    test:     ", .{});
                for (test_cmd, 0..) |arg, i| {
                    if (i > 0) write(" ", .{});
                    write("{s}", .{arg});
                }
                write("\n", .{});
            }
            if (hc.Interval) |iv| {
                write("    interval: {d}ns\n", .{iv});
            }
            if (hc.Timeout) |to| {
                write("    timeout:  {d}ns\n", .{to});
            }
            if (hc.Retries) |r| {
                write("    retries:  {d}\n", .{r});
            }
        }

        if (cc.OnBuild) |onbuild| {
            if (onbuild.len > 0) {
                write("  onbuild:\n", .{});
                for (onbuild) |trigger| {
                    write("    {s}\n", .{trigger});
                }
            }
        }

        if (cc.Labels) |labels| {
            if (labels == .object) {
                write("  labels:\n", .{});
                var label_iter = labels.object.iterator();
                while (label_iter.next()) |entry| {
                    const val = entry.value_ptr.*;
                    if (val == .string) {
                        write("    {s}: {s}\n", .{ entry.key_ptr.*, val.string });
                    }
                }
            }
        }
    }
}

pub fn prune(alloc: std.mem.Allocator) void {
    // step 1: collect all referenced digests from image records
    var referenced = std.StringHashMap(void).init(alloc);
    defer referenced.deinit();

    var imgs = store.listImages(alloc) catch |err| {
        writeErr("failed to list images: {}\n", .{err});
        std.process.exit(1);
    };
    defer {
        for (imgs.items) |img| img.deinit(alloc);
        imgs.deinit(alloc);
    }

    for (imgs.items) |img| {
        // manifest and config digests are referenced
        addDigestHex(&referenced, img.manifest_digest);
        addDigestHex(&referenced, img.config_digest);

        // parse the manifest to find layer digests
        const manifest_digest = blob_store.Digest.parse(img.manifest_digest) orelse continue;
        const manifest_bytes = blob_store.getBlob(alloc, manifest_digest) catch continue;
        defer alloc.free(manifest_bytes);

        var parsed = spec.parseManifest(alloc, manifest_bytes) catch continue;
        defer parsed.deinit();

        for (parsed.value.layers) |l| {
            addDigestHex(&referenced, l.digest);
        }

        // also parse config to get diff_ids (referenced as extracted layers)
        const config_digest = blob_store.Digest.parse(img.config_digest) orelse continue;
        const config_bytes = blob_store.getBlob(alloc, config_digest) catch continue;
        defer alloc.free(config_bytes);

        var parsed_config = spec.parseImageConfig(alloc, config_bytes) catch continue;
        defer parsed_config.deinit();

        if (parsed_config.value.rootfs) |rootfs| {
            for (rootfs.diff_ids) |diff_id| {
                addDigestHex(&referenced, diff_id);
            }
        }
    }

    // add build cache digests
    var cache_digests = store.listBuildCacheDigests(alloc) catch std.ArrayList([]const u8).empty;
    defer {
        for (cache_digests.items) |d| alloc.free(d);
        cache_digests.deinit(alloc);
    }
    for (cache_digests.items) |d| {
        addDigestHex(&referenced, d);
    }

    // step 2: walk blobs on disk and delete unreferenced ones
    var blobs = blob_store.listBlobsOnDisk(alloc) catch |err| {
        writeErr("failed to list blobs: {}\n", .{err});
        std.process.exit(1);
    };
    defer {
        for (blobs.items) |item| alloc.free(item);
        blobs.deinit(alloc);
    }

    var blobs_removed: usize = 0;
    var bytes_reclaimed: u64 = 0;

    for (blobs.items) |hex| {
        if (referenced.contains(hex)) continue;

        // unreferenced blob — delete it
        const digest_str_buf = std.fmt.allocPrint(alloc, "sha256:{s}", .{hex}) catch continue;
        defer alloc.free(digest_str_buf);

        if (blob_store.Digest.parse(digest_str_buf)) |digest| {
            const size = blob_store.getBlobSize(digest) orelse 0;
            blob_store.removeBlob(digest);
            blobs_removed += 1;
            bytes_reclaimed += size;
        }
    }

    // step 3: walk extracted layers and delete unreferenced ones
    var layers = layer.listExtractedLayersOnDisk(alloc) catch |err| {
        writeErr("failed to list layers: {}\n", .{err});
        std.process.exit(1);
    };
    defer {
        for (layers.items) |item| alloc.free(item);
        layers.deinit(alloc);
    }

    var layers_removed: usize = 0;
    for (layers.items) |hex| {
        if (referenced.contains(hex)) continue;
        layer.deleteExtractedLayer(hex);
        layers_removed += 1;
    }

    // report
    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginObject();
        w.uintField("blobs_removed", blobs_removed);
        w.uintField("layers_removed", layers_removed);
        w.uintField("bytes_reclaimed", bytes_reclaimed);
        w.endObject();
        w.flush();
    } else if (blobs_removed == 0 and layers_removed == 0) {
        write("nothing to prune\n", .{});
    } else {
        const mb = @divTrunc(bytes_reclaimed, 1024 * 1024);
        write("pruned {d} blob(s), {d} layer(s), reclaimed {d} MB\n", .{
            blobs_removed,
            layers_removed,
            mb,
        });
    }
}

/// extract the hex portion from a "sha256:<hex>" digest string and
/// add it to the referenced set. silently ignores malformed digests.
fn addDigestHex(set: *std.StringHashMap(void), digest_str: []const u8) void {
    const prefix = "sha256:";
    if (std.mem.startsWith(u8, digest_str, prefix)) {
        const hex = digest_str[prefix.len..];
        if (hex.len == 64) {
            set.put(hex, {}) catch {};
        }
    }
}
