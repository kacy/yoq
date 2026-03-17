const std = @import("std");
const cli = @import("../../lib/cli.zig");
const json_out = @import("../../lib/json_output.zig");
const spec = @import("../spec.zig");
const store = @import("../../state/store.zig");
const common = @import("common.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const requireArg = cli.requireArg;

pub fn images(alloc: std.mem.Allocator) !void {
    var imgs = store.listImages(alloc) catch |err| {
        writeErr("failed to list images: {}\n", .{err});
        return common.ImageCommandsError.StoreFailed;
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

pub fn rmi(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const image_str = requireArg(args, "usage: yoq rmi <image>\n");
    const ref = spec.parseImageRef(image_str);
    const image = store.findImage(alloc, ref.repository, ref.reference) catch |err| {
        writeErr("image not found: {s} ({})", .{ image_str, err });
        return common.ImageCommandsError.ImageNotFound;
    };
    defer image.deinit(alloc);

    store.removeImage(image.id) catch |err| {
        writeErr("failed to remove image record: {}\n", .{err});
        return common.ImageCommandsError.StoreFailed;
    };

    write("untagged: {s}:{s}\n", .{ image.repository, image.tag });
}

pub fn inspect(args: *std.process.ArgIterator, alloc: std.mem.Allocator) !void {
    const image_str = requireArg(args, "usage: yoq inspect <image>\n");

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) cli.output_mode = .json;
    }

    const ref = spec.parseImageRef(image_str);
    const image = store.findImage(alloc, ref.repository, ref.reference) catch |err| {
        writeErr("image not found: {s} ({})", .{ image_str, err });
        return common.ImageCommandsError.ImageNotFound;
    };
    defer image.deinit(alloc);

    const blobs = common.loadImageBlobs(alloc, image) catch return common.ImageCommandsError.StoreFailed;
    defer blobs.deinit(alloc);

    var parsed_manifest = spec.parseManifest(alloc, blobs.manifest_bytes) catch |err| {
        writeErr("failed to parse manifest: {}\n", .{err});
        return common.ImageCommandsError.InvalidDigest;
    };
    defer parsed_manifest.deinit();

    var parsed_config = spec.parseImageConfig(alloc, blobs.config_bytes) catch |err| {
        writeErr("failed to parse config: {}\n", .{err});
        return common.ImageCommandsError.InvalidDigest;
    };
    defer parsed_config.deinit();

    const config = parsed_config.value;
    const manifest = parsed_manifest.value;

    if (cli.output_mode == .json) {
        inspectJson(&image, &config, &manifest);
        return;
    }

    write("{s}:{s}\n\n", .{ image.repository, image.tag });

    const short_digest = if (image.manifest_digest.len > 19) image.manifest_digest[0..19] else image.manifest_digest;
    write("  digest:       {s}...\n", .{short_digest});

    if (config.architecture) |arch| {
        if (config.os) |os_name| {
            write("  platform:     {s}/{s}\n", .{ os_name, arch });
        }
    }

    if (config.created) |created| {
        write("  created:      {s}\n", .{created});
    }

    const size_mb = @divTrunc(image.total_size, 1024 * 1024);
    write("  size:         {d} MB\n", .{size_mb});

    write("  layers:       {d}\n", .{manifest.layers.len});
    for (manifest.layers, 0..) |entry, i| {
        const layer_mb = entry.size / (1024 * 1024);
        const layer_short = if (entry.digest.len > 19) entry.digest[7..19] else entry.digest;
        write("    [{d}] {s}  {d} MB\n", .{ i, layer_short, layer_mb });
    }

    if (config.config) |cc| {
        write("\n", .{});
        writeOptionalArgs("  entrypoint:   ", cc.Entrypoint);
        writeOptionalArgs("  cmd:          ", cc.Cmd);
        writeOptionalEnv(cc.Env);
        writeOptionalObjectKeys("  ports:        ", cc.ExposedPorts);
        writeOptionalObjectKeys("  volumes:      ", cc.Volumes);

        if (cc.WorkingDir) |wd| write("  workdir:      {s}\n", .{wd});
        if (cc.User) |user| write("  user:         {s}\n", .{user});
        writeOptionalArgs("  shell:        ", cc.Shell);
        if (cc.StopSignal) |sig| write("  stopsignal:   {s}\n", .{sig});
        writeOptionalHealthcheck(cc.Healthcheck);
        writeOptionalLines("  onbuild:\n", "    {s}\n", cc.OnBuild);
        writeOptionalLabels(cc.Labels);
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
        w.uintField("size_bytes", @intCast(img.total_size));
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
    w.uintField("size_bytes", @intCast(image.total_size));
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
        w.endObject();
    }

    w.endObject();
    w.flush();
}

fn writeOptionalArgs(label: []const u8, args: ?[]const []const u8) void {
    const values = args orelse return;
    write("{s}", .{label});
    for (values, 0..) |arg, i| {
        if (i > 0) write(" ", .{});
        write("{s}", .{arg});
    }
    write("\n", .{});
}

fn writeOptionalEnv(env: ?[]const []const u8) void {
    const values = env orelse return;
    write("  env:\n", .{});
    for (values) |entry| {
        write("    {s}\n", .{entry});
    }
}

fn writeOptionalObjectKeys(label: []const u8, value: ?std.json.Value) void {
    const object_value = value orelse return;
    if (object_value != .object) return;

    write("{s}", .{label});
    var first = true;
    var iter = object_value.object.iterator();
    while (iter.next()) |entry| {
        if (!first) write(", ", .{});
        write("{s}", .{entry.key_ptr.*});
        first = false;
    }
    write("\n", .{});
}

fn writeOptionalHealthcheck(healthcheck: ?spec.Healthcheck) void {
    const hc = healthcheck orelse return;
    write("  healthcheck:\n", .{});

    if (hc.Test) |test_cmd| {
        write("    test:     ", .{});
        for (test_cmd, 0..) |arg, i| {
            if (i > 0) write(" ", .{});
            write("{s}", .{arg});
        }
        write("\n", .{});
    }
    if (hc.Interval) |iv| write("    interval: {d}ns\n", .{iv});
    if (hc.Timeout) |to| write("    timeout:  {d}ns\n", .{to});
    if (hc.Retries) |retries| write("    retries:  {d}\n", .{retries});
}

fn writeOptionalLines(header: []const u8, comptime line_fmt: []const u8, lines: ?[]const []const u8) void {
    const values = lines orelse return;
    if (values.len == 0) return;

    write("{s}", .{header});
    for (values) |line| {
        write(line_fmt, .{line});
    }
}

fn writeOptionalLabels(value: ?std.json.Value) void {
    const labels = value orelse return;
    if (labels != .object) return;

    write("  labels:\n", .{});
    var iter = labels.object.iterator();
    while (iter.next()) |entry| {
        const label_value = entry.value_ptr.*;
        if (label_value == .string) {
            write("    {s}: {s}\n", .{ entry.key_ptr.*, label_value.string });
        }
    }
}
