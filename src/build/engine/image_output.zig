const std = @import("std");
const blob_store = @import("../../image/store.zig");
const state_store = @import("../../state/store.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const log = @import("../../lib/log.zig");
const image_spec = @import("../../image/spec.zig");
const types = @import("types.zig");

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

pub fn produceImage(alloc: std.mem.Allocator, state: *types.BuildState, tag: ?[]const u8) types.BuildError!types.BuildResult {
    const config_json = buildConfigJson(alloc, state) catch return types.BuildError.ImageStoreFailed;
    defer alloc.free(config_json);

    const config_digest = blob_store.putBlob(config_json) catch return types.BuildError.ImageStoreFailed;

    const manifest_json = buildManifestJson(alloc, state, config_digest, config_json.len) catch
        return types.BuildError.ImageStoreFailed;
    defer alloc.free(manifest_json);

    const manifest_digest = blob_store.putBlob(manifest_json) catch
        return types.BuildError.ImageStoreFailed;

    var digest_str_buf: [71]u8 = undefined;
    const manifest_digest_str = manifest_digest.string(&digest_str_buf);
    const owned_digest = alloc.dupe(u8, manifest_digest_str) catch
        return types.BuildError.ImageStoreFailed;

    errdefer alloc.free(owned_digest);

    const ref = image_spec.parseImageRef(tag orelse "build:latest");

    var config_digest_str_buf: [71]u8 = undefined;
    const config_digest_str = config_digest.string(&config_digest_str_buf);

    state_store.saveImage(.{
        .id = owned_digest,
        .registry = ref.host,
        .repository = ref.repository,
        .tag = ref.reference,
        .manifest_digest = owned_digest,
        .config_digest = config_digest_str,
        .total_size = @intCast(state.total_size),
        .created_at = nowRealSeconds(),
    }) catch |err| {
        log.warn("failed to save built image record: {}", .{err});
        return error.ImageStoreFailed;
    };

    return types.BuildResult{
        .manifest_digest = owned_digest,
        .total_size = state.total_size,
        .layer_count = state.layers.items.len,
        .alloc = alloc,
    };
}

pub fn buildConfigJson(alloc: std.mem.Allocator, state: *const types.BuildState) ![]const u8 {
    return writeConfigJson(alloc, state) catch |err| switch (err) {
        error.WriteFailed => error.OutOfMemory,
        else => err,
    };
}

fn writeConfigJson(alloc: std.mem.Allocator, state: *const types.BuildState) ![]const u8 {
    var buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer buf_writer.deinit();

    const writer = &buf_writer.writer;

    try writer.writeAll("{");
    const native = @import("../../image/registry/manifest.zig").nativePlatform();
    try writer.writeAll("\"architecture\":");
    try std.json.Stringify.value(state.architecture orelse native.architecture, .{}, writer);
    try writer.writeAll(",\"os\":");
    try std.json.Stringify.value(state.os orelse native.os, .{}, writer);
    try writer.writeAll(",\"config\":{");

    var first = true;

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

    if (state.cmd) |cmd| {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"Cmd\":");
        try std.json.Stringify.value(cmd, .{}, writer);
        first = false;
    }
    if (state.entrypoint) |ep| {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"Entrypoint\":");
        try std.json.Stringify.value(ep, .{}, writer);
        first = false;
    }
    if (state.labels.count() > 0) {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"Labels\":{");
        var iter = state.labels.iterator();
        var label_first = true;
        while (iter.next()) |entry| {
            if (!label_first) try writer.writeAll(",");
            try std.json.Stringify.value(entry.key_ptr.*, .{}, writer);
            try writer.writeByte(':');
            try std.json.Stringify.value(entry.value_ptr.*, .{}, writer);
            label_first = false;
        }
        try writer.writeByte('}');
        first = false;
    }
    if (state.exposed_ports.items.len > 0) {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"ExposedPorts\":");
        try writeObjectKeys(writer, state.exposed_ports.items);
        first = false;
    }

    if (!std.mem.eql(u8, state.workdir, "/")) {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"WorkingDir\":\"");
        try json_helpers.writeJsonEscaped(writer, state.workdir);
        try writer.writeByte('"');
        first = false;
    }

    if (state.user) |u| {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"User\":\"");
        try json_helpers.writeJsonEscaped(writer, u);
        try writer.writeByte('"');
        first = false;
    }

    if (state.volumes.items.len > 0) {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"Volumes\":");
        try writeObjectKeys(writer, state.volumes.items);
        first = false;
    }

    if (state.shell) |sh| {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"Shell\":");
        try writer.writeAll(sh);
        first = false;
    }

    if (state.stop_signal) |sig| {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"StopSignal\":\"");
        try json_helpers.writeJsonEscaped(writer, sig);
        try writer.writeByte('"');
        first = false;
    }

    if (state.healthcheck) |hc| {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"Healthcheck\":");
        try writer.writeAll(hc);
        first = false;
    }

    if (state.onbuild_triggers.items.len > 0) {
        if (!first) try writer.writeAll(",");
        try writer.writeAll("\"OnBuild\":[");
        for (state.onbuild_triggers.items, 0..) |trigger, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeByte('"');
            try json_helpers.writeJsonEscaped(writer, trigger);
            try writer.writeByte('"');
        }
        try writer.writeAll("]");
    }

    try writer.writeAll("}");
    try writer.writeAll(",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[");
    for (state.layers.items, 0..) |item, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeByte('"');
        try writer.writeAll(item.diff_id);
        try writer.writeByte('"');
    }
    try writer.writeAll("]}}");

    return try buf_writer.toOwnedSlice();
}

fn writeObjectKeys(writer: *std.Io.Writer, keys: []const []const u8) !void {
    try writer.writeByte('{');
    var first = true;
    for (keys, 0..) |key, index| {
        var duplicate = false;
        for (keys[0..index]) |previous| {
            if (std.mem.eql(u8, previous, key)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        if (!first) try writer.writeByte(',');
        try std.json.Stringify.value(key, .{}, writer);
        try writer.writeAll(":{}");
        first = false;
    }
    try writer.writeByte('}');
}

pub fn buildManifestJson(
    alloc: std.mem.Allocator,
    state: *const types.BuildState,
    config_digest: blob_store.Digest,
    config_size: usize,
) ![]const u8 {
    var buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer buf_writer.deinit();

    const writer = &buf_writer.writer;

    try writer.writeAll("{\"schemaVersion\":2");
    try writer.writeAll(",\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\"");

    var digest_buf: [71]u8 = undefined;
    try writer.writeAll(",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\"");
    try writer.writeAll(",\"digest\":\"");
    try writer.writeAll(config_digest.string(&digest_buf));
    try writer.writeAll("\"");
    try writer.print(",\"size\":{d}", .{config_size});
    try writer.writeAll("}");

    try writer.writeAll(",\"layers\":[");
    for (state.layers.items, 0..) |item, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\"");
        try writer.writeAll(",\"digest\":\"");
        try writer.writeAll(item.digest);
        try writer.writeAll("\"");
        try writer.print(",\"size\":{d}", .{item.size});
        try writer.writeAll("}");
    }
    try writer.writeAll("]}");

    return try buf_writer.toOwnedSlice();
}

test "config json format" {
    const alloc = std.testing.allocator;
    var state = types.BuildState.init(alloc);
    defer state.deinit();

    const env = try alloc.dupe(u8, "PATH=/usr/bin");
    try state.env.append(alloc, env);
    try @import("handlers_meta.zig").processCmd(alloc, &state, "node server.js");
    state.workdir = try alloc.dupe(u8, "/app");

    const json = try buildConfigJson(alloc, &state);
    defer alloc.free(json);

    var parsed = try image_spec.parseImageConfig(alloc, json);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(@import("../../image/registry/manifest.zig").nativePlatform().architecture, parsed.value.architecture.?);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"WorkingDir\":\"/app\"") != null);
}

test "build metadata inheritance retains complete process and image configuration" {
    const alloc = std.testing.allocator;
    var base = try image_spec.parseImageConfig(alloc,
        \\{"architecture":"arm64","os":"linux","config":{
        \\ "Cmd":["server","--config","a b",""],"Entrypoint":["/init","--"],
        \\ "Shell":["/bin/bash","-e","-c"],"Labels":{"owner":"base"},
        \\ "ExposedPorts":{"80/tcp":{}},"Volumes":{"/data":{}},"StopSignal":"SIGQUIT",
        \\ "Healthcheck":{"Test":["CMD","probe","--ready"],"Interval":2000000000,"Retries":3}
        \\}}
    );
    defer base.deinit();
    var state = types.BuildState.init(alloc);
    defer state.deinit();
    try @import("config_inherit.zig").inheritConfig(alloc, &state, base.value);
    const meta = @import("handlers_meta.zig");
    try meta.processLabel(alloc, &state, "owner=derived description=\"two words\"");
    try meta.processExpose(alloc, &state, "8080 53/udp 80/tcp");
    const json = try buildConfigJson(alloc, &state);
    defer alloc.free(json);
    var result = try image_spec.parseImageConfig(alloc, json);
    defer result.deinit();
    const config = result.value.config.?;
    try std.testing.expectEqualStrings("arm64", result.value.architecture.?);
    try std.testing.expectEqualDeep(base.value.config.?.Cmd, config.Cmd);
    try std.testing.expectEqualDeep(base.value.config.?.Entrypoint, config.Entrypoint);
    try std.testing.expectEqualDeep(base.value.config.?.Shell, config.Shell);
    try std.testing.expectEqualDeep(base.value.config.?.Healthcheck, config.Healthcheck);
    try std.testing.expectEqualStrings("SIGQUIT", config.StopSignal.?);
    try std.testing.expect(config.Volumes.?.object.contains("/data"));
    try std.testing.expect(config.ExposedPorts.?.object.contains("80/tcp"));
    try std.testing.expect(config.ExposedPorts.?.object.contains("8080/tcp"));
    try std.testing.expect(config.ExposedPorts.?.object.contains("53/udp"));
    try std.testing.expectEqualStrings("derived", config.Labels.?.object.get("owner").?.string);
    try std.testing.expectEqualStrings("two words", config.Labels.?.object.get("description").?.string);
}

test "build commands retain their shell at declaration and preserve empty exec arrays" {
    const alloc = std.testing.allocator;
    var state = types.BuildState.init(alloc);
    defer state.deinit();
    const meta = @import("handlers_meta.zig");
    try meta.processShell(alloc, &state, "[\"/bin/bash\",\"-e\",\"-c\"]");
    try meta.processCmd(alloc, &state, "echo $HOME");
    try meta.processEntrypoint(alloc, &state, "exec server --flag");
    try meta.processShell(alloc, &state, "[\"/bin/sh\",\"-c\"]");
    const json = try buildConfigJson(alloc, &state);
    defer alloc.free(json);
    var result = try image_spec.parseImageConfig(alloc, json);
    defer result.deinit();
    try std.testing.expectEqualDeep(@as([]const []const u8, &.{ "/bin/bash", "-e", "-c", "echo $HOME" }), result.value.config.?.Cmd.?);
    try std.testing.expectEqualDeep(@as([]const []const u8, &.{ "/bin/bash", "-e", "-c", "exec server --flag" }), result.value.config.?.Entrypoint.?);
    try meta.processCmd(alloc, &state, "[]");
    try std.testing.expectEqual(@as(usize, 0), state.cmd.?.len);
    try std.testing.expectError(error.MetadataFailed, meta.processCmd(alloc, &state, "[1]"));
}

test "build healthchecks serialize exec shell disabled and timing forms" {
    const alloc = std.testing.allocator;
    var state = types.BuildState.init(alloc);
    defer state.deinit();
    const meta = @import("handlers_meta.zig");
    try meta.processHealthcheck(alloc, &state, "--interval=1m30s --timeout=0.5s --retries=4 CMD [\"probe\",\"--ready\"]");
    var parsed = try image_spec.parseJson(image_spec.Healthcheck, alloc, state.healthcheck.?);
    defer parsed.deinit();
    try std.testing.expectEqualDeep(@as([]const []const u8, &.{ "CMD", "probe", "--ready" }), parsed.value.Test.?);
    try std.testing.expectEqual(@as(i64, 90_000_000_000), parsed.value.Interval.?);
    try std.testing.expectEqual(@as(i64, 500_000_000), parsed.value.Timeout.?);
    try std.testing.expectEqual(@as(i64, 4), parsed.value.Retries.?);
    try meta.processHealthcheck(alloc, &state, "CMD curl -f localhost || exit 1");
    var shell = try image_spec.parseJson(image_spec.Healthcheck, alloc, state.healthcheck.?);
    defer shell.deinit();
    try std.testing.expectEqualStrings("CMD-SHELL", shell.value.Test.?[0]);
    try meta.processHealthcheck(alloc, &state, "NONE");
    var disabled = try image_spec.parseJson(image_spec.Healthcheck, alloc, state.healthcheck.?);
    defer disabled.deinit();
    try std.testing.expectEqualStrings("NONE", disabled.value.Test.?[0]);
    try std.testing.expectError(error.MetadataFailed, meta.processHealthcheck(alloc, &state, "--retries=0 CMD true"));
    try std.testing.expectError(error.MetadataFailed, meta.processHealthcheck(alloc, &state, "--timeout=99999999999999999999h CMD true"));
}

test "build metadata ownership survives allocation failures" {
    const Fixture = struct {
        fn run(alloc: std.mem.Allocator) !void {
            var base = try image_spec.parseImageConfig(alloc,
                \\{"architecture":"amd64","config":{"Cmd":["server","--ready"],"Entrypoint":["/init","--"],
                \\ "Shell":["/bin/sh","-c"],"Labels":{"owner":"base"},"Volumes":{"/data":{}},
                \\ "ExposedPorts":{"80/tcp":{}},"Healthcheck":{"Test":["CMD","true"]},"StopSignal":"SIGTERM"}}
            );
            defer base.deinit();
            var state = types.BuildState.init(alloc);
            defer state.deinit();
            try @import("config_inherit.zig").inheritConfig(alloc, &state, base.value);
            const meta = @import("handlers_meta.zig");
            try meta.processLabel(alloc, &state, "owner=derived another=value");
            try meta.processCmd(alloc, &state, "echo ready");
            try meta.processHealthcheck(alloc, &state, "--interval=2s CMD [\"true\"]");
            const json = try buildConfigJson(alloc, &state);
            defer alloc.free(json);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Fixture.run, .{});
}
