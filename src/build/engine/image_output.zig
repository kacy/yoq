const std = @import("std");
const dockerfile = @import("../dockerfile.zig");
const blob_store = @import("../../image/store.zig");
const state_store = @import("../../state/store.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");

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

    const repo = if (tag) |t| blk: {
        if (std.mem.lastIndexOfScalar(u8, t, ':')) |colon| break :blk t[0..colon];
        break :blk t;
    } else "build";

    const img_tag = if (tag) |t| blk: {
        if (std.mem.lastIndexOfScalar(u8, t, ':')) |colon| break :blk t[colon + 1 ..];
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
        .created_at = @import("compat").timestamp(),
    }) catch |err| {
        log.warn("failed to save built image record: {}", .{err});
    };

    return types.BuildResult{
        .manifest_digest = owned_digest,
        .total_size = state.total_size,
        .layer_count = state.layer_digests.items.len,
        .alloc = alloc,
    };
}

pub fn buildConfigJson(alloc: std.mem.Allocator, state: *const types.BuildState) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    const writer = @import("compat").arrayListWriter(&buf, alloc);

    try writer.writeAll("{");
    try writer.writeAll("\"architecture\":\"amd64\",\"os\":\"linux\"");
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

    if (state.shell) |sh| {
        if (!first) try writer.writeAll(",");
        if (dockerfile.isJsonForm(sh)) {
            try writer.writeAll("\"Shell\":");
            try writer.writeAll(sh);
        } else {
            try writer.writeAll("\"Shell\":[\"");
            try json_helpers.writeJsonEscaped(writer, sh);
            try writer.writeAll("\"]");
        }
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
        try writer.writeAll("\"Healthcheck\":{\"Test\":[\"CMD-SHELL\",\"");
        const cmd_str = if (std.mem.startsWith(u8, hc, "CMD ")) hc[4..] else hc;
        try json_helpers.writeJsonEscaped(writer, cmd_str);
        try writer.writeAll("\"]}");
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
    for (state.diff_ids.items, 0..) |diff_id, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeByte('"');
        try writer.writeAll(diff_id);
        try writer.writeByte('"');
    }
    try writer.writeAll("]}}");

    return try buf.toOwnedSlice(alloc);
}

pub fn buildManifestJson(
    alloc: std.mem.Allocator,
    state: *const types.BuildState,
    config_digest: blob_store.Digest,
    config_size: usize,
) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);
    const writer = @import("compat").arrayListWriter(&buf, alloc);

    try writer.writeAll("{\"schemaVersion\":2");
    try writer.writeAll(",\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\"");

    var digest_buf: [71]u8 = undefined;
    try writer.writeAll(",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\"");
    try writer.writeAll(",\"digest\":\"");
    try writer.writeAll(config_digest.string(&digest_buf));
    try writer.writeAll("\"");
    try @import("compat").format(writer, ",\"size\":{d}", .{config_size});
    try writer.writeAll("}");

    try writer.writeAll(",\"layers\":[");
    for (state.layer_digests.items, 0..) |digest, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\"");
        try writer.writeAll(",\"digest\":\"");
        try writer.writeAll(digest);
        try writer.writeAll("\"");
        try @import("compat").format(writer, ",\"size\":{d}", .{state.layer_sizes.items[i]});
        try writer.writeAll("}");
    }
    try writer.writeAll("]}");

    return try buf.toOwnedSlice(alloc);
}

test "config json format" {
    const alloc = std.testing.allocator;
    var state = types.BuildState.init(alloc);
    defer state.deinit();

    const env = try alloc.dupe(u8, "PATH=/usr/bin");
    try state.env.append(alloc, env);
    state.cmd = try alloc.dupe(u8, "node server.js");
    state.workdir = try alloc.dupe(u8, "/app");

    const json = try buildConfigJson(alloc, &state);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"architecture\":\"amd64\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"WorkingDir\":\"/app\"") != null);
}
