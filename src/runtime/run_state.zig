const std = @import("std");
const paths = @import("../lib/paths.zig");
const cgroups = @import("cgroups.zig");
const container = @import("container.zig");
const net_setup = @import("../network/setup.zig");
const log = @import("../lib/log.zig");

pub const RestartPolicy = enum {
    no,
    always,
    on_failure,

    pub fn label(self: RestartPolicy) []const u8 {
        return switch (self) {
            .no => "no",
            .always => "always",
            .on_failure => "on-failure",
        };
    }

    pub fn parse(value: []const u8) ?RestartPolicy {
        if (std.mem.eql(u8, value, "no")) return .no;
        if (std.mem.eql(u8, value, "always")) return .always;
        if (std.mem.eql(u8, value, "on-failure")) return .on_failure;
        return null;
    }
};

pub const SavedRunConfig = struct {
    rootfs: []const u8,
    command: []const u8,
    hostname: []const u8,
    working_dir: []const u8,
    args: [][]const u8,
    env: [][]const u8,
    lower_dirs: [][]const u8,
    mounts: []container.BindMount,
    network_enabled: bool,
    port_maps: []net_setup.PortMap,
    limits: cgroups.ResourceLimits,
    restart_policy: RestartPolicy,

    pub fn deinit(self: SavedRunConfig, alloc: std.mem.Allocator) void {
        alloc.free(self.rootfs);
        alloc.free(self.command);
        alloc.free(self.hostname);
        alloc.free(self.working_dir);
        freeStringList(alloc, self.args);
        freeStringList(alloc, self.env);
        freeStringList(alloc, self.lower_dirs);
        for (self.mounts) |mount| {
            alloc.free(mount.source);
            alloc.free(mount.target);
        }
        alloc.free(self.mounts);
        alloc.free(self.port_maps);
    }
};

pub const RunStateError = error{
    CreateFailed,
    ReadFailed,
    WriteFailed,
    NotFound,
    InvalidFormat,
    PathTooLong,
    InvalidId,
};

const configs_subdir = "run_configs";
const format_version: u32 = 1;
const max_serialized_string_bytes: u32 = 64 * 1024;
const max_serialized_list_items: u32 = 1024;
const max_serialized_mounts: u32 = 256;
const max_serialized_port_maps: u32 = 256;

fn configPath(buf: *[paths.max_path]u8, id: []const u8) RunStateError![]const u8 {
    return paths.dataPathFmt(buf, "{s}/{s}.bin", .{ configs_subdir, id }) catch
        return RunStateError.PathTooLong;
}

pub fn saveConfig(id: []const u8, cfg: SavedRunConfig) RunStateError!void {
    // validate container ID to prevent path traversal
    if (!container.isValidContainerId(id)) return RunStateError.InvalidId;

    paths.ensureDataDirStrict(configs_subdir) catch return RunStateError.CreateFailed;

    var path_buf: [paths.max_path]u8 = undefined;
    const path = try configPath(&path_buf, id);
    var tmp_buf: [paths.max_path]u8 = undefined;
    const tmp_path = paths.uniqueDataTempPath(&tmp_buf, configs_subdir, id, ".bin.tmp") catch
        return RunStateError.CreateFailed;

    var file = std.fs.cwd().createFile(tmp_path, .{ .truncate = true }) catch return RunStateError.CreateFailed;
    errdefer std.fs.cwd().deleteFile(tmp_path) catch {};
    defer file.close();

    var buf: [4096]u8 = undefined;
    var writer = file.writer(&buf);
    const out = &writer.interface;

    writeInt(out, u32, format_version) catch return RunStateError.WriteFailed;
    writeString(out, cfg.rootfs) catch return RunStateError.WriteFailed;
    writeString(out, cfg.command) catch return RunStateError.WriteFailed;
    writeString(out, cfg.hostname) catch return RunStateError.WriteFailed;
    writeString(out, cfg.working_dir) catch return RunStateError.WriteFailed;
    writeStringList(out, cfg.args) catch return RunStateError.WriteFailed;
    writeStringList(out, cfg.env) catch return RunStateError.WriteFailed;
    writeStringList(out, cfg.lower_dirs) catch return RunStateError.WriteFailed;
    writeMounts(out, cfg.mounts) catch return RunStateError.WriteFailed;
    out.writeByte(if (cfg.network_enabled) 1 else 0) catch return RunStateError.WriteFailed;
    writePortMaps(out, cfg.port_maps) catch return RunStateError.WriteFailed;
    writeLimits(out, cfg.limits) catch return RunStateError.WriteFailed;
    out.writeByte(@intFromEnum(cfg.restart_policy)) catch return RunStateError.WriteFailed;
    out.flush() catch return RunStateError.WriteFailed;
    file.sync() catch return RunStateError.WriteFailed;
    std.fs.cwd().rename(tmp_path, path) catch return RunStateError.WriteFailed;
}

pub fn loadConfig(alloc: std.mem.Allocator, id: []const u8) RunStateError!SavedRunConfig {
    // validate container ID to prevent path traversal
    if (!container.isValidContainerId(id)) return RunStateError.InvalidId;

    var path_buf: [paths.max_path]u8 = undefined;
    const path = try configPath(&path_buf, id);

    var file = std.fs.cwd().openFile(path, .{}) catch |err| return switch (err) {
        error.FileNotFound => RunStateError.NotFound,
        else => RunStateError.ReadFailed,
    };
    defer file.close();

    var buf: [4096]u8 = undefined;
    var reader = file.reader(&buf);
    const input = &reader.interface;

    const version = readInt(input, u32) catch return RunStateError.ReadFailed;
    if (version != format_version) return RunStateError.InvalidFormat;

    const rootfs = readString(alloc, input) catch |err| return mapReadError(err);
    errdefer alloc.free(rootfs);
    const command = readString(alloc, input) catch |err| return mapReadError(err);
    errdefer alloc.free(command);
    const hostname = readString(alloc, input) catch |err| return mapReadError(err);
    errdefer alloc.free(hostname);
    const working_dir = readString(alloc, input) catch |err| return mapReadError(err);
    errdefer alloc.free(working_dir);
    const args = readStringList(alloc, input) catch |err| return mapReadError(err);
    errdefer freeStringList(alloc, args);
    const env = readStringList(alloc, input) catch |err| return mapReadError(err);
    errdefer freeStringList(alloc, env);
    const lower_dirs = readStringList(alloc, input) catch |err| return mapReadError(err);
    errdefer freeStringList(alloc, lower_dirs);
    const mounts = readMounts(alloc, input) catch |err| return mapReadError(err);
    errdefer {
        for (mounts) |mount| {
            alloc.free(mount.source);
            alloc.free(mount.target);
        }
        alloc.free(mounts);
    }
    const network_enabled = (readByte(input) catch return RunStateError.ReadFailed) != 0;
    const port_maps = readPortMaps(alloc, input) catch |err| return mapReadError(err);
    errdefer alloc.free(port_maps);
    const limits = readLimits(input) catch |err| return mapReadError(err);
    const restart_raw = readByte(input) catch return RunStateError.ReadFailed;
    const restart_policy: RestartPolicy = std.meta.intToEnum(RestartPolicy, restart_raw) catch
        return RunStateError.InvalidFormat;

    return .{
        .rootfs = rootfs,
        .command = command,
        .hostname = hostname,
        .working_dir = working_dir,
        .args = args,
        .env = env,
        .lower_dirs = lower_dirs,
        .mounts = mounts,
        .network_enabled = network_enabled,
        .port_maps = port_maps,
        .limits = limits,
        .restart_policy = restart_policy,
    };
}

fn mapReadError(err: anyerror) RunStateError {
    return switch (err) {
        error.InvalidFormat => RunStateError.InvalidFormat,
        else => RunStateError.ReadFailed,
    };
}

pub fn removeConfig(id: []const u8) void {
    // validate container ID to prevent accidental deletion of wrong files
    if (!container.isValidContainerId(id)) return;

    var path_buf: [paths.max_path]u8 = undefined;
    const path = configPath(&path_buf, id) catch return;
    std.fs.cwd().deleteFile(path) catch {};
}

fn writeString(writer: anytype, value: []const u8) !void {
    try writeInt(writer, u32, @intCast(value.len));
    try writer.writeAll(value);
}

fn readString(alloc: std.mem.Allocator, reader: anytype) ![]const u8 {
    const len = try readInt(reader, u32);
    if (len > max_serialized_string_bytes) return error.InvalidFormat;
    const buf = try alloc.alloc(u8, len);
    errdefer alloc.free(buf);
    try reader.readSliceAll(buf);
    return buf;
}

fn writeStringList(writer: anytype, values: []const []const u8) !void {
    try writeInt(writer, u32, @intCast(values.len));
    for (values) |value| try writeString(writer, value);
}

fn readStringList(alloc: std.mem.Allocator, reader: anytype) ![][]const u8 {
    const count = try readInt(reader, u32);
    if (count > max_serialized_list_items) return error.InvalidFormat;
    const items = try alloc.alloc([]const u8, count);
    errdefer alloc.free(items);

    var idx: usize = 0;
    errdefer {
        for (items[0..idx]) |item| alloc.free(item);
    }

    while (idx < items.len) : (idx += 1) {
        items[idx] = try readString(alloc, reader);
    }
    return items;
}

fn freeStringList(alloc: std.mem.Allocator, values: []const []const u8) void {
    for (values) |value| alloc.free(value);
    alloc.free(values);
}

fn writeMounts(writer: anytype, mounts: []const container.BindMount) !void {
    try writeInt(writer, u32, @intCast(mounts.len));
    for (mounts) |mount| {
        try writeString(writer, mount.source);
        try writeString(writer, mount.target);
        try writer.writeByte(if (mount.read_only) 1 else 0);
    }
}

fn readMounts(alloc: std.mem.Allocator, reader: anytype) ![]container.BindMount {
    const count = try readInt(reader, u32);
    if (count > max_serialized_mounts) return error.InvalidFormat;
    const mounts = try alloc.alloc(container.BindMount, count);
    errdefer alloc.free(mounts);

    var idx: usize = 0;
    errdefer {
        for (mounts[0..idx]) |mount| {
            alloc.free(mount.source);
            alloc.free(mount.target);
        }
    }

    while (idx < mounts.len) : (idx += 1) {
        mounts[idx] = .{
            .source = try readString(alloc, reader),
            .target = try readString(alloc, reader),
            .read_only = (try readByte(reader)) != 0,
        };
    }
    return mounts;
}

fn writePortMaps(writer: anytype, port_maps: []const net_setup.PortMap) !void {
    try writeInt(writer, u32, @intCast(port_maps.len));
    for (port_maps) |pm| {
        try writeInt(writer, u16, pm.host_port);
        try writeInt(writer, u16, pm.container_port);
        try writer.writeByte(@intFromEnum(pm.protocol));
    }
}

fn readPortMaps(alloc: std.mem.Allocator, reader: anytype) ![]net_setup.PortMap {
    const count = try readInt(reader, u32);
    if (count > max_serialized_port_maps) return error.InvalidFormat;
    const port_maps = try alloc.alloc(net_setup.PortMap, count);
    errdefer alloc.free(port_maps);

    for (port_maps) |*pm| {
        pm.* = .{
            .host_port = try readInt(reader, u16),
            .container_port = try readInt(reader, u16),
        };
        const protocol_raw = try readByte(reader);
        pm.protocol = std.meta.intToEnum(net_setup.Protocol, protocol_raw) catch
            return error.InvalidFormat;
    }
    return port_maps;
}

fn writeInt(writer: anytype, comptime T: type, value: T) !void {
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &buf, value, .little);
    try writer.writeAll(&buf);
}

fn readInt(reader: anytype, comptime T: type) !T {
    var buf: [@sizeOf(T)]u8 = undefined;
    try reader.readSliceAll(&buf);
    return std.mem.readInt(T, &buf, .little);
}

fn readByte(reader: anytype) !u8 {
    return try readInt(reader, u8);
}

fn writeOptionalInt(writer: anytype, comptime T: type, value: ?T) !void {
    try writer.writeByte(if (value != null) 1 else 0);
    if (value) |v| try writeInt(writer, T, v);
}

fn readOptionalInt(reader: anytype, comptime T: type) !?T {
    const has_value = (try readByte(reader)) != 0;
    if (!has_value) return null;
    return try readInt(reader, T);
}

fn writeLimits(writer: anytype, limits: cgroups.ResourceLimits) !void {
    try writeOptionalInt(writer, u16, limits.cpu_weight);
    try writeOptionalInt(writer, u64, limits.cpu_max_usec);
    try writeInt(writer, u64, limits.cpu_max_period);
    try writeOptionalInt(writer, u64, limits.memory_max);
    try writeOptionalInt(writer, u64, limits.memory_high);
    try writeOptionalInt(writer, u32, limits.pids_max);
}

fn readLimits(reader: anytype) !cgroups.ResourceLimits {
    return .{
        .cpu_weight = try readOptionalInt(reader, u16),
        .cpu_max_usec = try readOptionalInt(reader, u64),
        .cpu_max_period = try readInt(reader, u64),
        .memory_max = try readOptionalInt(reader, u64),
        .memory_high = try readOptionalInt(reader, u64),
        .pids_max = try readOptionalInt(reader, u32),
    };
}

test "restart policy parse" {
    try std.testing.expectEqual(RestartPolicy.no, RestartPolicy.parse("no").?);
    try std.testing.expectEqual(RestartPolicy.always, RestartPolicy.parse("always").?);
    try std.testing.expectEqual(RestartPolicy.on_failure, RestartPolicy.parse("on-failure").?);
    try std.testing.expect(RestartPolicy.parse("invalid") == null);
}

test "save and load config round-trips" {
    const alloc = std.testing.allocator;
    const config_id = "deadbeefca11";

    const args = try alloc.alloc([]const u8, 2);
    defer alloc.free(args);
    args[0] = try alloc.dupe(u8, "sleep");
    defer alloc.free(args[0]);
    args[1] = try alloc.dupe(u8, "5");
    defer alloc.free(args[1]);

    const env = try alloc.alloc([]const u8, 1);
    defer alloc.free(env);
    env[0] = try alloc.dupe(u8, "FOO=bar");
    defer alloc.free(env[0]);

    const lower_dirs = try alloc.alloc([]const u8, 1);
    defer alloc.free(lower_dirs);
    lower_dirs[0] = try alloc.dupe(u8, "/tmp/lower");
    defer alloc.free(lower_dirs[0]);

    const mounts = try alloc.alloc(container.BindMount, 1);
    defer alloc.free(mounts);
    mounts[0] = .{
        .source = try alloc.dupe(u8, "/tmp/src"),
        .target = try alloc.dupe(u8, "/data"),
        .read_only = true,
    };
    defer {
        alloc.free(mounts[0].source);
        alloc.free(mounts[0].target);
    }

    const port_maps = try alloc.alloc(net_setup.PortMap, 1);
    defer alloc.free(port_maps);
    port_maps[0] = .{ .host_port = 8080, .container_port = 80 };

    const cfg: SavedRunConfig = .{
        .rootfs = "/tmp/rootfs",
        .command = "/bin/sh",
        .hostname = "test",
        .working_dir = "/work",
        .args = args,
        .env = env,
        .lower_dirs = lower_dirs,
        .mounts = mounts,
        .network_enabled = true,
        .port_maps = port_maps,
        .limits = .{ .cpu_max_usec = 200_000, .memory_max = 256 * 1024 * 1024 },
        .restart_policy = .always,
    };

    try saveConfig(config_id, cfg);
    defer removeConfig(config_id);

    const loaded = try loadConfig(alloc, config_id);
    defer loaded.deinit(alloc);

    try std.testing.expectEqualStrings("/tmp/rootfs", loaded.rootfs);
    try std.testing.expectEqualStrings("/bin/sh", loaded.command);
    try std.testing.expectEqualStrings("test", loaded.hostname);
    try std.testing.expectEqualStrings("/work", loaded.working_dir);
    try std.testing.expectEqual(@as(usize, 2), loaded.args.len);
    try std.testing.expectEqualStrings("sleep", loaded.args[0]);
    try std.testing.expectEqualStrings("FOO=bar", loaded.env[0]);
    try std.testing.expectEqual(@as(usize, 1), loaded.mounts.len);
    try std.testing.expect(loaded.mounts[0].read_only);
    try std.testing.expectEqual(@as(usize, 1), loaded.port_maps.len);
    try std.testing.expectEqual(@as(?u64, 256 * 1024 * 1024), loaded.limits.memory_max);
    try std.testing.expectEqual(RestartPolicy.always, loaded.restart_policy);
}

test "saveConfig validates container ID" {
    const alloc = std.testing.allocator;

    const cfg: SavedRunConfig = .{
        .rootfs = "/tmp/rootfs",
        .command = "/bin/sh",
        .hostname = "test",
        .working_dir = "/work",
        .args = try alloc.alloc([]const u8, 0),
        .env = try alloc.alloc([]const u8, 0),
        .lower_dirs = try alloc.alloc([]const u8, 0),
        .mounts = try alloc.alloc(container.BindMount, 0),
        .network_enabled = false,
        .port_maps = try alloc.alloc(net_setup.PortMap, 0),
        .limits = .{},
        .restart_policy = .no,
    };
    defer {
        alloc.free(cfg.args);
        alloc.free(cfg.env);
        alloc.free(cfg.lower_dirs);
        alloc.free(cfg.mounts);
        alloc.free(cfg.port_maps);
    }

    // valid ID should succeed (or fail for other reasons, but not InvalidId)
    saveConfig("abc123def456", cfg) catch |e| {
        try std.testing.expect(e != RunStateError.InvalidId);
    };
    defer removeConfig("abc123def456");

    // invalid IDs should return InvalidId
    try std.testing.expectError(RunStateError.InvalidId, saveConfig("../etc/passwd", cfg));
    try std.testing.expectError(RunStateError.InvalidId, saveConfig("/etc/passwd", cfg));
    try std.testing.expectError(RunStateError.InvalidId, saveConfig("invalid", cfg));
}

test "loadConfig validates container ID" {
    const alloc = std.testing.allocator;

    // invalid IDs should return InvalidId before attempting to open file
    try std.testing.expectError(RunStateError.InvalidId, loadConfig(alloc, "../etc/passwd"));
    try std.testing.expectError(RunStateError.InvalidId, loadConfig(alloc, "/etc/passwd"));
    try std.testing.expectError(RunStateError.InvalidId, loadConfig(alloc, "invalid"));
}

test "removeConfig validates container ID" {
    // should silently return on invalid ID (no crash, no file deletion attempt)
    removeConfig("../etc/passwd");
    removeConfig("/etc/passwd");
    // function should complete without error
    try std.testing.expect(true);
}

test "RestartPolicy parsing" {
    try std.testing.expectEqual(RestartPolicy.no, RestartPolicy.parse("no"));
    try std.testing.expectEqual(RestartPolicy.always, RestartPolicy.parse("always"));
    try std.testing.expectEqual(RestartPolicy.on_failure, RestartPolicy.parse("on-failure"));
    try std.testing.expectEqual(@as(?RestartPolicy, null), RestartPolicy.parse("invalid"));
}

test "RestartPolicy labels" {
    try std.testing.expectEqualStrings("no", RestartPolicy.no.label());
    try std.testing.expectEqualStrings("always", RestartPolicy.always.label());
    try std.testing.expectEqualStrings("on-failure", RestartPolicy.on_failure.label());
}

test "loadConfig rejects oversized serialized string length" {
    const config_id = "deadbeefca12";
    if (!container.isValidContainerId(config_id)) return error.SkipZigTest;

    paths.ensureDataDirStrict(configs_subdir) catch return error.SkipZigTest;

    var path_buf: [paths.max_path]u8 = undefined;
    const path = try configPath(&path_buf, config_id);

    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    defer removeConfig(config_id);

    var buf: [16]u8 = undefined;
    var writer = file.writer(&buf);
    const out = &writer.interface;
    try writeInt(out, u32, format_version);
    try writeInt(out, u32, max_serialized_string_bytes + 1);
    try out.flush();

    try std.testing.expectError(RunStateError.InvalidFormat, loadConfig(std.testing.allocator, config_id));
}
