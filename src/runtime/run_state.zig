const std = @import("std");
const linux_platform = @import("linux_platform");
const paths = @import("../lib/paths.zig");
const cgroups = @import("cgroups.zig");
const filesystem = @import("filesystem.zig");
const container = @import("container.zig");
const net_setup = @import("../network/setup.zig");
const log = @import("../lib/log.zig");

fn cwd() std.Io.Dir {
    return std.Io.Dir.cwd();
}

pub const RestartPolicy = enum {
    no,
    always,
    on_failure,
    unless_stopped,

    pub fn label(self: RestartPolicy) []const u8 {
        return switch (self) {
            .no => "no",
            .always => "always",
            .on_failure => "on-failure",
            .unless_stopped => "unless-stopped",
        };
    }

    pub const Parsed = struct { policy: RestartPolicy, max_retries: ?u32 = null };

    pub fn parseWithRetries(value: []const u8) !Parsed {
        if (std.mem.indexOfScalar(u8, value, ':')) |colon| {
            if (!std.mem.eql(u8, value[0..colon], "on-failure")) return error.InvalidRestartPolicy;
            const count = std.fmt.parseUnsigned(u32, value[colon + 1 ..], 10) catch return error.InvalidRestartPolicy;
            if (count == 0) return error.InvalidRestartPolicy;
            return .{ .policy = .on_failure, .max_retries = count };
        }
        return .{ .policy = parse(value) orelse return error.InvalidRestartPolicy };
    }

    pub fn parse(value: []const u8) ?RestartPolicy {
        if (std.mem.eql(u8, value, "no")) return .no;
        if (std.mem.eql(u8, value, "always")) return .always;
        if (std.mem.eql(u8, value, "on-failure")) return .on_failure;
        if (std.mem.eql(u8, value, "unless-stopped")) return .unless_stopped;
        return null;
    }
};

pub const SavedRunConfig = struct {
    rootfs: []const u8,
    command: []const u8,
    hostname: []const u8,
    working_dir: []const u8,
    user: ?[]const u8 = null,
    image_reference: ?[]const u8 = null,
    healthcheck_json: ?[]const u8 = null,
    network_name: ?[]const u8 = null,
    network_aliases: []const []const u8 = &.{},
    stop_signal: u8 = 15,
    stop_timeout_seconds: u32 = 10,
    auto_remove: bool = false,
    interactive: bool = false,
    tty: bool = false,
    args: [][]const u8,
    env: [][]const u8,
    lower_dirs: [][]const u8,
    mounts: []container.BindMount,
    shm_size: u64 = filesystem.default_shm_size,
    tmpfs_mounts: []const filesystem.TmpfsMount = &.{},
    network_enabled: bool,
    port_maps: []net_setup.PortMap,
    limits: cgroups.ResourceLimits,
    restart_policy: RestartPolicy,
    restart_max_retries: ?u32 = null,

    pub fn deinit(self: SavedRunConfig, alloc: std.mem.Allocator) void {
        alloc.free(self.rootfs);
        alloc.free(self.command);
        alloc.free(self.hostname);
        alloc.free(self.working_dir);
        if (self.user) |user| alloc.free(user);
        if (self.image_reference) |value| alloc.free(value);
        if (self.healthcheck_json) |value| alloc.free(value);
        if (self.network_name) |value| alloc.free(value);
        freeStringList(alloc, self.network_aliases);
        freeStringList(alloc, self.args);
        freeStringList(alloc, self.env);
        freeStringList(alloc, self.lower_dirs);
        for (self.mounts) |mount| {
            alloc.free(mount.source);
            alloc.free(mount.target);
        }
        alloc.free(self.mounts);
        freeTmpfsMounts(alloc, self.tmpfs_mounts);
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
const format_version: u32 = 7;
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

    if (cfg.limits.cpuset_cpus) |*cpus| {
        if (cpus.len > cpus.buffer.len) return RunStateError.InvalidFormat;
        _ = cgroups.CpuSet.parse(cpus.text()) catch return RunStateError.InvalidFormat;
    }
    if (cfg.restart_max_retries) |count| if (count == 0 or cfg.restart_policy != .on_failure) return RunStateError.InvalidFormat;
    if (cfg.shm_size == 0 or cfg.shm_size > std.math.maxInt(i64)) return RunStateError.InvalidFormat;
    paths.ensureDataDirStrict(configs_subdir) catch return RunStateError.CreateFailed;

    var path_buf: [paths.max_path]u8 = undefined;
    const path = try configPath(&path_buf, id);
    var tmp_buf: [paths.max_path]u8 = undefined;
    const tmp_path = paths.uniqueDataTempPath(&tmp_buf, configs_subdir, id, ".bin.tmp") catch
        return RunStateError.CreateFailed;

    var file = cwd().createFile(std.Options.debug_io, tmp_path, .{ .truncate = true }) catch return RunStateError.CreateFailed;
    errdefer cwd().deleteFile(std.Options.debug_io, tmp_path) catch {};
    defer file.close(std.Options.debug_io);

    var buf: [4096]u8 = undefined;
    var writer = file.writer(std.Options.debug_io, &buf);
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
    writeString(out, cfg.user orelse "") catch return RunStateError.WriteFailed;
    writeString(out, cfg.image_reference orelse "") catch return RunStateError.WriteFailed;
    out.writeByte(cfg.stop_signal) catch return RunStateError.WriteFailed;
    writeInt(out, u32, cfg.stop_timeout_seconds) catch return RunStateError.WriteFailed;
    out.writeByte(@intFromBool(cfg.auto_remove)) catch return RunStateError.WriteFailed;
    out.writeByte(@intFromBool(cfg.interactive)) catch return RunStateError.WriteFailed;
    out.writeByte(@intFromBool(cfg.tty)) catch return RunStateError.WriteFailed;
    writeString(out, cfg.healthcheck_json orelse "") catch return RunStateError.WriteFailed;
    writeString(out, cfg.network_name orelse "") catch return RunStateError.WriteFailed;
    writeStringList(out, cfg.network_aliases) catch return RunStateError.WriteFailed;
    writeString(out, if (cfg.limits.cpuset_cpus) |*cpus| cpus.text() else "") catch return RunStateError.WriteFailed;
    writeInt(out, u64, cfg.shm_size) catch return RunStateError.WriteFailed;
    writeTmpfsMounts(out, cfg.tmpfs_mounts) catch return RunStateError.WriteFailed;
    writeOptionalInt(out, u32, cfg.restart_max_retries) catch return RunStateError.WriteFailed;
    out.flush() catch return RunStateError.WriteFailed;
    file.sync(std.Options.debug_io) catch return RunStateError.WriteFailed;
    cwd().rename(tmp_path, cwd(), path, std.Options.debug_io) catch return RunStateError.WriteFailed;
}

pub fn loadConfig(alloc: std.mem.Allocator, id: []const u8) RunStateError!SavedRunConfig {
    // validate container ID to prevent path traversal
    if (!container.isValidContainerId(id)) return RunStateError.InvalidId;

    var path_buf: [paths.max_path]u8 = undefined;
    const path = try configPath(&path_buf, id);

    var file = cwd().openFile(std.Options.debug_io, path, .{}) catch |err| return switch (err) {
        error.FileNotFound => RunStateError.NotFound,
        else => RunStateError.ReadFailed,
    };
    defer file.close(std.Options.debug_io);

    var buf: [4096]u8 = undefined;
    var reader = file.reader(std.Options.debug_io, &buf);
    const input = &reader.interface;

    const version = readInt(input, u32) catch return RunStateError.ReadFailed;
    if (version < 1 or version > format_version) return RunStateError.InvalidFormat;

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
    const port_maps = readPortMaps(alloc, input, version) catch |err| return mapReadError(err);
    errdefer alloc.free(port_maps);
    var limits = readLimits(input) catch |err| return mapReadError(err);
    const restart_raw = readByte(input) catch return RunStateError.ReadFailed;
    const restart_policy = std.enums.fromInt(RestartPolicy, restart_raw) orelse
        return RunStateError.InvalidFormat;

    const user_text = if (version >= 2) readString(alloc, input) catch |err| return mapReadError(err) else null;
    const user = if (user_text) |text| if (text.len > 0) text else blk: {
        alloc.free(text);
        break :blk null;
    } else null;

    errdefer if (user) |value| alloc.free(value);
    const image_text = if (version >= 3) readString(alloc, input) catch |err| return mapReadError(err) else null;
    const image_reference = if (image_text) |value| if (value.len > 0) value else blk: {
        alloc.free(value);
        break :blk null;
    } else null;
    errdefer if (image_reference) |value| alloc.free(value);
    const stop_signal = if (version >= 3) readByte(input) catch return RunStateError.ReadFailed else 15;
    const stop_timeout_seconds = if (version >= 3) readInt(input, u32) catch return RunStateError.ReadFailed else 5;
    const auto_remove = if (version >= 3) (readByte(input) catch return RunStateError.ReadFailed) != 0 else false;
    const interactive = if (version >= 4) (readByte(input) catch return RunStateError.ReadFailed) != 0 else false;
    const tty = if (version >= 4) (readByte(input) catch return RunStateError.ReadFailed) != 0 else false;
    const health_text = if (version >= 5) readString(alloc, input) catch |err| return mapReadError(err) else null;
    const healthcheck_json = if (health_text) |value| if (value.len > 0) value else blk: {
        alloc.free(value);
        break :blk null;
    } else null;
    errdefer if (healthcheck_json) |value| alloc.free(value);
    const network_text = if (version >= 6) readString(alloc, input) catch |err| return mapReadError(err) else null;
    const network_name = if (network_text) |value| if (value.len > 0) value else blk: {
        alloc.free(value);
        break :blk null;
    } else null;
    errdefer if (network_name) |value| alloc.free(value);
    const network_aliases: []const []const u8 = if (version >= 6) readStringList(alloc, input) catch |err| return mapReadError(err) else &.{};
    errdefer freeStringList(alloc, network_aliases);
    if (version >= 7) {
        const cpuset_text = readString(alloc, input) catch |err| return mapReadError(err);
        defer alloc.free(cpuset_text);
        if (cpuset_text.len > 0) limits.cpuset_cpus = cgroups.CpuSet.parse(cpuset_text) catch return RunStateError.InvalidFormat;
    }
    const shm_size = if (version >= 7) readInt(input, u64) catch return RunStateError.ReadFailed else filesystem.default_shm_size;
    if (shm_size == 0 or shm_size > std.math.maxInt(i64)) return RunStateError.InvalidFormat;
    const tmpfs_mounts: []const filesystem.TmpfsMount = if (version >= 7) readTmpfsMounts(alloc, input) catch |err| return mapReadError(err) else &.{};
    errdefer freeTmpfsMounts(alloc, tmpfs_mounts);
    const restart_max_retries = if (version >= 7) readOptionalInt(input, u32) catch |err| return mapReadError(err) else null;
    if (restart_max_retries) |count| if (count == 0 or restart_policy != .on_failure) return RunStateError.InvalidFormat;
    if (stop_signal == 0 or stop_signal > 64) return RunStateError.InvalidFormat;

    return .{
        .user = user,
        .image_reference = image_reference,
        .healthcheck_json = healthcheck_json,
        .network_name = network_name,
        .network_aliases = network_aliases,
        .stop_signal = stop_signal,
        .stop_timeout_seconds = stop_timeout_seconds,
        .auto_remove = auto_remove,
        .interactive = interactive,
        .tty = tty,
        .rootfs = rootfs,
        .command = command,
        .hostname = hostname,
        .working_dir = working_dir,
        .args = args,
        .env = env,
        .lower_dirs = lower_dirs,
        .mounts = mounts,
        .shm_size = shm_size,
        .tmpfs_mounts = tmpfs_mounts,
        .network_enabled = network_enabled,
        .port_maps = port_maps,
        .limits = limits,
        .restart_policy = restart_policy,
        .restart_max_retries = restart_max_retries,
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
    cwd().deleteFile(std.Options.debug_io, path) catch {};
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

fn freeTmpfsMounts(alloc: std.mem.Allocator, mounts: []const filesystem.TmpfsMount) void {
    for (mounts) |mount| alloc.free(mount.target);
    alloc.free(mounts);
}

fn writeTmpfsMounts(writer: anytype, mounts: []const filesystem.TmpfsMount) !void {
    if (mounts.len > max_serialized_mounts) return error.InvalidFormat;
    try writeInt(writer, u32, @intCast(mounts.len));
    for (mounts) |mount| {
        try mount.validate();
        try writeString(writer, mount.target);
        try writeInt(writer, u64, mount.size_bytes);
        try writeInt(writer, u16, mount.mode);
        const flags: u8 = @as(u8, @intFromBool(mount.read_only)) | (@as(u8, @intFromBool(mount.noexec)) << 1) | (@as(u8, @intFromBool(mount.nosuid)) << 2) | (@as(u8, @intFromBool(mount.nodev)) << 3);
        try writer.writeByte(flags);
    }
}

fn readTmpfsMounts(alloc: std.mem.Allocator, reader: anytype) ![]filesystem.TmpfsMount {
    const count = try readInt(reader, u32);
    if (count > max_serialized_mounts) return error.InvalidFormat;
    const mounts = try alloc.alloc(filesystem.TmpfsMount, count);
    var loaded: usize = 0;
    errdefer {
        for (mounts[0..loaded]) |mount| alloc.free(mount.target);
        alloc.free(mounts);
    }
    for (mounts) |*mount| {
        mount.* = .{ .target = try readString(alloc, reader) };
        loaded += 1;
        mount.size_bytes = try readInt(reader, u64);
        mount.mode = try readInt(reader, u16);
        const flags = try readByte(reader);
        if (flags & 0xf0 != 0) return error.InvalidFormat;
        mount.read_only = flags & 1 != 0;
        mount.noexec = flags & 2 != 0;
        mount.nosuid = flags & 4 != 0;
        mount.nodev = flags & 8 != 0;
        mount.validate() catch return error.InvalidFormat;
    }
    return mounts;
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
        try writer.writeByte(@intFromBool(pm.host_ip != null));
        if (pm.host_ip) |address| try writer.writeAll(&address);
    }
}

fn readPortMaps(alloc: std.mem.Allocator, reader: anytype, version: u32) ![]net_setup.PortMap {
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
        pm.protocol = std.enums.fromInt(net_setup.Protocol, protocol_raw) orelse
            return error.InvalidFormat;
        if (version >= 5 and (try readByte(reader)) != 0) {
            var address: [4]u8 = undefined;
            try reader.readSliceAll(&address);
            pm.host_ip = address;
        }
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

fn uniqueTestConfigId() [12]u8 {
    var raw: [6]u8 = undefined;
    linux_platform.randomBytes(&raw);
    return std.fmt.bytesToHex(raw, .lower);
}

test "restart policy parse" {
    try std.testing.expectEqual(RestartPolicy.no, RestartPolicy.parse("no").?);
    try std.testing.expectEqual(RestartPolicy.always, RestartPolicy.parse("always").?);
    try std.testing.expectEqual(RestartPolicy.on_failure, RestartPolicy.parse("on-failure").?);
    try std.testing.expect(RestartPolicy.parse("invalid") == null);
}

test "save and load config round-trips" {
    const alloc = std.testing.allocator;
    const config_id = uniqueTestConfigId();

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
        .user = "app:staff",
        .image_reference = "sha256:fixture",
        .stop_signal = 10,
        .stop_timeout_seconds = 3,
        .interactive = true,
        .tty = true,
        .args = args,
        .env = env,
        .lower_dirs = lower_dirs,
        .mounts = mounts,
        .network_enabled = true,
        .port_maps = port_maps,
        .limits = .{ .cpuset_cpus = try cgroups.CpuSet.parse("0-2,4"), .cpu_max_usec = 200_000, .memory_max = 256 * 1024 * 1024 },
        .shm_size = 128 * 1024 * 1024,
        .tmpfs_mounts = &.{.{ .target = "/cache", .size_bytes = 32 * 1024 * 1024, .mode = 0o750, .read_only = true, .noexec = true }},
        .restart_policy = .on_failure,
        .restart_max_retries = 3,
    };

    removeConfig(&config_id);
    try saveConfig(&config_id, cfg);
    defer removeConfig(&config_id);

    const loaded = try loadConfig(alloc, &config_id);
    defer loaded.deinit(alloc);

    try std.testing.expectEqualStrings("/tmp/rootfs", loaded.rootfs);
    try std.testing.expectEqualStrings("0-2,4", loaded.limits.cpuset_cpus.?.text());
    try std.testing.expectEqual(cfg.shm_size, loaded.shm_size);
    try std.testing.expectEqual(@as(usize, 1), loaded.tmpfs_mounts.len);
    try std.testing.expectEqualStrings("/cache", loaded.tmpfs_mounts[0].target);
    try std.testing.expectEqual(@as(u64, 32 * 1024 * 1024), loaded.tmpfs_mounts[0].size_bytes);
    try std.testing.expectEqual(@as(u16, 0o750), loaded.tmpfs_mounts[0].mode);
    try std.testing.expect(loaded.tmpfs_mounts[0].read_only and loaded.tmpfs_mounts[0].noexec);
    try std.testing.expectEqualStrings("/bin/sh", loaded.command);
    try std.testing.expectEqualStrings("test", loaded.hostname);
    try std.testing.expectEqualStrings("/work", loaded.working_dir);
    try std.testing.expectEqualStrings("app:staff", loaded.user.?);
    try std.testing.expectEqualStrings("sha256:fixture", loaded.image_reference.?);
    try std.testing.expectEqual(@as(u8, 10), loaded.stop_signal);
    try std.testing.expectEqual(@as(u32, 3), loaded.stop_timeout_seconds);
    try std.testing.expect(loaded.interactive and loaded.tty);
    try std.testing.expectEqual(@as(usize, 2), loaded.args.len);
    try std.testing.expectEqualStrings("sleep", loaded.args[0]);
    try std.testing.expectEqualStrings("FOO=bar", loaded.env[0]);
    try std.testing.expectEqual(@as(usize, 1), loaded.mounts.len);
    try std.testing.expect(loaded.mounts[0].read_only);
    try std.testing.expectEqual(@as(usize, 1), loaded.port_maps.len);
    try std.testing.expectEqual(@as(?u64, 256 * 1024 * 1024), loaded.limits.memory_max);
    try std.testing.expectEqual(RestartPolicy.on_failure, loaded.restart_policy);
    try std.testing.expectEqual(@as(?u32, 3), loaded.restart_max_retries);
}

test "saveConfig validates container ID" {
    const alloc = std.testing.allocator;
    const valid_id = uniqueTestConfigId();

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
    removeConfig(&valid_id);
    saveConfig(&valid_id, cfg) catch |e| {
        try std.testing.expect(e != RunStateError.InvalidId);
    };
    defer removeConfig(&valid_id);

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
    const config_id = uniqueTestConfigId();
    if (!container.isValidContainerId(&config_id)) return error.SkipZigTest;

    paths.ensureDataDirStrict(configs_subdir) catch return error.SkipZigTest;

    var path_buf: [paths.max_path]u8 = undefined;
    const path = try configPath(&path_buf, &config_id);

    removeConfig(&config_id);

    var file = try cwd().createFile(std.testing.io, path, .{ .truncate = true });
    defer file.close(std.testing.io);
    defer removeConfig(&config_id);

    var buf: [16]u8 = undefined;
    var writer = file.writer(std.testing.io, &buf);
    const out = &writer.interface;
    try writeInt(out, u32, format_version);
    try writeInt(out, u32, max_serialized_string_bytes + 1);
    try out.flush();

    try std.testing.expectError(RunStateError.InvalidFormat, loadConfig(std.testing.allocator, &config_id));
}

test "legacy run config version 1 retains effective defaults" {
    const id = uniqueTestConfigId();
    try paths.ensureDataDirStrict(configs_subdir);
    var path_buf: [paths.max_path]u8 = undefined;
    const path = try configPath(&path_buf, &id);
    var bytes: [68]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, "01000000070000002f726f6f74667302000000736803000000626f78010000002f0000000000000000000000000000000000000000000000a08601000000000000000001");
    {
        const file = try cwd().createFile(std.testing.io, path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, &bytes);
    }
    defer removeConfig(&id);
    const cfg = try loadConfig(std.testing.allocator, &id);
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("/rootfs", cfg.rootfs);
    try std.testing.expectEqual(RestartPolicy.always, cfg.restart_policy);
    try std.testing.expectEqual(@as(u32, 5), cfg.stop_timeout_seconds);
    try std.testing.expect(!cfg.interactive and !cfg.tty and !cfg.auto_remove);
    try std.testing.expect(cfg.user == null);
    try std.testing.expect(cfg.limits.cpuset_cpus == null);
    try std.testing.expectEqual(filesystem.default_shm_size, cfg.shm_size);
    try std.testing.expectEqual(@as(usize, 0), cfg.tmpfs_mounts.len);
}

test "legacy run config version 2 retains effective defaults" {
    const id = uniqueTestConfigId();
    try paths.ensureDataDirStrict(configs_subdir);
    var path_buf: [paths.max_path]u8 = undefined;
    const path = try configPath(&path_buf, &id);
    var bytes: [75]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, "02000000070000002f726f6f74667302000000736803000000626f78010000002f0000000000000000000000000000000000000000000000a0860100000000000000000103000000617070");
    {
        const file = try cwd().createFile(std.testing.io, path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, &bytes);
    }
    defer removeConfig(&id);
    const cfg = try loadConfig(std.testing.allocator, &id);
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("/rootfs", cfg.rootfs);
    try std.testing.expectEqual(RestartPolicy.always, cfg.restart_policy);
    try std.testing.expectEqual(@as(u32, 5), cfg.stop_timeout_seconds);
    try std.testing.expect(!cfg.interactive and !cfg.tty and !cfg.auto_remove);
    try std.testing.expectEqualStrings("app", cfg.user.?);
}

test "restart retry limits apply only to on-failure and require positive count" {
    const policy = try RestartPolicy.parseWithRetries("on-failure:3");
    try std.testing.expectEqual(RestartPolicy.on_failure, policy.policy);
    try std.testing.expectEqual(@as(?u32, 3), policy.max_retries);
    try std.testing.expect((try RestartPolicy.parseWithRetries("always")).max_retries == null);
    for ([_][]const u8{ "always:3", "no:2", "on-failure:0", "on-failure:-1", "on-failure:", "on-failure:3:2", "on-failure:4294967296" }) |value|
        try std.testing.expectError(error.InvalidRestartPolicy, RestartPolicy.parseWithRetries(value));
}
