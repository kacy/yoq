const std = @import("std");
const oci = @import("../image/oci.zig");
const image_spec = @import("../image/spec.zig");
pub const max_encoded_bytes = 8192;
pub const sql_buffer_size = max_encoded_bytes * 2 + 4096;

/// Stored in the existing command column so replication and cache copies retain
/// argument boundaries and workload overrides without another schema migration.
pub const Execution = struct {
    version: u8 = 1,
    argv: []const []const u8 = &.{},
    env: []const []const u8 = &.{},
    working_dir: ?[]const u8 = null,
};

pub fn fromWorkload(alloc: std.mem.Allocator, json: []const u8) ![]u8 {
    const Workload = struct {
        command: std.json.Value = .null,
        env: []const []const u8 = &.{},
        working_dir: ?[]const u8 = null,
    };
    const parsed = try std.json.parseFromSlice(Workload, alloc, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(alloc);
    switch (parsed.value.command) {
        .null => {},
        .string => |value| if (value.len > 0) {
            try argv.append(alloc, value);
        },
        .array => |values| for (values.items) |value| {
            if (value != .string) return error.InvalidRequest;
            try argv.append(alloc, value.string);
        },
        else => return error.InvalidRequest,
    }
    const execution = Execution{ .argv = argv.items, .env = parsed.value.env, .working_dir = parsed.value.working_dir };
    try validate(execution);
    const encoded = try std.json.Stringify.valueAlloc(alloc, execution, .{});
    errdefer alloc.free(encoded);
    if (encoded.len > max_encoded_bytes) return error.InvalidRequest;
    return encoded;
}

pub fn decode(alloc: std.mem.Allocator, encoded: []const u8) !std.json.Parsed(Execution) {
    if (encoded.len > max_encoded_bytes) return error.InvalidRequest;
    if (std.mem.startsWith(u8, encoded, "{")) {
        var parsed = try std.json.parseFromSlice(Execution, alloc, encoded, .{});
        errdefer parsed.deinit();
        try validate(parsed.value);
        return parsed;
    }
    // Old entries contain one executable string. Do not guess shell quoting.
    const legacy = Execution{ .argv = if (encoded.len == 0) &.{} else &.{encoded} };
    const json = try std.json.Stringify.valueAlloc(alloc, legacy, .{});
    defer alloc.free(json);
    return std.json.parseFromSlice(Execution, alloc, json, .{ .allocate = .alloc_always });
}

fn validate(execution: Execution) !void {
    if (execution.version != 1 or execution.argv.len > 256 or execution.env.len > 256) return error.InvalidRequest;
    for (execution.argv, 0..) |arg, index| {
        if ((index == 0 and arg.len == 0) or std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidRequest;
    }
    for (execution.env) |env| {
        if (std.mem.indexOfScalar(u8, env, 0) != null or std.mem.indexOfScalar(u8, env, '=') == null) return error.InvalidRequest;
    }
    if (execution.working_dir) |dir| {
        if (dir.len == 0 or dir[0] != '/' or std.mem.indexOfScalar(u8, dir, 0) != null) return error.InvalidRequest;
    }
}

pub const Resolved = struct {
    command: oci.ResolvedCommand,
    env: std.ArrayList([]const u8),
    working_dir: []const u8,

    pub fn deinit(self: *Resolved, alloc: std.mem.Allocator) void {
        self.command.args.deinit(alloc);
        self.env.deinit(alloc);
    }
};

pub fn resolve(alloc: std.mem.Allocator, execution: Execution, image: ?image_spec.ContainerConfig, extra_env: []const []const u8) !Resolved {
    const defaults = image orelse image_spec.ContainerConfig{};
    var command = try oci.resolveCommand(alloc, defaults.Entrypoint orelse &.{}, defaults.Cmd orelse &.{}, execution.argv);
    errdefer command.args.deinit(alloc);
    var env: std.ArrayList([]const u8) = .empty;
    errdefer env.deinit(alloc);
    for ([_][]const []const u8{ defaults.Env orelse &.{}, execution.env, extra_env }) |source| {
        for (source) |entry| {
            const key_end = std.mem.indexOfScalar(u8, entry, '=') orelse return error.InvalidRequest;
            var replaced = false;
            for (env.items) |*existing| {
                const existing_end = std.mem.indexOfScalar(u8, existing.*, '=') orelse continue;
                if (std.mem.eql(u8, entry[0..key_end], existing.*[0..existing_end])) {
                    existing.* = entry;
                    replaced = true;
                    break;
                }
            }
            if (!replaced) try env.append(alloc, entry);
        }
    }
    const image_dir = defaults.WorkingDir orelse "/";
    return .{ .command = command, .env = env, .working_dir = execution.working_dir orelse if (image_dir.len > 0) image_dir else "/" };
}

pub fn resourceLimits(cpu_millicores: i64, memory_mb: i64) !@import("../runtime/cgroups.zig").ResourceLimits {
    if (cpu_millicores <= 0 or memory_mb < 4) return error.InvalidRequest;
    const cpu = try std.math.mul(u64, @intCast(cpu_millicores), 100);
    const memory = try std.math.mul(u64, @intCast(memory_mb), 1024 * 1024);
    return .{ .cpu_max_usec = cpu, .memory_max = memory };
}

test "assignment execution preserves escaped argv and OCI defaults" {
    const alloc = std.testing.allocator;
    const encoded = try fromWorkload(alloc,
        \\{"command":["-c","printf '%s' \"a b\""],"env":["MODE=override"]}
    );
    defer alloc.free(encoded);
    var decoded = try decode(alloc, encoded);
    defer decoded.deinit();
    var resolved = try resolve(alloc, decoded.value, .{ .Entrypoint = &.{"/bin/sh"}, .Cmd = &.{"ignored"}, .Env = &.{ "MODE=image", "KEEP=yes" }, .WorkingDir = "/app" }, &.{"RANK=2"});
    defer resolved.deinit(alloc);
    try std.testing.expectEqualStrings("/bin/sh", resolved.command.command);
    try std.testing.expectEqualStrings("printf '%s' \"a b\"", resolved.command.args.items[1]);
    try std.testing.expectEqualStrings("/app", resolved.working_dir);
    try std.testing.expectEqualStrings("MODE=override", resolved.env.items[0]);
    try std.testing.expectEqualStrings("KEEP=yes", resolved.env.items[1]);
    try std.testing.expectEqualStrings("RANK=2", resolved.env.items[2]);
    const limits = try resourceLimits(1500, 1024);
    try std.testing.expectEqual(@as(?u64, 150000), limits.cpu_max_usec);
    try std.testing.expectEqual(@as(?u64, 1073741824), limits.memory_max);
    try std.testing.expectError(error.InvalidRequest, resourceLimits(-1, 128));
    try std.testing.expectError(error.Overflow, resourceLimits(1, std.math.maxInt(i64)));
}

test "assignment execution runs preserved argv and image environment in a real process" {
    const alloc = std.testing.allocator;
    const encoded = try fromWorkload(alloc,
        \\{"command":["-c","test \"$1\" = \"a b\" && test \"$MODE\" = image", "fixture", "a b"]}
    );
    defer alloc.free(encoded);
    var decoded = try decode(alloc, encoded);
    defer decoded.deinit();
    var resolved = try resolve(alloc, decoded.value, .{ .Entrypoint = &.{"/bin/sh"}, .Env = &.{"MODE=image"} }, &.{});
    defer resolved.deinit(alloc);
    const linux = std.os.linux;
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.ForkFailed;
    if (pid == 0) linux.exit_group(@import("../runtime/container/exec_runtime.zig").execCommand(resolved.command.command, resolved.command.args.items, resolved.env.items));
    const result = try @import("../runtime/process.zig").wait(@intCast(pid), false);
    try std.testing.expectEqual(@import("../runtime/process.zig").ExitStatus{ .exited = 0 }, result.status);
}
