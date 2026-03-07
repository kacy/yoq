// test helpers — subprocess execution and temp directory utilities
//
// provides common helpers for integration tests that run the yoq binary
// as a subprocess and inspect its output. also includes temp dir management
// for tests that need isolated state directories.

const std = @import("std");

pub const RunOptions = struct {
    env_map: ?*const std.process.EnvMap = null,
    cwd: ?[]const u8 = null,
};

/// result of running a subprocess
pub const RunResult = struct {
    stdout: []const u8,
    stderr: []const u8,
    exit_code: u8,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *RunResult) void {
        self.alloc.free(self.stdout);
        self.alloc.free(self.stderr);
    }
};

/// run a command and capture stdout, stderr, and exit code.
pub fn run(alloc: std.mem.Allocator, args: []const []const u8) !RunResult {
    return runWithOptions(alloc, args, .{});
}

/// run a command with a custom environment or cwd.
pub fn runWithOptions(alloc: std.mem.Allocator, args: []const []const u8, options: RunOptions) !RunResult {
    var child = std.process.Child.init(args, alloc);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.env_map = options.env_map;
    child.cwd = options.cwd;

    try child.spawn();

    var stdout_buf: std.ArrayListUnmanaged(u8) = .empty;
    var stderr_buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer stdout_buf.deinit(alloc);
    errdefer stderr_buf.deinit(alloc);

    child.collectOutput(alloc, &stdout_buf, &stderr_buf, 1024 * 1024) catch |err| {
        if (err != error.BrokenPipe) return err;
    };

    const term = try child.wait();

    const exit_code: u8 = switch (term) {
        .Exited => |code| code,
        .Signal => 128,
        else => 255,
    };

    return .{
        .stdout = try stdout_buf.toOwnedSlice(alloc),
        .stderr = try stderr_buf.toOwnedSlice(alloc),
        .exit_code = exit_code,
        .alloc = alloc,
    };
}

/// run the yoq binary with the given arguments.
/// assumes the binary is at zig-out/bin/yoq.
pub fn runYoq(alloc: std.mem.Allocator, args: []const []const u8) !RunResult {
    return runYoqWithOptions(alloc, args, .{});
}

pub fn runYoqWithOptions(alloc: std.mem.Allocator, args: []const []const u8, options: RunOptions) !RunResult {
    var full_args: std.ArrayListUnmanaged([]const u8) = .empty;
    defer full_args.deinit(alloc);

    try full_args.append(alloc, "zig-out/bin/yoq");
    try full_args.appendSlice(alloc, args);

    return runWithOptions(alloc, full_args.items, options);
}

/// create a temporary directory for test isolation.
pub fn tmpDir() !TmpDir {
    // generate a pseudo-random name using the clock
    var name_buf: [32]u8 = undefined;
    const ts: u64 = @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())));
    const name = std.fmt.bufPrint(&name_buf, "yoq-test-{x}", .{ts}) catch unreachable;

    var path_buf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/tmp/{s}", .{name}) catch unreachable;

    std.fs.cwd().makeDir(path) catch |err| {
        if (err == error.PathAlreadyExists) {
            // extremely unlikely with nanosecond timestamp, but handle it
            return error.TmpDirFailed;
        }
        return error.TmpDirFailed;
    };

    var result: TmpDir = undefined;
    const len = path.len;
    @memcpy(result.path[0..len], path);
    result.len = len;
    return result;
}

pub const TmpDir = struct {
    path: [128]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const TmpDir) []const u8 {
        return self.path[0..self.len];
    }

    /// remove the temp directory and all its contents.
    pub fn cleanup(self: *const TmpDir) void {
        std.fs.cwd().deleteTree(self.slice()) catch {};
    }
};

pub const TestEnv = struct {
    alloc: std.mem.Allocator,
    tmp: TmpDir,
    cwd: []const u8,
    home: []const u8,
    xdg_data_home: []const u8,
    env_map: std.process.EnvMap,

    pub fn init(alloc: std.mem.Allocator) !TestEnv {
        var tmp = try tmpDir();
        errdefer tmp.cleanup();

        const cwd = try std.fs.cwd().realpathAlloc(alloc, ".");
        errdefer alloc.free(cwd);

        const home = try std.fmt.allocPrint(alloc, "{s}/home", .{tmp.slice()});
        errdefer alloc.free(home);
        try std.fs.cwd().makePath(home);

        const xdg_data_home = try std.fmt.allocPrint(alloc, "{s}/xdg-data", .{tmp.slice()});
        errdefer alloc.free(xdg_data_home);
        try std.fs.cwd().makePath(xdg_data_home);

        var env_map = try std.process.getEnvMap(alloc);
        errdefer env_map.deinit();
        try env_map.put("HOME", home);
        try env_map.put("XDG_DATA_HOME", xdg_data_home);

        return .{
            .alloc = alloc,
            .tmp = tmp,
            .cwd = cwd,
            .home = home,
            .xdg_data_home = xdg_data_home,
            .env_map = env_map,
        };
    }

    pub fn deinit(self: *TestEnv) void {
        self.env_map.deinit();
        self.alloc.free(self.cwd);
        self.alloc.free(self.home);
        self.alloc.free(self.xdg_data_home);
        self.tmp.cleanup();
    }

    pub fn run(self: *const TestEnv, args: []const []const u8) !RunResult {
        return runWithOptions(self.alloc, args, .{
            .env_map = &self.env_map,
            .cwd = self.cwd,
        });
    }

    pub fn runYoq(self: *const TestEnv, args: []const []const u8) !RunResult {
        return runYoqWithOptions(self.alloc, args, .{
            .env_map = &self.env_map,
            .cwd = self.cwd,
        });
    }
};

pub const RootfsFixture = struct {
    alloc: std.mem.Allocator,
    tmp: TmpDir,
    rootfs_path: []const u8,

    pub fn deinit(self: *RootfsFixture) void {
        self.alloc.free(self.rootfs_path);
        self.tmp.cleanup();
    }
};

pub fn uniqueName(alloc: std.mem.Allocator, prefix: []const u8) ![]const u8 {
    var rand_bytes: [4]u8 = undefined;
    std.crypto.random.bytes(&rand_bytes);
    var rand_hex: [8]u8 = undefined;
    _ = std.fmt.bufPrint(&rand_hex, "{s}", .{std.fmt.bytesToHex(rand_bytes[0..], .lower)}) catch unreachable;

    const ts: u64 = @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())));
    return std.fmt.allocPrint(alloc, "{s}-{x}-{s}", .{
        prefix,
        ts,
        &rand_hex,
    });
}

pub fn createShellRootfs(alloc: std.mem.Allocator) !RootfsFixture {
    var tmp = try tmpDir();
    errdefer tmp.cleanup();

    const rootfs_path = try std.fmt.allocPrint(alloc, "{s}/rootfs", .{tmp.slice()});
    errdefer alloc.free(rootfs_path);

    try std.fs.cwd().makePath(rootfs_path);
    const tmp_path = try std.fmt.allocPrint(alloc, "{s}/tmp", .{rootfs_path});
    defer alloc.free(tmp_path);
    try std.fs.cwd().makePath(tmp_path);

    try copyHostFileIntoRootfs(alloc, rootfs_path, "/bin/sh");
    try copyBinaryDependencies(alloc, rootfs_path, "/bin/sh");

    return .{
        .alloc = alloc,
        .tmp = tmp,
        .rootfs_path = rootfs_path,
    };
}

fn copyBinaryDependencies(alloc: std.mem.Allocator, rootfs_path: []const u8, host_binary: []const u8) !void {
    var result = try run(alloc, &.{ "ldd", host_binary });
    defer result.deinit();

    if (result.exit_code != 0) return error.DependencyScanFailed;

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \r\t");
        if (line.len == 0) continue;

        const dep_path = extractDependencyPath(line) orelse continue;
        try copyHostFileIntoRootfs(alloc, rootfs_path, dep_path);
    }
}

fn extractDependencyPath(line: []const u8) ?[]const u8 {
    if (std.mem.indexOf(u8, line, " => ")) |idx| {
        const rest = line[idx + 4 ..];
        const end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
        if (end == 0) return null;

        const candidate = rest[0..end];
        if (std.mem.startsWith(u8, candidate, "/")) return candidate;
        return null;
    }

    if (!std.mem.startsWith(u8, line, "/")) return null;
    const end = std.mem.indexOfScalar(u8, line, ' ') orelse line.len;
    return line[0..end];
}

fn copyHostFileIntoRootfs(alloc: std.mem.Allocator, rootfs_path: []const u8, source_path: []const u8) !void {
    if (!std.mem.startsWith(u8, source_path, "/")) return error.InvalidSourcePath;

    const relative = source_path[1..];
    const destination = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ rootfs_path, relative });
    defer alloc.free(destination);

    const parent = std.fs.path.dirname(destination) orelse rootfs_path;
    try std.fs.cwd().makePath(parent);
    std.fs.cwd().copyFile(source_path, std.fs.cwd(), destination, .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
}

/// write content to a file inside a directory.
pub fn writeFile(dir_path: []const u8, filename: []const u8, content: []const u8) !void {
    var dir = try std.fs.cwd().openDir(dir_path, .{});
    defer dir.close();

    var file = try dir.createFile(filename, .{});
    defer file.close();
    try file.writeAll(content);
}

/// assert that a string contains a substring.
pub fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("expected to contain: \"{s}\"\n  actual: \"{s}\"\n", .{ needle, haystack });
        return error.TestExpectedContains;
    }
}

/// assert that a string does NOT contain a substring.
pub fn expectNotContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) {
        std.debug.print("expected NOT to contain: \"{s}\"\n  actual: \"{s}\"\n", .{ needle, haystack });
        return error.TestExpectedNotContains;
    }
}

test "tmpDir creates and cleans up" {
    var dir = try tmpDir();
    defer dir.cleanup();

    // directory should exist
    var d = std.fs.cwd().openDir(dir.slice(), .{}) catch {
        return error.TmpDirNotCreated;
    };
    d.close();
}

test "writeFile creates file in directory" {
    var dir = try tmpDir();
    defer dir.cleanup();

    try writeFile(dir.slice(), "test.txt", "hello");

    var d = try std.fs.cwd().openDir(dir.slice(), .{});
    defer d.close();
    const contents = try d.readFileAlloc(std.testing.allocator, "test.txt", 1024);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings("hello", contents);
}

test "uniqueName prefixes generated value" {
    const name = try uniqueName(std.testing.allocator, "yoq-test");
    defer std.testing.allocator.free(name);

    try std.testing.expect(std.mem.startsWith(u8, name, "yoq-test-"));
}
