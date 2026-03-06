// test helpers — subprocess execution and temp directory utilities
//
// provides common helpers for integration tests that run the yoq binary
// as a subprocess and inspect its output. also includes temp dir management
// for tests that need isolated state directories.

const std = @import("std");

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
    var child = std.process.Child.init(args, alloc);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

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
    var full_args: std.ArrayListUnmanaged([]const u8) = .empty;
    defer full_args.deinit(alloc);

    try full_args.append(alloc, "zig-out/bin/yoq");
    try full_args.appendSlice(alloc, args);

    return run(alloc, full_args.items);
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
