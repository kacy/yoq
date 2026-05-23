const std = @import("std");
const linux = std.os.linux;
const paths = @import("../lib/paths.zig");

pub const ApplyLockError = error{
    AlreadyLocked,
    CreateFailed,
    ReleaseFailed,
};

pub const ApplyLock = struct {
    path: [paths.max_path]u8,
    path_len: usize,
    file: std.Io.File,
    held: bool = true,

    pub fn release(self: *ApplyLock) void {
        if (!self.held) return;
        self.file.close(std.Options.debug_io);
        std.Io.Dir.cwd().deleteFile(std.Options.debug_io, self.path[0..self.path_len]) catch {};
        self.held = false;
    }
};

pub fn acquire(alloc: std.mem.Allocator, app_name: []const u8) ApplyLockError!ApplyLock {
    _ = alloc;
    paths.ensureDataDirStrict("apply-locks") catch return ApplyLockError.CreateFailed;

    var path_buf: [paths.max_path]u8 = undefined;
    const lock_path = lockPath(&path_buf, app_name) catch return ApplyLockError.CreateFailed;

    return createLock(lock_path) catch |err| switch (err) {
        error.PathAlreadyExists => {
            if (try clearStaleLock(lock_path)) {
                return createLock(lock_path) catch |retry_err| switch (retry_err) {
                    error.PathAlreadyExists => ApplyLockError.AlreadyLocked,
                    else => ApplyLockError.CreateFailed,
                };
            }
            return ApplyLockError.AlreadyLocked;
        },
        else => ApplyLockError.CreateFailed,
    };
}

fn createLock(lock_path: []const u8) !ApplyLock {
    const file = try std.Io.Dir.cwd().createFile(std.Options.debug_io, lock_path, .{
        .read = true,
        .truncate = false,
        .exclusive = true,
        .permissions = @enumFromInt(0o600),
    });
    errdefer file.close(std.Options.debug_io);

    const pid = linux.getpid();
    var body_buf: [64]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{d}\n", .{pid}) catch return error.WriteFailed;
    try file.writePositionalAll(std.Options.debug_io, body, 0);

    var owned_path: [paths.max_path]u8 = undefined;
    @memcpy(owned_path[0..lock_path.len], lock_path);
    return .{
        .path = owned_path,
        .path_len = lock_path.len,
        .file = file,
    };
}

fn clearStaleLock(lock_path: []const u8) ApplyLockError!bool {
    const pid = readLockPid(lock_path) catch return false;
    if (pid > 0 and pidAlive(pid)) return false;
    std.Io.Dir.cwd().deleteFile(std.Options.debug_io, lock_path) catch return false;
    return true;
}

fn readLockPid(lock_path: []const u8) !i32 {
    const content = try std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, lock_path, std.heap.page_allocator, .limited(64));
    defer std.heap.page_allocator.free(content);
    const text = std.mem.trim(u8, content, " \t\r\n");
    return std.fmt.parseInt(i32, text, 10);
}

fn pidAlive(pid: i32) bool {
    if (pid <= 0) return false;
    std.posix.kill(pid, @enumFromInt(0)) catch |err| return err == error.PermissionDenied;
    return true;
}

fn lockPath(buf: *[paths.max_path]u8, app_name: []const u8) paths.PathError![]const u8 {
    const hash = std.hash.Wyhash.hash(0, app_name);
    return paths.dataPathFmt(buf, "apply-locks/app-{x}.lock", .{hash});
}

test "apply lock acquire release and re-acquire" {
    const alloc = std.testing.allocator;
    var first = try acquire(alloc, "demo-app");
    first.release();

    var second = try acquire(alloc, "demo-app");
    second.release();
}

test "apply lock rejects concurrent lock for same app" {
    const alloc = std.testing.allocator;
    var first = try acquire(alloc, "locked-app");
    defer first.release();

    try std.testing.expectError(ApplyLockError.AlreadyLocked, acquire(alloc, "locked-app"));
}

test "apply lock allows different apps" {
    const alloc = std.testing.allocator;
    var first = try acquire(alloc, "app-one");
    defer first.release();

    var second = try acquire(alloc, "app-two");
    second.release();
}

test "apply lock removes stale pid file" {
    var path_buf: [paths.max_path]u8 = undefined;
    const path = try lockPath(&path_buf, "stale-app");
    paths.ensureDataDirStrict("apply-locks") catch return error.SkipZigTest;

    {
        const file = try std.Io.Dir.cwd().createFile(std.Options.debug_io, path, .{
            .read = true,
            .truncate = true,
            .permissions = @enumFromInt(0o600),
        });
        defer file.close(std.Options.debug_io);
        try file.writePositionalAll(std.Options.debug_io, "99999999\n", 0);
    }

    var lock = try acquire(std.testing.allocator, "stale-app");
    lock.release();
}
