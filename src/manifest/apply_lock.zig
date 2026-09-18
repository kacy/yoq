const std = @import("std");
const linux = std.os.linux;
const paths = @import("../lib/paths.zig");

pub const ApplyLockError = error{
    AlreadyLocked,
    CreateFailed,
    ReleaseFailed,
};

pub const ApplyLock = struct {
    file: std.Io.File,
    held: bool = true,

    pub fn release(self: *ApplyLock) void {
        if (!self.held) return;
        // keep the inode: unlinking it lets a contender lock a different file.
        self.file.close(std.Options.debug_io);
        self.held = false;
    }
};

pub fn acquire(alloc: std.mem.Allocator, app_name: []const u8) ApplyLockError!ApplyLock {
    _ = alloc;
    paths.ensureDataDirStrict("apply-locks") catch return ApplyLockError.CreateFailed;
    var path_buf: [paths.max_path]u8 = undefined;
    const lock_path = lockPath(&path_buf, app_name) catch return ApplyLockError.CreateFailed;
    const file = std.Io.Dir.cwd().createFile(std.Options.debug_io, lock_path, .{
        .read = true,
        .truncate = false,
        .lock = .exclusive,
        .lock_nonblocking = true,
        .permissions = @enumFromInt(0o600),
    }) catch |err| return if (err == error.WouldBlock) error.AlreadyLocked else error.CreateFailed;
    errdefer file.close(std.Options.debug_io);

    // respect a complete pid file left by a still-running older binary. new
    // owners use the kernel lease; empty and malformed abandoned files recover.
    var content: [64]u8 = undefined;
    const count = file.readPositional(std.Options.debug_io, &.{&content}, 0) catch return error.CreateFailed;
    const text = std.mem.trim(u8, content[0..count], " \t\r\n");
    if (count > 0 and content[count - 1] == '\n') {
        if (std.fmt.parseInt(i32, text, 10)) |pid| {
            if (pidAlive(pid)) return error.AlreadyLocked;
        } else |_| {}
    }
    file.setLength(std.Options.debug_io, 0) catch return error.CreateFailed;
    file.writePositionalAll(std.Options.debug_io, "lease\n", 0) catch return error.CreateFailed;
    return .{ .file = file };
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

test "apply lock recovers stale pid file" {
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

test "owner lease recovers abandoned files and preserves a replacement owner" {
    const io = std.testing.io;
    try paths.ensureDataDirStrict("apply-locks");
    var path_buf: [paths.max_path]u8 = undefined;
    const path = try lockPath(&path_buf, "abandoned-owner");
    for ([_][]const u8{ "", "123", "unfinished\n" }) |text| {
        const file = try std.Io.Dir.cwd().createFile(io, path, .{});
        try file.writePositionalAll(io, text, 0);
        file.close(io);
        var first = try acquire(std.testing.allocator, "abandoned-owner");
        first.release();
        var second = try acquire(std.testing.allocator, "abandoned-owner");
        defer second.release();
        first.release();
        try std.testing.expectError(error.AlreadyLocked, acquire(std.testing.allocator, "abandoned-owner"));
    }
}

test "owner lease respects a live legacy pid owner" {
    try paths.ensureDataDirStrict("apply-locks");
    var path_buf: [paths.max_path]u8 = undefined;
    const path = try lockPath(&path_buf, "legacy-owner");
    const file = try std.Io.Dir.cwd().createFile(std.testing.io, path, .{});
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};
    var buffer: [32]u8 = undefined;
    const body = try std.fmt.bufPrint(&buffer, "{d}\n", .{linux.getpid()});
    try file.writePositionalAll(std.testing.io, body, 0);
    file.close(std.testing.io);
    try std.testing.expectError(error.AlreadyLocked, acquire(std.testing.allocator, "legacy-owner"));
}

test "owner lease admits only one concurrent claimant" {
    const Worker = struct {
        inside: std.atomic.Value(u32) = .init(0),
        failed: std.atomic.Value(bool) = .init(false),
        acquired: std.atomic.Value(u32) = .init(0),
        fn run(self: *@This()) void {
            for (0..32) |_| {
                var lock = acquire(std.heap.page_allocator, "contended-owner") catch |err| {
                    if (err != error.AlreadyLocked) self.failed.store(true, .release);
                    continue;
                };
                if (self.inside.fetchAdd(1, .acq_rel) != 0) self.failed.store(true, .release);
                _ = self.acquired.fetchAdd(1, .monotonic);
                std.Io.sleep(std.Options.debug_io, .fromMilliseconds(1), .awake) catch {};
                _ = self.inside.fetchSub(1, .acq_rel);
                lock.release();
            }
        }
    };
    var worker = Worker{};
    var threads: [8]?std.Thread = @splat(null);
    defer for (threads) |thread| if (thread) |running| running.join();
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    for (&threads) |*thread| {
        thread.*.?.join();
        thread.* = null;
    }
    try std.testing.expect(!worker.failed.load(.acquire));
    try std.testing.expect(worker.acquired.load(.acquire) > 0);
}
