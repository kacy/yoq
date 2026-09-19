const std = @import("std");
const platform = @import("linux_platform");
const linux = std.os.linux;
const AppContext = @import("../../lib/app_context.zig").AppContext;
const volumes = @import("../local_volumes.zig");
const id_paths = @import("id_paths.zig");

/// The runtime child waits with only its image overlay mounted. Reexec keeps
/// allocations and copying out of the child created by clone, which may have
/// inherited allocator or database locks from other threads.
pub fn initialize(io: std.Io, id: []const u8, pid: std.posix.pid_t, rootfs: []const u8) !void {
    if (!try volumes.needsInitialization(id)) return;
    var pid_buf: [20]u8 = undefined;
    const pid_text = try std.fmt.bufPrint(&pid_buf, "{d}", .{pid});
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try std.Io.Dir.cwd().realPathFile(io, rootfs, &root_buf);
    var helper_io = @import("../helper_io.zig").init();
    defer helper_io.deinit();
    var helper = try std.process.spawn(helper_io.io(), .{
        .argv = &.{ "/proc/self/exe", "__init-volumes", id, pid_text, root_buf[0..root_len] },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .inherit,
    });
    defer helper.kill(helper_io.io());
    const result = try helper.wait(helper_io.io());
    if (result != .exited or result.exited != 0) return error.VolumeInitializationFailed;
}

/// Join only the mount namespace. The helper still needs host executables and
/// state paths; it must finish before the runtime child binds volumes or pivots.
pub fn initVolumes(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const id = args.next() orelse return error.InvalidArgument;
    const pid_text = args.next() orelse return error.InvalidArgument;
    const rootfs = args.next() orelse return error.InvalidArgument;
    if (args.next() != null or !id_paths.isValidContainerId(id)) return error.InvalidArgument;
    const pid = std.fmt.parseUnsigned(u31, pid_text, 10) catch return error.InvalidArgument;
    if (pid == 0 or rootfs.len == 0 or rootfs[0] != '/') return error.InvalidArgument;
    var ns_buf: [64]u8 = undefined;
    const ns_path = try std.fmt.bufPrintZ(&ns_buf, "/proc/{d}/ns/mnt", .{pid});
    const fd = try platform.posix.open(ns_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    defer platform.posix.close(fd);
    if (linux.errno(linux.unshare(linux.CLONE.FS)) != .SUCCESS) return error.SetNsFailed;
    if (linux.errno(linux.syscall2(.setns, @intCast(fd), linux.CLONE.NEWNS)) != .SUCCESS) return error.SetNsFailed;
    // All filesystem work stays on this thread after setns.
    const io = std.Io.Threaded.global_single_threaded.io();
    try volumes.initializeContainer(io, ctx.alloc, id, rootfs);
}
