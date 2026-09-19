const std = @import("std");
const linux = std.os.linux;
const cli = @import("../../../lib/cli.zig");
const paths = @import("../../../lib/paths.zig");
const AppContext = @import("../../../lib/app_context.zig").AppContext;
const store = @import("../../../state/store.zig");
const control = @import("../../local_control.zig");
const run_state = @import("../../run_state.zig");
const id_paths = @import("../../container/id_paths.zig");
const filesystem = @import("../../filesystem.zig");
const state_support = @import("state_support.zig");
const copy_support = @import("filesystem_copy.zig");
const diff_support = @import("filesystem_diff.zig");

const Operand = struct { container: ?[]const u8 = null, path: []const u8 };

fn operand(value: []const u8) !Operand {
    if (value.len == 0) return error.InvalidArgument;
    if (std.mem.indexOfScalar(u8, value, ':')) |colon| {
        const reference = value[0..colon];
        if (std.mem.indexOfScalar(u8, reference, '/') == null) {
            if (colon == 0 or colon + 1 == value.len) return error.InvalidArgument;
            return .{ .container = reference, .path = value[colon + 1 ..] };
        }
    }
    return .{ .path = value };
}

pub fn cp(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const source = try operand(args.next() orelse return error.InvalidArgument);
    const destination = try operand(args.next() orelse return error.InvalidArgument);
    if (args.next() != null or (source.container == null) == (destination.container == null)) {
        cli.writeErr("usage: yoq cp <host-path> <container:path> or yoq cp <container:path> <host-path>\n", .{});
        return error.InvalidArgument;
    }
    const reference = source.container orelse destination.container.?;
    try invoke(ctx, reference, if (source.container != null) "copy-out" else "copy-in", source.path, destination.path);
}

pub fn diff(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const reference = args.next() orelse return error.InvalidArgument;
    if (args.next() != null) return error.InvalidArgument;
    try invoke(ctx, reference, "diff", "", "");
}

fn invoke(ctx: AppContext, reference: []const u8, operation: []const u8, source: []const u8, destination: []const u8) !void {
    const resolved = try state_support.resolveContainerRef(ctx.alloc, reference);
    defer resolved.deinit(ctx.alloc);
    const command = try control.lock(resolved.id, .command, true);
    defer command.deinit();
    const transition = try control.lock(resolved.id, .transition, true);
    defer transition.deinit();
    const record = try store.load(ctx.alloc, resolved.id);
    defer record.deinit(ctx.alloc);
    const running = state_support.currentOwnedRunningPid(&record);
    if (running == null and (std.mem.eql(u8, record.status, "running") or try control.wantsRunning(record.id))) return error.ContainerStateUnknown;
    // a stopped writable layer must be free of any previous owner's cleanup.
    const owner = if (running == null) try control.lock(record.id, .owner, false) else null;
    defer if (owner) |lock| lock.deinit();
    var pid_buf: [32]u8 = undefined;
    const pid = try std.fmt.bufPrint(&pid_buf, "{d}", .{running orelse 0});
    var child = try std.process.spawn(ctx.io, .{
        .argv = &.{ "/proc/self/exe", "__container-filesystem", record.id, operation, pid, source, destination },
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    defer child.kill(ctx.io);
    const result = try child.wait(ctx.io);
    if (result != .exited or result.exited != 0) return error.FilesystemOperationFailed;
}

/// this helper can allocate after namespace entry without inherited fork locks.
/// the parent holds lifecycle locks until the helper exits; unmounting preserves upper data.
pub fn helper(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const id = args.next() orelse return error.InvalidArgument;
    const operation = args.next() orelse return error.InvalidArgument;
    const pid_text = args.next() orelse return error.InvalidArgument;
    const source = args.next() orelse return error.InvalidArgument;
    const destination = args.next() orelse return error.InvalidArgument;
    if (args.next() != null or !id_paths.isValidContainerId(id)) return error.InvalidArgument;
    const pid = try std.fmt.parseUnsigned(u31, pid_text, 10);
    const config = try run_state.loadConfig(ctx.alloc, id);
    defer config.deinit(ctx.alloc);
    const copying_in = std.mem.eql(u8, operation, "copy-in");
    const copying_out = std.mem.eql(u8, operation, "copy-out");
    const showing_diff = std.mem.eql(u8, operation, "diff");
    if (!copying_in and !copying_out and !showing_diff) return error.InvalidArgument;
    if (showing_diff and config.lower_dirs.len == 0) return error.DiffRequiresImage;

    // only the helper's current thread performs filesystem work in this namespace.
    if ((pid == 0 and config.lower_dirs.len > 0) or showing_diff) {
        if (linux.errno(linux.unshare(linux.CLONE.NEWNS | linux.CLONE.FS)) != .SUCCESS) return error.MountNamespaceFailed;
        if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS) return error.MountNamespaceFailed;
    }
    const io = std.Io.Threaded.global_single_threaded.io();
    var mounted: ?TemporaryView = null;
    defer if (mounted) |*view| view.deinit(io, ctx.alloc);
    if (showing_diff) {
        var dirs = try id_paths.createContainerDirs("containers", id);
        mounted = try TemporaryView.init(io, ctx.alloc, id, config.lower_dirs, null);
        var lower = try std.Io.Dir.cwd().openDir(io, mounted.?.merged, .{ .iterate = true });
        defer lower.close(io);
        var upper = try std.Io.Dir.cwd().openDir(io, dirs.upperPath(), .{ .iterate = true, .follow_symlinks = false });
        defer upper.close(io);
        var buffer: [4096]u8 = undefined;
        var output = std.Io.File.stdout().writer(io, &buffer);
        try diff_support.diff(io, ctx.alloc, upper, lower, &output.interface);
        try output.interface.flush();
        return;
    }

    var root_buf: [64]u8 = undefined;
    const root_path = if (pid > 0)
        try std.fmt.bufPrint(&root_buf, "/proc/{d}/root", .{pid})
    else if (config.lower_dirs.len > 0) blk: {
        var dirs = try id_paths.createContainerDirs("containers", id);
        mounted = try TemporaryView.init(io, ctx.alloc, id, config.lower_dirs, &dirs);
        break :blk mounted.?.merged;
    } else config.rootfs;
    const root = try std.Io.Dir.cwd().openDir(io, root_path, .{ .iterate = true });
    defer root.close(io);
    if (copying_in) {
        try copy_support.copy(io, null, source, root, destination);
    } else try copy_support.copy(io, root, source, null, destination);
}

const TemporaryView = struct {
    base: []const u8,
    upper: []const u8,
    work: []const u8,
    merged: []const u8,
    mounted: bool = false,

    fn init(io: std.Io, alloc: std.mem.Allocator, id: []const u8, lower: []const []const u8, persistent: ?*const id_paths.OverlayDirs) !TemporaryView {
        try paths.ensureDataDirStrictWithIo(io, "container-tools");
        var path_buf: [paths.max_path]u8 = undefined;
        const base = try alloc.dupe(u8, try paths.uniqueDataTempPath(&path_buf, "container-tools", id, ".view"));
        errdefer alloc.free(base);
        const upper = if (persistent) |dirs| try alloc.dupe(u8, dirs.upperPath()) else try std.fmt.allocPrint(alloc, "{s}/upper", .{base});
        errdefer alloc.free(upper);
        const work = if (persistent) |dirs| try alloc.dupe(u8, dirs.workPath()) else try std.fmt.allocPrint(alloc, "{s}/work", .{base});
        errdefer alloc.free(work);
        const merged = try std.fmt.allocPrint(alloc, "{s}/root", .{base});
        errdefer alloc.free(merged);
        try std.Io.Dir.cwd().createDirPath(io, merged);
        errdefer std.Io.Dir.cwd().deleteTree(io, base) catch {};
        if (persistent == null) {
            try std.Io.Dir.cwd().createDirPath(io, upper);
            try std.Io.Dir.cwd().createDirPath(io, work);
        }
        try filesystem.mountOverlay(.{ .lower_dirs = lower, .upper_dir = upper, .work_dir = work, .merged_dir = merged });
        return .{ .base = base, .upper = upper, .work = work, .merged = merged, .mounted = true };
    }

    fn deinit(self: *TemporaryView, io: std.Io, alloc: std.mem.Allocator) void {
        defer alloc.free(self.base);
        defer alloc.free(self.upper);
        defer alloc.free(self.work);
        defer alloc.free(self.merged);
        if (self.mounted) {
            const target = std.posix.toPosixPath(self.merged) catch return;
            if (linux.errno(linux.umount2(&target, linux.MNT.DETACH)) != .SUCCESS) return;
        }
        std.Io.Dir.cwd().deleteTree(io, self.base) catch {};
    }
};

test "copy operands distinguish container refs from explicit host paths" {
    try std.testing.expectEqualStrings("web", (try operand("web:/app/file")).container.?);
    try std.testing.expectEqualStrings("relative", (try operand("web:relative")).path);
    try std.testing.expect((try operand("./host:filename")).container == null);
    try std.testing.expect((try operand("/tmp/host:filename")).container == null);
    try std.testing.expectError(error.InvalidArgument, operand("web:"));
}

test {
    _ = copy_support;
    _ = diff_support;
}

fn mountedFixture(lower: []const u8, dirs: *const id_paths.OverlayDirs, source: []const u8, destination: []const u8) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    const alloc = std.heap.page_allocator;
    {
        var view = try TemporaryView.init(io, alloc, "fe0123456789", &.{lower}, dirs);
        defer view.deinit(io, alloc);
        const root = try std.Io.Dir.cwd().openDir(io, view.merged, .{ .iterate = true });
        defer root.close(io);
        try copy_support.copy(io, null, source, root, "/file");
        try root.deleteFile(io, "deleted");
    }
    {
        var view = try TemporaryView.init(io, alloc, "fe0123456789", &.{lower}, dirs);
        defer view.deinit(io, alloc);
        const root = try std.Io.Dir.cwd().openDir(io, view.merged, .{ .iterate = true });
        defer root.close(io);
        try copy_support.copy(io, root, "/file", null, destination);
        if (root.access(io, "deleted", .{})) |_| return error.DeletionLost else |err| if (err != error.FileNotFound) return err;
    }
    var base = try TemporaryView.init(io, alloc, "fe0123456789", &.{lower}, null);
    defer base.deinit(io, alloc);
    const lower_view = try std.Io.Dir.cwd().openDir(io, base.merged, .{ .iterate = true });
    defer lower_view.close(io);
    const upper = try std.Io.Dir.cwd().openDir(io, dirs.upperPath(), .{ .iterate = true });
    defer upper.close(io);
    var output = std.Io.Writer.Allocating.init(alloc);
    defer output.deinit();
    try diff_support.diff(io, alloc, upper, lower_view, &output.writer);
    if (std.mem.indexOf(u8, output.written(), "C /file\n") == null or std.mem.indexOf(u8, output.written(), "D /deleted\n") == null) return error.IncorrectDiff;
}

test "stopped container views retain copied data and native deletions across remounts" {
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const io = std.testing.io;
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "lower", "upper", "work", "merged" }) |name| try tmp.dir.createDirPath(io, name);
    try tmp.dir.writeFile(io, .{ .sub_path = "lower/file", .data = "image bytes" });
    try tmp.dir.writeFile(io, .{ .sub_path = "lower/deleted", .data = "remove me" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source", .data = "copied bytes" });
    var path_buf: [4096]u8 = undefined;
    const len = try tmp.dir.realPath(io, &path_buf);
    const base = path_buf[0..len];
    const lower = try std.fmt.allocPrint(alloc, "{s}/lower", .{base});
    defer alloc.free(lower);
    const source = try std.fmt.allocPrint(alloc, "{s}/source", .{base});
    defer alloc.free(source);
    const destination = try std.fmt.allocPrint(alloc, "{s}/destination", .{base});
    defer alloc.free(destination);
    var dirs: id_paths.OverlayDirs = undefined;
    dirs.upper_len = (try std.fmt.bufPrint(&dirs.upper, "{s}/upper", .{base})).len;
    dirs.work_len = (try std.fmt.bufPrint(&dirs.work, "{s}/work", .{base})).len;
    dirs.merged_len = (try std.fmt.bufPrint(&dirs.merged, "{s}/merged", .{base})).len;
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return error.ForkFailed;
    if (rc == 0) {
        if (linux.errno(linux.unshare(linux.CLONE.NEWNS | linux.CLONE.FS)) != .SUCCESS) linux.exit_group(77);
        if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS) linux.exit_group(77);
        mountedFixture(lower, &dirs, source, destination) catch linux.exit_group(1);
        linux.exit_group(0);
    }
    const result = try @import("../../process.zig").waitForExit(@intCast(rc));
    if (result.status == .exited and result.status.exited == 77) return error.SkipZigTest;
    try std.testing.expectEqual(@import("../../process.zig").ExitStatus{ .exited = 0 }, result.status);
    const copied = try tmp.dir.readFileAlloc(io, "destination", alloc, .limited(100));
    defer alloc.free(copied);
    try std.testing.expectEqualStrings("copied bytes", copied);
    const original = try tmp.dir.readFileAlloc(io, "lower/file", alloc, .limited(100));
    defer alloc.free(original);
    try std.testing.expectEqualStrings("image bytes", original);
}
