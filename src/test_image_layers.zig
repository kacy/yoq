//! Disposable image-layer fixture driver. Mount mode enters a private mount
//! namespace and touches only the synthetic directories supplied by the test.
const std = @import("std");
const linux = std.os.linux;
const fs = @import("runtime/filesystem.zig");
const tar = @import("lib/tar_extract.zig");

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const mode = args.next() orelse return error.MissingMode;
    const first = args.next() orelse return error.MissingPath;
    const second = args.next() orelse return error.MissingPath;
    if (std.mem.eql(u8, mode, "extract")) return tar.extractImageLayer(first, second);
    if (std.mem.eql(u8, mode, "generic")) return tar.extractTarGzFile(first, second, "generic fixture");
    if (std.mem.eql(u8, mode, "export")) {
        _ = try @import("image/layer/create.zig").writeTarFromDir(init.gpa, first, second);
        return;
    }
    if (!std.mem.eql(u8, mode, "mount")) return error.InvalidMode;
    if (linux.errno(linux.unshare(linux.CLONE.NEWNS)) != .SUCCESS) return error.NamespaceFailed;
    if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS) return error.NamespaceFailed;
    const upper = args.next() orelse return error.MissingPath;
    const work = args.next() orelse return error.MissingPath;
    const merged = args.next() orelse return error.MissingPath;
    try fs.mountOverlay(.{ .lower_dirs = &.{ first, second }, .upper_dir = upper, .work_dir = work, .merged_dir = merged });
    const merged_z = try std.posix.toPosixPath(merged);
    defer _ = linux.umount2(&merged_z, linux.MNT.DETACH);
    var root = try std.Io.Dir.cwd().openDir(init.io, merged, .{ .iterate = true });
    defer root.close(init.io);
    var output = std.Io.Writer.Allocating.init(init.gpa);
    defer output.deinit();
    var walker = try root.walk(init.gpa);
    defer walker.deinit();
    try output.writer.writeAll("{");
    var first_entry = true;
    while (try walker.next(init.io)) |entry| {
        if (entry.kind != .file) continue;
        const data = try root.readFileAlloc(init.io, entry.path, init.gpa, .limited(4096));
        defer init.gpa.free(data);
        if (!first_entry) try output.writer.writeAll(",");
        first_entry = false;
        try std.json.Stringify.value(entry.path, .{}, &output.writer);
        try output.writer.writeAll(":");
        try std.json.Stringify.value(data, .{}, &output.writer);
    }
    try output.writer.writeAll("}");
    const stdout: std.Io.File = .{ .handle = 1, .flags = .{ .nonblocking = false } };
    try stdout.writeStreamingAll(init.io, output.written());
}
