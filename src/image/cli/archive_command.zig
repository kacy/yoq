const std = @import("std");
const cli = @import("../../lib/cli.zig");
const save_archive = @import("../archive/save.zig");
const load_archive = @import("../archive/load.zig");

pub fn save(io: std.Io, args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var output: ?[]const u8 = null;
    var images: std.ArrayList([]const u8) = .empty;
    defer images.deinit(alloc);
    var options = true;
    while (args.next()) |arg| {
        if (options and std.mem.eql(u8, arg, "--")) {
            options = false;
        } else if (options and (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output"))) {
            if (output != null) return saveUsage();
            output = args.next() orelse return saveUsage();
        } else if (options and std.mem.startsWith(u8, arg, "-")) {
            return saveUsage();
        } else {
            try images.append(alloc, arg);
        }
    }
    if (images.items.len == 0) return saveUsage();
    saveFile(io, alloc, output orelse "-", images.items) catch |err| {
        cli.writeErr("failed to save image archive: {}\n", .{err});
        return err;
    };
}

pub fn saveFile(io: std.Io, alloc: std.mem.Allocator, output: []const u8, images: []const []const u8) !void {
    var buffer: [64 * 1024]u8 = undefined;
    if (std.mem.eql(u8, output, "-")) {
        var writer = std.Io.File.stdout().writerStreaming(io, &buffer);
        try save_archive.save(io, alloc, &writer.interface, images);
        try writer.interface.flush();
    } else {
        var file = try std.Io.Dir.cwd().createFileAtomic(io, output, .{ .replace = true });
        defer file.deinit(io);
        var writer = file.file.writerStreaming(io, &buffer);
        try save_archive.save(io, alloc, &writer.interface, images);
        try writer.interface.flush();
        try file.file.sync(io);
        try file.replace(io);
    }
}

pub fn load(io: std.Io, args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var input: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--input")) {
            if (input != null) return loadUsage();
            input = args.next() orelse return loadUsage();
        } else return loadUsage();
    }
    const path = input orelse "-";
    const stdin = std.mem.eql(u8, path, "-");
    const file = if (stdin) std.Io.File.stdin() else try std.Io.Dir.cwd().openFile(io, path, .{});
    defer if (!stdin) file.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var reader = file.readerStreaming(io, &buffer);
    const count = load_archive.load(io, alloc, &reader.interface) catch |err| {
        cli.writeErr("failed to load image archive: {}\n", .{err});
        return err;
    };
    cli.write("loaded {d} image reference(s)\n", .{count});
}

fn saveUsage() error{InvalidArgument} {
    cli.writeErr("usage: yoq save [-o archive.tar] <image> [image...]\n", .{});
    return error.InvalidArgument;
}

fn loadUsage() error{InvalidArgument} {
    cli.writeErr("usage: yoq load [-i archive.tar]\n", .{});
    return error.InvalidArgument;
}

test {
    _ = @import("../archive/tests.zig");
}
