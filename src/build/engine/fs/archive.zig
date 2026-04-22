const std = @import("std");
const platform = @import("platform");

const log = @import("../../../lib/log.zig");
const paths = @import("../../../lib/paths.zig");
const copy_args = @import("copy_args.zig");

pub const ExtractError = error{
    UnsupportedArchive,
    ExtractFailed,
};

const max_file_size: u64 = 10 * 1024 * 1024 * 1024;

pub fn extractArchive(
    _: std.mem.Allocator,
    archive_path: []const u8,
    format: copy_args.ArchiveFormat,
    dest_path: []const u8,
) ExtractError!void {
    switch (format) {
        .tar => extractUncompressedTar(archive_path, dest_path) catch return error.ExtractFailed,
        .tar_gz => extractTarGz(archive_path, dest_path) catch return error.ExtractFailed,
        .tar_xz => return error.UnsupportedArchive,
        .tar_bz2 => return error.UnsupportedArchive,
    }
}

fn extractTarGz(gz_path: []const u8, dest_path: []const u8) !void {
    var tmp_path_buf: [paths.max_path]u8 = undefined;
    const tmp_path = paths.uniqueDataTempPath(&tmp_path_buf, "tmp", "build-add-extract", ".tar") catch
        return error.PathTooLong;
    paths.ensureDataDir("tmp") catch return error.FileNotFound;

    {
        const gz_file = try platform.cwd().openFile(gz_path, .{});
        defer gz_file.close();

        const tmp_file = try platform.cwd().createFile(tmp_path, .{});
        defer tmp_file.close();

        var read_buf: [4096]u8 = undefined;
        var gz_reader = gz_file.reader(&read_buf);

        var decompress = std.compress.flate.Decompress.init(
            &gz_reader.interface,
            .gzip,
            &.{},
        );

        var write_buf: [std.compress.flate.max_window_len]u8 = undefined;
        var tmp_writer = tmp_file.writer(&write_buf);

        _ = try decompress.reader.streamRemaining(&tmp_writer.interface);
        try tmp_writer.interface.flush();
        tmp_file.sync() catch {};
    }
    defer platform.cwd().deleteFile(tmp_path) catch {};

    try extractUncompressedTar(tmp_path, dest_path);
}

fn extractUncompressedTar(tar_path: []const u8, dest_path: []const u8) !void {
    const tar_file = try platform.cwd().openFile(tar_path, .{});
    defer tar_file.close();

    var tar_read_buf: [4096]u8 = undefined;
    var tar_reader = tar_file.reader(&tar_read_buf);

    var dest_dir = try platform.cwd().openDir(dest_path, .{});
    defer dest_dir.close();

    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&tar_reader.interface, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    while (try it.next()) |entry| {
        if (!isSafeTarPath(entry.name)) {
            log.warn("build add: skipping unsafe archive path '{s}'", .{entry.name});
            continue;
        }

        switch (entry.kind) {
            .directory => {
                if (entry.name.len > 0) try dest_dir.makePath(entry.name);
            },
            .file => {
                const mode: platform.File.Mode = @intCast(entry.mode & 0o777);
                const fs_file = try createDirAndFile(dest_dir, entry.name, mode);
                defer fs_file.close();
                try copyTarEntryToFile(&it, entry, fs_file);
            },
            .sym_link => {
                if (!isSafeSymlinkTarget(entry.name, entry.link_name)) {
                    log.warn("build add: skipping unsafe symlink '{s}' -> '{s}'", .{
                        entry.name,
                        entry.link_name,
                    });
                    continue;
                }
                try createDirAndSymlink(dest_dir, entry.link_name, entry.name);
            },
        }
    }
}

fn isSafeTarPath(name: []const u8) bool {
    if (name.len == 0) return true;
    if (name[0] == '/') return false;

    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

fn isSafeSymlinkTarget(entry_path: []const u8, link_target: []const u8) bool {
    if (link_target.len > 0 and link_target[0] == '/') return true;

    var parent_depth: isize = 0;
    var entry_it = std.mem.splitScalar(u8, entry_path, '/');
    var component_count: usize = 0;
    while (entry_it.next()) |_| component_count += 1;
    if (component_count > 0) parent_depth = @intCast(component_count - 1);

    var depth = parent_depth;
    var link_it = std.mem.splitScalar(u8, link_target, '/');
    while (link_it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            depth -= 1;
            if (depth < 0) return false;
        } else {
            depth += 1;
        }
    }
    return true;
}

fn copyTarEntryToFile(it: *std.tar.Iterator, entry: std.tar.Iterator.File, fs_file: platform.File) !void {
    if (entry.size > max_file_size) return error.FileTooBig;

    var remaining = entry.size;
    var buf: [8192]u8 = undefined;
    while (remaining > 0) {
        const chunk_len: usize = @intCast(@min(remaining, buf.len));
        try it.reader.readSliceAll(buf[0..chunk_len]);
        try fs_file.writeAll(buf[0..chunk_len]);
        remaining -= chunk_len;
    }

    it.unread_file_bytes = 0;
}

fn createDirAndFile(dir: platform.Dir, name: []const u8, mode: platform.File.Mode) !platform.File {
    return dir.createFile(name, .{ .mode = mode }) catch |err| {
        if (err == error.FileNotFound) {
            if (std.fs.path.dirname(name)) |dir_name| {
                try dir.makePath(dir_name);
                return try dir.createFile(name, .{ .mode = mode });
            }
        }
        return err;
    };
}

fn createDirAndSymlink(dir: platform.Dir, link_name: []const u8, file_name: []const u8) !void {
    dir.symLink(link_name, file_name, .{}) catch |err| {
        if (err == error.FileNotFound) {
            if (std.fs.path.dirname(file_name)) |dir_name| {
                try dir.makePath(dir_name);
                return try dir.symLink(link_name, file_name, .{});
            }
        }
        return err;
    };
}

test "safe tar paths" {
    try std.testing.expect(isSafeTarPath("usr/bin/hello"));
    try std.testing.expect(isSafeTarPath("single_file"));
    try std.testing.expect(!isSafeTarPath("../../etc/shadow"));
    try std.testing.expect(!isSafeTarPath("/etc/passwd"));
}

test "safe symlink targets" {
    try std.testing.expect(isSafeSymlinkTarget("usr/lib/libfoo.so", "../lib64/libfoo.so"));
    try std.testing.expect(isSafeSymlinkTarget("etc/resolv.conf", "/run/resolv.conf"));
    try std.testing.expect(!isSafeSymlinkTarget("etc/shadow", "../../etc/shadow"));
}
