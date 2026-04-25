const std = @import("std");

const tar_extract = @import("../../../lib/tar_extract.zig");
const copy_args = @import("copy_args.zig");

pub const ExtractError = error{
    UnsupportedArchive,
    ExtractFailed,
};

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
    try tar_extract.extractTarGzFile(gz_path, dest_path, "build add");
}

fn extractUncompressedTar(tar_path: []const u8, dest_path: []const u8) !void {
    try tar_extract.extractTarFile(tar_path, dest_path, "build add");
}

test "safe tar paths" {
    try std.testing.expect(tar_extract.isSafeTarPath("usr/bin/hello"));
    try std.testing.expect(tar_extract.isSafeTarPath("single_file"));
    try std.testing.expect(!tar_extract.isSafeTarPath("../../etc/shadow"));
    try std.testing.expect(!tar_extract.isSafeTarPath("/etc/passwd"));
}

test "safe symlink targets" {
    try std.testing.expect(tar_extract.isSafeSymlinkTarget("usr/lib/libfoo.so", "../lib64/libfoo.so"));
    try std.testing.expect(tar_extract.isSafeSymlinkTarget("etc/resolv.conf", "/run/resolv.conf"));
    try std.testing.expect(!tar_extract.isSafeSymlinkTarget("etc/shadow", "../../etc/shadow"));
}
