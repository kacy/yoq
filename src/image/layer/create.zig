const std = @import("std");

const blob_store = @import("../store.zig");
const paths = @import("../../lib/paths.zig");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");

const max_path = paths.max_path;

const GzipResult = struct {
    digest: blob_store.Digest,
    size: u64,
};

fn cwd() std.Io.Dir {
    return std.Io.Dir.cwd();
}

pub fn createLayerFromDir(
    alloc: std.mem.Allocator,
    dir_path: []const u8,
) types.LayerError!?types.LayerCreateResult {
    var dir = cwd().openDir(std.Options.debug_io, dir_path, .{ .iterate = true }) catch
        return types.LayerError.CreateFailed;
    defer dir.close(std.Options.debug_io);

    var check_iter = dir.iterate();
    const has_entries = (check_iter.next(std.Options.debug_io) catch return types.LayerError.CreateFailed) != null;
    if (!has_entries) return null;

    var tar_path_buf: [max_path]u8 = undefined;
    const tar_path = paths.uniqueDataTempPath(&tar_path_buf, "tmp", "build-layer", ".tar") catch
        return types.LayerError.PathTooLong;
    paths.ensureDataDir("tmp") catch return types.LayerError.CreateFailed;

    const uncompressed_digest = writeTarFromDir(alloc, dir_path, tar_path) catch
        return types.LayerError.CreateFailed;
    defer cwd().deleteFile(std.Options.debug_io, tar_path) catch {};

    var gz_path_buf: [max_path]u8 = undefined;
    const gz_path = paths.uniqueDataTempPath(&gz_path_buf, "tmp", "build-layer", ".tar.gz") catch
        return types.LayerError.PathTooLong;

    const compress_result = gzipCompress(alloc, tar_path, gz_path) catch
        return types.LayerError.CreateFailed;
    defer cwd().deleteFile(std.Options.debug_io, gz_path) catch {};

    blob_store.putBlobFromFile(gz_path, compress_result.digest) catch
        return types.LayerError.CreateFailed;

    return .{
        .compressed_digest = compress_result.digest,
        .uncompressed_digest = uncompressed_digest,
        .compressed_size = compress_result.size,
    };
}

fn gzipCompress(alloc: std.mem.Allocator, src_path: []const u8, dst_path: []const u8) !GzipResult {
    var src_file = try cwd().openFile(std.Options.debug_io, src_path, .{});
    defer src_file.close(std.Options.debug_io);

    var dst_file = try cwd().createFile(std.Options.debug_io, dst_path, .{});
    defer dst_file.close(std.Options.debug_io);

    const compressor = try alloc.create(std.compress.flate.Compress);
    defer alloc.destroy(compressor);

    var write_buf: [8192]u8 = undefined;
    var dst_writer = dst_file.writer(std.Options.debug_io, &write_buf);

    var compress_window: [std.compress.flate.max_window_len]u8 = undefined;
    compressor.* = std.compress.flate.Compress.init(
        &dst_writer.interface,
        &compress_window,
        .gzip,
        .default,
    ) catch return error.CompressFailed;

    var src_reader_buf: [8192]u8 = undefined;
    var src_reader = src_file.readerStreaming(std.Options.debug_io, &src_reader_buf);
    var read_buf: [8192]u8 = undefined;
    while (true) {
        const bytes_read = try src_reader.interface.readSliceShort(&read_buf);
        if (bytes_read == 0) break;
        compressor.writer.writeAll(read_buf[0..bytes_read]) catch return error.CompressFailed;
    }

    compressor.finish() catch return error.CompressFailed;
    try dst_writer.interface.flush();

    const stat = try dst_file.stat(std.Options.debug_io);
    const size = stat.size;

    var verify_file = try cwd().openFile(std.Options.debug_io, dst_path, .{});
    defer verify_file.close(std.Options.debug_io);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var verify_reader_buf: [8192]u8 = undefined;
    var verify_reader = verify_file.readerStreaming(std.Options.debug_io, &verify_reader_buf);
    var hash_buf: [8192]u8 = undefined;
    while (true) {
        const bytes_read = try verify_reader.interface.readSliceShort(&hash_buf);
        if (bytes_read == 0) break;
        hasher.update(hash_buf[0..bytes_read]);
    }

    return .{
        .digest = .{ .hash = hasher.finalResult() },
        .size = size,
    };
}

fn writeTarFromDir(
    alloc: std.mem.Allocator,
    dir_path: []const u8,
    tar_path: []const u8,
) !blob_store.Digest {
    var dir = try cwd().openDir(std.Options.debug_io, dir_path, .{ .iterate = true });
    defer dir.close(std.Options.debug_io);

    var tar_file = try cwd().createFile(std.Options.debug_io, tar_path, .{});
    defer tar_file.close(std.Options.debug_io);

    var write_buf: [8192]u8 = undefined;
    var file_writer = tar_file.writer(std.Options.debug_io, &write_buf);
    var tar_writer: std.tar.Writer = .{ .underlying_writer = &file_writer.interface };

    var walker = try dir.walk(alloc);
    defer walker.deinit();

    while (try walker.next(std.Options.debug_io)) |entry| {
        try writeTarEntry(dir, &tar_writer, entry);
    }

    try file_writer.interface.flush();
    tar_file.sync(std.Options.debug_io) catch {};

    var hash_file = try cwd().openFile(std.Options.debug_io, tar_path, .{});
    defer hash_file.close(std.Options.debug_io);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var hash_reader_buf: [8192]u8 = undefined;
    var hash_reader = hash_file.readerStreaming(std.Options.debug_io, &hash_reader_buf);
    var hash_buf: [8192]u8 = undefined;
    while (true) {
        const bytes_read = try hash_reader.interface.readSliceShort(&hash_buf);
        if (bytes_read == 0) break;
        hasher.update(hash_buf[0..bytes_read]);
    }

    return .{ .hash = hasher.finalResult() };
}

pub fn writeTarEntry(
    dir: std.Io.Dir,
    tar_writer: *std.tar.Writer,
    entry: std.Io.Dir.Walker.Entry,
) !void {
    switch (entry.kind) {
        .directory => try writeTarDirectoryEntry(tar_writer, entry.path),
        .file => try writeTarFileEntry(dir, tar_writer, entry.path),
        .sym_link => try writeTarSymlinkEntry(dir, tar_writer, entry.path),
        else => {
            log.warn("tar: unsupported entry kind for '{s}'", .{entry.path});
            return error.UnsupportedEntry;
        },
    }
}

fn writeTarDirectoryEntry(tar_writer: *std.tar.Writer, path: []const u8) !void {
    tar_writer.writeDir(path, .{}) catch |err| {
        log.warn("tar: failed to write dir entry '{s}': {}", .{ path, err });
        return err;
    };
}

fn writeTarFileEntry(dir: std.Io.Dir, tar_writer: *std.tar.Writer, path: []const u8) !void {
    var file = dir.openFile(std.Options.debug_io, path, .{}) catch |err| {
        log.warn("tar: failed to open '{s}': {}", .{ path, err });
        return err;
    };
    defer file.close(std.Options.debug_io);

    var file_read_buf: [4096]u8 = undefined;
    var reader = file.reader(std.Options.debug_io, &file_read_buf);
    const stat = file.stat(std.Options.debug_io) catch |err| {
        log.warn("tar: failed to stat '{s}': {}", .{ path, err });
        return err;
    };

    tar_writer.writeFileStream(path, stat.size, &reader.interface, .{
        .mtime = @intCast(stat.mtime.toSeconds()),
    }) catch |err| {
        log.warn("tar: failed to write file '{s}': {}", .{ path, err });
        return err;
    };
}

fn writeTarSymlinkEntry(dir: std.Io.Dir, tar_writer: *std.tar.Writer, path: []const u8) !void {
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_len = dir.readLink(std.Options.debug_io, path, &link_buf) catch |err| {
        log.warn("tar: failed to read symlink '{s}': {}", .{ path, err });
        return err;
    };
    const link_target = link_buf[0..link_len];

    tar_writer.writeLink(path, link_target, .{}) catch |err| {
        log.warn("tar: failed to write symlink '{s}': {}", .{ path, err });
        return err;
    };
}
