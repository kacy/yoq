const std = @import("std");

const blob_store = @import("../store.zig");
const paths = @import("../../lib/paths.zig");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");
const metadata = @import("../../lib/tar_metadata.zig");

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
    // a failed fsync means the layer tar may not be durable; surface it
    // rather than silently hashing a possibly-unflushed file.
    tar_file.sync(std.Options.debug_io) catch |err| log.warn("layer tar fsync failed: {}", .{err});

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
        .directory => try writeTarDirectoryEntry(dir, tar_writer, entry.path),
        .file => try writeTarFileEntry(dir, tar_writer, entry.path),
        .sym_link => try writeTarSymlinkEntry(dir, tar_writer, entry.path),
        else => {
            log.warn("tar: unsupported entry kind for '{s}'", .{entry.path});
            return error.UnsupportedEntry;
        },
    }
}

fn writeTarDirectoryEntry(dir: std.Io.Dir, writer: *std.tar.Writer, path: []const u8) !void {
    try writeOwnedHeader(writer, .directory, path, "", 0, try metadata.Metadata.stat(dir, path));
}

/// Use the standard header encoder, adding the numeric ownership that the
/// standard Writer.Options does not expose. GNU extensions retain long paths.
fn writeOwnedHeader(writer: *std.tar.Writer, kind: std.tar.Writer.Header.FileType, path: []const u8, link: []const u8, size: u64, owner: metadata.Metadata) !void {
    var header = std.tar.Writer.Header.init(kind);
    header.setPath(writer.prefix, path) catch |err| switch (err) {
        error.NameTooLong => {
            var full_path_buf: [max_path]u8 = undefined;
            const full_path = if (writer.prefix.len == 0) path else try std.fmt.bufPrint(&full_path_buf, "{s}/{s}", .{ writer.prefix, path });
            try writeLongName(writer, .gnu_long_name, full_path);
        },
        else => return err,
    };
    if (kind == .symbolic_link) {
        header.setLinkname(link) catch |err| switch (err) {
            error.NameTooLong => try writeLongName(writer, .gnu_long_link, link),
            else => return err,
        };
    }
    try header.setSize(size);
    @memset(&header.mode, '0');
    try header.setMode(owner.mode);
    try header.setMtime(owner.mtime);
    // Patch raw bytes rather than writing binary IDs through the standard
    // header's sentinel-terminated octal fields.
    var bytes: [512]u8 = std.mem.asBytes(&header).*;
    metadata.encodeId(bytes[108..116], owner.uid);
    metadata.encodeId(bytes[116..124], owner.gid);
    @memset(bytes[148..156], ' ');
    var checksum: u32 = 0;
    for (bytes) |byte| checksum += byte;
    _ = try std.fmt.bufPrint(bytes[148..156], "{o:0>6}\x00 ", .{checksum});
    try writer.underlying_writer.writeAll(&bytes);
}

fn writeLongName(writer: *std.tar.Writer, kind: std.tar.Writer.Header.FileType, value: []const u8) !void {
    var header = std.tar.Writer.Header.init(kind);
    try header.setSize(value.len + 1);
    try header.write(writer.underlying_writer);
    try writer.underlying_writer.writeAll(value);
    try writer.underlying_writer.writeByte(0);
    try writePadding(writer, value.len + 1);
}

fn writePadding(writer: *std.tar.Writer, size: u64) !void {
    const zeros = [_]u8{0} ** 512;
    try writer.underlying_writer.writeAll(zeros[0..@intCast((512 - size % 512) % 512)]);
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

    try writeOwnedHeader(tar_writer, .regular, path, "", stat.size, try metadata.Metadata.stat(dir, path));
    try reader.interface.streamExact64(tar_writer.underlying_writer, stat.size);
    try writePadding(tar_writer, stat.size);
}

fn writeTarSymlinkEntry(dir: std.Io.Dir, tar_writer: *std.tar.Writer, path: []const u8) !void {
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_len = dir.readLink(std.Options.debug_io, path, &link_buf) catch |err| {
        log.warn("tar: failed to read symlink '{s}': {}", .{ path, err });
        return err;
    };
    const link_target = link_buf[0..link_len];

    try writeOwnedHeader(tar_writer, .symbolic_link, path, link_target, 0, try metadata.Metadata.stat(dir, path));
}

test "layer metadata roundtrip preserves numeric owners and ordinary modes only" {
    if (std.os.linux.geteuid() != 0) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    var source = std.testing.tmpDir(.{});
    defer source.cleanup();
    var target = std.testing.tmpDir(.{});
    defer target.cleanup();
    var generic = std.testing.tmpDir(.{});
    defer generic.cleanup();
    try source.dir.createDir(io, "work", .default_dir);
    var work = try source.dir.openDir(io, "work", .{});
    defer work.close(io);
    try work.writeFile(io, .{ .sub_path = "tool", .data = "#!/bin/sh\necho ok\n" });
    const file = try work.openFile(io, "tool", .{});
    defer file.close(io);
    try file.setOwner(io, 1234, 2345);
    try file.setPermissions(io, .fromMode(0o6755));
    const directory: std.Io.File = .{ .handle = work.handle, .flags = .{ .nonblocking = false } };
    try directory.setOwner(io, 1234, 2345);
    try directory.setPermissions(io, .fromMode(0o750));
    var source_buf: [max_path]u8 = undefined;
    const source_len = try source.dir.realPath(io, &source_buf);
    const result = (try createLayerFromDir(alloc, source_buf[0..source_len])).?;
    defer blob_store.deleteBlob(result.compressed_digest) catch {};
    var blob_buf: [max_path]u8 = undefined;
    const blob_path = try blob_store.blobPath(result.compressed_digest, &blob_buf);
    var target_buf: [max_path]u8 = undefined;
    const target_len = try target.dir.realPath(io, &target_buf);
    try @import("../../lib/tar_extract.zig").extractImageLayer(blob_path, target_buf[0..target_len]);
    const work_meta = try metadata.Metadata.stat(target.dir, "work");
    const file_meta = try metadata.Metadata.stat(target.dir, "work/tool");
    try std.testing.expectEqual(@as(u32, 1234), work_meta.uid);
    try std.testing.expectEqual(@as(u32, 2345), work_meta.gid);
    try std.testing.expectEqual(@as(u32, 0o750), work_meta.mode);
    try std.testing.expectEqual(@as(u32, 1234), file_meta.uid);
    try std.testing.expectEqual(@as(u32, 2345), file_meta.gid);
    try std.testing.expectEqual(@as(u32, 0o755), file_meta.mode);
    const file_stat = try target.dir.statFile(io, "work/tool", .{});
    try std.testing.expectEqual(@as(u32, 0), file_stat.permissions.toMode() & 0o6000);
    var generic_buf: [max_path]u8 = undefined;
    const generic_len = try generic.dir.realPath(io, &generic_buf);
    try @import("../../lib/tar_extract.zig").extractTarGzFile(blob_path, generic_buf[0..generic_len], "generic archive");
    try std.testing.expectEqual(@as(u32, 0), (try metadata.Metadata.stat(generic.dir, "work/tool")).uid);
}

test "layer metadata header preserves long names prefix and zero modes" {
    const alloc = std.testing.allocator;
    var bytes: std.Io.Writer.Allocating = .init(alloc);
    defer bytes.deinit();
    var writer: std.tar.Writer = .{ .underlying_writer = &bytes.writer, .prefix = "prefix" };
    const name = "n" ** 300;
    const link = "l" ** 300;
    try writeOwnedHeader(&writer, .symbolic_link, name, link, 0, .{ .uid = 4000000000, .gid = 2345, .mode = 0, .mtime = 123 });
    var reader: std.Io.Reader = .fixed(bytes.written());
    var name_buf: [4096]u8 = undefined;
    var link_buf: [4096]u8 = undefined;
    var iterator: std.tar.Iterator = .init(&reader, .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf });
    const entry = (try iterator.next()).?;
    try std.testing.expectEqualStrings("prefix/" ++ name, entry.name);
    try std.testing.expectEqualStrings(link, entry.link_name);
    try std.testing.expectEqual(@as(u32, 0), entry.mode);
    const owner = try metadata.Metadata.fromHeader(&iterator.header_buffer, entry.mode);
    try std.testing.expectEqual(@as(u32, 4000000000), owner.uid);
    try std.testing.expectEqual(@as(u32, 2345), owner.gid);
}
