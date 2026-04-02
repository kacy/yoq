const std = @import("std");
const log = @import("../../lib/log.zig");
const paths = @import("../../lib/paths.zig");
const digest_support = @import("digest_support.zig");
const types = @import("types.zig");

pub fn putBlob(data: []const u8) types.BlobError!digest_support.Digest {
    const digest = digest_support.computeDigest(data);
    if (hasVerifiedBlob(digest)) return digest;
    try writeToStore(data, digest);
    return digest;
}

pub fn putBlobFromFile(source_path: []const u8, expected_digest: digest_support.Digest) types.BlobError!void {
    if (hasVerifiedBlob(expected_digest)) return;

    var dir_buf: [types.max_path]u8 = undefined;
    const dir_path = blobDir(&dir_buf) catch return types.BlobError.PathTooLong;
    std.fs.cwd().makePath(dir_path) catch {};

    var tmp_buf: [types.max_path]u8 = undefined;
    const tmp_path = paths.uniqueDataTempPath(&tmp_buf, types.blob_subdir, "blob", ".tmp") catch
        return types.BlobError.PathTooLong;

    const src_file = std.fs.cwd().openFile(source_path, .{}) catch return types.BlobError.ReadFailed;
    defer src_file.close();

    const dest_file = std.fs.cwd().createFile(tmp_path, .{}) catch return types.BlobError.WriteFailed;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [8192]u8 = undefined;
    var write_ok = true;
    while (true) {
        const bytes_read = src_file.read(&buf) catch |e| {
            log.warn("blob copy read failed: {}", .{e});
            write_ok = false;
            break;
        };
        if (bytes_read == 0) break;
        hasher.update(buf[0..bytes_read]);
        dest_file.writeAll(buf[0..bytes_read]) catch |e| {
            log.warn("blob copy write failed: {}", .{e});
            write_ok = false;
            break;
        };
    }
    dest_file.sync() catch {};
    dest_file.close();

    if (!write_ok) {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return types.BlobError.WriteFailed;
    }

    const actual = hasher.finalResult();
    if (!std.mem.eql(u8, &actual, &expected_digest.hash)) {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return types.BlobError.HashMismatch;
    }

    renameTempToBlob(tmp_path, expected_digest) catch return types.BlobError.WriteFailed;
}

pub fn putBlobDirect(data: []const u8, digest: digest_support.Digest) types.BlobError!void {
    if (hasVerifiedBlob(digest)) return;
    try writeToStore(data, digest);
}

fn writeToStore(data: []const u8, digest: digest_support.Digest) types.BlobError!void {
    var dir_buf: [types.max_path]u8 = undefined;
    const dir_path = blobDir(&dir_buf) catch return types.BlobError.PathTooLong;
    std.fs.cwd().makePath(dir_path) catch {};

    var tmp_buf: [types.max_path]u8 = undefined;
    const tmp_path = paths.uniqueDataTempPath(&tmp_buf, types.blob_subdir, "blob", ".tmp") catch
        return types.BlobError.PathTooLong;

    const file = std.fs.cwd().createFile(tmp_path, .{}) catch return types.BlobError.WriteFailed;

    file.writeAll(data) catch |e| {
        log.warn("blob store write failed: {}", .{e});
        file.close();
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return types.BlobError.WriteFailed;
    };
    file.sync() catch {};
    file.close();

    renameTempToBlob(tmp_path, digest) catch return types.BlobError.WriteFailed;
}

fn renameTempToBlob(tmp_path: []const u8, digest: digest_support.Digest) types.BlobError!void {
    var path_buf: [types.max_path]u8 = undefined;
    const final_path = blobPath(digest, &path_buf) catch return types.BlobError.PathTooLong;
    std.fs.cwd().rename(tmp_path, final_path) catch |e| {
        if (hasVerifiedBlob(digest)) {
            std.fs.cwd().deleteFile(tmp_path) catch {};
            return;
        }

        log.warn("blob rename failed, retrying after cleanup: {}", .{e});
        removeBlob(digest);
        std.fs.cwd().rename(tmp_path, final_path) catch |e2| {
            log.warn("blob rename retry failed: {}", .{e2});
            std.fs.cwd().deleteFile(tmp_path) catch {};
            return types.BlobError.WriteFailed;
        };
    };
}

pub fn getBlob(alloc: std.mem.Allocator, digest: digest_support.Digest) types.BlobError![]u8 {
    var path_buf: [types.max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return types.BlobError.PathTooLong;
    const file = std.fs.cwd().openFile(path, .{}) catch return types.BlobError.NotFound;
    defer file.close();

    const stat = file.stat() catch return types.BlobError.NotFound;
    const alloc_size = blobAllocSize(stat.size) catch return types.BlobError.ReadFailed;
    return file.readToEndAlloc(alloc, alloc_size) catch return types.BlobError.NotFound;
}

pub fn openBlob(digest: digest_support.Digest) types.BlobError!types.BlobHandle {
    var path_buf: [types.max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return types.BlobError.PathTooLong;
    const file = std.fs.cwd().openFile(path, .{}) catch return types.BlobError.NotFound;
    errdefer file.close();

    const stat = file.stat() catch return types.BlobError.NotFound;
    return .{
        .file = file,
        .size = stat.size,
    };
}

pub fn hasBlob(digest: digest_support.Digest) bool {
    var path_buf: [types.max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return false;
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn hasVerifiedBlob(digest: digest_support.Digest) bool {
    if (!hasBlob(digest)) return false;
    if (verifyBlob(digest)) return true;
    removeBlob(digest);
    return false;
}

pub fn deleteBlob(digest: digest_support.Digest) types.BlobError!void {
    var path_buf: [types.max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return types.BlobError.PathTooLong;
    std.fs.cwd().deleteFile(path) catch return types.BlobError.NotFound;
}

pub fn verifyBlob(digest: digest_support.Digest) bool {
    var path_buf: [types.max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return false;

    const file = std.fs.cwd().openFile(path, .{}) catch return false;
    defer file.close();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [8192]u8 = undefined;
    while (true) {
        const bytes_read = file.read(&buf) catch return false;
        if (bytes_read == 0) break;
        hasher.update(buf[0..bytes_read]);
    }

    const actual = hasher.finalResult();
    return std.mem.eql(u8, &actual, &digest.hash);
}

pub fn removeBlob(digest: digest_support.Digest) void {
    var path_buf: [types.max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return;
    std.fs.cwd().deleteFile(path) catch |err| {
        if (err != error.FileNotFound) {
            log.warn("failed to remove blob {s}: {}", .{ path, err });
        }
    };
}

pub fn tempBlobPath(buf: *[types.max_path]u8) types.BlobError![]const u8 {
    var dir_buf: [types.max_path]u8 = undefined;
    const dir_path = blobDir(&dir_buf) catch return types.BlobError.PathTooLong;
    std.fs.cwd().makePath(dir_path) catch {};
    return paths.uniqueDataTempPath(buf, types.blob_subdir, "blob", ".tmp") catch
        return types.BlobError.PathTooLong;
}

pub fn commitTempBlob(tmp_path: []const u8, digest: digest_support.Digest) types.BlobError!void {
    return renameTempToBlob(tmp_path, digest);
}

pub fn blobPath(digest: digest_support.Digest, buf: *[types.max_path]u8) types.BlobError![]const u8 {
    const hex = digest.hex();
    return paths.dataPathFmt(buf, "{s}/{s}", .{ types.blob_subdir, hex }) catch
        return types.BlobError.PathTooLong;
}

fn blobDir(buf: *[types.max_path]u8) types.BlobError![]const u8 {
    return paths.dataPath(buf, types.blob_subdir) catch return types.BlobError.PathTooLong;
}

pub fn listBlobsOnDisk(alloc: std.mem.Allocator) types.BlobError!std.ArrayList([]const u8) {
    var dir_buf: [types.max_path]u8 = undefined;
    const dir_path = blobDir(&dir_buf) catch return types.BlobError.PathTooLong;

    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |e| {
        if (e != error.FileNotFound) log.warn("failed to open blob directory: {}", .{e});
        return std.ArrayList([]const u8).empty;
    };
    defer dir.close();

    var blobs = std.ArrayList([]const u8).empty;
    errdefer {
        for (blobs.items) |item| alloc.free(item);
        blobs.deinit(alloc);
    }

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        if (entry.name.len != 64) continue;
        const owned = alloc.dupe(u8, entry.name) catch continue;
        blobs.append(alloc, owned) catch {
            alloc.free(owned);
            continue;
        };
    }

    return blobs;
}

pub fn getBlobSize(digest: digest_support.Digest) ?u64 {
    var path_buf: [types.max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return null;
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();
    const stat = file.stat() catch return null;
    return stat.size;
}

pub fn blobAllocSize(size: u64) types.BlobError!usize {
    return std.math.cast(usize, size) orelse types.BlobError.ReadFailed;
}
