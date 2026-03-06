// store — content-addressable blob store
//
// stores image blobs (manifests, configs, layers) addressed by their
// sha256 digest. blobs are immutable — same content always gets the
// same path. deduplication is automatic.
//
// layout: ~/.local/share/yoq/blobs/sha256/<hex>
//
// this module only handles raw blob storage. image metadata tracking
// (which images are pulled, tags, etc.) lives in state/store.zig.

const std = @import("std");
const paths = @import("../lib/paths.zig");
const log = @import("../lib/log.zig");

pub const BlobError = error{
    /// failed to write blob data or rename temp file into place
    WriteFailed,
    /// failed to read source file during putBlobFromFile
    ReadFailed,
    /// blob with the requested digest does not exist in the store
    NotFound,
    /// blob contents don't match the expected sha256 digest
    HashMismatch,
    /// constructed blob path exceeds max_path buffer
    PathTooLong,
    /// HOME environment variable not set, can't locate data directory
    HomeDirNotFound,
};

/// the base directory for all blob storage
const blob_subdir = "blobs/sha256";

const max_path = paths.max_path;

/// write a blob to the store. returns the sha256 digest.
/// if a blob with the same digest already exists, this is a no-op.
///
/// writes to a temp file first, then renames to the final path.
/// this ensures a crash during write never leaves a partial blob
/// that hasBlob() would consider valid.
pub fn putBlob(data: []const u8) BlobError!Digest {
    const digest = computeDigest(data);

    // check if already stored
    if (hasBlob(digest)) return digest;

    var dir_buf: [max_path]u8 = undefined;
    const dir_path = blobDir(&dir_buf) catch return BlobError.PathTooLong;
    std.fs.cwd().makePath(dir_path) catch {};

    // write to a temp file, then rename for atomicity
    var tmp_buf: [max_path]u8 = undefined;
    const tmp_path = paths.dataPathFmt(&tmp_buf, "{s}/.tmp.{s}", .{ blob_subdir, digest.hex() }) catch
        return BlobError.PathTooLong;

    const file = std.fs.cwd().createFile(tmp_path, .{}) catch
        return BlobError.WriteFailed;

    file.writeAll(data) catch {
        file.close();
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return BlobError.WriteFailed;
    };
    file.close();

    // atomic rename to final path
    var path_buf: [max_path]u8 = undefined;
    const final_path = blobPath(digest, &path_buf) catch return BlobError.PathTooLong;
    std.fs.cwd().rename(tmp_path, final_path) catch {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return BlobError.WriteFailed;
    };

    return digest;
}

/// write a blob from a file path instead of memory.
/// useful for large layers that shouldn't be loaded entirely into RAM.
/// the file is copied to the blob store and its digest is verified.
///
/// writes to a temp file first, then renames to the final path.
/// on failure or digest mismatch, the temp file is cleaned up.
pub fn putBlobFromFile(source_path: []const u8, expected_digest: Digest) BlobError!void {
    if (hasBlob(expected_digest)) return;

    var dir_buf: [max_path]u8 = undefined;
    const dir_path = blobDir(&dir_buf) catch return BlobError.PathTooLong;
    std.fs.cwd().makePath(dir_path) catch {};

    // write to a temp file, then rename for atomicity
    var tmp_buf: [max_path]u8 = undefined;
    const tmp_path = paths.dataPathFmt(&tmp_buf, "{s}/.tmp.{s}", .{ blob_subdir, expected_digest.hex() }) catch
        return BlobError.PathTooLong;

    const src_file = std.fs.cwd().openFile(source_path, .{}) catch
        return BlobError.ReadFailed;
    defer src_file.close();

    const dest_file = std.fs.cwd().createFile(tmp_path, .{}) catch
        return BlobError.WriteFailed;

    // copy in chunks and compute digest simultaneously
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [8192]u8 = undefined;
    var write_ok = true;
    while (true) {
        const n = src_file.read(&buf) catch {
            write_ok = false;
            break;
        };
        if (n == 0) break;
        hasher.update(buf[0..n]);
        dest_file.writeAll(buf[0..n]) catch {
            write_ok = false;
            break;
        };
    }
    dest_file.close();

    if (!write_ok) {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return BlobError.WriteFailed;
    }

    // verify digest before committing
    const actual = hasher.finalResult();
    if (!std.mem.eql(u8, &actual, &expected_digest.hash)) {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return BlobError.HashMismatch;
    }

    // atomic rename to final path
    var path_buf: [max_path]u8 = undefined;
    const final_path = blobPath(expected_digest, &path_buf) catch return BlobError.PathTooLong;
    std.fs.cwd().rename(tmp_path, final_path) catch {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return BlobError.WriteFailed;
    };
}

/// write a blob with a pre-verified digest, skipping the hash computation.
/// use this when the caller has already verified the data matches the digest
/// (e.g. after downloading and checking against the registry's expected digest).
pub fn putBlobDirect(data: []const u8, digest: Digest) BlobError!void {
    if (hasBlob(digest)) return;

    var dir_buf: [max_path]u8 = undefined;
    const dir_path = blobDir(&dir_buf) catch return BlobError.PathTooLong;
    std.fs.cwd().makePath(dir_path) catch {};

    // write to a temp file, then rename for atomicity
    var tmp_buf: [max_path]u8 = undefined;
    const tmp_path = paths.dataPathFmt(&tmp_buf, "{s}/.tmp.{s}", .{ blob_subdir, digest.hex() }) catch
        return BlobError.PathTooLong;

    const file = std.fs.cwd().createFile(tmp_path, .{}) catch
        return BlobError.WriteFailed;

    file.writeAll(data) catch {
        file.close();
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return BlobError.WriteFailed;
    };
    file.close();

    var path_buf: [max_path]u8 = undefined;
    const final_path = blobPath(digest, &path_buf) catch return BlobError.PathTooLong;
    std.fs.cwd().rename(tmp_path, final_path) catch {
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return BlobError.WriteFailed;
    };
}

/// read a blob's contents by digest.
/// caller owns the returned slice.
pub fn getBlob(alloc: std.mem.Allocator, digest: Digest) BlobError![]u8 {
    var path_buf: [max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return BlobError.PathTooLong;

    return std.fs.cwd().readFileAlloc(alloc, path, 256 * 1024 * 1024) catch
        return BlobError.NotFound;
}

/// check if a blob exists without reading it
pub fn hasBlob(digest: Digest) bool {
    var path_buf: [max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return false;
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

/// delete a blob by digest. returns BlobError.NotFound if the blob
/// doesn't exist — use removeBlob() instead for best-effort cleanup
/// where missing blobs are expected.
pub fn deleteBlob(digest: Digest) BlobError!void {
    var path_buf: [max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return BlobError.PathTooLong;
    std.fs.cwd().deleteFile(path) catch return BlobError.NotFound;
}

/// verify a cached blob's integrity by re-hashing its contents.
/// returns true if the blob exists and its contents match the expected digest.
/// returns false if the blob is missing, unreadable, or corrupted.
pub fn verifyBlob(digest: Digest) bool {
    var path_buf: [max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return false;

    const file = std.fs.cwd().openFile(path, .{}) catch return false;
    defer file.close();

    // hash the file contents in chunks to avoid loading the entire blob into memory
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = file.read(&buf) catch return false;
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }

    const actual = hasher.finalResult();
    return std.mem.eql(u8, &actual, &digest.hash);
}

/// remove a blob file from the store without error.
/// intended for cleaning up corrupted cache entries — file-not-found
/// is expected and silent, but other errors (permission denied, etc.)
/// are logged as warnings.
pub fn removeBlob(digest: Digest) void {
    var path_buf: [max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return;
    std.fs.cwd().deleteFile(path) catch |err| {
        if (err != error.FileNotFound) {
            log.warn("failed to remove blob {s}: {}", .{ path, err });
        }
    };
}

/// get the filesystem path for a blob
pub fn blobPath(digest: Digest, buf: *[max_path]u8) BlobError![]const u8 {
    const hex = digest.hex();
    return paths.dataPathFmt(buf, "{s}/{s}", .{ blob_subdir, hex }) catch
        return BlobError.PathTooLong;
}

/// get the blob store directory
fn blobDir(buf: *[max_path]u8) BlobError![]const u8 {
    return paths.dataPath(buf, blob_subdir) catch return BlobError.PathTooLong;
}

// -- digest type --

/// a sha256 digest — the primary identifier for blobs
pub const Digest = struct {
    hash: [32]u8,

    /// format as "sha256:<hex>"
    pub fn string(self: Digest, buf: *[71]u8) []const u8 {
        const result = std.fmt.bufPrint(buf, "sha256:{s}", .{self.hex()}) catch unreachable;
        return result;
    }

    /// format as hex string (64 chars)
    pub fn hex(self: Digest) [64]u8 {
        return std.fmt.bytesToHex(self.hash, .lower);
    }

    /// parse a "sha256:<hex>" string into a Digest
    pub fn parse(s: []const u8) ?Digest {
        const prefix = "sha256:";
        if (!std.mem.startsWith(u8, s, prefix)) return null;
        const hex_str = s[prefix.len..];
        if (hex_str.len != 64) return null;

        var hash: [32]u8 = undefined;
        for (0..32) |i| {
            hash[i] = std.fmt.parseInt(u8, hex_str[i * 2 ..][0..2], 16) catch return null;
        }
        return Digest{ .hash = hash };
    }

    pub fn eql(self: Digest, other: Digest) bool {
        return std.mem.eql(u8, &self.hash, &other.hash);
    }
};

/// compute the sha256 digest of some data
pub fn computeDigest(data: []const u8) Digest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    return Digest{ .hash = hasher.finalResult() };
}

/// list all blob hex digests present on disk in the blob store directory.
/// walks ~/.local/share/yoq/blobs/sha256/ and collects filenames.
/// caller owns the returned list.
pub fn listBlobsOnDisk(alloc: std.mem.Allocator) BlobError!std.ArrayList([]const u8) {
    var dir_buf: [max_path]u8 = undefined;
    const dir_path = blobDir(&dir_buf) catch return BlobError.PathTooLong;

    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch {
        // directory doesn't exist yet â no blobs
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
        // blob filenames are 64-char hex strings
        if (entry.name.len != 64) continue;
        const owned = alloc.dupe(u8, entry.name) catch continue;
        blobs.append(alloc, owned) catch {
            alloc.free(owned);
            continue;
        };
    }

    return blobs;
}

/// get the size in bytes of a blob on disk.
/// returns null if the blob doesn't exist or can't be stat'd.
pub fn getBlobSize(digest: Digest) ?u64 {
    var path_buf: [max_path]u8 = undefined;
    const path = blobPath(digest, &path_buf) catch return null;
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();
    const stat = file.stat() catch return null;
    return stat.size;
}

// -- tests --

test "compute digest" {
    const digest = computeDigest("hello world");
    const hex = digest.hex();
    // sha256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    try std.testing.expectEqualStrings("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", &hex);
}

test "digest parse and round-trip" {
    const original = computeDigest("test data");
    var buf: [71]u8 = undefined;
    const str = original.string(&buf);

    try std.testing.expect(std.mem.startsWith(u8, str, "sha256:"));

    const parsed = Digest.parse(str).?;
    try std.testing.expect(original.eql(parsed));
}

test "digest parse — invalid" {
    try std.testing.expect(Digest.parse("md5:abc") == null);
    try std.testing.expect(Digest.parse("sha256:tooshort") == null);
    try std.testing.expect(Digest.parse("not-a-digest") == null);
}

test "put and get blob" {
    // skip if HOME isn't set (CI environments)
    const home = std.posix.getenv("HOME") orelse return;
    _ = home;

    const data = "test blob content for yoq store";
    const digest = try putBlob(data);

    // verify it exists
    try std.testing.expect(hasBlob(digest));

    // read it back
    const alloc = std.testing.allocator;
    const read_back = try getBlob(alloc, digest);
    defer alloc.free(read_back);
    try std.testing.expectEqualStrings(data, read_back);

    // clean up
    try deleteBlob(digest);
    try std.testing.expect(!hasBlob(digest));
}

test "put blob is idempotent" {
    const home = std.posix.getenv("HOME") orelse return;
    _ = home;

    const data = "idempotent test blob";
    const d1 = try putBlob(data);
    const d2 = try putBlob(data);

    try std.testing.expect(d1.eql(d2));

    // clean up
    try deleteBlob(d1);
}

test "has blob returns false for missing" {
    const digest = computeDigest("definitely not stored");
    try std.testing.expect(!hasBlob(digest));
}

test "verify blob — valid blob passes" {
    const home = std.posix.getenv("HOME") orelse return;
    _ = home;

    const data = "verify blob test content";
    const digest = try putBlob(data);
    defer deleteBlob(digest) catch {};

    try std.testing.expect(verifyBlob(digest));
}

test "verify blob — corrupted blob fails" {
    const home = std.posix.getenv("HOME") orelse return;
    _ = home;

    // store a valid blob first
    const data = "original content for corruption test";
    const digest = try putBlob(data);
    defer removeBlob(digest);

    // overwrite the file with different content to simulate corruption
    var path_buf: [max_path]u8 = undefined;
    const path = try blobPath(digest, &path_buf);
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll("corrupted data");

    // verification should fail — the hash no longer matches
    try std.testing.expect(!verifyBlob(digest));
}

test "verify blob — missing blob returns false" {
    const digest = computeDigest("blob that was never stored");
    try std.testing.expect(!verifyBlob(digest));
}

test "remove blob — silently handles missing blob" {
    const digest = computeDigest("never stored blob for remove test");
    // should not crash or return an error
    removeBlob(digest);
}

test "listBlobsOnDisk returns stored blobs" {
    const home = std.posix.getenv("HOME") orelse return;
    _ = home;
    const alloc = std.testing.allocator;

    const d1 = try putBlob("blob one for list test");
    defer deleteBlob(d1) catch {};

    var blobs = try listBlobsOnDisk(alloc);
    defer {
        for (blobs.items) |item| alloc.free(item);
        blobs.deinit(alloc);
    }

    // should contain at least the blob we just stored
    try std.testing.expect(blobs.items.len >= 1);

    // verify our blob's hex is in the list
    const our_hex = d1.hex();
    var found = false;
    for (blobs.items) |item| {
        if (std.mem.eql(u8, item, &our_hex)) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "getBlobSize returns correct size" {
    const home = std.posix.getenv("HOME") orelse return;
    _ = home;

    const data = "blob size test content";
    const digest = try putBlob(data);
    defer deleteBlob(digest) catch {};

    const size = getBlobSize(digest);
    try std.testing.expect(size != null);
    try std.testing.expectEqual(@as(u64, data.len), size.?);
}

test "getBlobSize returns null for missing blob" {
    const digest = computeDigest("never stored blob for size test");
    try std.testing.expect(getBlobSize(digest) == null);
}
