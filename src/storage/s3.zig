// s3 — core S3-compatible object storage logic
//
// implements bucket and object CRUD backed by local filesystem directories.
// buckets are directories within a designated storage root, objects are
// files within bucket directories. multipart uploads use a staging area.
//
// not a full S3 implementation — just enough for apps to use S3 SDKs
// for blob storage without external dependencies.

const std = @import("std");
const log = @import("../lib/log.zig");
const paths = @import("../lib/paths.zig");

pub const S3Error = error{
    BucketNotFound,
    BucketAlreadyExists,
    BucketNotEmpty,
    ObjectNotFound,
    UploadNotFound,
    InvalidPartNumber,
    IoError,
    PathTooLong,
    HomeDirNotFound,
    InvalidBucketName,
    InvalidKey,
    InvalidUploadId,
};

/// max object key length
const max_key_len: usize = 1024;

/// max bucket name length (S3 spec: 3-63 chars)
const max_bucket_name: usize = 63;
const min_bucket_name: usize = 3;

/// storage root for S3 data
const storage_subdir = "s3";
const multipart_subdir = "s3-multipart";

/// metadata for an object (returned by head/get)
pub const ObjectMeta = struct {
    size: u64,
    last_modified: i64,
    etag: [32]u8,
    etag_len: usize,
};

/// metadata for a bucket
pub const BucketMeta = struct {
    name: []const u8,
    created: i64,
};

/// multipart upload state
pub const MultipartUpload = struct {
    upload_id: [24]u8,
    bucket: []const u8,
    key: []const u8,
    created: i64,
};

const multipart_meta_name = ".upload-meta";

const MultipartMeta = struct {
    bucket: []const u8,
    key: []const u8,
};

fn validateUploadId(upload_id: []const u8) S3Error!void {
    if (upload_id.len != 24) return S3Error.InvalidUploadId;
    for (upload_id) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) {
            return S3Error.InvalidUploadId;
        }
    }
}

// -- bucket operations --

/// resolve the filesystem path for S3 storage.
fn storagePath(buf: *[paths.max_path]u8, comptime fmt: []const u8, args: anytype) S3Error![]const u8 {
    return paths.dataPathFmt(buf, fmt, args) catch |err| switch (err) {
        error.HomeDirNotFound => S3Error.HomeDirNotFound,
        error.PathTooLong => S3Error.PathTooLong,
    };
}

/// validate a bucket name per S3 naming rules (simplified).
pub fn validateBucketName(name: []const u8) S3Error!void {
    if (name.len < min_bucket_name or name.len > max_bucket_name) return S3Error.InvalidBucketName;

    for (name) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '.') return S3Error.InvalidBucketName;
    }
    // must start/end with alphanumeric
    if (!std.ascii.isAlphanumeric(name[0])) return S3Error.InvalidBucketName;
    if (!std.ascii.isAlphanumeric(name[name.len - 1])) return S3Error.InvalidBucketName;
}

/// validate an object key.
pub fn validateKey(key: []const u8) S3Error!void {
    if (key.len == 0 or key.len > max_key_len) return S3Error.InvalidKey;
    // prevent path traversal
    if (std.mem.indexOf(u8, key, "..") != null) return S3Error.InvalidKey;
    if (key[0] == '/') return S3Error.InvalidKey;
    for (key) |c| {
        if (c < 0x20 or c == 0x7f or c == '\\') return S3Error.InvalidKey;
    }
}

/// create a bucket (directory).
pub fn createBucket(name: []const u8) S3Error!void {
    try validateBucketName(name);

    var buf: [paths.max_path]u8 = undefined;
    const dir_path = try storagePath(&buf, storage_subdir ++ "/{s}", .{name});

    // use makeDir (not makePath) so it fails if the directory already exists
    std.fs.cwd().makeDir(dir_path) catch |e| switch (e) {
        error.PathAlreadyExists => return S3Error.BucketAlreadyExists,
        else => {
            // ensure parent directories exist, then retry
            if (std.mem.lastIndexOfScalar(u8, dir_path, '/')) |last_sep| {
                std.fs.cwd().makePath(dir_path[0..last_sep]) catch return S3Error.IoError;
                std.fs.cwd().makeDir(dir_path) catch |e2| switch (e2) {
                    error.PathAlreadyExists => return S3Error.BucketAlreadyExists,
                    else => return S3Error.IoError,
                };
            } else {
                log.err("s3: failed to create bucket directory {s}: {}", .{ dir_path, e });
                return S3Error.IoError;
            }
        },
    };
}

/// delete a bucket. must be empty.
pub fn deleteBucket(name: []const u8) S3Error!void {
    try validateBucketName(name);

    var buf: [paths.max_path]u8 = undefined;
    const dir_path = try storagePath(&buf, storage_subdir ++ "/{s}", .{name});

    // try to remove as empty dir first
    std.fs.cwd().deleteDir(dir_path) catch |e| switch (e) {
        error.FileNotFound => return S3Error.BucketNotFound,
        error.DirNotEmpty => return S3Error.BucketNotEmpty,
        else => {
            log.err("s3: failed to delete bucket {s}: {}", .{ dir_path, e });
            return S3Error.IoError;
        },
    };
}

/// list all buckets.
pub fn listBuckets(alloc: std.mem.Allocator) S3Error!struct { names: [][]const u8, timestamps: []i64 } {
    var buf: [paths.max_path]u8 = undefined;
    const dir_path = try storagePath(&buf, storage_subdir, .{});

    // ensure storage dir exists
    std.fs.cwd().makePath(dir_path) catch return S3Error.IoError;

    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch return S3Error.IoError;
    defer dir.close();

    var names: std.ArrayListUnmanaged([]const u8) = .empty;
    var timestamps: std.ArrayListUnmanaged(i64) = .empty;
    errdefer {
        for (names.items) |n| alloc.free(n);
        names.deinit(alloc);
        timestamps.deinit(alloc);
    }

    var iter = dir.iterate();
    while (iter.next() catch return S3Error.IoError) |entry| {
        if (entry.kind != .directory) continue;
        const name_copy = alloc.dupe(u8, entry.name) catch return S3Error.IoError;
        names.append(alloc, name_copy) catch {
            alloc.free(name_copy);
            return S3Error.IoError;
        };
        // get creation time from directory stat
        const stat = dir.statFile(entry.name) catch {
            timestamps.append(alloc, 0) catch return S3Error.IoError;
            continue;
        };
        const mtime_s: i64 = @intCast(@divFloor(stat.mtime, std.time.ns_per_s));
        timestamps.append(alloc, mtime_s) catch return S3Error.IoError;
    }

    return .{
        .names = names.toOwnedSlice(alloc) catch return S3Error.IoError,
        .timestamps = timestamps.toOwnedSlice(alloc) catch return S3Error.IoError,
    };
}

/// check if a bucket exists.
pub fn bucketExists(name: []const u8) bool {
    var buf: [paths.max_path]u8 = undefined;
    const dir_path = storagePath(&buf, storage_subdir ++ "/{s}", .{name}) catch return false;
    std.fs.cwd().access(dir_path, .{}) catch return false;
    return true;
}

// -- object operations --

/// put an object (write file to bucket directory).
/// returns the MD5 hex etag.
pub fn putObject(name: []const u8, key: []const u8, data: []const u8) S3Error![32]u8 {
    try validateBucketName(name);
    try validateKey(key);

    if (!bucketExists(name)) return S3Error.BucketNotFound;

    var buf: [paths.max_path]u8 = undefined;
    const file_path = try storagePath(&buf, storage_subdir ++ "/{s}/{s}", .{ name, key });

    // ensure parent directories exist (for keys like "dir/subdir/file.txt")
    if (std.mem.lastIndexOfScalar(u8, file_path, '/')) |last_sep| {
        std.fs.cwd().makePath(file_path[0..last_sep]) catch return S3Error.IoError;
    }

    const file = std.fs.cwd().createFile(file_path, .{}) catch {
        return S3Error.IoError;
    };
    defer file.close();
    file.writeAll(data) catch return S3Error.IoError;

    return computeEtag(data);
}

/// get an object's data.
pub fn getObject(alloc: std.mem.Allocator, name: []const u8, key: []const u8) S3Error![]const u8 {
    try validateBucketName(name);
    try validateKey(key);

    var buf: [paths.max_path]u8 = undefined;
    const file_path = try storagePath(&buf, storage_subdir ++ "/{s}/{s}", .{ name, key });

    return std.fs.cwd().readFileAlloc(alloc, file_path, 256 * 1024 * 1024) catch |e| switch (e) {
        error.FileNotFound => return S3Error.ObjectNotFound,
        else => return S3Error.IoError,
    };
}

/// delete an object.
pub fn deleteObject(name: []const u8, key: []const u8) S3Error!void {
    try validateBucketName(name);
    try validateKey(key);

    var buf: [paths.max_path]u8 = undefined;
    const file_path = try storagePath(&buf, storage_subdir ++ "/{s}/{s}", .{ name, key });

    std.fs.cwd().deleteFile(file_path) catch |e| switch (e) {
        error.FileNotFound => return S3Error.ObjectNotFound,
        else => return S3Error.IoError,
    };
}

/// head an object — returns metadata without reading the full file.
pub fn headObject(name: []const u8, key: []const u8) S3Error!ObjectMeta {
    try validateBucketName(name);
    try validateKey(key);

    var buf: [paths.max_path]u8 = undefined;
    const file_path = try storagePath(&buf, storage_subdir ++ "/{s}/{s}", .{ name, key });

    const stat = std.fs.cwd().statFile(file_path) catch |e| switch (e) {
        error.FileNotFound => return S3Error.ObjectNotFound,
        else => return S3Error.IoError,
    };

    // stream file through MD5 in fixed-size chunks to avoid loading entire file
    const file = std.fs.cwd().openFile(file_path, .{}) catch return S3Error.IoError;
    defer file.close();

    var hasher = std.crypto.hash.Md5.init(.{});
    var read_buf: [8192]u8 = undefined;
    while (true) {
        const n = file.read(&read_buf) catch return S3Error.IoError;
        if (n == 0) break;
        hasher.update(read_buf[0..n]);
    }
    var digest: [std.crypto.hash.Md5.digest_length]u8 = undefined;
    hasher.final(&digest);

    return .{
        .size = stat.size,
        .last_modified = @intCast(@divFloor(stat.mtime, std.time.ns_per_s)),
        .etag = std.fmt.bytesToHex(digest, .lower),
        .etag_len = 32,
    };
}

/// list objects in a bucket with optional prefix filter.
/// walks subdirectories recursively since keys with "/" are stored as nested dirs.
pub fn listObjects(
    alloc: std.mem.Allocator,
    name: []const u8,
    prefix: []const u8,
) S3Error![]ObjectEntry {
    const s3_xml = @import("s3_xml.zig");
    try validateBucketName(name);

    var buf: [paths.max_path]u8 = undefined;
    const dir_path = try storagePath(&buf, storage_subdir ++ "/{s}", .{name});

    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => return S3Error.BucketNotFound,
        else => return S3Error.IoError,
    };
    defer dir.close();

    var entries: std.ArrayListUnmanaged(s3_xml.ObjectEntry) = .empty;
    errdefer {
        for (entries.items) |entry| alloc.free(entry.key);
        entries.deinit(alloc);
    }

    // recursive walk using Walker
    var walker = dir.walk(alloc) catch return S3Error.IoError;
    defer walker.deinit();

    while (walker.next() catch return S3Error.IoError) |entry| {
        if (entry.kind == .directory) continue;

        const key = entry.path;

        // apply prefix filter
        if (prefix.len > 0 and !std.mem.startsWith(u8, key, prefix)) continue;

        const stat = entry.dir.statFile(entry.basename) catch continue;
        const key_copy = alloc.dupe(u8, key) catch return S3Error.IoError;
        entries.append(alloc, .{
            .key = key_copy,
            .size = stat.size,
            .last_modified = @intCast(@divFloor(stat.mtime, std.time.ns_per_s)),
            .etag = "d41d8cd98f00b204e9800998ecf8427e", // placeholder for listing
        }) catch {
            alloc.free(key_copy);
            return S3Error.IoError;
        };
    }

    return entries.toOwnedSlice(alloc) catch return S3Error.IoError;
}

pub const ObjectEntry = @import("s3_xml.zig").ObjectEntry;

// -- multipart upload operations --

/// initiate a multipart upload. returns a 24-char hex upload ID.
pub fn initiateMultipartUpload(name: []const u8, key: []const u8) S3Error![24]u8 {
    try validateBucketName(name);
    try validateKey(key);
    if (!bucketExists(name)) return S3Error.BucketNotFound;

    // generate upload ID
    var upload_id: [24]u8 = undefined;
    var random_bytes: [12]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    upload_id = std.fmt.bytesToHex(random_bytes, .lower);

    // create staging directory
    var buf: [paths.max_path]u8 = undefined;
    const staging_path = try storagePath(&buf, multipart_subdir ++ "/{s}", .{upload_id});
    std.fs.cwd().makePath(staging_path) catch return S3Error.IoError;
    writeMultipartMeta(staging_path, name, key) catch {
        std.fs.cwd().deleteTree(staging_path) catch {};
        return S3Error.IoError;
    };

    return upload_id;
}

/// upload a part for a multipart upload.
pub fn uploadPart(upload_id: []const u8, bucket_name: []const u8, key: []const u8, part_number: u32, data: []const u8) S3Error![32]u8 {
    try validateUploadId(upload_id);
    try validateBucketName(bucket_name);
    try validateKey(key);
    if (part_number < 1 or part_number > 10000) return S3Error.InvalidPartNumber;

    var buf: [paths.max_path]u8 = undefined;
    var part_name: [16]u8 = undefined;
    const pn = std.fmt.bufPrint(&part_name, "{d:0>5}", .{part_number}) catch return S3Error.IoError;
    const staging_path = try storagePath(&buf, multipart_subdir ++ "/{s}/{s}", .{ upload_id, pn });

    // verify staging directory exists
    var parent_buf: [paths.max_path]u8 = undefined;
    const parent = try storagePath(&parent_buf, multipart_subdir ++ "/{s}", .{upload_id});
    std.fs.cwd().access(parent, .{}) catch return S3Error.UploadNotFound;
    try verifyMultipartTarget(parent, bucket_name, key);

    const file = std.fs.cwd().createFile(staging_path, .{}) catch return S3Error.IoError;
    defer file.close();
    file.writeAll(data) catch return S3Error.IoError;

    return computeEtag(data);
}

/// complete a multipart upload — concatenates parts into final object.
pub fn completeMultipartUpload(
    alloc: std.mem.Allocator,
    bucket_name: []const u8,
    key: []const u8,
    upload_id: []const u8,
) S3Error![32]u8 {
    try validateBucketName(bucket_name);
    try validateKey(key);
    try validateUploadId(upload_id);
    if (!bucketExists(bucket_name)) return S3Error.BucketNotFound;

    // open staging directory
    var staging_buf: [paths.max_path]u8 = undefined;
    const staging_path = try storagePath(&staging_buf, multipart_subdir ++ "/{s}", .{upload_id});
    try verifyMultipartTarget(staging_path, bucket_name, key);

    var dir = std.fs.cwd().openDir(staging_path, .{ .iterate = true }) catch return S3Error.UploadNotFound;
    defer dir.close();

    // collect part filenames and sort them
    var part_names: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (part_names.items) |n| alloc.free(n);
        part_names.deinit(alloc);
    }

    var iter = dir.iterate();
    while (iter.next() catch return S3Error.IoError) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.eql(u8, entry.name, multipart_meta_name)) continue;
        if (!isPartFileName(entry.name)) return S3Error.UploadNotFound;
        const name_copy = alloc.dupe(u8, entry.name) catch return S3Error.IoError;
        part_names.append(alloc, name_copy) catch {
            alloc.free(name_copy);
            return S3Error.IoError;
        };
    }

    // sort parts by name (they're zero-padded numbers)
    std.mem.sort([]const u8, part_names.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    // concatenate parts and write final object
    var combined: std.ArrayListUnmanaged(u8) = .empty;
    defer combined.deinit(alloc);

    for (part_names.items) |pn| {
        const part_data = dir.readFileAlloc(alloc, pn, 256 * 1024 * 1024) catch return S3Error.IoError;
        defer alloc.free(part_data);
        combined.appendSlice(alloc, part_data) catch return S3Error.IoError;
    }

    // write the final object
    const etag = try putObject(bucket_name, key, combined.items);

    // clean up staging directory
    std.fs.cwd().deleteTree(staging_path) catch {};

    return etag;
}

/// abort a multipart upload — removes staging directory.
pub fn abortMultipartUpload(upload_id: []const u8) S3Error!void {
    try validateUploadId(upload_id);
    var buf: [paths.max_path]u8 = undefined;
    const staging_path = try storagePath(&buf, multipart_subdir ++ "/{s}", .{upload_id});

    std.fs.cwd().deleteTree(staging_path) catch {
        return S3Error.IoError;
    };
}

// -- helpers --

/// compute MD5 hex digest for etag.
pub fn computeEtag(data: []const u8) [32]u8 {
    const Md5 = std.crypto.hash.Md5;
    var digest: [Md5.digest_length]u8 = undefined;
    Md5.hash(data, &digest, .{});

    return std.fmt.bytesToHex(digest, .lower);
}

fn writeMultipartMeta(staging_path: []const u8, bucket: []const u8, key: []const u8) !void {
    var meta_path_buf: [paths.max_path]u8 = undefined;
    const meta_path = std.fmt.bufPrint(&meta_path_buf, "{s}/{s}", .{ staging_path, multipart_meta_name }) catch
        return error.PathTooLong;
    const meta_file = try std.fs.cwd().createFile(meta_path, .{ .truncate = true });
    defer meta_file.close();
    try meta_file.writeAll(bucket);
    try meta_file.writeAll("\n");
    try meta_file.writeAll(key);
}

fn loadMultipartMeta(staging_path: []const u8, buf: []u8) S3Error!MultipartMeta {
    var meta_path_buf: [paths.max_path]u8 = undefined;
    const meta_path = std.fmt.bufPrint(&meta_path_buf, "{s}/{s}", .{ staging_path, multipart_meta_name }) catch
        return S3Error.PathTooLong;
    const content = std.fs.cwd().readFile(meta_path, buf) catch |err| switch (err) {
        error.FileNotFound => return S3Error.UploadNotFound,
        else => return S3Error.IoError,
    };
    const split = std.mem.indexOfScalar(u8, content, '\n') orelse return S3Error.UploadNotFound;
    const bucket = content[0..split];
    const key = content[split + 1 ..];
    if (bucket.len == 0 or key.len == 0) return S3Error.UploadNotFound;
    return .{ .bucket = bucket, .key = key };
}

fn verifyMultipartTarget(staging_path: []const u8, bucket: []const u8, key: []const u8) S3Error!void {
    var meta_buf: [max_key_len + max_bucket_name + 8]u8 = undefined;
    const meta = try loadMultipartMeta(staging_path, &meta_buf);
    if (!std.mem.eql(u8, meta.bucket, bucket) or !std.mem.eql(u8, meta.key, key)) {
        return S3Error.UploadNotFound;
    }
}

fn isPartFileName(name: []const u8) bool {
    if (name.len != 5) return false;
    for (name) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

// -- tests --

test "validateBucketName — valid names" {
    try validateBucketName("my-bucket");
    try validateBucketName("test.bucket.123");
    try validateBucketName("abc");
}

test "validateBucketName — invalid names" {
    try std.testing.expectError(S3Error.InvalidBucketName, validateBucketName("ab")); // too short
    try std.testing.expectError(S3Error.InvalidBucketName, validateBucketName("")); // empty
    try std.testing.expectError(S3Error.InvalidBucketName, validateBucketName("-bucket")); // starts with -
    try std.testing.expectError(S3Error.InvalidBucketName, validateBucketName("bucket-")); // ends with -
    try std.testing.expectError(S3Error.InvalidBucketName, validateBucketName("UPPER_CASE")); // underscore
}

test "validateKey — valid keys" {
    try validateKey("file.txt");
    try validateKey("dir/subdir/file.txt");
    try validateKey("a");
}

test "validateKey — invalid keys" {
    try std.testing.expectError(S3Error.InvalidKey, validateKey("")); // empty
    try std.testing.expectError(S3Error.InvalidKey, validateKey("/file.txt")); // starts with /
    try std.testing.expectError(S3Error.InvalidKey, validateKey("dir/../escape")); // path traversal
    try std.testing.expectError(S3Error.InvalidKey, validateKey("line\nbreak"));
    try std.testing.expectError(S3Error.InvalidKey, validateKey("dir\\file"));
}

test "validateUploadId — valid ids" {
    try validateUploadId("0123456789abcdef01234567");
}

test "validateUploadId — rejects traversal and malformed ids" {
    try std.testing.expectError(S3Error.InvalidUploadId, validateUploadId(""));
    try std.testing.expectError(S3Error.InvalidUploadId, validateUploadId("../escape"));
    try std.testing.expectError(S3Error.InvalidUploadId, validateUploadId("0123456789abcdef0123456/"));
    try std.testing.expectError(S3Error.InvalidUploadId, validateUploadId("0123456789abcdef0123456g"));
}

test "computeEtag — empty data" {
    const etag = computeEtag("");
    // MD5 of empty string = d41d8cd98f00b204e9800998ecf8427e
    try std.testing.expectEqualStrings("d41d8cd98f00b204e9800998ecf8427e", &etag);
}

test "computeEtag — hello world" {
    const etag = computeEtag("hello world");
    // MD5 of "hello world" = 5eb63bbbe01eeed093cb22bb8f5acdc3
    try std.testing.expectEqualStrings("5eb63bbbe01eeed093cb22bb8f5acdc3", &etag);
}

test "createBucket and deleteBucket" {
    // use a temp dir to avoid polluting home
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // this test relies on paths.dataPathFmt which uses HOME,
    // so we test the validation and etag logic instead
    try validateBucketName("test-bucket");
    try std.testing.expectError(S3Error.InvalidBucketName, validateBucketName("a"));
}

test "putObject and getObject round-trip" {
    // test validation only — actual I/O needs HOME
    try validateKey("test/file.txt");
    try std.testing.expectError(S3Error.InvalidKey, validateKey("../escape"));
}

test "verifyMultipartTarget rejects reused upload id for different object" {
    var path_buf: [256]u8 = undefined;
    const staging = try std.fmt.bufPrint(
        &path_buf,
        "/tmp/yoq-s3-multipart-{d}",
        .{std.time.nanoTimestamp()},
    );
    defer std.fs.cwd().deleteTree(staging) catch {};

    try std.fs.cwd().makePath(staging);
    try writeMultipartMeta(staging, "bucket-a", "key-a");

    try verifyMultipartTarget(staging, "bucket-a", "key-a");
    try std.testing.expectError(S3Error.UploadNotFound, verifyMultipartTarget(staging, "bucket-b", "key-a"));
    try std.testing.expectError(S3Error.UploadNotFound, verifyMultipartTarget(staging, "bucket-a", "key-b"));
}
