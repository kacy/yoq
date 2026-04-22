const std = @import("std");
const paths = @import("../../lib/paths.zig");

pub const BlobError = error{
    WriteFailed,
    ReadFailed,
    NotFound,
    HashMismatch,
    PathTooLong,
    HomeDirNotFound,
};

pub const max_path = paths.max_path;
pub const blob_subdir = "blobs/sha256";

pub const BlobHandle = struct {
    file: @import("compat").File,
    size: u64,

    pub fn close(self: *BlobHandle) void {
        self.file.close();
    }
};
