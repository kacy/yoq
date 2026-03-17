const blob_store = @import("../store.zig");

pub const LayerError = error{
    /// gzip decompression or tar extraction failed
    ExtractionFailed,
    /// layer digest not found in the blob store
    BlobNotFound,
    /// constructed layer path exceeds max_path buffer
    PathTooLong,
    /// HOME environment variable not set, can't locate data directory
    HomeDirNotFound,
    /// one or more layers in assembleRootfs failed to extract
    AssemblyFailed,
    /// failed to create a new layer from a directory
    CreateFailed,
    /// tar archive contained an unsupported entry type
    UnsupportedEntry,
};

pub const LayerCreateResult = struct {
    /// digest of the compressed (gzipped tar) layer — used in manifest
    compressed_digest: blob_store.Digest,
    /// digest of the uncompressed tar — used in config diff_ids
    uncompressed_digest: blob_store.Digest,
    /// size of the compressed layer in bytes
    compressed_size: u64,
};
