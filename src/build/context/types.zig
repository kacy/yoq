pub const ContextError = error{
    /// content hashing failed (file read error or directory walk error)
    HashFailed,
    /// file copy from build context to layer directory failed
    CopyFailed,
    /// source path does not exist in the build context
    NotFound,
    /// source path attempts to escape the build context via ".." or symlink resolution
    PathTraversal,
};
