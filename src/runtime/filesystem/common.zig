pub const FilesystemError = error{
    MountFailed,
    MountPermissionDenied,
    PivotFailed,
    UnmountFailed,
    MkdirFailed,
    PathTooLong,
    SymlinkNotAllowed,
    BindSourceIsSymlink,
    BindSourceValidationFailed,
};

pub const FilesystemConfig = struct {
    lower_dirs: []const []const u8,
    upper_dir: []const u8,
    work_dir: []const u8,
    merged_dir: []const u8,
};
