pub const EbpfError = error{
    MapCreateFailed,
    MapUpdateFailed,
    ProgramLoadFailed,
    AttachFailed,
    /// Replacement is installed, but one or more legacy filters remain.
    LegacyCleanupFailed,
    DetachFailed,
    NotSupported,
    InvalidParameter,
    MapFull,
    SizeMismatch,
    ResourceExhausted,
    Timeout,
};

pub const Direction = enum {
    ingress,
    egress,
};
