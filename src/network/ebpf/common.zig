pub const EbpfError = error{
    MapCreateFailed,
    MapUpdateFailed,
    ProgramLoadFailed,
    AttachFailed,
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
