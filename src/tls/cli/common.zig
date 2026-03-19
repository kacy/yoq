pub const TlsCommandsError = error{
    InvalidArgument,
    CertificateNotFound,
    StoreFailed,
    ReadFailed,
    NotSupported,
    OutOfMemory,
};
