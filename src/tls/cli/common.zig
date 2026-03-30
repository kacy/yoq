pub const TlsCommandsError = error{
    InvalidArgument,
    CertificateNotFound,
    StoreFailed,
    ReadFailed,
    AcmeFailed,
    NetworkFailed,
    NotSupported,
    OutOfMemory,
};
