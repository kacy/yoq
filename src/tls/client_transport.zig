// Compatibility import for the TLS callers of the shared socket transport.
const transport = @import("../lib/socket_stream.zig");
pub const Error = transport.Error;
pub const Deadline = transport.Deadline;
pub const Stream = transport.Stream;
pub const stream = transport.stream;
