// one command may contain an atomic placement transaction. keep its limit
// separate from framing overhead so a full-sized transaction still fits.
pub const max_command_bytes: usize = 1024 * 1024;
pub const append_header_bytes: usize = 49;
pub const entry_header_bytes: usize = 20;
pub const max_append_frame_bytes: usize = append_header_bytes + entry_header_bytes + max_command_bytes;
