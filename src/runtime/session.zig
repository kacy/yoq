// Process stdio, terminal ownership, and attachment transport share one layer.
pub const Server = @import("session/server.zig").Server;
pub const attach = @import("session/client.zig").attach;
pub const ProcessIo = @import("session/process_io.zig").ProcessIo;
pub const foreground = @import("session/foreground.zig");
pub const terminal = @import("session/terminal.zig");
pub const protocol = @import("session/protocol.zig");

pub const Output = struct {
    context: *anyopaque,
    write: *const fn (*anyopaque, []const u8, []const u8) void,

    pub fn send(self: Output, stream: []const u8, bytes: []const u8) void {
        self.write(self.context, stream, bytes);
    }
};

test {
    _ = @import("session/process_io.zig");
    _ = protocol;
    _ = @import("session/server.zig");
    _ = @import("session/client.zig");
}
