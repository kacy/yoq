// Keep the privileged mount test module rooted at src so filesystem helpers
// can import the same shared library files as the runtime.
pub const bindMount = @import("runtime/filesystem/mount_ops.zig").bindMount;
