const std = @import("std");
const spec = @import("../../manifest/spec.zig");

pub const Upstream = struct {
    service: []const u8,
    endpoint_id: []const u8,
    address: []const u8,
    port: u16,
    eligible: bool = true,
    /// service-to-service mTLS posture, copied from the service's manifest.
    /// when `.off` the dial stays plaintext and uses the existing connection
    /// pool; when `.warn` or `.require` the dial runs an mTLS handshake and
    /// the resulting session is **not pooled** (each session carries its own
    /// encryption state — sharing it across requests is unsafe).
    peer_mode: spec.TlsConfig.PeerMode = .off,

    pub fn deinit(self: Upstream, alloc: std.mem.Allocator) void {
        alloc.free(self.service);
        alloc.free(self.endpoint_id);
        alloc.free(self.address);
    }
};
