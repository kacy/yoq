const std = @import("std");
const linux_platform = @import("linux_platform");
const types = @import("../raft_types.zig");
const common = @import("common.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const NodeId = types.NodeId;
const PeerAddr = common.PeerAddr;
const TransportError = common.TransportError;
const VerifiedBody = common.VerifiedBody;

// tcp and udp share this header: sender id (8 bytes), then hmac-sha256 (32 bytes).
// the tag covers the sender id followed by the payload.
pub const authenticated_header_size = 8 + HmacSha256.mac_length;

pub const AuthenticatedFrame = struct {
    sender_id: NodeId,
    payload: []const u8,
};

fn computeTag(key: [32]u8, sender_bytes: *const [8]u8, payload: []const u8) [32]u8 {
    var tag: [32]u8 = undefined;
    var hmac = HmacSha256.init(&key);
    hmac.update(sender_bytes);
    hmac.update(payload);
    hmac.final(&tag);
    return tag;
}

// writes into buf and returns the occupied slice, without a tcp length prefix.
pub fn encodeAuthenticatedFrame(
    buf: []u8,
    key: [32]u8,
    sender_id: NodeId,
    payload: []const u8,
) TransportError![]const u8 {
    if (buf.len < authenticated_header_size or
        payload.len > buf.len - authenticated_header_size)
    {
        return TransportError.SendFailed;
    }

    const frame = buf[0 .. authenticated_header_size + payload.len];
    common.writeU64(frame[0..8], sender_id);
    const tag = computeTag(key, frame[0..8], payload);
    @memcpy(frame[8..authenticated_header_size], &tag);
    @memcpy(frame[authenticated_header_size..], payload);
    return frame;
}

// checks the tag and borrows the payload from frame. the caller decides whether
// the authenticated sender is an allowed peer for this transport.
pub fn verifyAuthenticatedFrame(frame: []const u8, key: [32]u8) TransportError!AuthenticatedFrame {
    if (frame.len < authenticated_header_size) return TransportError.AuthenticationFailed;

    const sender_bytes = frame[0..8];
    const received_tag = frame[8..authenticated_header_size];
    const payload = frame[authenticated_header_size..];
    const expected_tag = computeTag(key, sender_bytes, payload);
    if (!std.crypto.timing_safe.eql([32]u8, received_tag.*, expected_tag)) {
        return TransportError.AuthenticationFailed;
    }

    return .{ .sender_id = common.readU64(sender_bytes), .payload = payload };
}

// without a key, the result borrows data. with a key, the caller owns the result.
pub fn applyHmac(
    alloc: std.mem.Allocator,
    shared_key: ?[32]u8,
    local_id: ?NodeId,
    data: []const u8,
) ![]const u8 {
    const key = shared_key orelse return data;
    const sender_id = local_id orelse return TransportError.SendFailed;
    if (data.len < 5) return TransportError.SendFailed;

    // replace the plain tcp length prefix with the authenticated body length.
    const payload = data[4..];
    if (payload.len > std.math.maxInt(u32) - authenticated_header_size) {
        return TransportError.SendFailed;
    }
    const authenticated_len = authenticated_header_size + payload.len;
    const out = try alloc.alloc(u8, 4 + authenticated_len);
    errdefer alloc.free(out);
    std.mem.writeInt(u32, out[0..4], @intCast(authenticated_len), .little);
    _ = try encodeAuthenticatedFrame(out[4..], key, sender_id, payload);
    return out;
}

pub fn verifyAuthenticatedBody(
    body: []const u8,
    key: [32]u8,
    from_addr: linux_platform.net.Address,
    peers: *const std.AutoHashMap(NodeId, PeerAddr),
) TransportError!VerifiedBody {
    // a tcp message needs at least its one-byte message type after the header.
    if (body.len <= authenticated_header_size) return TransportError.AuthenticationFailed;

    const authenticated = try verifyAuthenticatedFrame(body, key);
    const peer = peers.get(authenticated.sender_id) orelse return TransportError.AuthenticationFailed;
    if (!common.samePeerIp(peer.addr, from_addr)) return TransportError.AuthenticationFailed;

    return .{
        .sender_id = authenticated.sender_id,
        .payload = authenticated.payload,
    };
}
