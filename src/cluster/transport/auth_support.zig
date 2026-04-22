const std = @import("std");
const types = @import("../raft_types.zig");
const common = @import("common.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const NodeId = types.NodeId;
const PeerAddr = common.PeerAddr;
const TransportError = common.TransportError;
const VerifiedBody = common.VerifiedBody;

pub fn applyHmac(
    alloc: std.mem.Allocator,
    shared_key: ?[32]u8,
    local_id: ?NodeId,
    data: []const u8,
) ![]const u8 {
    const key = shared_key orelse return data;
    const sender_id = local_id orelse return TransportError.SendFailed;
    if (data.len < 5) return TransportError.SendFailed;

    const body = data[4..];
    var sender_buf: [8]u8 = undefined;
    common.writeU64(&sender_buf, sender_id);
    var hmac_tag: [32]u8 = undefined;
    var hmac = HmacSha256.init(&key);
    hmac.update(&sender_buf);
    hmac.update(body);
    hmac.final(&hmac_tag);

    const authenticated_len = body.len + 8 + 32;
    if (authenticated_len > std.math.maxInt(u32)) return TransportError.SendFailed;

    const out = try alloc.alloc(u8, 4 + 8 + 32 + body.len);
    std.mem.writeInt(u32, out[0..4], @intCast(authenticated_len), .little);
    @memcpy(out[4..12], &sender_buf);
    @memcpy(out[12..44], &hmac_tag);
    @memcpy(out[44..], body);
    return out;
}

pub fn verifyAuthenticatedBody(
    body: []const u8,
    key: [32]u8,
    from_addr: @import("compat").net.Address,
    peers: *const std.AutoHashMap(NodeId, PeerAddr),
) TransportError!VerifiedBody {
    if (body.len < 41) return TransportError.AuthenticationFailed;

    const sender_bytes = body[0..8];
    const received_hmac = body[8..40];
    const signed_data = body[40..];

    var expected: [32]u8 = undefined;
    var hmac = HmacSha256.init(&key);
    hmac.update(sender_bytes);
    hmac.update(signed_data);
    hmac.final(&expected);

    if (!std.crypto.timing_safe.eql([32]u8, received_hmac[0..32].*, expected)) {
        return TransportError.AuthenticationFailed;
    }

    const sender_id = common.readU64(sender_bytes);
    const peer = peers.get(sender_id) orelse return TransportError.AuthenticationFailed;
    if (!common.samePeerIp(peer.addr, from_addr)) return TransportError.AuthenticationFailed;

    return .{
        .sender_id = sender_id,
        .payload = signed_data,
    };
}
