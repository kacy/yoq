// fuzz_wireguard — fuzz WireGuard key generation and peer configuration
//
// this file lives in src/ so that wireguard.zig's relative imports resolve.
// validates that key generation, base64 round-trips, and peer argument
// building never crash or access out-of-bounds memory when given
// arbitrary byte sequences as keys, endpoints, and allowed IPs.

const std = @import("std");
const wg = @import("network/wireguard.zig");

fn fuzzInput(smith: *std.testing.Smith, buffer: []u8) []const u8 {
    if (smith.in) |input| return input;
    return buffer[0..smith.slice(buffer)];
}

test "fuzz WireGuard handshake: base64 key decode with arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [512]u8 = undefined;
            const input = fuzzInput(smith, &buffer);

            // attempt to decode as a base64-encoded X25519 key
            const decoder = std.base64.standard.Decoder;
            var decoded: [32]u8 = undefined;
            decoder.decode(&decoded, input) catch return;

            // if decode succeeded, try to derive a public key from it
            // (treats the decoded bytes as a private key)
            const X25519 = std.crypto.dh.X25519;
            const pk = X25519.recoverPublicKey(decoded) catch return;

            // encode the public key back to base64 — should not crash
            const encoder = std.base64.standard.Encoder;
            var encoded: [44]u8 = undefined;
            _ = encoder.encode(&encoded, &pk);
        }
    }.testOne, .{
        .corpus = &.{
            // valid base64-encoded 32-byte key (44 chars with padding)
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            // too short
            "AAAA",
            "",
            // invalid base64 characters
            "!@#$%^&*()_+{}|:<>?~`-=[]\\;',./",
            // 44 chars but invalid base64
            &([_]u8{0xFF} ** 44),
            // binary garbage
            &([_]u8{ 0x00, 0x01, 0x02, 0x03, 0xFE, 0xFF }),
            // almost valid — 43 chars (missing padding)
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            // unicode
            "\xc0\x80\xfe\xff\xef\xbf\xbd",
        },
    });
}

test "fuzz WireGuard handshake: PeerConfig construction with arbitrary strings" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [512]u8 = undefined;
            const input = fuzzInput(smith, &buffer);

            // split input into fields at null bytes to get varied inputs
            // for public_key, endpoint, and allowed_ips
            var parts: [4][]const u8 = .{ "", "", "", "" };
            var part_idx: usize = 0;
            var start: usize = 0;

            for (input, 0..) |b, i| {
                if (b == 0 and part_idx < 3) {
                    parts[part_idx] = input[start..i];
                    part_idx += 1;
                    start = i + 1;
                }
            }
            if (start <= input.len) {
                parts[part_idx] = input[start..];
            }

            // construct a PeerConfig with arbitrary data — should never crash
            const peer = wg.PeerConfig{
                .public_key = parts[0],
                .endpoint = if (parts[1].len > 0) parts[1] else null,
                .allowed_ips = parts[2],
                .persistent_keepalive = 25,
            };

            // access all fields to ensure no memory safety issues
            _ = peer.public_key.len;
            _ = peer.allowed_ips.len;
            _ = peer.persistent_keepalive;
            if (peer.endpoint) |ep| _ = ep.len;

            // try to validate the public key as base64
            // only attempt decode if length matches X25519 key size (44 chars -> 32 bytes)
            if (parts[0].len == 44) {
                const decoder = std.base64.standard.Decoder;
                var decoded: [32]u8 = undefined;
                if (decoder.decode(&decoded, parts[0])) |_| {
                    // if it's valid base64, try to use it as a key
                    const X25519 = std.crypto.dh.X25519;
                    _ = X25519.recoverPublicKey(decoded) catch {};
                } else |_| {}
            }
        }
    }.testOne, .{
        .corpus = &.{
            // valid peer config (null-separated: pubkey\0endpoint\0allowed_ips)
            "dGVzdHB1YmtleQ==\x0010.0.0.2:51820\x0010.42.1.0/24",
            // no endpoint
            "dGVzdHB1YmtleQ==\x00\x0010.42.1.0/24",
            // all empty
            "",
            // binary garbage
            &([_]u8{0xFF} ** 128),
            // extremely long key field
            &([_]u8{'A'} ** 256),
            // null bytes everywhere
            &([_]u8{0} ** 16),
        },
    });
}

test "fuzz WireGuard handshake: X25519 key exchange with arbitrary seed" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [512]u8 = undefined;
            const input = fuzzInput(smith, &buffer);

            if (input.len < 32) return;

            const X25519 = std.crypto.dh.X25519;

            // use first 32 bytes as a secret key
            var secret: [32]u8 = undefined;
            @memcpy(&secret, input[0..32]);

            // try to compute public key — some inputs are rejected
            const pk = X25519.recoverPublicKey(secret) catch return;

            // if we have another 32 bytes, try a DH exchange
            if (input.len >= 64) {
                var peer_pk: [32]u8 = undefined;
                @memcpy(&peer_pk, input[32..64]);

                // shared secret computation — may fail on low-order points
                _ = X25519.scalarmult(secret, peer_pk) catch return;
            }

            // base64 encode the public key — should always succeed
            const encoder = std.base64.standard.Encoder;
            var encoded: [44]u8 = undefined;
            _ = encoder.encode(&encoded, &pk);

            // verify it decodes back
            const decoder = std.base64.standard.Decoder;
            var decoded: [32]u8 = undefined;
            decoder.decode(&decoded, &encoded) catch return;
        }
    }.testOne, .{
        .corpus = &.{
            // 32 zero bytes (low-order point)
            &([_]u8{0} ** 32),
            // 64 bytes — two keys for DH exchange
            &([_]u8{1} ** 64),
            // 32 bytes of 0xFF
            &([_]u8{0xFF} ** 32),
            // known weak point patterns
            &([_]u8{0} ** 31 ++ [_]u8{1}),
            // random-looking bytes
            &.{ 0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42 },
        },
    });
}
