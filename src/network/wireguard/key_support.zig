const std = @import("std");
const platform = @import("platform");
const types = @import("types.zig");

pub fn generateKeyPair() types.WireguardError!types.KeyPair {
    const X25519 = std.crypto.dh.X25519;
    var raw_kp = X25519.KeyPair.generate(platform.io());
    defer std.crypto.secureZero(u8, &raw_kp.secret_key);

    var kp: types.KeyPair = undefined;
    const encoder = std.base64.standard.Encoder;

    _ = encoder.encode(&kp.private_key, &raw_kp.secret_key);
    _ = encoder.encode(&kp.public_key, &raw_kp.public_key);

    return kp;
}
