const common = @import("common.zig");

pub fn deriveEarlySecret() [common.hash_len]u8 {
    const zero_ikm = [_]u8{0} ** common.hash_len;
    const zero_salt = [_]u8{0} ** common.hash_len;
    return common.HkdfSha384.extract(&zero_salt, &zero_ikm);
}

pub fn deriveHandshakeSecret(early_secret: [common.hash_len]u8, shared_secret: [32]u8) [common.hash_len]u8 {
    const empty_hash = hashEmpty();
    const derived = expandLabel(early_secret, "derived", &empty_hash, common.hash_len);
    return common.HkdfSha384.extract(&derived, &shared_secret);
}

pub fn deriveHandshakeTrafficSecrets(
    handshake_secret: [common.hash_len]u8,
    transcript_hash: [common.hash_len]u8,
) common.HandshakeKeys {
    const c_hs = expandLabel(handshake_secret, "c hs traffic", &transcript_hash, common.hash_len);
    const s_hs = expandLabel(handshake_secret, "s hs traffic", &transcript_hash, common.hash_len);

    return .{
        .client_handshake_traffic_secret = c_hs,
        .server_handshake_traffic_secret = s_hs,
        .handshake_secret = handshake_secret,
    };
}

pub fn deriveTrafficKeys(secret: [common.hash_len]u8) common.TrafficKeys {
    const key = expandLabel(secret, "key", &.{}, @sizeOf(@FieldType(common.TrafficKeys, "key")));
    const iv = expandLabel(secret, "iv", &.{}, @sizeOf(@FieldType(common.TrafficKeys, "iv")));

    return .{
        .key = key[0..@sizeOf(@FieldType(common.TrafficKeys, "key"))].*,
        .iv = iv[0..@sizeOf(@FieldType(common.TrafficKeys, "iv"))].*,
    };
}

pub fn deriveMasterSecret(handshake_secret: [common.hash_len]u8) [common.hash_len]u8 {
    const empty_hash = hashEmpty();
    const derived = expandLabel(handshake_secret, "derived", &empty_hash, common.hash_len);
    const zero_ikm = [_]u8{0} ** common.hash_len;
    return common.HkdfSha384.extract(&derived, &zero_ikm);
}

pub fn deriveApplicationSecrets(
    master_secret: [common.hash_len]u8,
    transcript_hash: [common.hash_len]u8,
) common.ApplicationKeys {
    const c_ap = expandLabel(master_secret, "c ap traffic", &transcript_hash, common.hash_len);
    const s_ap = expandLabel(master_secret, "s ap traffic", &transcript_hash, common.hash_len);

    return .{
        .client = deriveTrafficKeys(c_ap),
        .server = deriveTrafficKeys(s_ap),
    };
}

pub fn computeFinished(base_key: [common.hash_len]u8, transcript_hash: [common.hash_len]u8) [common.hash_len]u8 {
    const finished_key = expandLabel(base_key, "finished", &.{}, common.hash_len);
    var hmac = common.HmacSha384.init(&finished_key);
    hmac.update(&transcript_hash);
    var result: [common.hash_len]u8 = undefined;
    hmac.final(&result);
    return result;
}

pub fn expandLabel(secret: [common.hash_len]u8, comptime label: []const u8, context: []const u8, comptime length: usize) [length]u8 {
    const full_label = "tls13 " ++ label;

    var info: [256]u8 = undefined;
    var pos: usize = 0;

    info[pos] = @intCast(length >> 8);
    info[pos + 1] = @intCast(length & 0xFF);
    pos += 2;

    info[pos] = @intCast(full_label.len);
    pos += 1;
    @memcpy(info[pos .. pos + full_label.len], full_label);
    pos += full_label.len;

    info[pos] = @intCast(context.len);
    pos += 1;
    if (context.len > 0) {
        @memcpy(info[pos .. pos + context.len], context);
        pos += context.len;
    }

    var out: [length]u8 = undefined;
    common.HkdfSha384.expand(&out, info[0..pos], secret);
    return out;
}

pub fn hashEmpty() [common.hash_len]u8 {
    var h = common.Sha384.init(.{});
    var result: [common.hash_len]u8 = undefined;
    h.final(&result);
    return result;
}
