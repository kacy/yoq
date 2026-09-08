//! Durable identity is created before enrollment, then retained across uncertain
//! responses and process restarts. Different join targets/tokens use different files.
const std = @import("std");
const paths = @import("../../lib/paths.zig");
const private_bytes = @import("../../lib/master_key.zig");
const wireguard = @import("../../network/wireguard.zig");

pub const Identity = struct {
    registration_key: [64]u8,
    keypair: wireguard.KeyPair,

    pub fn validateResponse(self: *const Identity, alloc: std.mem.Allocator, body: []const u8, credential: []const u8) !void {
        const Capability = struct { registration_key_accepted: bool = false };
        const response = try std.json.parseFromSlice(Capability, alloc, body, .{ .ignore_unknown_fields = true });
        defer response.deinit();
        if (response.value.registration_key_accepted and
            (credential.len != 64 or !std.crypto.timing_safe.eql([64]u8, self.registration_key, credential[0..64].*)))
            return error.IdentityMismatch;
    }

    pub fn deinit(self: *Identity) void {
        std.crypto.secureZero(u8, &self.registration_key);
        std.crypto.secureZero(u8, &self.keypair.private_key);
    }
};

pub fn loadOrCreate(address: [4]u8, port: u16, token: []const u8) !Identity {
    try paths.ensureDataDirStrict("enrollment");
    var path_buffer: [paths.max_path]u8 = undefined;
    const path = try paths.dataPath(&path_buffer, "enrollment");
    var dir = try std.Io.Dir.cwd().openDir(std.Options.debug_io, path, .{ .iterate = true });
    defer dir.close(std.Options.debug_io);
    return loadOrCreateAt(dir, address, port, token);
}

fn scopeName(address: [4]u8, port: u16, token: []const u8) [64]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("yoq-enrollment-v1");
    hash.update(&address);
    var encoded_port: [2]u8 = undefined;
    std.mem.writeInt(u16, &encoded_port, port, .big);
    hash.update(&encoded_port);
    hash.update(token);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

fn loadOrCreateAt(dir: std.Io.Dir, address: [4]u8, port: u16, token: []const u8) !Identity {
    const name = scopeName(address, port, token);
    // Independent random halves: disclosing the registration credential to the
    // server does not disclose the worker's WireGuard private key.
    var bytes = try private_bytes.loadOrCreateBytesAt(64, dir, &name);
    defer std.crypto.secureZero(u8, &bytes);
    var keypair = try std.crypto.dh.X25519.KeyPair.generateDeterministic(bytes[32..64].*);
    defer std.crypto.secureZero(u8, &keypair.secret_key);
    var identity: Identity = .{ .registration_key = std.fmt.bytesToHex(bytes[0..32].*, .lower), .keypair = undefined };
    _ = std.base64.standard.Encoder.encode(&identity.keypair.private_key, &keypair.secret_key);
    _ = std.base64.standard.Encoder.encode(&identity.keypair.public_key, &keypair.public_key);
    return identity;
}

test "enrollment identity survives reopen and separates join scopes" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var first = try loadOrCreateAt(tmp.dir, .{ 10, 0, 0, 1 }, 7700, "cluster-a");
    defer first.deinit();
    var reopened = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer reopened.close(std.testing.io);
    var retry = try loadOrCreateAt(reopened, .{ 10, 0, 0, 1 }, 7700, "cluster-a");
    defer retry.deinit();
    try std.testing.expectEqualDeep(first, retry);
    const request = try @import("request_support.zig").buildRegisterBody(std.testing.allocator, "cluster-a", "10.0.0.2", 7701, .{ .cpu_cores = 1, .memory_mb = 512 }, &retry.keypair.public_key, 51820, .agent, null, &retry.registration_key);
    defer std.testing.allocator.free(request);
    const wire = try std.json.parseFromSlice(struct { registration_key: []const u8, wg_public_key: []const u8 }, std.testing.allocator, request, .{ .ignore_unknown_fields = true });
    defer wire.deinit();
    try std.testing.expectEqualStrings(&first.registration_key, wire.value.registration_key);
    try std.testing.expectEqualStrings(&first.keypair.public_key, wire.value.wg_public_key);
    for ([_]struct { address: [4]u8, port: u16, token: []const u8 }{
        .{ .address = .{ 10, 0, 0, 2 }, .port = 7700, .token = "cluster-a" },
        .{ .address = .{ 10, 0, 0, 1 }, .port = 7701, .token = "cluster-a" },
        .{ .address = .{ 10, 0, 0, 1 }, .port = 7700, .token = "cluster-b" },
    }) |scope| {
        var other = try loadOrCreateAt(tmp.dir, scope.address, scope.port, scope.token);
        defer other.deinit();
        try std.testing.expect(!std.mem.eql(u8, &first.registration_key, &other.registration_key));
        try std.testing.expect(!std.mem.eql(u8, &first.keypair.private_key, &other.keypair.private_key));
    }
}

test "enrollment identity rejects incomplete persisted data" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const name = scopeName(.{ 10, 0, 0, 1 }, 7700, "cluster-a");
    var file = try tmp.dir.createFile(std.testing.io, &name, .{ .permissions = .fromMode(0o600) });
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, "partial");
    try std.testing.expectError(error.KeyLoadFailed, loadOrCreateAt(tmp.dir, .{ 10, 0, 0, 1 }, 7700, "cluster-a"));
}

test "enrollment identity validates acknowledged credential and accepts legacy response" {
    const identity = Identity{ .registration_key = [_]u8{'a'} ** 64, .keypair = undefined };
    try identity.validateResponse(std.testing.allocator, "{\"registration_key_accepted\":true}", &identity.registration_key);
    try std.testing.expectError(error.IdentityMismatch, identity.validateResponse(std.testing.allocator, "{\"registration_key_accepted\":true}", "wrong"));
    try identity.validateResponse(std.testing.allocator, "{}", "legacy-credential");
}
